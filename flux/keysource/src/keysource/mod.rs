//! [`KeySource`] trait, [`KeySessionHandle`], and the caller-storage
//! [`KeySessionSlot`] — the machinery every key source shares.
//!
//! A key source answers one question: *open me a signing session*. Where the
//! material comes from (steel-plate QR scan vs. secure element) and what
//! `auth` means there is implementation-defined; see [`KeySource`].

use core::mem::MaybeUninit;

use shlosilo::types::key_session::KeySession;

pub mod qr;

pub use qr::QrKeySource;

/// Why a key source refused to open — or failed to hand over — a session.
///
/// The `AuthFailed` / `SeComm` variants exist for the secure-element source
/// (PIN rejection / SE transport failure); the QR path never produces them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySourceErrorKind {
    /// The `auth` credential was rejected (SE/PIN sources only).
    AuthFailed,
    /// No key material is staged: never loaded, or already consumed by an
    /// earlier `open_session`.
    NoSession,
    /// Secure-element communication failure (SE sources only).
    SeComm,
    /// Key material present but rejected (derivation/decode failure).
    DecodeRejected,
    /// The single session slot is already occupied.
    Capacity,
}

/// Key source failure: a small, `Copy`-able error (flux diagnostics style,
/// same shape as `forms::error::ShlosiloError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySourceError {
    pub kind: KeySourceErrorKind,
}

impl KeySourceError {
    pub const fn new(kind: KeySourceErrorKind) -> Self {
        Self { kind }
    }
}

impl core::fmt::Display for KeySourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.kind)
    }
}

/// Key-material acquisition face (flux side).
///
/// # `auth` semantics are per implementation
///
/// - **SE source (future)**: `auth` is the device password / PIN; rejection is
///   [`KeySourceErrorKind::AuthFailed`].
/// - **QR source ([`QrKeySource`])**: the material is already in RAM when the
///   session opens, so `auth` is **semantically empty** — a non-empty `auth`
///   is accepted and ignored (never an error), exactly as the frozen QR
///   contract requires ("QR = 无参").
///
/// # Lifecycle
///
/// `open_session` derives the [`KeySession`] and writes it IN PLACE into the
/// source's [`KeySessionSlot`] (caller storage, `MaybeUninit` — never `Box`),
/// then hands back a single-owner [`KeySessionHandle`]. The handle is not
/// `Copy`/`Clone` and is moved into [`KeySource::close_session`] when done;
/// dropping the handle is the fallback close (a safety net for error paths
/// that skip the explicit close). Either way the drop runs exactly once and
/// `KeySession: ZeroizeOnDrop` wipes the key bytes.
pub trait KeySource<'s> {
    /// Open a session from the staged material.
    ///
    /// Errors: [`KeySourceErrorKind::Capacity`] if the slot is occupied (the
    /// staged material survives for a retry), [`KeySourceErrorKind::NoSession`]
    /// if nothing is staged / it was already consumed,
    /// [`KeySourceErrorKind::DecodeRejected`] if the material fails to derive.
    fn open_session(&mut self, auth: &str) -> Result<KeySessionHandle<'s>, KeySourceError>;

    /// Close the session early (error-path teardown) and zeroize.
    ///
    /// Consuming the handle by value makes re-close impossible in safe code;
    /// a stale/forged handle closes as a defined no-op (never UB, never a
    /// double drop).
    fn close_session(&mut self, handle: KeySessionHandle<'s>);
}

/// Caller-storage session slot (R3 / Z3.3c caller-workspace contract).
///
/// The flux caller owns this memory for the whole session lifetime — a
/// `static` or a task workspace — and lends it to a key source at
/// construction. It is exactly the `MaybeUninit<KeySession>` slot the session
/// FFI contract prescribes ("static slot or caller workspace; never `Box`"),
/// plus the occupancy state the handle's close consults.
///
/// Slot capacity is 1: one live session per slot.
pub struct KeySessionSlot {
    /// Interior-mutability cell: install/close run through a shared `&'s`
    /// reference so [`KeySessionHandle`] can carry a lifetime-tied shared
    /// borrow (the handle's `'s` is structurally bound to the caller's slot —
    /// forging one from a local slot is a compile error, E0515). The cell is
    /// `!Sync`, so cross-thread aliasing of the session is a compile error as
    /// well; the remaining runtime discipline (close-while-borrowing etc.) is
    /// carried by the one-live-handle + serial invariants below.
    inner: core::cell::UnsafeCell<SlotInner>,
}

struct SlotInner {
    session: MaybeUninit<KeySession>,
    state: SlotState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SlotState {
    Empty,
    /// Occupied by the session opened under this serial (double-close guard).
    Occupied(u32),
}

impl KeySessionSlot {
    /// Empty slot. `const` so a caller can place it in a `static`.
    pub const fn empty() -> Self {
        Self {
            inner: core::cell::UnsafeCell::new(SlotInner {
                session: MaybeUninit::uninit(),
                state: SlotState::Empty,
            }),
        }
    }

    /// Is a session live in this slot?
    pub fn is_occupied(&self) -> bool {
        // SAFETY: reads of `state` through the cell are race-free because the
        // cell is `!Sync` (single-owner; interrupt discipline is the same
        // documented contract as the session FFI handles).
        matches!(unsafe { &*self.inner.get() }.state, SlotState::Occupied(_))
    }

    /// Write a freshly derived session into the free slot (in place — the
    /// caller's storage, no allocator involved). Occupied slot is a real
    /// error (defense in depth: the release build must never overwrite and
    /// silently skip the old session's zeroizing drop).
    fn install(&self, session: KeySession, serial: u32) -> Result<(), KeySourceError> {
        // SAFETY: exclusive by the one-live-handle invariant (open-while-
        // occupied is Capacity) + `!Sync`; see `inner` docs.
        let inner = unsafe { &mut *self.inner.get() };
        if matches!(inner.state, SlotState::Occupied(_)) {
            return Err(KeySourceError::new(KeySourceErrorKind::Capacity));
        }
        inner.session = MaybeUninit::new(session);
        inner.state = SlotState::Occupied(serial);
        Ok(())
    }

    /// Close the live session if `serial` is the one that opened it: drop in
    /// place (`ZeroizeOnDrop` wipes the key bytes) and mark the slot empty.
    ///
    /// A stale or duplicate handle sees a serial/state mismatch and this is a
    /// defined no-op — the drop glue runs exactly once per session.
    fn close_if(&self, serial: u32) {
        // SAFETY: shared-ref interior access; the state machine serializes
        // drops (state cleared before `assume_init_drop`, so re-entry or a
        // duplicated handle can never drop twice). See `inner` docs.
        let inner = unsafe { &mut *self.inner.get() };
        if inner.state == SlotState::Occupied(serial) {
            inner.state = SlotState::Empty;
            // SAFETY: `Occupied(serial)` means `session` was `install`ed and
            // not yet dropped; the state is cleared BEFORE the drop, so no
            // re-entry (re-panic, duplicate handle) can drop twice.
            unsafe { inner.session.assume_init_drop() };
        }
    }

    /// Borrow the session live under `serial`; `None` for a stale handle.
    fn live_session(&self, serial: u32) -> Option<&KeySession> {
        // SAFETY: shared borrow of the installed session; the returned
        // reference borrows `&self`, so `close_if` (which needs the handle by
        // value) cannot run while it is live. Serial gate → stale = `None`.
        let inner = unsafe { &*self.inner.get() };
        if inner.state == SlotState::Occupied(serial) {
            // SAFETY: same invariant as `close_if` — occupied ⇒ initialized.
            Some(unsafe { inner.session.assume_init_ref() })
        } else {
            None
        }
    }
}

impl Drop for KeySessionSlot {
    fn drop(&mut self) {
        // Defensive teardown: a slot dropped while occupied still zeroizes.
        // `&mut self` gives exclusive access, so the cell is not contended.
        if let SlotState::Occupied(serial) = unsafe { &*self.inner.get() }.state {
            self.close_if(serial);
        }
    }
}

/// Single-owner handle to a live [`KeySession`] in a [`KeySessionSlot`].
///
/// - Not `Copy`/`Clone`: each copy would double the live-key access surface
///   (v2-security §2 discipline, same as `KeySession` itself).
/// - **Drop closes**: dropping the handle drops the session in place
///   (`ZeroizeOnDrop` wipe) and frees the slot. [`KeySource::close_session`]
///   is the explicit form (error paths close early on purpose).
/// - **Lifetime**: the handle borrows the caller's slot (`'s`), so safe code
///   cannot move or drop the slot while the handle — and therefore the
///   session — is live. Do NOT use one handle concurrently (another thread /
///   interrupt), same rule as the session FFI handles.
/// - **Double-close defense**: the slot tracks which serial is live; a stale
///   or duplicated handle closes as a defined no-op (no UB, no double drop).
pub struct KeySessionHandle<'s> {
    /// Lifetime-tied shared borrow of the caller's slot: `'s` is structurally
    /// bound to this reference, so a handle can never outlive its slot —
    /// forging one from a function-local slot is E0515 (see the compile-fail
    /// probe on [`KeySessionHandle::new`]).
    slot: &'s KeySessionSlot,
    serial: u32,
}

impl<'s> KeySessionHandle<'s> {
    /// Build a handle for the session just installed in `slot`.
    ///
    /// For [`KeySource`] implementations (e.g. `QrKeySource` today,
    /// `SeKeySource` in its own crate later) — callers use
    /// [`KeySource::open_session`]. The `serial` must be the one
    /// [`KeySessionSlot::install`] stamped on the session.
    ///
    /// The lifetime of the returned handle is bound to `slot`: any attempt to
    /// return a handle outliving the slot fails to compile.
    ///
    /// ```compile_fail,E0515
    /// use shlosilo_flux_keysource::keysource::{KeySessionHandle, KeySessionSlot};
    /// fn forge() -> KeySessionHandle<'static> {
    ///     let slot = KeySessionSlot::empty();
    ///     // ERROR: borrowed data escapes outside of function (E0515) —
    ///     // the handle's `'s` is tied to `slot`, which dies at the end of
    ///     // this function. This is the UAF probe: it MUST stay red.
    ///     KeySessionHandle::new(&slot, 1)
    /// }
    /// ```
    pub fn new(slot: &'s KeySessionSlot, serial: u32) -> KeySessionHandle<'s> {
        KeySessionHandle { slot, serial }
    }

    /// Borrow the live session (e.g. to sign). `None` once the handle is
    /// stale (already closed through a duplicate) — defined, never UB.
    pub fn session(&self) -> Option<&KeySession> {
        // SAFETY: the slot outlives the handle by construction (`'s` on the
        // stored reference); the serial gate makes stale access return `None`.
        self.slot.live_session(self.serial)
    }

    /// Is the session still live for this handle?
    pub fn is_open(&self) -> bool {
        self.session().is_some()
    }
}

impl Drop for KeySessionHandle<'_> {
    fn drop(&mut self) {
        // `close_if` is serial-guarded, so a stale/duplicate handle drops as
        // a defined no-op. The slot is borrowed for 's, hence valid here.
        self.slot.close_if(self.serial);
    }
}

// Redacted Debug (KeySession style): serial + liveness are diagnostics, the
// pointed-at session (key material) is never printed.
impl core::fmt::Debug for KeySessionHandle<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeySessionHandle")
            .field("serial", &self.serial)
            .field("open", &self.is_open())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-vector convention (tests/key_session_ffi.rs): fixed plaintext
    /// entropy fixtures, never real seed material.
    const FIXTURE_ENTROPY: [u8; 16] = [
        0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29,
        0x16,
    ];

    fn open_fixture(slot: &KeySessionSlot) -> KeySessionHandle<'_> {
        let serial = 1;
        slot.install(
            KeySession::from_entropy(&FIXTURE_ENTROPY, b"").expect("session"),
            serial,
        )
        .expect("install into empty slot");
        KeySessionHandle::new(slot, serial)
    }

    // Forensic byte view of the slot: used by the zeroization poison tests.
    // NOTE: after a close, the session region is formally uninitialized
    // (MaybeUninit) but physically zeroed by ZeroizeOnDrop; the raw byte copy
    // below is deliberate forensic practice, test-only (not in the Miri
    // subset, which covers forms only).
    fn slot_bytes(slot: &KeySessionSlot) -> [u8; core::mem::size_of::<KeySessionSlot>()] {
        let mut out = [0u8; core::mem::size_of::<KeySessionSlot>()];
        unsafe {
            core::ptr::copy_nonoverlapping(
                slot as *const KeySessionSlot as *const u8,
                out.as_mut_ptr(),
                out.len(),
            );
        }
        out
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    /// Reference key bytes for the fixture, derived independently of the
    /// slot (same derivation the session ran) — the poison patterns.
    fn reference_keys() -> ([u8; 32], [u8; 32]) {
        let s = KeySession::from_entropy(&FIXTURE_ENTROPY, b"").expect("session");
        let m = s.monero();
        let mut spend = [0u8; 32];
        spend.copy_from_slice(m.spend_sk.expose());
        let mut view = [0u8; 32];
        view.copy_from_slice(m.view_sk.expose());
        (spend, view)
    }

    // NOTE on borrow discipline in these tests: the handle borrows the slot
    // for its lifetime (that is the move/drop protection), so the slot itself
    // can only be inspected once every handle is dead. Liveness mid-flight is
    // asserted through the handle instead.

    #[test]
    fn handle_drop_closes_and_frees_the_slot() {
        let slot = KeySessionSlot::empty();
        assert!(!slot.is_occupied());
        let h = open_fixture(&slot);
        assert!(h.is_open());
        drop(h); // 兜底 close: drop_in_place + ZeroizeOnDrop
        assert!(!slot.is_occupied(), "handle drop must free the slot");
    }

    #[test]
    fn double_close_is_a_defined_noop() {
        let slot = KeySessionSlot::empty();
        let h = open_fixture(&slot);
        // TEST-ONLY misuse probe: duplicate the single-owner handle the way a
        // buggy caller could (ptr::read). The serial guard must make the
        // second close a no-op — defined behavior, never UB / double drop.
        let dup = unsafe { core::ptr::read(&h) };
        assert!(h.is_open());
        assert!(dup.is_open());
        drop(h); // closes: drop_in_place + slot empty
        assert!(!dup.is_open(), "stale handle: defined state");
        assert!(dup.session().is_none());
        drop(dup); // second close: serial/state mismatch → no-op
        assert!(
            !slot.is_occupied(),
            "double close must not corrupt the slot"
        );
    }

    #[test]
    fn handle_is_not_copy_or_clone() {
        // P1-03 compile-fail equivalent: adding Copy/Clone breaks this build.
        static_assertions::assert_not_impl_any!(KeySessionHandle<'static>: Copy, Clone);
        // Drop = the fallback close (兜底): the drop glue must exist.
        assert!(core::mem::needs_drop::<KeySessionHandle<'static>>());
    }

    /// Zeroization poison: the close path MUST wipe the key bytes. Deleting
    /// the `assume_init_drop` in `close_if` turns this red (`close must wipe
    /// the spend key bytes`) — the mutation kill the plain tests missed.
    #[test]
    fn close_wipes_key_bytes() {
        let slot = KeySessionSlot::empty();
        let h = open_fixture(&slot);
        let (spend, view) = reference_keys();
        let before = slot_bytes(&slot);
        assert!(
            contains(&before, &spend) && contains(&before, &view),
            "precondition: live key bytes visible in the slot"
        );
        drop(h);
        let after = slot_bytes(&slot);
        assert!(
            !contains(&after, &spend),
            "close must wipe the spend key bytes"
        );
        assert!(
            !contains(&after, &view),
            "close must wipe the view key bytes"
        );
    }

    /// Same poison for the slot's own Drop fallback (previously name-only).
    #[test]
    fn slot_drop_while_occupied_zeroizes() {
        let mut slot = core::mem::ManuallyDrop::new(KeySessionSlot::empty());
        let h = open_fixture(&slot);
        // Worst-case caller bug: leak the handle — the SLOT's Drop must still
        // close the session (drop glue exactly once, zeroize intact).
        core::mem::forget(h);
        let (spend, view) = reference_keys();
        let before = slot_bytes(&slot);
        assert!(contains(&before, &spend) && contains(&before, &view));
        unsafe { core::mem::ManuallyDrop::drop(&mut slot) };
        let after = slot_bytes(&slot);
        assert!(
            !contains(&after, &spend) && !contains(&after, &view),
            "slot Drop must wipe the key bytes"
        );
    }

    /// Debug redaction: the handle's Debug must never leak key bytes.
    /// Stack-buffered `core::fmt::Write` — no allocator tokens in this file
    /// (the no_persistence face greps for them).
    #[test]
    fn handle_debug_is_redacted() {
        struct StackBuf {
            buf: [u8; 256],
            len: usize,
        }
        impl core::fmt::Write for StackBuf {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let b = s.as_bytes();
                let n = b.len().min(self.buf.len() - self.len);
                self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
                self.len += n;
                Ok(())
            }
        }
        let slot = KeySessionSlot::empty();
        let h = open_fixture(&slot);
        let mut sb = StackBuf {
            buf: [0u8; 256],
            len: 0,
        };
        use core::fmt::Write as _;
        let _ = core::write!(&mut sb, "{:?}", h);
        let (spend, view) = reference_keys();
        assert!(
            !contains(&sb.buf[..sb.len], &spend) && !contains(&sb.buf[..sb.len], &view),
            "Debug output must not contain key material"
        );
    }
}
