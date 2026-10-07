//! [`KeySource`] trait, [`KeySessionHandle`], and the caller-storage
//! [`KeySessionSlot`] — the machinery every key source shares.
//!
//! A key source answers one question: *open me a signing session*. Where the
//! material comes from (steel-plate QR scan vs. secure element) and what
//! `auth` means there is implementation-defined; see [`KeySource`].

use core::mem::MaybeUninit;
use core::ptr::NonNull;

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
            session: MaybeUninit::uninit(),
            state: SlotState::Empty,
        }
    }

    /// Is a session live in this slot?
    pub const fn is_occupied(&self) -> bool {
        matches!(self.state, SlotState::Occupied(_))
    }

    /// Write a freshly derived session into the free slot (in place — the
    /// caller's storage, no allocator involved).
    fn install(&mut self, session: KeySession, serial: u32) {
        debug_assert!(!self.is_occupied(), "install over an occupied slot");
        self.session = MaybeUninit::new(session);
        self.state = SlotState::Occupied(serial);
    }

    /// Close the live session if `serial` is the one that opened it: drop in
    /// place (`ZeroizeOnDrop` wipes the key bytes) and mark the slot empty.
    ///
    /// A stale or duplicate handle sees a serial/state mismatch and this is a
    /// defined no-op — the drop glue runs exactly once per session.
    fn close_if(&mut self, serial: u32) {
        if self.state == SlotState::Occupied(serial) {
            self.state = SlotState::Empty;
            // SAFETY: `Occupied(serial)` means `session` was `install`ed and
            // not yet dropped; the state is cleared BEFORE the drop, so no
            // re-entry (re-panic, duplicate handle) can drop twice.
            unsafe { self.session.assume_init_drop() };
        }
    }

    /// Borrow the session live under `serial`; `None` for a stale handle.
    fn live_session(&self, serial: u32) -> Option<&KeySession> {
        if self.state == SlotState::Occupied(serial) {
            // SAFETY: same invariant as `close_if` — occupied ⇒ initialized.
            Some(unsafe { self.session.assume_init_ref() })
        } else {
            None
        }
    }
}

impl Drop for KeySessionSlot {
    fn drop(&mut self) {
        // Defensive teardown: a slot dropped while occupied still zeroizes.
        if let SlotState::Occupied(serial) = self.state {
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
    slot: NonNull<KeySessionSlot>,
    serial: u32,
    /// Carries the slot borrow so the caller's storage cannot move or drop
    /// while this handle is live (drop-check + region inference).
    _slot_borrow: core::marker::PhantomData<&'s mut KeySessionSlot>,
}

impl<'s> KeySessionHandle<'s> {
    /// Build a handle for the session just installed in `slot`.
    ///
    /// For `KeySource` implementations only (crate-internal): the `serial`
    /// must be the one `KeySessionSlot::install` stamped on the session, and
    /// `'s` must be the caller's slot-borrow region. [`QrKeySource`] upholds
    /// both; safe code outside the crate cannot forge a handle.
    pub(crate) fn new(slot: &mut KeySessionSlot, serial: u32) -> KeySessionHandle<'s> {
        KeySessionHandle {
            slot: NonNull::from(slot),
            serial,
            _slot_borrow: core::marker::PhantomData,
        }
    }

    /// Borrow the live session (e.g. to sign). `None` once the handle is
    /// stale (already closed through a duplicate) — defined, never UB.
    pub fn session(&self) -> Option<&KeySession> {
        // SAFETY: the handle's contract keeps the slot alive for 's (see
        // `_slot_borrow`); the serial gate makes stale access return `None`.
        unsafe { self.slot.as_ref() }.live_session(self.serial)
    }

    /// Is the session still live for this handle?
    pub fn is_open(&self) -> bool {
        self.session().is_some()
    }
}

impl Drop for KeySessionHandle<'_> {
    fn drop(&mut self) {
        // SAFETY: slot valid for 's (see `_slot_borrow`); `close_if` is
        // serial-guarded, so a stale/duplicate handle drops as a no-op.
        unsafe { self.slot.as_mut() }.close_if(self.serial);
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

    fn open_fixture(slot: &mut KeySessionSlot) -> KeySessionHandle<'_> {
        let serial = 1;
        slot.install(
            KeySession::from_entropy(&FIXTURE_ENTROPY, b"").expect("session"),
            serial,
        );
        KeySessionHandle::new(slot, serial)
    }

    // NOTE on borrow discipline in these tests: the handle borrows the slot
    // for its lifetime (that is the move/drop protection), so the slot itself
    // can only be inspected once every handle is dead. Liveness mid-flight is
    // asserted through the handle instead.

    #[test]
    fn handle_drop_closes_and_frees_the_slot() {
        let mut slot = KeySessionSlot::empty();
        assert!(!slot.is_occupied());
        let h = open_fixture(&mut slot);
        assert!(h.is_open());
        drop(h); // 兜底 close: drop_in_place + ZeroizeOnDrop
        assert!(!slot.is_occupied(), "handle drop must free the slot");
    }

    #[test]
    fn double_close_is_a_defined_noop() {
        let mut slot = KeySessionSlot::empty();
        let h = open_fixture(&mut slot);
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
    fn slot_drop_while_occupied_zeroizes() {
        let mut slot = KeySessionSlot::empty();
        let h = open_fixture(&mut slot);
        assert!(h.is_open());
        // Leak the handle (worst-case caller bug): the SLOT's own Drop must
        // still close the session — the drop glue runs exactly once, no
        // double drop, zeroize intact. `slot` drops at the end of the test
        // while still occupied.
        core::mem::forget(h);
    }

    #[test]
    fn handle_is_not_copy_or_clone() {
        // P1-03 compile-fail equivalent: adding Copy/Clone breaks this build.
        static_assertions::assert_not_impl_any!(KeySessionHandle<'static>: Copy, Clone);
        // Drop = the fallback close (兜底): the drop glue must exist.
        assert!(core::mem::needs_drop::<KeySessionHandle<'static>>());
    }
}
