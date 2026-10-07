//! [`QrKeySource`]: steel-plate / QR-fed key source — thin shell, RAM only.
//!
//! The scan flow feeds it a [`SeedEntropy`] (the `seed_qr::decode` product);
//! `open_session` takes that staged material, derives a [`KeySession`], and
//! writes it into the caller's [`KeySessionSlot`] in place. **No
//! persistence**: the material never leaves RAM (threat model: a powered-down
//! device holds zero key material) — nothing here touches flash or a
//! filesystem.

use shlosilo::entropy::seed_qr::SeedEntropy;
use shlosilo::types::key_session::KeySession;

use super::{KeySessionHandle, KeySessionSlot, KeySource, KeySourceError, KeySourceErrorKind};

/// QR-fed key source: one staged [`SeedEntropy`] + one caller-storage slot.
///
/// Semantics (frozen contract):
/// - **construction/loading** takes `SeedEntropy` — [`QrKeySource::new`] or
///   [`QrKeySource::load`] (the scan flow re-feeds after a close);
/// - **`auth` is semantically empty** — the material is already in RAM, so a
///   non-empty `auth` is accepted and ignored (never an error);
/// - **`open_session` consumes the staged material** (`take`): not loaded or
///   already consumed → [`KeySourceErrorKind::NoSession`];
/// - **slot capacity is 1**: occupied slot → [`KeySourceErrorKind::Capacity`]
///   (checked FIRST, so the staged material survives for a retry after close);
/// - **`close_session`** drops the session in place (`ZeroizeOnDrop` wipes the
///   key bytes) and clears the slot; dropping the handle does the same as a
///   fallback.
pub struct QrKeySource<'s> {
    /// Shared slot borrow (interior-mutability slot): the handle handed out by
    /// [`KeySource::open_session`] carries the same `'s`, so it can never
    /// outlive the caller's storage. A `static` slot works (`&'static`).
    slot: &'s KeySessionSlot,
    /// Staged scan material, RAM-only (dropped = zeroized).
    pending: Option<SeedEntropy>,
    /// Next handle serial (wrapping; a wrap needs 2^32 opens to matter).
    next_serial: u32,
}

impl<'s> QrKeySource<'s> {
    /// New source with material staged (the scan flow just decoded a plate).
    pub fn new(slot: &'s KeySessionSlot, entropy: SeedEntropy) -> Self {
        Self {
            slot,
            pending: Some(entropy),
            next_serial: 1,
        }
    }

    /// New source with nothing staged (scan not done yet) — `open_session`
    /// answers [`KeySourceErrorKind::NoSession`] until [`QrKeySource::load`].
    pub fn empty(slot: &'s KeySessionSlot) -> Self {
        Self {
            slot,
            pending: None,
            next_serial: 1,
        }
    }

    /// Stage scanned material. Any previously staged material is dropped
    /// (zeroized) — RAM-only, never written anywhere persistent.
    pub fn load(&mut self, entropy: SeedEntropy) {
        self.pending = Some(entropy);
    }

    /// Is material staged? (diagnostics)
    pub fn has_material(&self) -> bool {
        self.pending.is_some()
    }
}

impl<'s> KeySource<'s> for QrKeySource<'s> {
    fn open_session(&mut self, _auth: &str) -> Result<KeySessionHandle<'s>, KeySourceError> {
        // Capacity FIRST: a busy slot must not consume the staged material —
        // the caller can close the live session and retry without re-scanning.
        if self.slot.is_occupied() {
            return Err(KeySourceError::new(KeySourceErrorKind::Capacity));
        }
        // take() — the staged material is single-use (未入料/已消耗 → NoSession).
        // NOTE: a DecodeRejected outcome also consumes the material (take()
        // already ran) — the caller must re-scan to retry. This is the frozen
        // "consumes" contract, not a bug.
        let entropy = self
            .pending
            .take()
            .ok_or_else(|| KeySourceError::new(KeySourceErrorKind::NoSession))?;
        // `auth` is semantically empty on the QR path (frozen contract: material
        // is already in RAM; a non-empty auth is accepted and IGNORED, never an
        // error and never a passphrase) — the passphrase is always empty here.
        let session = KeySession::from_entropy(entropy.expose(), b"")
            .map_err(|_| KeySourceError::new(KeySourceErrorKind::DecodeRejected))?;
        // Staged plaintext dies before the session goes live (SecretBytes
        // hygiene: only the KeySession's own ZeroizeOnDrop fields persist).
        drop(entropy);
        let serial = self.next_serial;
        self.next_serial = self.next_serial.wrapping_add(1);
        // In-place into the CALLER's slot (MaybeUninit-backed, never Boxed).
        // install is also a real guard (never overwrites a live session).
        self.slot.install(session, serial)?;
        Ok(KeySessionHandle::new(self.slot, serial))
    }

    fn close_session(&mut self, handle: KeySessionHandle<'s>) {
        // Consuming drop = drop_in_place (ZeroizeOnDrop) + slot cleared, the
        // serial guard making any stale duplicate a defined no-op. The
        // explicit call exists so error paths close early on purpose instead
        // of waiting for the handle's fallback drop.
        drop(handle);
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
    /// 24-word fixture entropy (KeySession's other supported shape).
    const FIXTURE_ENTROPY_24: [u8; 32] = [0x11u8; 32];

    fn entropy16() -> SeedEntropy {
        SeedEntropy::from_entropy(&FIXTURE_ENTROPY).expect("entropy")
    }

    /// Reference: the same material fed straight to `KeySession::from_entropy`.
    fn expected_keys(entropy: &[u8]) -> ([u8; 32], [u8; 32]) {
        let s = KeySession::from_entropy(entropy, b"").expect("session");
        (*s.monero().spend_sk.expose(), *s.monero().view_sk.expose())
    }

    /// Task 4 test 1: load → open → close full cycle. The session keys must
    /// match direct `from_entropy`, and closing must free the slot for a
    /// re-open (re-fed material).
    #[test]
    fn full_cycle_keys_match_from_entropy_and_slot_reopens() {
        let slot = KeySessionSlot::empty();
        let mut src = QrKeySource::new(&slot, entropy16());
        let h = src.open_session("").expect("open");
        let (spend, view) = expected_keys(&FIXTURE_ENTROPY);
        assert_eq!(
            h.session().expect("live").monero().spend_sk.expose(),
            &spend
        );
        assert_eq!(h.session().expect("live").monero().view_sk.expose(), &view);
        src.close_session(h);
        // The slot is free again: a FREE slot answers NoSession (an occupied
        // one answers Capacity) on an empty open.
        let err = src.open_session("").expect_err("consumed");
        assert_eq!(err.kind, KeySourceErrorKind::NoSession);

        // close 后槽位可重开 (24-word material through the same source).
        src.load(SeedEntropy::from_entropy(&FIXTURE_ENTROPY_24).expect("entropy"));
        let h2 = src.open_session("").expect("re-open");
        let (spend2, view2) = expected_keys(&FIXTURE_ENTROPY_24);
        assert_eq!(
            h2.session().expect("live").monero().spend_sk.expose(),
            &spend2
        );
        assert_eq!(
            h2.session().expect("live").monero().view_sk.expose(),
            &view2
        );
        src.close_session(h2);
    }

    /// Task 4 test 2a: never-fed → NoSession; consumed → NoSession again.
    #[test]
    fn open_without_material_is_no_session() {
        let slot = KeySessionSlot::empty();
        let mut src = QrKeySource::empty(&slot);
        let err = src.open_session("").expect_err("no material");
        assert_eq!(err.kind, KeySourceErrorKind::NoSession);

        src.load(entropy16());
        let h = src.open_session("").expect("open");
        src.close_session(h);
        // Staged material was consumed by the open (take semantics).
        let err = src.open_session("").expect_err("consumed");
        assert_eq!(err.kind, KeySourceErrorKind::NoSession);
    }

    /// Task 4 test 2b: occupied slot → Capacity (and the newly staged
    /// material must SURVIVE the failed open for a retry after close).
    #[test]
    fn open_while_occupied_is_capacity_and_material_survives() {
        let slot = KeySessionSlot::empty();
        let mut src = QrKeySource::new(&slot, entropy16());
        let h = src.open_session("").expect("open");
        // Scan produced a NEW plate while the session is live:
        src.load(SeedEntropy::from_entropy(&FIXTURE_ENTROPY_24).expect("entropy"));
        let err = src.open_session("").expect_err("slot busy");
        assert_eq!(err.kind, KeySourceErrorKind::Capacity);
        assert!(src.has_material(), "Capacity must not consume the material");
        src.close_session(h);
        // Retry without re-scanning: the material survived AND the slot is
        // free (a busy slot would have answered Capacity above).
        let h2 = src.open_session("").expect("retry after close");
        let (spend2, view2) = expected_keys(&FIXTURE_ENTROPY_24);
        assert_eq!(
            h2.session().expect("live").monero().spend_sk.expose(),
            &spend2
        );
        assert_eq!(
            h2.session().expect("live").monero().view_sk.expose(),
            &view2
        );
        src.close_session(h2);
    }

    /// Task 4 test 3: QR auth semantics — non-empty auth is accepted and
    /// semantically empty (keys derive exactly as with an empty auth).
    #[test]
    fn non_empty_auth_is_accepted_and_semantically_empty() {
        let slot = KeySessionSlot::empty();
        let mut src = QrKeySource::new(&slot, entropy16());
        let h = src
            .open_session("1234")
            .expect("auth ignored, not an error");
        let (spend, view) = expected_keys(&FIXTURE_ENTROPY);
        // Ignored = no passphrase: identical to the empty-auth derivation.
        assert_eq!(
            h.session().expect("live").monero().spend_sk.expose(),
            &spend
        );
        assert_eq!(h.session().expect("live").monero().view_sk.expose(), &view);
        src.close_session(h);
    }

    /// Double-close across the trait face: a duplicated handle moved through
    /// `close_session` twice is a defined no-op (serial guard), never UB.
    #[test]
    fn close_session_on_stale_handle_is_defined() {
        let slot = KeySessionSlot::empty();
        let mut src = QrKeySource::new(&slot, entropy16());
        let h = src.open_session("").expect("open");
        // TEST-ONLY misuse probe (see keysource/mod.rs tests).
        let dup = unsafe { core::ptr::read(&h) };
        src.close_session(h);
        src.close_session(dup); // stale: serial mismatch → no-op
                                // Slot intact and free: an empty open answers NoSession, not Capacity.
        let err = src.open_session("").expect_err("consumed");
        assert_eq!(err.kind, KeySourceErrorKind::NoSession);
    }
}
