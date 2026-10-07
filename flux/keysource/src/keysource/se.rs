//! [`SeKeySource`]: secure-element-fed key source — password unlock to a
//! signing session (Task 8, Phase 3 close-out).
//!
//! Pipeline (the C chain, keystone3-parity): `LoadAccountSecret` (keystore
//! data plane: SE key pieces + HMAC + AES slot decrypt) → `entropy` →
//! [`KeySession::from_entropy`] → the caller's [`KeySessionSlot`]. The
//! password enters, a session handle comes out — **the seed/entropy never
//! crosses a new FFI signature** (it is consumed here, in RAM).
//!
//! # `auth` semantics (contrast with [`super::QrKeySource`])
//!
//! Here `auth` IS the device password (non-empty = the real credential):
//! - wrong password → [`KeySourceErrorKind::AuthFailed`] — **one attempt,
//!   refused, never retried, never downgraded** to another key source;
//! - empty `auth` → `AuthFailed` (an empty string can never be the password;
//!   the keystore floor is `MIN_PASSWORD_LEN` = 6);
//! - over-long `auth` (> [`PASSWORD_MAX_LEN`], what the SE side clamps to) →
//!   `AuthFailed` — rejected rather than silently truncated to another
//!   credential's length.
//!
//! # Trust boundary (pool item #24)
//!
//! `AccountSecret_t.entropyLen` arrives from the *unauthenticated* param page
//! (the HMAC covers the encrypted slot, not this length byte). It is
//! **untrusted input**: only 16 or 32 is accepted (the two shapes
//! [`KeySession::from_entropy`] derives); anything else is
//! [`KeySourceErrorKind::DecodeRejected`] BEFORE any slice is formed — a
//! lying 255 must never become a `&entropy[..255]` over a 32-byte buffer.
//! (Pool item #24 note: `entropyLen = 0` is silently coerced to 32 in the C
//! layer — keystore.c:228 `(entropyLen == 0) ? 32 : …`, keystone3 parity,
//! unchanged — so tampering the byte to 0 is equivalent to specifying 32 and
//! the real chain can never deliver a 0 here.)
//!
//! # Key hygiene
//!
//! - the password is copied into a stack buffer only for the C call and
//!   wiped with a volatile walk immediately after (dead-store elimination
//!   cannot drop the wipe);
//! - the whole decrypted [`AccountSecret`] (entropy AND seed AND the
//!   reserved tail) is wiped before return on every path — only the
//!   `KeySession`'s own `ZeroizeOnDrop` fields survive;
//! - close = zeroize through the same single-owner [`KeySessionHandle`]
//!   discipline as the QR source (`slot.open()` is the sole handle source).
//!
//! # Account scope (v1)
//!
//! Account index 0 only. keystone3 resolves the account from the password
//! (`FindAccountByPassword`, pool item #23 neighbourhood) — not yet ported;
//! multi-account unlock rides that port. The fixed index is marked at the
//! call site below.

use core::ffi::c_char;

use shlosilo::types::key_session::KeySession;

use super::{KeySessionHandle, KeySessionSlot, KeySource, KeySourceError, KeySourceErrorKind};

/// keystone3 `se_manager.h` PASSWORD_MAX_LEN: the SE piece derivations clamp
/// the password with `strnlen_s(password, PASSWORD_MAX_LEN)`. A longer input
/// could never authenticate (it would be compared truncated), so it is
/// refused up front instead of silently aliasing a shorter password.
pub const PASSWORD_MAX_LEN: usize = 128;

/// v1 account scope: account slot 0. `FindAccountByPassword` (keystone3
/// account lookup by credential) is not ported yet (pool item #23
/// neighbourhood) — multi-account unlock waits for it.
const ACCOUNT_INDEX_V1: u8 = 0;

/// keystore `err_code.h` `ERR_KEYSTORE_AUTH` — the one wrong-password /
/// HMAC-rejection outcome of the keystore data plane. The firmware-side
/// `_Static_assert` in product_task.c pins this value against the header.
const ERR_KEYSTORE_AUTH: i32 = 20;

/// Success code (`err_code.h` `SUCCESS_CODE`).
const C_SUCCESS: i32 = 0;

/// C mirror of keystore.h `AccountSecret_t` (field order and sizes verbatim —
/// the struct is an internal wire between `LoadAccountSecret` and here, both
/// sides of one link unit).
#[repr(C)]
pub struct AccountSecret {
    pub entropy: [u8; 32],
    pub seed: [u8; 64],
    pub slip39_ems_or_ton_entropy_l32: [u8; 32],
    pub reserved_data: [u8; 32],
    /// Untrusted (pool item #24) — see the module docs. Only 16/32 accepted.
    pub entropy_len: u8,
}

impl AccountSecret {
    const fn zeroed() -> Self {
        Self {
            entropy: [0u8; 32],
            seed: [0u8; 64],
            slip39_ems_or_ton_entropy_l32: [0u8; 32],
            reserved_data: [0u8; 32],
            entropy_len: 0,
        }
    }

    /// Volatile wipe of every byte of the decrypted secret (entropy, seed,
    /// reserved tail, length). Runs on EVERY exit path.
    fn wipe(&mut self) {
        wipe_bytes(&mut self.entropy);
        wipe_bytes(&mut self.seed);
        wipe_bytes(&mut self.slip39_ems_or_ton_entropy_l32);
        wipe_bytes(&mut self.reserved_data);
        wipe_bytes(core::slice::from_mut(&mut self.entropy_len));
    }
}

/// Volatile wipe (dead-store-elimination-proof): same walk as
/// `product_task.c`'s plate wipe (pool item #22 direction).
fn wipe_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: writing a valid `u8` through its own exclusive borrow.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    // The writes must be complete before any later observation of the
    // buffer; a compiler fence keeps the volatile writes ordered against
    // surrounding non-volatile code.
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// The C chain (Task 6/7 port: keystore data plane + SE communication plane).
// Provided by flux/forgebox/src/keystore/keystore.c in the firmware; the host
// tests substitute a behavioural shim at link level (tests/se_ffi.rs — the
// same shim discipline as tests/host_keystore / tests/host_se).
extern "C" {
    /// keystore.h `LoadAccountSecret(accountIndex, accountSecret, password)`:
    /// password-gated read of one encrypted account slot. `password` is a
    /// NUL-terminated C string.
    fn LoadAccountSecret(
        account_index: u8,
        account_secret: *mut AccountSecret,
        password: *const c_char,
    ) -> i32;
}

/// Secure-element key source: one caller-storage slot + the SE-backed
/// account slot behind it.
///
/// Nothing is staged here (contrast [`super::QrKeySource`]): the material
/// lives in the SE, so every [`KeySource::open_session`] is a fresh
/// password-gated load. Semantics (pinned by `tests/se_ffi.rs`):
/// - **`auth` is the real password** (empty/over-long → `AuthFailed`);
/// - **one attempt, no retry, no fallback** — a rejected password surfaces
///   as [`KeySourceErrorKind::AuthFailed`] and nothing else runs;
/// - **slot capacity is 1**: occupied slot → [`KeySourceErrorKind::Capacity`]
///   checked FIRST (before any credential attempt reaches the SE), so
///   "unlock while unlocked" is refused without burning an auth attempt;
/// - **`close_session`** drops the handle in place (`ZeroizeOnDrop` wipes the
///   key bytes) and frees the slot — same discipline as the QR source.
pub struct SeKeySource<'s> {
    /// Shared slot borrow: the handle handed out by `open_session` carries
    /// the same `'s`, so it can never outlive the caller's storage. A
    /// `static` slot works (`&'static`).
    slot: &'s KeySessionSlot,
}

impl<'s> SeKeySource<'s> {
    /// New SE source over the caller's slot (empty or not — occupancy is
    /// checked at open, `slot.open()` stays the sole handle source).
    pub const fn new(slot: &'s KeySessionSlot) -> Self {
        Self { slot }
    }

    /// Open a session with a byte-string password (the FFI/console path —
    /// passwords are bytes, not necessarily UTF-8).
    ///
    /// Errors: [`KeySourceErrorKind::Capacity`] (slot busy — the password
    /// never reaches the SE), [`KeySourceErrorKind::AuthFailed`] (empty /
    /// over-long / wrong password, one shot),
    /// [`KeySourceErrorKind::SeComm`] (the SE/keystore path failed for a
    /// reason that is not the password),
    /// [`KeySourceErrorKind::DecodeRejected`] (entropyLen not 16/32 — pool
    /// item #24 — or derivation failure).
    pub fn open_session_with_password(
        &mut self,
        password: &[u8],
    ) -> Result<KeySessionHandle<'s>, KeySourceError> {
        // Capacity FIRST: a busy slot must not consume a credential attempt
        // (and must never disturb the live session).
        if self.slot.is_occupied() {
            return Err(KeySourceError::new(KeySourceErrorKind::Capacity));
        }
        // Empty or over-long password: refused BEFORE the SE sees anything.
        if password.is_empty() || password.len() > PASSWORD_MAX_LEN {
            return Err(KeySourceError::new(KeySourceErrorKind::AuthFailed));
        }
        // Stack NUL-terminated copy for the C call (fixed size, Z6). The
        // length is already bounded by PASSWORD_MAX_LEN, so this cannot
        // overflow.
        let mut pw = [0u8; PASSWORD_MAX_LEN + 1];
        pw[..password.len()].copy_from_slice(password);
        let mut secret = AccountSecret::zeroed();
        // SAFETY: `pw` is a valid NUL-terminated string of ≤ PASSWORD_MAX_LEN
        // bytes (checked above); `secret` is a valid out-struct. Single
        // thread (the flux key path is single-owner, `!Sync` slot discipline).
        let ret = unsafe {
            LoadAccountSecret(ACCOUNT_INDEX_V1, &mut secret, pw.as_ptr() as *const c_char)
        };
        // Password hygiene: the stack copy dies HERE on every path (volatile
        // walk — never a bare memset).
        wipe_bytes(&mut pw);
        if ret != C_SUCCESS {
            // Error normalization (invariant): the wrong password is
            // AuthFailed — refused once, no retry, no fallback. Everything
            // else on the C path is the SE/keystore transport.
            secret.wipe();
            let kind = if ret == ERR_KEYSTORE_AUTH {
                KeySourceErrorKind::AuthFailed
            } else {
                KeySourceErrorKind::SeComm
            };
            return Err(KeySourceError::new(kind));
        }
        // Pool item #24: `entropyLen` is an UNAUTHENTICATED byte. Validate
        // the value before it is ever used as a length — only 16/32 may reach
        // `from_entropy`; 33/255/anything else is refused (it must never
        // form a slice over the 32-byte entropy buffer). Defense-in-depth:
        // in the real chain a stored 0 is ALREADY coerced to 32 at
        // keystore.c:228 (keystone3 parity — see the module docs), so this
        // gate catches the other tampered values of the unauthenticated byte
        // (pool item #24), not the 0 case.
        let entropy_len = secret.entropy_len as usize;
        if entropy_len != 16 && entropy_len != 32 {
            secret.wipe();
            return Err(KeySourceError::new(KeySourceErrorKind::DecodeRejected));
        }
        let session = KeySession::from_entropy(&secret.entropy[..entropy_len], b"");
        // The decrypted account secret (entropy AND seed) dies before the
        // session goes live — only the KeySession's ZeroizeOnDrop fields
        // persist (SecretBytes hygiene).
        secret.wipe();
        let session =
            session.map_err(|_| KeySourceError::new(KeySourceErrorKind::DecodeRejected))?;
        // In-place into the CALLER's slot (MaybeUninit-backed, never Boxed).
        // `open` is the sole handle source (serial is slot-owned) and
        // refuses while occupied — never overwrites a live session.
        self.slot
            .open(session)
            .map_err(|_| KeySourceError::new(KeySourceErrorKind::Capacity))
    }
}

impl<'s> KeySource<'s> for SeKeySource<'s> {
    /// `auth` is the real password here (non-empty semantics — see the
    /// module docs): unlike [`super::QrKeySource`] it is never ignored.
    fn open_session(&mut self, auth: &str) -> Result<KeySessionHandle<'s>, KeySourceError> {
        self.open_session_with_password(auth.as_bytes())
    }

    fn close_session(&mut self, handle: KeySessionHandle<'s>) {
        // Consuming drop = drop_in_place (ZeroizeOnDrop) + slot cleared, the
        // serial guard making any stale duplicate a defined no-op. Same
        // discipline as the QR source: explicit close for error paths, the
        // handle's Drop as the fallback.
        drop(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wipe must actually zero the buffer (volatile walk, not a no-op).
    #[test]
    fn wipe_bytes_zeroes() {
        let mut buf = [0xAAu8; 40];
        wipe_bytes(&mut buf);
        assert!(
            buf.iter().all(|&b| b == 0),
            "volatile wipe must zero all bytes"
        );
    }

    /// AccountSecret::wipe covers every field (entropy + seed + tail + len).
    #[test]
    fn account_secret_wipe_covers_all_fields() {
        let mut s = AccountSecret::zeroed();
        s.entropy = [0x11u8; 32];
        s.seed = [0x22u8; 64];
        s.slip39_ems_or_ton_entropy_l32 = [0x33u8; 32];
        s.reserved_data = [0x44u8; 32];
        s.entropy_len = 32;
        s.wipe();
        assert!(s.entropy.iter().all(|&b| b == 0));
        assert!(s.seed.iter().all(|&b| b == 0));
        assert!(s.slip39_ems_or_ton_entropy_l32.iter().all(|&b| b == 0));
        assert!(s.reserved_data.iter().all(|&b| b == 0));
        assert_eq!(s.entropy_len, 0);
    }
}
