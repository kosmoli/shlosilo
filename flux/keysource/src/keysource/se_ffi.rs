//! C-ABI glue for the SE password-unlock flow (Task 8): **password in,
//! session pointer out**.
//!
//! Three entries, mirroring the QR scan-flow glue (`ffi.rs`) — same
//! workspace contract, same handle discipline, and (Task 8) literally the
//! SAME teardown (`ws::ws_close`, shared with
//! `shlosilo_keysource_qr_close_ffi`):
//!
//! - [`shlosilo_keysource_se_ws_len`] — workspace capacity query.
//! - [`shlosilo_keysource_se_open_ffi`] — password → [`SeKeySource`] →
//!   [`KeySession`] in the caller's workspace; hands the live session
//!   pointer out for `shlosilo_sign_session_ffi`.
//! - [`shlosilo_keysource_se_close_ffi`] — drop the live handle in place
//!   (`ZeroizeOnDrop` wipes the key bytes).
//!
//! # Invariants (pinned by `tests/se_ffi.rs`)
//!
//! 1. **Seed/entropy never appears in any FFI signature** — in or out. The
//!    password goes in, a session POINTER goes out; the decrypted material
//!    lives only inside [`SeKeySource`] for the duration of the open.
//! 2. **The workspace is caller-pinned** — `static` / task workspace at a
//!    stable address, never moved or reused while a session is live (same
//!    self-referential contract as the QR glue).
//! 3. **At most one live session per workspace** — a second `open` on a busy
//!    workspace answers `ERR_SLOT_OCCUPIED` (-23) BEFORE any credential
//!    attempt runs (this covers "SE unlock while a QR session is live" when
//!    both entries share one workspace — the product flow does).
//! 4. **`close` is total and idempotent** — fresh workspace, failed open,
//!    already-closed workspace all answer `OK` as a defined no-op; the
//!    zeroizing drop runs exactly once per session. After `close` the same
//!    workspace may be re-opened with a new password.
//! 5. **Wrong password = `ERR_AUTH_FAILED` (-24), one shot** — no retry, no
//!    fallback key source; the out-session stays NULL and the workspace
//!    stays untouched (close on it is still a defined no-op).
//! 6. **`entropyLen` is untrusted (pool item #24)** — only 16/32 derive;
//!    anything else is refused (`MnemonicInvalidEntropyLength`, -31 family)
//!    before any slice is formed.
//!
//! # SAFETY posture
//!
//! Single-threaded firmware discipline, same as the QR glue: one workspace
//! is owned by one execution context — never used concurrently from an
//! interrupt or another thread while a call on it is in flight. All raw
//! dereferences below are bounded by the checked entry contracts documented
//! on each function.

use core::ffi::{c_int, c_uint};

use shlosilo::error::{ShlosiloError, ShlosiloErrorKind};
use shlosilo::ffi::error_code::{
    to_ffi_code, ERR_AUTH_FAILED, ERR_BUFFER_TOO_SMALL, ERR_NULL_POINTER, ERR_SE_COMM,
    ERR_SLOT_OCCUPIED,
};
use shlosilo::types::key_session::KeySession;

use super::se::SeKeySource;
use super::ws;
use super::KeySessionSlot;

/// Workspace capacity for one SE unlock session (same layout as the QR
/// workspace — one shared `ws::KeyWs`, so both queries agree by
/// construction).
#[no_mangle]
pub extern "C" fn shlosilo_keysource_se_ws_len() -> c_uint {
    ws::ws_len()
}

/// Task 8: open a signing session from the account slot behind `password`.
///
/// Pipeline (all in RAM, zero persistence): [`SeKeySource`] runs the C chain
/// `LoadAccountSecret` (account 0, v1) → untrusted-`entropyLen` validation →
/// `KeySession::from_entropy` → [`KeySessionSlot::open`] in the caller
/// workspace. The decrypted secret dies before the session goes live.
///
/// - `ws` / `ws_len`: caller workspace — `shlosilo_keysource_se_ws_len()`
///   bytes, zero-initialized, pinned (module docs). `ws_len` under capacity
///   answers `ERR_BUFFER_TOO_SMALL` (-20) before anything runs.
/// - `password` / `password_len`: the device password bytes (NOT necessarily
///   NUL-terminated — the entry takes an explicit length and copies into its
///   own bounded stack buffer). **The only credential input** — there is no
///   seed/mnemonic parameter (v2 §4.1).
/// - `out_session`: receives the live [`KeySession`] pointer for
///   `shlosilo_sign_session_ffi` — valid until
///   [`shlosilo_keysource_se_close_ffi`]; zeroed (`NULL`) on every failure.
///
/// Returns `0` = Ok, negative = error:
/// - `ERR_NULL_POINTER` (-2): `ws` / `password` / `out_session` NULL;
/// - `ERR_BUFFER_TOO_SMALL` (-20): `ws_len` under capacity;
/// - `ERR_SLOT_OCCUPIED` (-23): a session is already live in this workspace
///   (capacity 1 — close it first; refused BEFORE any password attempt);
/// - `ERR_AUTH_FAILED` (-24): empty / over-long / wrong password (one shot,
///   no retry);
/// - `ERR_SE_COMM` (-25): the SE/keystore path failed for a non-password
///   reason;
/// - `-31` (Invalid mnemonic family): `entropyLen` not 16/32 (pool item #24)
///   or `from_entropy` rejected the material.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: entry null-checks first; all raw derefs below are bounded by that contract
pub extern "C" fn shlosilo_keysource_se_open_ffi(
    ws: *mut u8,
    ws_len: c_uint,
    password: *const u8,
    password_len: c_uint,
    out_session: *mut *const KeySession,
) -> c_int {
    if ws.is_null() || password.is_null() || out_session.is_null() {
        return ERR_NULL_POINTER;
    }
    // Gate4 #2 discipline: out-param zeroed up front — every failure path
    // below leaves a deterministic NULL behind.
    unsafe {
        *out_session = core::ptr::null();
    }
    // Capacity BEFORE execution (workspace contract): under-capacity is an
    // explicit error, never a truncated carve.
    if (ws_len as usize) < shlosilo_keysource_se_ws_len() as usize {
        return ERR_BUFFER_TOO_SMALL;
    }
    // SAFETY: `ws` is non-null with `ws_len >= ws_len()` (checked above) — the
    // documented caller-workspace contract; exclusive single-context use.
    let state = unsafe { ws::ws_state(ws) };
    // Occupancy gate FIRST (invariant 3): a busy workspace is refused before
    // any credential attempt — the live session (and any borrowed pointer to
    // it) is never disturbed. This is the product-level "unlock while
    // unlocked = Capacity" leg.
    if unsafe { ws::ws_busy(ws) } == ERR_SLOT_OCCUPIED {
        return ERR_SLOT_OCCUPIED;
    }
    // Bounded credential slice: `password_len` is explicit, so no NUL scan
    // and no unbounded read. Over-long is refused by the source itself
    // (AuthFailed) — checked there so the trait face shares the rule.
    let pw: &[u8] = if password_len == 0 {
        &[]
    } else {
        // SAFETY: non-null (entry-checked), non-zero bounded length; pointer
        // validity for `password_len` bytes is the C side's contract.
        unsafe { core::slice::from_raw_parts(password, password_len as usize) }
    };
    // SAFETY: `state` is the pinned workspace and `live == 0` (the occupancy
    // gate above ran). `ws_prepare` places the empty slot in the workspace
    // and lends it out; the `SeKeySource` borrows it with a fabricated
    // `'static` under the same caller-pinning contract as the QR glue (R3
    // `UrMultipartDecoder`). The handle the trait hands out borrows THAT
    // slot and is committed right back into the workspace below — the
    // self-referential placement, `ptr::write`, never `Box` (Z6).
    unsafe {
        let slot = ws::ws_prepare(state);
        let slot_static: &'static KeySessionSlot = &*(slot as *const KeySessionSlot);
        let mut src = SeKeySource::new(slot_static);
        // One attempt, through the KeySource trait: wrong password →
        // AuthFailed (-24), never retried, never downgraded. On success the
        // handle already owns the session in the workspace slot — `slot.open`
        // is the sole handle source (serial is slot-owned). The handle's
        // lifetime is `'static` because the workspace slot borrow is
        // (caller-pinning contract).
        let handle = match src.open_session_with_password(pw) {
            Ok(h) => h,
            Err(e) => return se_error_to_ffi(&e),
        };
        // Commit the handle + live session pointer into the workspace.
        ws::ws_store_handle(state, handle, out_session)
    }
}

/// Map a [`super::KeySourceError`] to the SE entry's C-ABI codes.
fn se_error_to_ffi(e: &super::KeySourceError) -> c_int {
    use super::KeySourceErrorKind::*;
    match e.kind {
        // Invariant 5: one-shot refusal, workspace untouched.
        AuthFailed => ERR_AUTH_FAILED,
        Capacity => ERR_SLOT_OCCUPIED,
        SeComm => ERR_SE_COMM,
        // Pool item #24 / derivation: the -31 "invalid mnemonic" family
        // (MnemonicInvalidEntropyLength maps there too).
        DecodeRejected => to_ffi_code(&ShlosiloError::new(
            ShlosiloErrorKind::MnemonicInvalidEntropyLength,
        )),
        NoSession => to_ffi_code(&ShlosiloError::new(ShlosiloErrorKind::InvariantViolation)),
    }
}

/// Task 8: close the live SE session in this workspace (error-path and
/// end-of-flow teardown).
///
/// This is the SAME teardown as `shlosilo_keysource_qr_close_ffi`
/// (`ws::ws_close`): dropping the single-owner handle runs the slot's
/// serial-guarded close — `ZeroizeOnDrop` wipes the seed/spend/view key
/// bytes — and the workspace goes back to the reusable state (invariant 4:
/// the same workspace may be re-opened with a new password afterwards).
///
/// Total and idempotent by construction:
/// - fresh workspace (`live == 0` from BSS): defined no-op, `OK`;
/// - workspace whose `open` failed: defined no-op, `OK`;
/// - second `close` after a successful one: defined no-op, `OK` — the
///   zeroizing drop already ran exactly once.
///
/// - `ws` NULL → `ERR_NULL_POINTER` (-2). There is no `ws_len`: `ws` must be
///   the same workspace buffer `open` was given (caller-pinned).
///
/// **Lifetime rule**: never call this while a `shlosilo_sign_session_ffi`
/// call on the session pointer from `open` is in flight (same rule as the QR
/// glue) — and per the two-model boundary: a keysource-glue session is
/// closed HERE, never through `shlosilo_session_free_ffi`.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: null-checked first; single-owner workspace (see module docs)
pub extern "C" fn shlosilo_keysource_se_close_ffi(ws: *mut u8) -> c_int {
    if ws.is_null() {
        return ERR_NULL_POINTER;
    }
    // Shared teardown (Task 8: identical to the QR close entry) — total +
    // idempotent, drop runs exactly once per session (see `ws::ws_close`).
    unsafe { ws::ws_close(ws) }
}
