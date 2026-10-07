//! Task 8 tests — the SE key source: password unlock → signing session
//! (`shlosilo_keysource_se_ws_len` / `..._open_ffi` / `..._close_ffi`, and the
//! [`SeKeySource`] trait face behind them).
//!
//! Host-runnable full-cycle tests over the FFI entries + trait, following the
//! host_keystore / host_se precedent: the PRODUCTION Rust chain runs against
//! a behavioural `LoadAccountSecret` shim (link-level substitution of the SE
//! dependency — the same discipline as tests/host_keystore/host_shims.c and
//! tests/host_se/se_shims.c substitute the drivers).
//!
//! Test-vector convention (tests/key_session_ffi.rs): fixed plaintext
//! entropy fixtures, never real seed material. Every test carves its OWN
//! zero-initialized workspace (the BSS `static` / task-workspace contract) —
//! no shared state. The shim is process-global, so every test that drives it
//! holds `shim_lock()` for its whole body (tests run in parallel threads).
//!
//! Pinned invariants (see `src/keysource/se_ffi.rs` module docs):
//! - unlock success → session keys == `from_entropy(entropy)` direct feed;
//! - wrong password → `ERR_AUTH_FAILED` (-24), ONE LoadAccountSecret call
//!   (no retry), no session;
//! - `entropyLen` is untrusted (pool item #24): 33 / 255 / other ≠ 16/32 →
//!   refused before any slice is formed;
//! - close wipes the key bytes (forensic workspace scan) and is total +
//!   idempotent; QR/SE close entries share ONE teardown;
//! - double unlock / unlock-while-live = `ERR_SLOT_OCCUPIED` (-23), refused
//!   BEFORE a credential attempt runs;
//! - the v1 account scope is account 0 (asserted inside the shim).

use std::sync::{Mutex, MutexGuard};

use shlosilo::error::{ShlosiloError, ShlosiloErrorKind};
use shlosilo::ffi::error_code::to_ffi_code;
use shlosilo::types::key_session::KeySession;
use shlosilo_flux_keysource::keysource::ffi::{
    shlosilo_keysource_qr_close_ffi, shlosilo_keysource_qr_open_ffi,
};
use shlosilo_flux_keysource::keysource::se::{AccountSecret, SeKeySource, PASSWORD_MAX_LEN};
use shlosilo_flux_keysource::keysource::se_ffi::{
    shlosilo_keysource_se_close_ffi, shlosilo_keysource_se_open_ffi, shlosilo_keysource_se_ws_len,
};

const OK: i32 = 0;
const ERR_NULL_POINTER: i32 = -2;
const ERR_BUFFER_TOO_SMALL: i32 = -20;
const ERR_SLOT_OCCUPIED: i32 = -23;
const ERR_AUTH_FAILED: i32 = -24;
const ERR_SE_COMM: i32 = -25;
/// `MnemonicInvalidEntropyLength` through the L2b mapping (-31 family): the
/// entropyLen/derivation rejection code (computed — `to_ffi_code` is not
/// `const`).
fn err_entropy_rejected() -> i32 {
    to_ffi_code(&ShlosiloError::new(
        ShlosiloErrorKind::MnemonicInvalidEntropyLength,
    ))
}

/// Test-vector convention: fixed plaintext entropy fixtures, never real seed
/// material.
const FIXTURE_ENTROPY: [u8; 16] = [
    0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29, 0x16,
];
/// 24-word fixture entropy (KeySession's other supported shape).
const FIXTURE_ENTROPY_24: [u8; 32] = [0x11u8; 32];
/// The shim's "stored" password: right password = unlock, anything else =
/// ERR_KEYSTORE_AUTH.
const FIXTURE_PWD: &[u8] = b"shlosilo-se-test-pwd";
/// Wrong-password fixture.
const WRONG_PWD: &[u8] = b"not-the-password";

// ── LoadAccountSecret shim (link-level SE/keystore substitution) ────────────

const C_ERR_KEYSTORE_AUTH: i32 = 20; // err_code.h ERR_KEYSTORE_AUTH
const C_ERR_GENERAL_FAIL: i32 = 1; // err_code.h ERR_GENERAL_FAIL

const MODE_OK16: u8 = 0; // success, 16-byte entropy
const MODE_OK32: u8 = 1; // success, 32-byte entropy
const MODE_AUTH: u8 = 2; // always ERR_KEYSTORE_AUTH
const MODE_COMM: u8 = 3; // always ERR_GENERAL_FAIL (non-password SE failure)
const MODE_LEN33: u8 = 4; // success but entropyLen = 33 (lying length)
const MODE_LEN255: u8 = 5; // success but entropyLen = 255 (lying length)
const MODE_LEN24: u8 = 6; // success but entropyLen = 24 (not 16/32)
const MODE_LEN0: u8 = 7; // success but entropyLen = 0 (not 16/32 — fail-closed)

static SHIM_LOCK: Mutex<()> = Mutex::new(());
static SHIM_MODE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(MODE_OK16);
static SHIM_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static SHIM_LAST_PWD: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// Hold for the whole test body: the shim state is process-global.
fn shim_lock() -> MutexGuard<'static, ()> {
    SHIM_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn shim_set_mode(mode: u8) {
    SHIM_MODE.store(mode, std::sync::atomic::Ordering::SeqCst);
    SHIM_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
    SHIM_LAST_PWD.lock().unwrap().clear();
}

fn shim_calls() -> usize {
    SHIM_CALLS.load(std::sync::atomic::Ordering::SeqCst)
}

fn shim_last_pwd() -> Vec<u8> {
    SHIM_LAST_PWD.lock().unwrap().clone()
}

/// The keystore.c link-level substitute: same contract as
/// `LoadAccountSecret(accountIndex, accountSecret, password)`. The v1 account
/// scope pin (account 0) lives HERE — a call with any other index is a
/// wrong-scope bug and trips the assert.
///
/// # Safety
///
/// C-ABI shim: `account_secret` must point to a valid `AccountSecret`, and
/// `password` to a NUL-terminated string no longer than `PASSWORD_MAX_LEN`
/// (the Rust chain's own bounded stack copy). Both contracts are the
/// caller's, hence the `unsafe` signature.
#[no_mangle]
pub unsafe extern "C" fn LoadAccountSecret(
    account_index: u8,
    account_secret: *mut AccountSecret,
    password: *const core::ffi::c_char,
) -> i32 {
    use std::sync::atomic::Ordering;
    assert_eq!(
        account_index, 0,
        "v1 scope: SeKeySource must unlock account 0 only"
    );
    assert!(!account_secret.is_null());
    assert!(!password.is_null());
    // SAFETY: C-string from the caller (the Rust side's NUL-terminated stack
    // copy); bounded walk (the Rust side never passes > PASSWORD_MAX_LEN).
    // (fn is `unsafe extern "C"`: the raw-pointer contract is the caller's.)
    let pw = {
        let mut n = 0usize;
        while *password.add(n) != 0 && n <= PASSWORD_MAX_LEN {
            n += 1;
        }
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            v.push(*password.add(i) as u8);
        }
        v
    };
    SHIM_CALLS.fetch_add(1, Ordering::SeqCst);
    *SHIM_LAST_PWD.lock().unwrap() = pw.clone();

    let mode = SHIM_MODE.load(Ordering::SeqCst);
    // SAFETY: the out-struct is a valid `AccountSecret` (the Rust chain's own
    // type); written field-wise below. (fn is `unsafe extern "C"`.)
    let secret = &mut *account_secret;
    // Default fill: the fixture entropy, real length, matching password gate.
    secret.entropy = [0u8; 32];
    secret.seed = [0u8; 64];
    secret.slip39_ems_or_ton_entropy_l32 = [0u8; 32];
    secret.reserved_data = [0u8; 32];
    secret.entropy_len = 0;

    match mode {
        MODE_OK16 | MODE_OK32 | MODE_LEN33 | MODE_LEN255 | MODE_LEN24 | MODE_LEN0 => {
            if pw != FIXTURE_PWD {
                return C_ERR_KEYSTORE_AUTH; // wrong password, one shot
            }
            match mode {
                MODE_OK16 => {
                    secret.entropy[..16].copy_from_slice(&FIXTURE_ENTROPY);
                    secret.entropy_len = 16;
                }
                MODE_OK32 => {
                    secret.entropy.copy_from_slice(&FIXTURE_ENTROPY_24);
                    secret.entropy_len = 32;
                }
                MODE_LEN33 => {
                    secret.entropy[..16].copy_from_slice(&FIXTURE_ENTROPY);
                    secret.entropy_len = 33; // pool item #24: lying length
                }
                MODE_LEN255 => {
                    secret.entropy[..16].copy_from_slice(&FIXTURE_ENTROPY);
                    secret.entropy_len = 255; // pool item #24: lying length
                }
                MODE_LEN24 => {
                    secret.entropy[..16].copy_from_slice(&FIXTURE_ENTROPY);
                    secret.entropy_len = 24; // not 16/32
                }
                MODE_LEN0 => {
                    secret.entropy_len = 0; // not 16/32 (fail-closed)
                }
                _ => unreachable!(),
            }
            // The seed field carries a distinguishable marker so the wipe
            // test can prove the decrypted secret dies before return.
            secret.seed = [0x5eu8; 64];
            OK
        }
        MODE_AUTH => C_ERR_KEYSTORE_AUTH,
        MODE_COMM => C_ERR_GENERAL_FAIL,
        _ => C_ERR_GENERAL_FAIL,
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

/// Reference key bytes, derived straight through `KeySession::from_entropy`
/// (the oracle the unlock flow must match).
fn reference_keys(entropy: &[u8]) -> ([u8; 32], [u8; 32]) {
    let s = KeySession::from_entropy(entropy, b"").expect("session");
    (*s.monero().spend_sk.expose(), *s.monero().view_sk.expose())
}

/// A fresh zero-initialized workspace (the BSS contract) + its length.
fn fresh_ws() -> Vec<u8> {
    vec![0u8; shlosilo_keysource_se_ws_len() as usize]
}

fn se_open(ws: &mut [u8], password: &[u8], out: &mut *const KeySession) -> i32 {
    shlosilo_keysource_se_open_ffi(
        ws.as_mut_ptr(),
        ws.len() as core::ffi::c_uint,
        password.as_ptr(),
        password.len() as core::ffi::c_uint,
        out,
    )
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// ── FFI: the unlock → sign-session cycle ───────────────────────────────────

#[test]
fn unlock_16_session_keys_match_from_entropy_direct_feed() {
    let _g = shim_lock();
    shim_set_mode(MODE_OK16);
    let mut ws = fresh_ws();
    let mut out: *const KeySession = core::ptr::null();
    assert_eq!(se_open(&mut ws, FIXTURE_PWD, &mut out), OK);
    assert!(!out.is_null(), "unlock must hand out a session pointer");
    assert_eq!(shim_calls(), 1);
    assert_eq!(
        shim_last_pwd(),
        FIXTURE_PWD,
        "password must reach the C side"
    );
    let (want_spend, want_view) = reference_keys(&FIXTURE_ENTROPY);
    {
        // SAFETY: `out` is the live slot session the glue just opened (valid
        // until close — read the keys before closing).
        let sess = unsafe { &*out };
        assert_eq!(sess.monero().spend_sk.expose(), &want_spend);
        assert_eq!(sess.monero().view_sk.expose(), &want_view);
    }
    assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
}

#[test]
fn unlock_32_session_keys_match_from_entropy_direct_feed() {
    let _g = shim_lock();
    shim_set_mode(MODE_OK32);
    let mut ws = fresh_ws();
    let mut out: *const KeySession = core::ptr::null();
    assert_eq!(se_open(&mut ws, FIXTURE_PWD, &mut out), OK);
    let (want_spend, want_view) = reference_keys(&FIXTURE_ENTROPY_24);
    {
        let sess = unsafe { &*out };
        assert_eq!(sess.monero().spend_sk.expose(), &want_spend);
        assert_eq!(sess.monero().view_sk.expose(), &want_view);
    }
    assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
}

#[test]
fn wrong_password_is_auth_failed_one_shot_and_no_session() {
    let _g = shim_lock();
    shim_set_mode(MODE_OK16);
    let mut ws = fresh_ws();
    let mut out: *const KeySession = core::ptr::null();
    assert_eq!(se_open(&mut ws, WRONG_PWD, &mut out), ERR_AUTH_FAILED);
    assert!(out.is_null(), "failed unlock must leave a NULL out-param");
    // 错密码一次即拒，不重试: exactly ONE LoadAccountSecret call.
    assert_eq!(shim_calls(), 1, "no retry after a rejected password");
    // 无会话: the workspace holds nothing — close is a defined no-op and the
    // right password still unlocks afterwards (no lockout state left behind).
    assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
    assert_eq!(se_open(&mut ws, FIXTURE_PWD, &mut out), OK);
    assert!(!out.is_null());
    assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
}

#[test]
fn se_comm_failure_is_se_comm_not_auth_failed() {
    let _g = shim_lock();
    shim_set_mode(MODE_COMM);
    let mut ws = fresh_ws();
    let mut out: *const KeySession = core::ptr::null();
    assert_eq!(se_open(&mut ws, FIXTURE_PWD, &mut out), ERR_SE_COMM);
    assert!(out.is_null());
    assert_eq!(shim_calls(), 1);
    assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
}

#[test]
fn auth_failure_mode_maps_to_auth_failed() {
    let _g = shim_lock();
    shim_set_mode(MODE_AUTH);
    let mut ws = fresh_ws();
    let mut out: *const KeySession = core::ptr::null();
    assert_eq!(se_open(&mut ws, FIXTURE_PWD, &mut out), ERR_AUTH_FAILED);
    assert!(out.is_null());
    assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
}

// ── pool item #24: entropyLen is untrusted ─────────────────────────────────

#[test]
fn entropy_len_not_16_or_32_is_refused() {
    let _g = shim_lock();
    for mode in [MODE_LEN33, MODE_LEN255, MODE_LEN24, MODE_LEN0] {
        shim_set_mode(mode);
        let mut ws = fresh_ws();
        let mut out: *const KeySession = core::ptr::null();
        let rc = se_open(&mut ws, FIXTURE_PWD, &mut out);
        assert_eq!(
            rc,
            err_entropy_rejected(),
            "mode {mode}: lying entropyLen must be rejected before any slice"
        );
        assert!(out.is_null(), "no session may come out of a lying length");
        // no session left behind: close is a defined no-op, ws re-opens.
        assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
        shim_set_mode(MODE_OK16);
        assert_eq!(se_open(&mut ws, FIXTURE_PWD, &mut out), OK);
        assert!(!out.is_null());
        assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
    }
}

// ── capacity + close discipline ────────────────────────────────────────────

#[test]
fn second_unlock_on_busy_ws_is_slot_occupied_before_any_credential_attempt() {
    let _g = shim_lock();
    shim_set_mode(MODE_OK16);
    let mut ws = fresh_ws();
    let mut out: *const KeySession = core::ptr::null();
    assert_eq!(se_open(&mut ws, FIXTURE_PWD, &mut out), OK);
    let calls_after_first = shim_calls();
    // 解锁中再解锁 = Capacity (-23): refused BEFORE the password reaches the
    // SE — the live session is undisturbed and no credential is burned.
    let mut out2: *const KeySession = core::ptr::null();
    assert_eq!(se_open(&mut ws, FIXTURE_PWD, &mut out2), ERR_SLOT_OCCUPIED);
    assert!(out2.is_null());
    assert_eq!(
        shim_calls(),
        calls_after_first,
        "a busy workspace must not burn a credential attempt"
    );
    // the FIRST session is undisturbed (same pointer, live keys)
    let (want_spend, want_view) = reference_keys(&FIXTURE_ENTROPY);
    {
        let sess = unsafe { &*out };
        assert_eq!(sess.monero().spend_sk.expose(), &want_spend);
        assert_eq!(sess.monero().view_sk.expose(), &want_view);
    }
    assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
}

#[test]
fn close_is_total_and_idempotent_and_ws_reopens() {
    let _g = shim_lock();
    shim_set_mode(MODE_OK16);
    let mut ws = fresh_ws();
    let mut out: *const KeySession = core::ptr::null();
    // close before any open: defined no-op (zeroed workspace = no session)
    assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
    assert_eq!(se_open(&mut ws, FIXTURE_PWD, &mut out), OK);
    assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
    // second close after a successful one: defined no-op
    assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
    assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
    // the same workspace re-opens after close (24-word material this time)
    shim_set_mode(MODE_OK32);
    assert_eq!(se_open(&mut ws, FIXTURE_PWD, &mut out), OK);
    assert!(!out.is_null());
    assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
}

#[test]
fn close_wipes_the_key_bytes_forensic() {
    let _g = shim_lock();
    shim_set_mode(MODE_OK16);
    let mut ws = fresh_ws();
    let mut out: *const KeySession = core::ptr::null();
    assert_eq!(se_open(&mut ws, FIXTURE_PWD, &mut out), OK);
    let (spend, view) = reference_keys(&FIXTURE_ENTROPY);
    assert!(
        contains(&ws, &spend) && contains(&ws, &view),
        "precondition: live key bytes visible in the workspace"
    );
    // Also pin the decrypted-secret wipe: the shim's seed marker (0x5e
    // fill) must never survive the open — the AccountSecret dies before the
    // session goes live.
    assert!(
        !contains(&ws, &[0x5eu8; 4]),
        "decrypted secret must not leak into the workspace"
    );
    assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
    assert!(
        !contains(&ws, &spend),
        "close must wipe the spend key bytes"
    );
    assert!(!contains(&ws, &view), "close must wipe the view key bytes");
}

#[test]
fn ws_len_under_capacity_is_buffer_too_small_and_null_params_are_err_null_pointer() {
    let _g = shim_lock();
    shim_set_mode(MODE_OK16);
    let need = shlosilo_keysource_se_ws_len() as usize;
    assert!(need > 0);
    assert_eq!(
        need,
        shlosilo_flux_keysource::keysource::ffi::shlosilo_keysource_qr_ws_len() as usize,
        "QR and SE entries share ONE workspace layout"
    );
    let mut ws = fresh_ws();
    let mut out: *const KeySession = core::ptr::null();
    for short in [0usize, 1, need - 1] {
        let rc = shlosilo_keysource_se_open_ffi(
            ws.as_mut_ptr(),
            short as core::ffi::c_uint,
            FIXTURE_PWD.as_ptr(),
            FIXTURE_PWD.len() as core::ffi::c_uint,
            &mut out,
        );
        assert_eq!(rc, ERR_BUFFER_TOO_SMALL, "ws_len {short} must be refused");
        assert!(out.is_null());
    }
    assert_eq!(
        shlosilo_keysource_se_open_ffi(
            core::ptr::null_mut(),
            ws.len() as core::ffi::c_uint,
            FIXTURE_PWD.as_ptr(),
            FIXTURE_PWD.len() as core::ffi::c_uint,
            &mut out
        ),
        ERR_NULL_POINTER
    );
    assert_eq!(
        shlosilo_keysource_se_open_ffi(
            ws.as_mut_ptr(),
            ws.len() as core::ffi::c_uint,
            core::ptr::null(),
            4,
            &mut out
        ),
        ERR_NULL_POINTER
    );
    assert_eq!(
        shlosilo_keysource_se_open_ffi(
            ws.as_mut_ptr(),
            ws.len() as core::ffi::c_uint,
            FIXTURE_PWD.as_ptr(),
            FIXTURE_PWD.len() as core::ffi::c_uint,
            core::ptr::null_mut()
        ),
        ERR_NULL_POINTER
    );
    assert_eq!(
        shlosilo_keysource_se_close_ffi(core::ptr::null_mut()),
        ERR_NULL_POINTER
    );
    // none of the refusals ran the credential path
    assert_eq!(shim_calls(), 0, "refused calls must not reach the SE");
    // the workspace still opens fine at full capacity
    assert_eq!(se_open(&mut ws, FIXTURE_PWD, &mut out), OK);
    assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
}

#[test]
fn empty_and_over_long_password_are_auth_failed_before_the_se() {
    let _g = shim_lock();
    shim_set_mode(MODE_OK16);
    let mut ws = fresh_ws();
    let mut out: *const KeySession = core::ptr::null();
    assert_eq!(se_open(&mut ws, b"", &mut out), ERR_AUTH_FAILED);
    assert!(out.is_null());
    let too_long = vec![b'x'; PASSWORD_MAX_LEN + 1];
    assert_eq!(se_open(&mut ws, &too_long, &mut out), ERR_AUTH_FAILED);
    assert!(out.is_null());
    assert_eq!(shim_calls(), 0, "empty/over-long must never reach the SE");
    // exactly at the bound is accepted as input (the password gate then runs)
    let at_bound = vec![b'x'; PASSWORD_MAX_LEN];
    assert_eq!(se_open(&mut ws, &at_bound, &mut out), ERR_AUTH_FAILED);
    assert_eq!(
        shim_calls(),
        1,
        "bounded input must reach the SE exactly once"
    );
}

// ── shared teardown: QR and SE close entries are ONE function ──────────────

#[test]
fn qr_and_se_close_entries_share_one_teardown() {
    let _g = shim_lock();
    shim_set_mode(MODE_OK16);
    // An SE-opened workspace closes through the QR close entry …
    let mut ws = fresh_ws();
    let mut out: *const KeySession = core::ptr::null();
    assert_eq!(se_open(&mut ws, FIXTURE_PWD, &mut out), OK);
    assert_eq!(shlosilo_keysource_qr_close_ffi(ws.as_mut_ptr()), OK);
    assert_eq!(
        shlosilo_keysource_qr_close_ffi(ws.as_mut_ptr()),
        OK,
        "idempotent"
    );
    // … and a QR-opened workspace closes through the SE close entry.
    assert_eq!(
        shlosilo_keysource_qr_open_ffi(
            ws.as_mut_ptr(),
            ws.len() as core::ffi::c_uint,
            FIXTURE_ENTROPY.as_ptr(),
            16,
            &mut out
        ),
        OK
    );
    let (spend, view) = reference_keys(&FIXTURE_ENTROPY);
    assert!(contains(&ws, &spend) && contains(&ws, &view));
    assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
    assert!(!contains(&ws, &spend) && !contains(&ws, &view));
    // and the workspace is reusable for an SE unlock afterwards
    assert_eq!(se_open(&mut ws, FIXTURE_PWD, &mut out), OK);
    assert_eq!(shlosilo_keysource_se_close_ffi(ws.as_mut_ptr()), OK);
}

// ── trait face: SeKeySource implements KeySource ───────────────────────────

#[test]
fn trait_face_unlock_close_cycle_and_wrong_password() {
    let _g = shim_lock();
    shim_set_mode(MODE_OK16);
    use shlosilo_flux_keysource::keysource::{KeySessionSlot, KeySource, KeySourceErrorKind};
    let slot = KeySessionSlot::empty();
    let mut src = SeKeySource::new(&slot);
    // auth = the real password (contrast the QR source, where it is ignored).
    let h = src
        .open_session(core::str::from_utf8(FIXTURE_PWD).unwrap())
        .expect("unlock");
    let (want_spend, want_view) = reference_keys(&FIXTURE_ENTROPY);
    assert_eq!(
        h.session().expect("live").monero().spend_sk.expose(),
        &want_spend
    );
    assert_eq!(
        h.session().expect("live").monero().view_sk.expose(),
        &want_view
    );
    src.close_session(h);
    assert!(!slot.is_occupied(), "close must free the slot");

    // wrong password → AuthFailed, no session
    let err = src.open_session("wrong").expect_err("auth failed");
    assert_eq!(err.kind, KeySourceErrorKind::AuthFailed);
    assert!(!slot.is_occupied());
    // empty auth → AuthFailed too (an empty string is never the password)
    let err = src.open_session("").expect_err("empty auth");
    assert_eq!(err.kind, KeySourceErrorKind::AuthFailed);
}

#[test]
fn trait_face_unlock_while_unlocked_is_capacity() {
    let _g = shim_lock();
    shim_set_mode(MODE_OK16);
    use shlosilo_flux_keysource::keysource::{KeySessionSlot, KeySource, KeySourceErrorKind};
    let slot = KeySessionSlot::empty();
    let mut src = SeKeySource::new(&slot);
    let h = src
        .open_session(core::str::from_utf8(FIXTURE_PWD).unwrap())
        .expect("unlock");
    // 解锁中再解锁 = Capacity (checked FIRST — no second credential attempt).
    let before = shim_calls();
    let err = src
        .open_session(core::str::from_utf8(FIXTURE_PWD).unwrap())
        .expect_err("busy slot");
    assert_eq!(err.kind, KeySourceErrorKind::Capacity);
    assert_eq!(shim_calls(), before, "busy slot must not burn an attempt");
    src.close_session(h);
    // after close the same source unlocks again
    let h2 = src
        .open_session(core::str::from_utf8(FIXTURE_PWD).unwrap())
        .expect("re-unlock");
    src.close_session(h2);
}

// ── source-level pins (same discipline as qr_ffi.rs / no_persistence.rs) ──

/// Invariant 1 pinned at the source level: no key-material word appears in
/// any SE FFI SIGNATURE — password in, session pointer out.
#[test]
fn seed_never_appears_in_se_ffi_signatures() {
    let src = include_str!("../src/keysource/se_ffi.rs");
    const FORBIDDEN: &[&str] = &["seed", "entropy", "mnemonic", "passphrase"];
    let mut checked = 0usize;
    let mut rest = src;
    while let Some(pos) = rest.find("pub extern \"C\" fn") {
        rest = &rest[pos..];
        let end = rest.find("->").expect("extern fn must return");
        let signature = rest[..end].to_ascii_lowercase();
        for token in FORBIDDEN {
            assert!(
                !signature.contains(token),
                "FFI signature must not mention `{token}`: {}",
                rest[..end].lines().next().unwrap_or("")
            );
        }
        checked += 1;
        rest = &rest[end..];
    }
    assert_eq!(checked, 3, "the three keysource SE entries");
}

/// Key hygiene pins (pool items #22/#24): the password and the decrypted
/// secret are wiped with a volatile walk on every path — deleting the wipes
/// from se.rs turns this red.
#[test]
fn password_and_secret_wipes_are_present() {
    let src = include_str!("../src/keysource/se.rs");
    assert!(
        src.contains("write_volatile"),
        "the wipes must be volatile walks (dead-store-elimination-proof)"
    );
    assert!(
        src.contains("wipe_bytes(&mut pw)"),
        "the password stack copy must be wiped after the C call"
    );
    assert!(
        src.contains("secret.wipe()"),
        "the decrypted account secret must be wiped on every path"
    );
    // Pool item #24: the untrusted entropyLen is validated before use.
    assert!(
        src.contains("entropy_len != 16 && entropy_len != 32"),
        "entropyLen must be range-checked (16/32 only)"
    );
}
