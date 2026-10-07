//! Task 5a tests — the keysource QR C glue: scan bytes in, session pointer
//! out (`shlosilo_keysource_qr_ws_len` / `..._open_ffi` / `..._close_ffi`).
//!
//! Host-runnable full-cycle tests over the FFI entries. Test-vector convention
//! (tests/key_session_ffi.rs): fixed plaintext entropy fixtures, never real
//! seed material. Every test carves its OWN zero-initialized workspace
//! (the BSS `static` / task-workspace contract) — no shared state.
//!
//! Pinned invariants (see `src/keysource/ffi.rs` module docs):
//! - seed appears in NO FFI signature (source-level grep below);
//! - one live session per workspace (re-open = `ERR_SLOT_OCCUPIED`);
//! - `close` is total + idempotent; after close the workspace re-opens;
//! - `ws_len` under capacity = `ERR_BUFFER_TOO_SMALL`; NULL args = -2;
//! - QR-glue sessions are closed by the glue ONLY — never through
//!   `shlosilo_session_free_ffi` (two-model boundary).

use shlosilo::entropy::mnemonic::Mnemonic;
use shlosilo::types::key_session::KeySession;
use shlosilo_flux_keysource::keysource::ffi::{
    shlosilo_keysource_qr_close_ffi, shlosilo_keysource_qr_open_ffi, shlosilo_keysource_qr_ws_len,
};

const OK: i32 = 0;
const ERR_NULL_POINTER: i32 = -2;
const ERR_BUFFER_TOO_SMALL: i32 = -20;
const ERR_SLOT_OCCUPIED: i32 = -23;
/// `ur:` transport rejected by `seed_qr::decode` (FeatureNotImplemented).
const ERR_FEATURE_NOT_IMPLEMENTED: i32 = -14;
/// Non-plate payload (EncodingInvalidFormat) / over-budget scan length.
const ERR_ENCODING: i32 = -21;

/// Test-vector convention: fixed plaintext entropy fixtures, never real seed
/// material.
const FIXTURE_ENTROPY: [u8; 16] = [
    0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29, 0x16,
];
/// 24-word fixture (KeySession's other supported shape).
const FIXTURE_ENTROPY_24: [u8; 32] = [0x11u8; 32];

/// Reference key bytes, derived straight through `KeySession::from_entropy`
/// (the oracle the scan flow must match).
fn reference_keys(entropy: &[u8]) -> ([u8; 32], [u8; 32]) {
    let s = KeySession::from_entropy(entropy, b"").expect("session");
    (*s.monero().spend_sk.expose(), *s.monero().view_sk.expose())
}

/// SeedQR standard plate for an entropy fixture: `%04d` word indices,
/// 48 digits (12 words). Built from the mnemonic the same entropy derives —
/// so the BIP-39 checksum validates.
fn standard_plate(entropy: &[u8]) -> Vec<u8> {
    let m = Mnemonic::from_entropy(entropy).expect("mnemonic");
    let mut out = Vec::with_capacity(m.indices().len() * 4);
    for &idx in m.indices() {
        out.push(b'0' + (idx / 1000) as u8);
        out.push(b'0' + ((idx / 100) % 10) as u8);
        out.push(b'0' + ((idx / 10) % 10) as u8);
        out.push(b'0' + (idx % 10) as u8);
    }
    out
}

/// A fresh zero-initialized workspace (the BSS contract) + its length.
fn fresh_ws() -> Vec<u8> {
    vec![0u8; shlosilo_keysource_qr_ws_len() as usize]
}

/// open → live session pointer; compares against direct `from_entropy` and
/// closes. Returns nothing: the whole cycle, keys included.
fn full_cycle(ws: &mut [u8], plate: &[u8], entropy: &[u8]) {
    let mut out: *const KeySession = core::ptr::null();
    let rc = shlosilo_keysource_qr_open_ffi(
        ws.as_mut_ptr(),
        ws.len() as core::ffi::c_uint,
        plate.as_ptr(),
        plate.len() as core::ffi::c_uint,
        &mut out,
    );
    assert_eq!(rc, OK, "open must succeed");
    assert!(!out.is_null(), "open must hand out a session pointer");
    let (want_spend, want_view) = reference_keys(entropy);
    {
        // SAFETY: `out` is the live slot session the glue just opened (valid
        // until close — read the keys before closing).
        let sess = unsafe { &*out };
        assert_eq!(sess.monero().spend_sk.expose(), &want_spend);
        assert_eq!(sess.monero().view_sk.expose(), &want_view);
    }
    assert_eq!(shlosilo_keysource_qr_close_ffi(ws.as_mut_ptr()), OK);
}

#[test]
fn compact_16_full_cycle_keys_match_from_entropy() {
    let mut ws = fresh_ws();
    full_cycle(&mut ws, &FIXTURE_ENTROPY, &FIXTURE_ENTROPY);
}

#[test]
fn standard_48_full_cycle_keys_match_from_entropy() {
    let mut ws = fresh_ws();
    let plate = standard_plate(&FIXTURE_ENTROPY);
    assert_eq!(plate.len(), 48);
    full_cycle(&mut ws, &plate, &FIXTURE_ENTROPY);
}

#[test]
fn compact_32_full_cycle_keys_match_from_entropy() {
    let mut ws = fresh_ws();
    full_cycle(&mut ws, &FIXTURE_ENTROPY_24, &FIXTURE_ENTROPY_24);
}

#[test]
fn second_open_on_busy_ws_is_slot_occupied() {
    let mut ws = fresh_ws();
    let mut out: *const KeySession = core::ptr::null();
    let rc = shlosilo_keysource_qr_open_ffi(
        ws.as_mut_ptr(),
        ws.len() as core::ffi::c_uint,
        FIXTURE_ENTROPY.as_ptr(),
        16,
        &mut out,
    );
    assert_eq!(rc, OK);
    assert!(!out.is_null());
    // second open on the SAME workspace: refused before anything is touched
    let mut out2: *const KeySession = core::ptr::null();
    let rc2 = shlosilo_keysource_qr_open_ffi(
        ws.as_mut_ptr(),
        ws.len() as core::ffi::c_uint,
        FIXTURE_ENTROPY_24.as_ptr(),
        32,
        &mut out2,
    );
    assert_eq!(rc2, ERR_SLOT_OCCUPIED, "one live session per workspace");
    assert!(out2.is_null(), "failed open must leave a NULL out-param");
    // the FIRST session is undisturbed (same pointer, live keys)
    let (want_spend, want_view) = reference_keys(&FIXTURE_ENTROPY);
    {
        let sess = unsafe { &*out };
        assert_eq!(sess.monero().spend_sk.expose(), &want_spend);
        assert_eq!(sess.monero().view_sk.expose(), &want_view);
    }
    assert_eq!(shlosilo_keysource_qr_close_ffi(ws.as_mut_ptr()), OK);
}

#[test]
fn close_is_total_and_idempotent_and_ws_reopens() {
    let mut ws = fresh_ws();
    // close before any open: defined no-op (zeroed workspace = no session)
    assert_eq!(shlosilo_keysource_qr_close_ffi(ws.as_mut_ptr()), OK);
    // full cycle …
    full_cycle(&mut ws, &FIXTURE_ENTROPY, &FIXTURE_ENTROPY);
    // … then a second close: defined no-op, the zeroizing drop already ran
    assert_eq!(shlosilo_keysource_qr_close_ffi(ws.as_mut_ptr()), OK);
    assert_eq!(shlosilo_keysource_qr_close_ffi(ws.as_mut_ptr()), OK);
    // same workspace re-opens after close (24-word plate this time)
    full_cycle(&mut ws, &FIXTURE_ENTROPY_24, &FIXTURE_ENTROPY_24);
}

#[test]
fn ws_len_under_capacity_is_buffer_too_small() {
    let need = shlosilo_keysource_qr_ws_len() as usize;
    assert!(need > 0);
    let mut ws = fresh_ws();
    let mut out: *const KeySession = core::ptr::null();
    for short in [0usize, 1, need - 1] {
        let rc = shlosilo_keysource_qr_open_ffi(
            ws.as_mut_ptr(),
            short as core::ffi::c_uint,
            FIXTURE_ENTROPY.as_ptr(),
            16,
            &mut out,
        );
        assert_eq!(rc, ERR_BUFFER_TOO_SMALL, "ws_len {short} must be refused");
        assert!(out.is_null());
    }
    // the refused calls must not have consumed anything: the workspace still
    // opens fine at full capacity
    full_cycle(&mut ws, &FIXTURE_ENTROPY, &FIXTURE_ENTROPY);
}

#[test]
fn null_params_are_err_null_pointer() {
    let mut ws = fresh_ws();
    let mut out: *const KeySession = core::ptr::null();
    let ws_len = ws.len() as core::ffi::c_uint;
    assert_eq!(
        shlosilo_keysource_qr_open_ffi(
            core::ptr::null_mut(),
            ws_len,
            FIXTURE_ENTROPY.as_ptr(),
            16,
            &mut out
        ),
        ERR_NULL_POINTER
    );
    assert_eq!(
        shlosilo_keysource_qr_open_ffi(ws.as_mut_ptr(), ws_len, core::ptr::null(), 16, &mut out),
        ERR_NULL_POINTER
    );
    assert_eq!(
        shlosilo_keysource_qr_open_ffi(
            ws.as_mut_ptr(),
            ws_len,
            FIXTURE_ENTROPY.as_ptr(),
            16,
            core::ptr::null_mut()
        ),
        ERR_NULL_POINTER
    );
    assert_eq!(
        shlosilo_keysource_qr_close_ffi(core::ptr::null_mut()),
        ERR_NULL_POINTER
    );
}

#[test]
fn decode_rejections_flow_through_the_l2b_mapping() {
    let mut ws = fresh_ws();
    let ws_len = ws.len() as core::ffi::c_uint;
    let mut out: *const KeySession = core::ptr::null();
    // ur: transport → FeatureNotImplemented (-14), never silently misread
    let ur = b"ur:crypto-seed/abc";
    assert_eq!(
        shlosilo_keysource_qr_open_ffi(
            ws.as_mut_ptr(),
            ws_len,
            ur.as_ptr(),
            ur.len() as core::ffi::c_uint,
            &mut out
        ),
        ERR_FEATURE_NOT_IMPLEMENTED
    );
    assert!(out.is_null());
    // off-length payload → EncodingInvalidFormat (-21)
    let short = [0x5au8; 15];
    assert_eq!(
        shlosilo_keysource_qr_open_ffi(ws.as_mut_ptr(), ws_len, short.as_ptr(), 15, &mut out),
        ERR_ENCODING
    );
    // digit plate with out-of-range word indices → rejected (L2b-mapped,
    // negative) — full validation (index range + checksum) runs at open time
    let bogus = [b'9'; 48];
    let rc = shlosilo_keysource_qr_open_ffi(ws.as_mut_ptr(), ws_len, bogus.as_ptr(), 48, &mut out);
    assert!(rc < 0, "bogus plate must be rejected, got {rc}");
    assert!(out.is_null());
    // none of the failed opens left a live session behind
    assert_eq!(shlosilo_keysource_qr_close_ffi(ws.as_mut_ptr()), OK);
    full_cycle(&mut ws, &FIXTURE_ENTROPY, &FIXTURE_ENTROPY);
}

/// Invariant 1 pinned at the source level (same discipline as
/// tests/no_persistence.rs): no key-material word appears in any FFI
/// SIGNATURE — scan bytes in, session pointer out.
#[test]
fn seed_never_appears_in_ffi_signatures() {
    let src = include_str!("../src/keysource/ffi.rs");
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
    assert_eq!(checked, 3, "the three keysource QR entries");
}
