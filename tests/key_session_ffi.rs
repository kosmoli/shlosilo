//! Task 3 — session-based sign FFI: `shlosilo_sign_session_ffi` round-trip
//! against the deprecated `shlosilo_sign_typed_ffi`, the handle lifecycle
//! contract of `shlosilo_session_free_ffi`, and old-entry behavior preservation.
//!
//! Audit requirements:
//! 1. Session FFI round-trip: a `KeySession` handed over as a raw handle signs
//!    the fixture ETH request and reproduces the typed entry's output **byte
//!    for byte** (the old entry delegates to the same sign core).
//! 2. Handle lifecycle: `shlosilo_session_free_ffi` takes the handle slot by
//!    pointer; a second free of the same slot returns an error code (the slot
//!    was NULLed), never UB. A NULL slot or NULL handle is likewise an error.
//! 3. Old entry behavior: the deprecated typed entry's output is byte-identical
//!    to the session path's (same sign core) — asserted separately from the
//!    round-trip, on the 24-word fixture.
//! 4. Negative probes (M2): undersized output buffer (BufferTooSmall +
//!    zeroed `actual_len`), NULL required args, ws under-capacity (reports the
//!    required length), and the §B.5 XMR entropy misuse guard via the session
//!    path.
//!
//! Handle construction contract (Z6 / R3 Z3.3c caller-workspace): the caller
//! OWNS the handle storage and the session is constructed IN PLACE — Rust glue
//! `ptr::write`s it into a static slot / caller workspace; here that is
//! `MaybeUninit` + `ptr::write` over a workspace buffer. `Box::into_raw` is
//! deliberately absent: the handle lifecycle must not touch the allocator
//! (see `scripts/z6_langitem_check.sh` / `probes/noalloc`).
//!
//! The ETH request fixture is reused (tests/pico2_smoke_parity.rs's UR, shared
//! with flux/host-sim/sim_l3.c) — nothing here hand-rolls an ETH sign request.
#![cfg(feature = "alloc-fallback")]

use core::mem::MaybeUninit;

use shlosilo::business;
use shlosilo::business::sign::SignInput;
use shlosilo::entropy::mnemonic::Mnemonic;
use shlosilo::error::ShlosiloErrorCode;
use shlosilo::ffi::c_abi::r3::{
    shlosilo_session_free_ffi, shlosilo_sign_session_ffi, shlosilo_sign_typed_ffi,
};
use shlosilo::ffi::c_abi::shlosilo_sign_ws_len;
use shlosilo::types::key_session::KeySession;
use shlosilo::ur::ur_decode;

const OK: i32 = 0;
const ERR_NULL_POINTER: i32 = ShlosiloErrorCode::InvalidArgument as i32;
const ERR_BUFFER_TOO_SMALL: i32 = ShlosiloErrorCode::BufferTooSmall as i32;

/// ETH sign-request fixture UR — the same string as tests/pico2_smoke_parity.rs
/// and flux/host-sim/sim_l3.c (the shared C-oracle fixture). Reused verbatim.
const ETH_SIGN_REQUEST_URI: &str = "ur:eth-sign-request/otaohddmaowpadlalrfrnysgaelrktecmwaelfgmaymwcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcplfaxvdlartlalalaaxadaaadrpceaadt";

/// Fixture wallet entropy (same fixture entropy as tests/xmr_sign_zero_alloc.rs).
const FIXTURE_ENTROPY: [u8; 16] = [
    0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29, 0x16,
];

/// 24-word fixture entropy (KeySession's other supported shape).
const FIXTURE_ENTROPY_24: [u8; 32] = [0x11u8; 32];

/// Network value for the ETH fixture: EthereumMainnet maps to EIP-155 chain
/// id 1, which matches the fixture tx (see forms/network.rs + check_network).
const ETHEREUM_MAINNET: u32 = 10;

/// Z6/R3 caller-workspace handle contract: construct the session IN PLACE in
/// caller-owned storage (Rust glue: `ptr::write` into a static slot / workspace;
/// here `MaybeUninit` + `ptr::write` — the r3_tests `dec_ws.as_mut_ptr()`
/// discipline). `Box::into_raw` is deliberately NOT used: the handle lifecycle
/// must stay off the allocator (zero-heap face).
fn place_session(slot: &mut MaybeUninit<KeySession>, entropy: &[u8]) -> *mut KeySession {
    let session = KeySession::from_entropy(entropy, b"").expect("session");
    let handle = slot.as_mut_ptr();
    unsafe { core::ptr::write(handle, session) };
    handle
}

fn eth_fixture_payload() -> std::vec::Vec<u8> {
    let decoded = ur_decode::decode(ETH_SIGN_REQUEST_URI).expect("fixture UR decodes");
    decoded.as_ref().to_vec()
}

/// Deprecated typed entry wrapper: allocates the sign workspace per contract
/// (ws == NULL is the pure probe), returns (rc, output bytes, actual_len).
fn sign_via_typed(indices: &[u16], network: u32, payload: &[u8]) -> (i32, std::vec::Vec<u8>, u32) {
    let mut out = std::vec![0u8; 512];
    let mut actual: u32 = 0;
    let need = shlosilo_sign_ws_len();
    let mut ws = std::vec![0u8; need as usize];
    let rc = shlosilo_sign_typed_ffi(
        c"eth-sign-request".as_ptr(),
        payload.as_ptr(),
        payload.len() as u32,
        indices.as_ptr(),
        indices.len() as i32,
        core::ptr::null(),
        0,
        network,
        core::ptr::null(),
        0,
        out.as_mut_ptr(),
        out.len() as u32,
        &mut actual,
        ws.as_mut_ptr(),
        need,
    );
    (rc, out, actual)
}

/// Session entry wrapper (same buffer discipline as the typed wrapper).
fn sign_via_session(session: *const KeySession, payload: &[u8]) -> (i32, std::vec::Vec<u8>, u32) {
    let mut out = std::vec![0u8; 512];
    let mut actual: u32 = 0;
    let need = shlosilo_sign_ws_len();
    let mut ws = std::vec![0u8; need as usize];
    let rc = shlosilo_sign_session_ffi(
        session,
        c"eth-sign-request".as_ptr(),
        payload.as_ptr(),
        payload.len() as u32,
        core::ptr::null(),
        0,
        out.as_mut_ptr(),
        out.len() as u32,
        &mut actual,
        ws.as_mut_ptr(),
        need,
        core::ptr::null(),
        0,
    );
    (rc, out, actual)
}

fn indices_for(entropy: &[u8]) -> std::vec::Vec<u16> {
    Mnemonic::from_entropy(entropy)
        .expect("mnemonic")
        .indices()
        .to_vec()
}

//-- 1. Session FFI round-trip: session output == typed entry output, byte for byte --

#[test]
fn session_sign_matches_typed_entry_byte_for_byte() {
    let payload = eth_fixture_payload();
    let indices = indices_for(&FIXTURE_ENTROPY);
    // caller-storage handle: flux owns the construction, the FFI only holds the pointer
    let mut slot_mem = MaybeUninit::<KeySession>::uninit();
    let handle = place_session(&mut slot_mem, &FIXTURE_ENTROPY);

    let (rc_old, out_old, n_old) = sign_via_typed(&indices, ETHEREUM_MAINNET, &payload);
    assert_eq!(rc_old, OK, "typed entry must sign the fixture");
    let (rc_new, out_new, n_new) = sign_via_session(handle, &payload);
    assert_eq!(rc_new, OK, "session entry must sign the fixture");

    assert_eq!(n_old, n_new, "signature lengths must match");
    assert!(
        n_old > 0 && (n_old as usize) <= out_old.len(),
        "sane signature length"
    );
    assert_eq!(
        &out_old[..n_old as usize],
        &out_new[..n_new as usize],
        "session path must reproduce the typed entry output byte for byte"
    );

    // reclaim through the FFI lifecycle contract
    let mut slot = handle;
    assert_eq!(shlosilo_session_free_ffi(&mut slot), OK);
    assert!(slot.is_null(), "free must NULL the caller's handle slot");
}

//-- 2. Handle lifecycle: double free / null free return error codes, never UB --

#[test]
fn session_free_lifecycle_contract() {
    let mut slot_mem = MaybeUninit::<KeySession>::uninit();
    let handle = place_session(&mut slot_mem, &FIXTURE_ENTROPY);
    let mut slot = handle;

    assert_eq!(shlosilo_session_free_ffi(&mut slot), OK);
    assert!(slot.is_null(), "free must NULL the caller's handle slot");
    // same variable freed twice: the second call sees the NULLed slot
    assert_eq!(
        shlosilo_session_free_ffi(&mut slot),
        ERR_NULL_POINTER,
        "second free must be an error code, not UB"
    );
    assert!(slot.is_null());

    // NULL slot pointer
    assert_eq!(
        shlosilo_session_free_ffi(core::ptr::null_mut()),
        ERR_NULL_POINTER,
        "NULL slot pointer must be an error"
    );
    // NULL handle inside a valid slot
    let mut null_handle: *mut KeySession = core::ptr::null_mut();
    assert_eq!(
        shlosilo_session_free_ffi(&mut null_handle),
        ERR_NULL_POINTER,
        "NULL handle must be an error"
    );
}

//-- 3. Old entry behavior: old entry output == session path, byte-identical
//       (separate assertion, 24-word fixture) --

#[test]
fn typed_entry_output_matches_session_byte_for_byte_24_word() {
    let payload = eth_fixture_payload();
    let indices = indices_for(&FIXTURE_ENTROPY_24);
    let mut slot_mem = MaybeUninit::<KeySession>::uninit();
    let handle = place_session(&mut slot_mem, &FIXTURE_ENTROPY_24);

    let (rc_old, out_old, n_old) = sign_via_typed(&indices, ETHEREUM_MAINNET, &payload);
    assert_eq!(rc_old, OK);
    let (rc_new, out_new, n_new) = sign_via_session(handle, &payload);
    assert_eq!(rc_new, OK);

    assert_eq!(n_old, n_new);
    assert_eq!(
        &out_old[..n_old as usize],
        &out_new[..n_new as usize],
        "deprecated typed entry must be byte-identical to the session path"
    );

    let mut slot = handle;
    assert_eq!(shlosilo_session_free_ffi(&mut slot), OK);
}

//-- 3b. Behavior preservation: the typed entry is byte-for-byte unchanged vs the
//       pre-session business path (SignInput::Mnemonic → sign_with_entropy). --

#[test]
fn typed_entry_output_unchanged_vs_business_path() {
    let payload = eth_fixture_payload();
    let decoded = ur_decode::decode(ETH_SIGN_REQUEST_URI).expect("fixture UR decodes");
    let indices = indices_for(&FIXTURE_ENTROPY);

    // pre-session reference: the direct business path the FFI used to reach
    let input = SignInput::Mnemonic {
        mnemonic: Mnemonic::from_entropy(&FIXTURE_ENTROPY).expect("mnemonic"),
        passphrase: b"",
    };
    let mut expected = [0u8; 512];
    let n = business::sign::sign_with_entropy(
        input,
        decoded.type_tag(),
        decoded.as_ref(),
        &[],
        &mut expected,
    )
    .expect("business sign");

    let (rc, out, actual) = sign_via_typed(&indices, ETHEREUM_MAINNET, &payload);
    assert_eq!(rc, OK);
    assert_eq!(actual as usize, n);
    assert_eq!(
        &out[..actual as usize],
        &expected[..n],
        "deprecated typed entry must stay byte-for-byte unchanged"
    );
}

//-- 4. Gate4 discipline on the new entry: null session / ws probe --
#[test]
fn session_sign_null_session_rejected() {
    let payload = eth_fixture_payload();
    let mut out = [0u8; 512];
    let mut actual: u32 = 0;
    let need = shlosilo_sign_ws_len();
    let mut ws = std::vec![0u8; need as usize];
    let rc = shlosilo_sign_session_ffi(
        core::ptr::null(),
        c"eth-sign-request".as_ptr(),
        payload.as_ptr(),
        payload.len() as u32,
        core::ptr::null(),
        0,
        out.as_mut_ptr(),
        out.len() as u32,
        &mut actual,
        ws.as_mut_ptr(),
        need,
        core::ptr::null(),
        0,
    );
    assert_eq!(rc, ERR_NULL_POINTER, "NULL session must be rejected");
    assert_eq!(actual, 0, "failure path must zero actual_len");
}

#[test]
fn session_sign_ws_probe_reports_requirement() {
    let payload = eth_fixture_payload();
    let mut out = [0u8; 512];
    let mut actual: u32 = 0;
    let rc = shlosilo_sign_session_ffi(
        core::ptr::null(), // probe must return BEFORE the session null-check
        c"eth-sign-request".as_ptr(),
        payload.as_ptr(),
        payload.len() as u32,
        core::ptr::null(),
        0,
        out.as_mut_ptr(),
        out.len() as u32,
        &mut actual,
        core::ptr::null_mut(), // ws == NULL: pure probe
        0,
        core::ptr::null(),
        0,
    );
    assert_eq!(rc, OK, "ws == NULL is the pure probe (family contract)");
    assert_eq!(
        actual,
        shlosilo_sign_ws_len(),
        "probe must report the workspace requirement"
    );
}

//-- 5. Negative probes (M2): buffers / pointers / entropy misuse — error codes, never UB --

/// Undersized output buffer → BufferTooSmall, `actual_len` zeroed (Gate4 #2:
/// zero on every failure path — a partial write is never reported as success).
#[test]
fn session_sign_output_buf_too_small_reports_buffer_too_small() {
    let payload = eth_fixture_payload();
    let mut slot_mem = MaybeUninit::<KeySession>::uninit();
    let handle = place_session(&mut slot_mem, &FIXTURE_ENTROPY);
    let mut out = [0u8; 8]; // ≪ ETH signature output
    let mut actual: u32 = 0;
    let need = shlosilo_sign_ws_len();
    let mut ws = std::vec![0u8; need as usize];
    let rc = shlosilo_sign_session_ffi(
        handle,
        c"eth-sign-request".as_ptr(),
        payload.as_ptr(),
        payload.len() as u32,
        core::ptr::null(),
        0,
        out.as_mut_ptr(),
        out.len() as u32,
        &mut actual,
        ws.as_mut_ptr(),
        need,
        core::ptr::null(),
        0,
    );
    assert_eq!(
        rc, ERR_BUFFER_TOO_SMALL,
        "undersized output buffer must report BufferTooSmall"
    );
    assert_eq!(actual, 0, "failure path must zero actual_len");

    let mut slot = handle;
    assert_eq!(shlosilo_session_free_ffi(&mut slot), OK);
}

/// NULL required args (type_name / payload / output_buf) → ERR_NULL_POINTER,
/// `actual_len` zeroed. The session handle may be NULL first (excluded in the
/// entry prologue), so each case is probed with a live session.
#[test]
fn session_sign_null_required_args_rejected() {
    let payload = eth_fixture_payload();
    let mut slot_mem = MaybeUninit::<KeySession>::uninit();
    let handle = place_session(&mut slot_mem, &FIXTURE_ENTROPY);
    let mut out = [0u8; 512];
    let need = shlosilo_sign_ws_len();
    let mut ws = std::vec![0u8; need as usize];

    let cases: [(*const u8, *const u8, *mut u8); 3] = [
        // (type_name, payload, output_buf)
        (core::ptr::null(), payload.as_ptr(), out.as_mut_ptr()),
        (
            c"eth-sign-request".as_ptr().cast(),
            core::ptr::null(),
            out.as_mut_ptr(),
        ),
        (
            c"eth-sign-request".as_ptr().cast(),
            payload.as_ptr(),
            core::ptr::null_mut(),
        ),
    ];
    for (i, (type_name, pl, ob)) in cases.into_iter().enumerate() {
        let mut actual: u32 = 0;
        let rc = shlosilo_sign_session_ffi(
            handle,
            type_name.cast(),
            pl,
            if pl.is_null() {
                0
            } else {
                payload.len() as u32
            },
            core::ptr::null(),
            0,
            ob,
            out.len() as u32,
            &mut actual,
            ws.as_mut_ptr(),
            need,
            core::ptr::null(),
            0,
        );
        assert_eq!(
            rc, ERR_NULL_POINTER,
            "case {i}: NULL required arg must be rejected"
        );
        assert_eq!(actual, 0, "case {i}: failure path must zero actual_len");
    }

    let mut slot = handle;
    assert_eq!(shlosilo_session_free_ffi(&mut slot), OK);
}

/// ws under-capacity → BufferTooSmall AND `actual_len` reports the required
/// workspace length (the documented exception to the zero-on-failure rule —
/// the caller needs the number to resize).
#[test]
fn session_sign_ws_under_capacity_reports_requirement() {
    let payload = eth_fixture_payload();
    let mut slot_mem = MaybeUninit::<KeySession>::uninit();
    let handle = place_session(&mut slot_mem, &FIXTURE_ENTROPY);
    let mut out = [0u8; 512];
    let mut actual: u32 = 0;
    let need = shlosilo_sign_ws_len();
    let mut ws = std::vec![0u8; need as usize - 1]; // one byte short
    let rc = shlosilo_sign_session_ffi(
        handle,
        c"eth-sign-request".as_ptr(),
        payload.as_ptr(),
        payload.len() as u32,
        core::ptr::null(),
        0,
        out.as_mut_ptr(),
        out.len() as u32,
        &mut actual,
        ws.as_mut_ptr(),
        need - 1,
        core::ptr::null(),
        0,
    );
    assert_eq!(rc, ERR_BUFFER_TOO_SMALL, "under-capacity ws must error");
    assert_eq!(
        actual,
        shlosilo_sign_ws_len(),
        "under-capacity ws must report the required length (documented exception)"
    );

    let mut slot = handle;
    assert_eq!(shlosilo_session_free_ffi(&mut slot), OK);
}

/// §B.5 XMR entropy misuse guard through the SESSION path: an XMR sign request
/// with < 16 B of signing entropy must fail with EntropyInjectionInvalid
/// (mapped to `InvalidDiceRolls` = -33 at the FFI, error.rs L2b), never sign.
///
/// The guard fires on the first `purpose_rng` call — i.e. AFTER decrypt+parse —
/// so the payload is the p1_06 fixture plaintext re-encrypted for the
/// session's OWN derived view key (helper duplicated from
/// tests/p1_06_xmr_business.rs). The round-trip is asserted first: if
/// decryption broke, the guard would never be reached and the test would fail
/// loudly instead of passing vacuously.
#[test]
fn session_sign_xmr_short_entropy_hits_misuse_guard() {
    let mut slot_mem = MaybeUninit::<KeySession>::uninit();
    let handle = place_session(&mut slot_mem, &FIXTURE_ENTROPY_24);
    let view_sk = *unsafe { &*handle }.monero().view_sk.expose();

    let plain: &[u8] = include_bytes!("fixtures/txset_plain.bin");
    use rand_chacha::rand_core::SeedableRng;
    let mut enc_rng = rand_chacha::ChaCha20Rng::from_seed([0xABu8; 32]);
    let encrypted = encrypt_unsigned_with_self_view(plain, &view_sk, &mut enc_rng);
    // the session's own view key must open the request (guard reachability)
    let dec = shlosilo::chain::xmr::unsigned_txset::decrypt_unsigned_txset(&encrypted, &view_sk)
        .expect("self-encrypted request decrypts");
    assert_eq!(&*dec, plain);

    let mut out = [0u8; 512];
    let mut actual: u32 = 0;
    let need = shlosilo_sign_ws_len();
    let mut ws = std::vec![0u8; need as usize];
    let short_entropy = [0x77u8; 8]; // < ENTROPY_MIN_LEN (16)
    let rc = shlosilo_sign_session_ffi(
        handle,
        c"xmr-txunsigned".as_ptr(),
        encrypted.as_ptr(),
        encrypted.len() as u32,
        short_entropy.as_ptr(),
        short_entropy.len() as u32,
        out.as_mut_ptr(),
        out.len() as u32,
        &mut actual,
        ws.as_mut_ptr(),
        need,
        core::ptr::null(),
        0,
    );
    assert_eq!(
        rc,
        ShlosiloErrorCode::InvalidDiceRolls as i32,
        "XMR + short entropy must hit the §B.5 misuse guard (EntropyInjectionInvalid)"
    );
    assert_eq!(actual, 0, "failure path must zero actual_len");

    let mut slot = handle;
    assert_eq!(shlosilo_session_free_ffi(&mut slot), OK);
}

/// Encrypt with the unsigned-side isomorphic format (duplicated from
/// tests/p1_06_xmr_business.rs — lets a test hand the wallet an XMR request
/// its own derived view key can decrypt):
/// magic(23) ‖ nonce(8 BE) ‖ chacha20-legacy(cn_v0(view_sk)) ‖ sig(64).
fn encrypt_unsigned_with_self_view(
    plain: &[u8],
    view_sk: &[u8; 32],
    rng: &mut rand_chacha::ChaCha20Rng,
) -> std::vec::Vec<u8> {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20Legacy;
    use rand_chacha::rand_core::RngCore;

    const PREFIX: &[u8] = b"Monero unsigned tx set\x05";
    let key = cuprate_cryptonight::cryptonight_hash_v0(view_sk);
    let nonce = rng.next_u64().to_be_bytes();
    let mut buf = plain.to_vec();
    #[allow(deprecated)]
    let mut cipher =
        ChaCha20Legacy::new_from_slices(&key, chacha20::LegacyNonce::from_slice(&nonce)).unwrap();
    cipher.apply_keystream(&mut buf);

    let mut unsigned = std::vec::Vec::with_capacity(8 + buf.len());
    unsigned.extend_from_slice(&nonce);
    unsigned.extend_from_slice(&buf);
    let hash = shlosilo::encoding::keccak256::hash(&unsigned).unwrap();
    let [c, r] = shlosilo::chain::xmr::signed_txset::monero_sign(&hash, view_sk, rng).unwrap();

    let mut out = std::vec::Vec::with_capacity(PREFIX.len() + 8 + buf.len() + 64);
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&c);
    out.extend_from_slice(&r);
    out
}
