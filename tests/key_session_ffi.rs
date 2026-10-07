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
//! 3. Old entry delegation: the deprecated typed entry's output equals the
//!    session path's — asserted separately from the round-trip.
//!
//! The ETH request fixture is reused (tests/pico2_smoke_parity.rs's UR, shared
//! with flux/host-sim/sim_l3.c) — nothing here hand-rolls an ETH sign request.

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
    let session = KeySession::from_entropy(&FIXTURE_ENTROPY, b"").expect("session");
    // leak-slot pattern: flux owns the construction, the FFI only holds the pointer
    let handle = Box::into_raw(Box::new(session));

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
    let session = KeySession::from_entropy(&FIXTURE_ENTROPY, b"").expect("session");
    let handle = Box::into_raw(Box::new(session));
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

//-- 3. Old entry delegation: old entry output == session path (separate assertion) --

#[test]
fn typed_entry_delegates_to_session_path() {
    let payload = eth_fixture_payload();
    let indices = indices_for(&FIXTURE_ENTROPY_24);
    let session = KeySession::from_entropy(&FIXTURE_ENTROPY_24, b"").expect("session");
    let handle = Box::into_raw(Box::new(session));

    let (rc_old, out_old, n_old) = sign_via_typed(&indices, ETHEREUM_MAINNET, &payload);
    assert_eq!(rc_old, OK);
    let (rc_new, out_new, n_new) = sign_via_session(handle, &payload);
    assert_eq!(rc_new, OK);

    assert_eq!(n_old, n_new);
    assert_eq!(
        &out_old[..n_old as usize],
        &out_new[..n_new as usize],
        "deprecated typed entry must route through the same sign core"
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
    );
    assert_eq!(rc, OK, "ws == NULL is the pure probe (family contract)");
    assert_eq!(
        actual,
        shlosilo_sign_ws_len(),
        "probe must report the workspace requirement"
    );
}
