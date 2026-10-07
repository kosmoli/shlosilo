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
use shlosilo::ffi::c_abi::r3::{
    shlosilo_sign_session_ffi, shlosilo_sign_typed_ffi, shlosilo_ur_decode_uri_ffi,
};
use shlosilo::ffi::c_abi::shlosilo_sign_ws_len;
use shlosilo::types::key_session::KeySession;
use shlosilo::ur::ur_decode;
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

//-- 2. Task 5b blind-spot absorption (5a review hand-over) -------------------

/// `data_len` above the scan budget (4096) is refused BEFORE any slice is
/// formed — a lying `data_len` must never reach `from_raw_parts`.
#[test]
fn data_len_over_budget_maps_to_encoding_error() {
    let mut ws = fresh_ws();
    let mut out: *const KeySession = core::ptr::null();
    let big = std::vec![0x5au8; 4097];
    assert_eq!(
        shlosilo_keysource_qr_open_ffi(
            ws.as_mut_ptr(),
            ws.len() as core::ffi::c_uint,
            big.as_ptr(),
            4097,
            &mut out
        ),
        ERR_ENCODING
    );
    assert!(out.is_null());
    // exactly at the budget is accepted as input (still not a plate -> -21
    // from the decode, but the budget gate itself passes)
    let ok_len = std::vec![0x5au8; 4096];
    assert_eq!(
        shlosilo_keysource_qr_open_ffi(
            ws.as_mut_ptr(),
            ws.len() as core::ffi::c_uint,
            ok_len.as_ptr(),
            4096,
            &mut out
        ),
        ERR_ENCODING,
        "at-budget input reaches decode (and rejects as non-plate)"
    );
    assert_eq!(shlosilo_keysource_qr_close_ffi(ws.as_mut_ptr()), OK);
}

/// `data_len == 0` with a non-NULL buffer: the empty slice reaches
/// `seed_qr::decode` and maps to `EncodingInvalidFormat` (-21) — the same
/// mapping as any non-plate payload (the length domains contain no 0).
#[test]
fn zero_len_non_null_payload_maps_to_encoding_error() {
    let mut ws = fresh_ws();
    let mut out: *const KeySession = core::ptr::null();
    assert_eq!(
        shlosilo_keysource_qr_open_ffi(
            ws.as_mut_ptr(),
            ws.len() as core::ffi::c_uint,
            FIXTURE_ENTROPY.as_ptr(), // non-NULL, length 0 below
            0,
            &mut out
        ),
        ERR_ENCODING
    );
    assert!(out.is_null());
    assert_eq!(shlosilo_keysource_qr_close_ffi(ws.as_mut_ptr()), OK);
}

/// 96-digit standard plate (24 words): end-to-end open -> key comparison
/// against the direct `from_entropy` oracle (the 48-digit/12-word sibling is
/// pinned above; the 24-word plate is the other half of the plate family).
#[test]
fn standard_96_full_cycle_keys_match_from_entropy() {
    let mut ws = fresh_ws();
    let plate = standard_plate(&FIXTURE_ENTROPY_24);
    assert_eq!(plate.len(), 96);
    full_cycle(&mut ws, &plate, &FIXTURE_ENTROPY_24);
}

/// The C product flow's re-entry path (confirm-continue while a session is
/// live): the second `open` answers `ERR_SLOT_OCCUPIED` (-23), the caller
/// closes the old session and reopens from the new plate bytes. The new
/// session must carry the NEW scan's keys; the old one dies (zeroized) at
/// the close. This sequence is what product_task.c runs — pinned here.
#[test]
fn slot_occupied_recovery_close_then_reopen_yields_new_scan_keys() {
    let mut ws = fresh_ws();
    let ws_len = ws.len() as core::ffi::c_uint;
    let mut out: *const KeySession = core::ptr::null();
    // session A: compact 16-byte scan
    assert_eq!(
        shlosilo_keysource_qr_open_ffi(
            ws.as_mut_ptr(),
            ws_len,
            FIXTURE_ENTROPY.as_ptr(),
            16,
            &mut out
        ),
        OK
    );
    assert!(!out.is_null());
    // re-entry with a different scan: refused (-23), out-param NULLed
    let plate_b = standard_plate(&FIXTURE_ENTROPY_24);
    let mut out2: *const KeySession = core::ptr::null();
    assert_eq!(
        shlosilo_keysource_qr_open_ffi(
            ws.as_mut_ptr(),
            ws_len,
            plate_b.as_ptr(),
            plate_b.len() as core::ffi::c_uint,
            &mut out2
        ),
        ERR_SLOT_OCCUPIED
    );
    assert!(out2.is_null());
    // recovery: close the old session (zeroize), reopen from the new bytes
    assert_eq!(shlosilo_keysource_qr_close_ffi(ws.as_mut_ptr()), OK);
    assert_eq!(
        shlosilo_keysource_qr_open_ffi(
            ws.as_mut_ptr(),
            ws_len,
            plate_b.as_ptr(),
            plate_b.len() as core::ffi::c_uint,
            &mut out2
        ),
        OK
    );
    assert!(!out2.is_null());
    let (want_spend, want_view) = reference_keys(&FIXTURE_ENTROPY_24);
    {
        let sess = unsafe { &*out2 };
        assert_eq!(sess.monero().spend_sk.expose(), &want_spend);
        assert_eq!(sess.monero().view_sk.expose(), &want_view);
    }
    assert_eq!(shlosilo_keysource_qr_close_ffi(ws.as_mut_ptr()), OK);
}

// -- Task 5b end-to-end sign equivalence: the QR-glue session pointer drives
// `shlosilo_sign_session_ffi` to the SAME bytes as the deprecated typed
// entry (fixture ETH request; same convention as tests/key_session_ffi.rs).

/// ETH sign-request fixture — the same shared C-oracle string as
/// tests/key_session_ffi.rs / tests/pico2_smoke_parity.rs / flux/host-sim.
const ETH_SIGN_REQUEST_URI: &str = "ur:eth-sign-request/otaohddmaowpadlalrfrnysgaelrktecmwaelfgmaymwcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcplfaxvdlartlalalaaxadaaadrpceaadt";

/// Network value for the ETH fixture (EthereumMainnet -> EIP-155 chain id 1).
const ETHEREUM_MAINNET: u32 = 10;

fn eth_fixture_payload() -> std::vec::Vec<u8> {
    ur_decode::decode(ETH_SIGN_REQUEST_URI)
        .expect("fixture UR decodes")
        .as_ref()
        .to_vec()
}

/// Single-frame request extraction exactly as the C scan flow does it
/// (product_task.c: `shlosilo_ur_decode_uri_ffi` -> (type, payload) ->
/// `shlosilo_sign_session_ffi`). Returns (type, payload).
fn single_frame_request(uri: &str) -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let mut ty = std::vec![0u8; 64];
    let mut payload = std::vec![0u8; 8192];
    let mut actual: u32 = 0;
    let c_uri = std::ffi::CString::new(uri).expect("uri is not NUL");
    let rc = shlosilo_ur_decode_uri_ffi(
        c_uri.as_ptr(),
        ty.as_mut_ptr(),
        ty.len() as u32,
        payload.as_mut_ptr(),
        payload.len() as u32,
        &mut actual,
    );
    assert_eq!(rc, OK, "single-frame decode must succeed");
    let nul = ty
        .iter()
        .position(|&b| b == 0)
        .expect("NUL-terminated type");
    (ty[..nul].to_vec(), payload[..actual as usize].to_vec())
}

/// Task 5b: the single-frame decode entry — round trip against the
/// `ur_decode` oracle + the two contract rejections (multipart shapes and
/// buffer-too-small with the required length in `actual_len`).
#[test]
fn single_frame_decode_uri_ffi_round_trip_and_rejections() {
    // round trip: type name + payload == the ur_decode oracle
    let (ty, payload) = single_frame_request(ETH_SIGN_REQUEST_URI);
    assert_eq!(ty, b"eth-sign-request".to_vec());
    assert_eq!(payload, eth_fixture_payload());
    // multipart shapes belong to the fountain decoder -> rejected here (-21)
    let c_multi = std::ffi::CString::new("ur:eth-sign-request/1-2/aabb").unwrap();
    let mut ty = std::vec![0u8; 64];
    let mut payload = std::vec![0u8; 8192];
    let mut actual: u32 = 0;
    assert_eq!(
        shlosilo_ur_decode_uri_ffi(
            c_multi.as_ptr(),
            ty.as_mut_ptr(),
            ty.len() as u32,
            payload.as_mut_ptr(),
            payload.len() as u32,
            &mut actual,
        ),
        ERR_ENCODING
    );
    // payload buffer too small: -20 with the required length in actual_len
    let c_uri = std::ffi::CString::new(ETH_SIGN_REQUEST_URI).unwrap();
    let mut tiny = std::vec![0u8; 4];
    actual = 0;
    assert_eq!(
        shlosilo_ur_decode_uri_ffi(
            c_uri.as_ptr(),
            ty.as_mut_ptr(),
            ty.len() as u32,
            tiny.as_mut_ptr(),
            tiny.len() as u32,
            &mut actual,
        ),
        ERR_BUFFER_TOO_SMALL
    );
    assert_eq!(actual as usize, eth_fixture_payload().len());
    // NULL argument
    assert_eq!(
        shlosilo_ur_decode_uri_ffi(
            core::ptr::null(),
            ty.as_mut_ptr(),
            ty.len() as u32,
            payload.as_mut_ptr(),
            payload.len() as u32,
            &mut actual,
        ),
        ERR_NULL_POINTER
    );
}

fn sign_via_typed(indices: &[u16], payload: &[u8]) -> (i32, std::vec::Vec<u8>, u32) {
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
        ETHEREUM_MAINNET,
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

#[test]
fn qr_session_sign_matches_typed_entry_byte_for_byte() {
    // the C scan flow's single-frame + live-session path:
    // shlosilo_ur_decode_uri_ffi -> (type, payload) -> sign_session_ffi
    let (ty, payload) = single_frame_request(ETH_SIGN_REQUEST_URI);
    assert_eq!(ty, b"eth-sign-request".to_vec());
    // legacy leg: the typed entry signs with the fixture mnemonic
    let indices = Mnemonic::from_entropy(&FIXTURE_ENTROPY)
        .expect("mnemonic")
        .indices()
        .to_vec();
    let (rc_t, out_t, len_t) = sign_via_typed(&indices, &payload);
    assert_eq!(rc_t, OK, "typed leg must sign");
    // scan-flow leg: plate -> QR glue open -> session pointer -> sign_session
    let mut ws = fresh_ws();
    let plate = standard_plate(&FIXTURE_ENTROPY);
    let mut session: *const KeySession = core::ptr::null();
    assert_eq!(
        shlosilo_keysource_qr_open_ffi(
            ws.as_mut_ptr(),
            ws.len() as core::ffi::c_uint,
            plate.as_ptr(),
            plate.len() as core::ffi::c_uint,
            &mut session
        ),
        OK
    );
    assert!(!session.is_null());
    let (rc_s, out_s, len_s) = sign_via_session(session, &payload);
    assert_eq!(rc_s, OK, "QR-session leg must sign");
    assert_eq!(len_s, len_t, "signature lengths must match");
    assert_eq!(
        &out_s[..len_s as usize],
        &out_t[..len_t as usize],
        "QR-glue session sign must be byte-identical to the typed entry"
    );
    assert_eq!(shlosilo_keysource_qr_close_ffi(ws.as_mut_ptr()), OK);
}
