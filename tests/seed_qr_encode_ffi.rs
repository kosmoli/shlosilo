//! Phase 4 acceptance ② tests — `shlosilo_seed_qr_encode_ffi`: the plate
//! EXPORT face (wallet entropy → SeedQR QR payload).
//!
//! Golden provenance (NOT hand-derived): the real SeedSigner encoders
//! `seedsigner.models.encode_qr.SeedQrEncoder` / `CompactSeedQrEncoder`
//! (tests/seed_qr_oracle.rs, entropy A/B fixtures). The device `key plate`
//! command renders EXACTLY these bytes into the QR symbol, so an external
//! SeedSigner scanning the screen must land on the same wallet.
//!
//! Test-vector convention (tests/key_session_ffi.rs): fixed plaintext
//! entropy fixtures, never real seed material.

use shlosilo::ffi::c_abi::{
    shlosilo_seed_qr_encode_ffi, SEED_QR_MODE_COMPACT, SEED_QR_MODE_STANDARD,
};

/// Golden vectors (tests/seed_qr_oracle.rs — SeedSigner oracle output).
const ENTROPY_A: [u8; 16] = [0x11; 16];
const GOLDEN_SEEDQR_A: &[u8] = b"013610920546027301361092054602730136109205460283";
const GOLDEN_COMPACT_A: [u8; 16] = [0x11; 16];

const ENTROPY_B: [u8; 32] = [0x22; 32];
const GOLDEN_SEEDQR_B: &[u8] = b"027301361092054602730136109205460273013610920546027301361092054602730136109205460273013610920671";
const GOLDEN_COMPACT_B: [u8; 32] = [0x22; 32];

const OK: i32 = 0;
const ERR_NULL_POINTER: i32 = -2;
const ERR_BUFFER_TOO_SMALL: i32 = -20;
const ERR_ENCODING: i32 = -21;
const ERR_MNEMONIC_INVALID_ENTROPY_LEN: i32 = -31;

/// Encode through the C ABI exactly the way the device `key plate` path does.
fn encode(mode: i32, entropy: &[u8]) -> (i32, Vec<u8>, u32) {
    let mut out = vec![0u8; 96];
    let mut actual: u32 = 0;
    let rc = shlosilo_seed_qr_encode_ffi(
        mode,
        entropy.as_ptr(),
        entropy.len() as core::ffi::c_uint,
        out.as_mut_ptr(),
        out.len() as core::ffi::c_uint,
        &mut actual,
    );
    out.truncate(actual as usize);
    (rc, out, actual)
}

#[test]
fn standard_payload_matches_oracle_golden() {
    let (rc, out, n) = encode(SEED_QR_MODE_STANDARD, &ENTROPY_A);
    assert_eq!(rc, OK);
    assert_eq!(n, 48);
    assert_eq!(out, GOLDEN_SEEDQR_A.to_vec(), "SeedQR 12w payload drift");

    let (rc, out, n) = encode(SEED_QR_MODE_STANDARD, &ENTROPY_B);
    assert_eq!(rc, OK);
    assert_eq!(n, 96);
    assert_eq!(out, GOLDEN_SEEDQR_B.to_vec(), "SeedQR 24w payload drift");
}

#[test]
fn compact_payload_matches_oracle_golden() {
    let (rc, out, n) = encode(SEED_QR_MODE_COMPACT, &ENTROPY_A);
    assert_eq!(rc, OK);
    assert_eq!(n, 16);
    assert_eq!(out, GOLDEN_COMPACT_A.to_vec(), "CompactSeedQR 12w drift");

    let (rc, out, n) = encode(SEED_QR_MODE_COMPACT, &ENTROPY_B);
    assert_eq!(rc, OK);
    assert_eq!(n, 32);
    assert_eq!(out, GOLDEN_COMPACT_B.to_vec(), "CompactSeedQR 24w drift");
}

#[test]
fn payload_round_trips_through_scan_decode() {
    // The acceptance loop closes on the device too: what `key plate` renders
    // must import back through the scan path (seed_qr::decode) to the same
    // entropy — the same bytes an external SeedSigner consumes.
    for (mode, entropy) in [
        (SEED_QR_MODE_STANDARD, &ENTROPY_A[..]),
        (SEED_QR_MODE_COMPACT, &ENTROPY_A[..]),
        (SEED_QR_MODE_STANDARD, &ENTROPY_B[..]),
        (SEED_QR_MODE_COMPACT, &ENTROPY_B[..]),
    ] {
        let (rc, out, _) = encode(mode, entropy);
        assert_eq!(rc, OK);
        let back = shlosilo::entropy::seed_qr::decode(&out).expect("scan decode");
        assert_eq!(back.expose(), entropy);
    }
}

#[test]
fn error_side() {
    let mut out = vec![0u8; 96];
    let mut actual: u32 = 7;

    // NULL buffers
    let rc = shlosilo_seed_qr_encode_ffi(
        SEED_QR_MODE_STANDARD,
        core::ptr::null(),
        16,
        out.as_mut_ptr(),
        96,
        &mut actual,
    );
    assert_eq!(rc, ERR_NULL_POINTER);
    assert_eq!(actual, 0, "actual_len must be zeroed on every error path");

    let rc = shlosilo_seed_qr_encode_ffi(
        SEED_QR_MODE_STANDARD,
        ENTROPY_A.as_ptr(),
        16,
        core::ptr::null_mut(),
        96,
        &mut actual,
    );
    assert_eq!(rc, ERR_NULL_POINTER);

    // out budget too small
    let rc = shlosilo_seed_qr_encode_ffi(
        SEED_QR_MODE_STANDARD,
        ENTROPY_A.as_ptr(),
        16,
        out.as_mut_ptr(),
        47,
        &mut actual,
    );
    assert_eq!(rc, ERR_BUFFER_TOO_SMALL);
    assert_eq!(actual, 0);

    // entropy length outside the steel-plate family (16/32 only)
    for bad_len in [0u32, 15, 17, 24, 31, 33] {
        let rc = shlosilo_seed_qr_encode_ffi(
            SEED_QR_MODE_STANDARD,
            out.as_ptr(),
            bad_len,
            out.as_mut_ptr(),
            96,
            &mut actual,
        );
        assert_eq!(
            rc, ERR_MNEMONIC_INVALID_ENTROPY_LEN,
            "len {bad_len} must be rejected with the documented length-class code"
        );
        assert_eq!(actual, 0);
    }

    // unknown mode
    let rc =
        shlosilo_seed_qr_encode_ffi(0, ENTROPY_A.as_ptr(), 16, out.as_mut_ptr(), 96, &mut actual);
    assert_eq!(rc, ERR_ENCODING);
    let rc =
        shlosilo_seed_qr_encode_ffi(3, ENTROPY_A.as_ptr(), 16, out.as_mut_ptr(), 96, &mut actual);
    assert_eq!(rc, ERR_ENCODING);
}
