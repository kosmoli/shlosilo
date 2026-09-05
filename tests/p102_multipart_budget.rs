//! P1-02 remediation landing tests (2026-09-01 Audit #4) — multipart decoder resource budgets
//!
//! Audit findings:
//! - wire message_length cast directly as usize; the decoder side had no MULTIPART_PAYLOAD_MAX_LEN check
//! - silent u64 → usize/u32 narrowing (dangerous on 32-bit Thumb)
//! - missing fragment/count/message consistency validation
//!
//! Covers: decoder-side budget constant locking + a legal-path smoke test + the FFI exit budget.
//! part_from_cbor's item-by-item validation (wire_len fallible / message_length budget /
//! fragment-count-message consistency) is covered at the ur_multipart::tests unit level.

use shlosilo::ur::ur_multipart::{UrMultipartDecoder, MULTIPART_PAYLOAD_MAX_LEN};

/// Legal multipart roundtrip smoke (budget tightening must not break legal paths)
#[test]
fn p102_valid_multipart_roundtrip() {
    let payload: std::vec::Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let mut enc =
        shlosilo::ur::ur_multipart::UrMultipartEncoder::new("bytes", &payload, 200).unwrap();
    let mut dec = UrMultipartDecoder::new();
    let n = enc.fragment_count();
    for _ in 0..n {
        let frame = enc.next_frame().unwrap();
        assert!(dec.receive_frame(frame.as_str()).unwrap());
    }
    assert!(dec.complete());
    let out = dec.payload().unwrap().unwrap();
    assert_eq!(out, payload);
}

/// Budget constant declarations unchanged (locked audit alignment: 16 KiB payload / 40 KiB frame)
#[test]
fn p102_budget_constants() {
    assert_eq!(MULTIPART_PAYLOAD_MAX_LEN, 16384);
    assert_eq!(shlosilo::ur::ur_multipart::MULTIPART_FRAME_MAX_LEN, 40960);
}

/// The encoder rejects over-budget payload (regression lock on existing behavior)
#[test]
fn p102_encoder_over_budget_rejected() {
    let big = std::vec![0u8; MULTIPART_PAYLOAD_MAX_LEN + 1];
    let r = shlosilo::ur::ur_multipart::UrMultipartEncoder::new("bytes", &big, 200);
    assert!(r.is_err(), "encoder payload > 16 KiB must be rejected");
}

/// FFI typed sign payload budget (the FFI exit of the same decoder-side budget)
#[test]
fn p102_typed_sign_over_budget_rejected() {
    use shlosilo::ffi::c_abi::r3::shlosilo_sign_typed_ffi;
    let big = std::vec![0u8; MULTIPART_PAYLOAD_MAX_LEN + 1];
    let idx: [u16; 12] = [0; 12];
    let mut out = [0u8; 64];
    let mut actual: u32 = 0;
    let tname = c"crypto-psbt";
    let rc = shlosilo_sign_typed_ffi(
        tname.as_ptr(),
        big.as_ptr(),
        big.len() as u32,
        idx.as_ptr(),
        12,
        core::ptr::null(),
        0,
        0,
        core::ptr::null(),
        0,
        out.as_mut_ptr(),
        out.len() as u32,
        &mut actual,
    );
    assert_ne!(rc, 0, "typed sign payload > budget must be rejected");
}

//-- Audit #6 P1-02: duplicate frames consume no budget + reset when work is exceeded --

/// Duplicate frames consume no retained budget — mass repeated scanning must not trigger a reset (usability DoS fix)
#[test]
fn p102_duplicate_frames_do_not_consume_budget() {
    let payload: std::vec::Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let mut enc =
        shlosilo::ur::ur_multipart::UrMultipartEncoder::new("bytes", &payload, 200).unwrap();
    let mut dec = UrMultipartDecoder::new();
    let n = enc.fragment_count();
    // First pass: all frames
    let mut frames = Vec::new();
    for _ in 0..n {
        frames.push(enc.next_frame().unwrap());
    }
    for f in &frames {
        assert!(dec.receive_frame(f.as_str()).unwrap());
    }
    // Re-scan the same frame 10000 times: each Ok(false); must not reset the session (the session stays complete)
    for _ in 0..10_000 {
        let accepted = dec.receive_frame(frames[0].as_str()).unwrap();
        assert!(!accepted, "duplicate frame must not be accepted");
        assert!(dec.complete(), "duplicate scan must not reset the session");
    }
}

/// Legal sessions are not collateral damage when the retained budget nears its cap (16KB payload = half the budget)
#[test]
fn p102_max_payload_session_within_budget() {
    let payload: std::vec::Vec<u8> = vec![0u8; MULTIPART_PAYLOAD_MAX_LEN];
    let mut enc =
        shlosilo::ur::ur_multipart::UrMultipartEncoder::new("bytes", &payload, 200).unwrap();
    let mut dec = UrMultipartDecoder::new();
    let n = enc.fragment_count();
    for _ in 0..n {
        let f = enc.next_frame().unwrap();
        assert!(
            dec.receive_frame(f.as_str()).is_ok(),
            "16KiB payload must fit within 32KiB retained budget"
        );
    }
    assert!(dec.complete());
    assert_eq!(dec.payload().unwrap().unwrap(), payload);
}
