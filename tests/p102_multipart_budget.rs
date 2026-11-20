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
#![cfg(feature = "alloc-fallback")]

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
    assert_eq!(MULTIPART_PAYLOAD_MAX_LEN, 256 * 240);
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
    let mut ws_buf = vec![0u8; shlosilo::ffi::c_abi::shlosilo_sign_ws_len() as usize];
    let rc = unsafe {
        shlosilo_sign_typed_ffi(
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
            ws_buf.as_mut_ptr(),
            shlosilo::ffi::c_abi::shlosilo_sign_ws_len(),
        )
    };
    // T1-14 (2026-11-19 audit, closed 2026-11-20): "rc != 0" cannot tell a budget rejection from a
    // content rejection - the payload here is zero-filled garbage, so several later checks would also
    // fail. The two shapes are now told apart by their codes: the oversized payload must be refused
    // with the capacity code *before* any content check, while the same call with a small payload
    // fails later (content), i.e. with a different code.
    let budget_code = shlosilo::error::ShlosiloErrorCode::BufferTooSmall as i32;
    assert_eq!(
        rc, budget_code,
        "payload > MULTIPART_PAYLOAD_MAX_LEN must be refused with the capacity code"
    );
    assert_eq!(actual, 0, "a refused call must not report a written length");

    let small = std::vec![0u8; 16];
    let rc_small = unsafe {
        shlosilo_sign_typed_ffi(
            tname.as_ptr(),
            small.as_ptr(),
            small.len() as u32,
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
            ws_buf.as_mut_ptr(),
            shlosilo::ffi::c_abi::shlosilo_sign_ws_len(),
        )
    };
    assert_ne!(
        rc_small, budget_code,
        "the in-budget control must fail for content reasons, not with the capacity code"
    );
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

/// Legal sessions are not collateral damage when the retained budget nears its cap.
///
/// The payload here is the largest one a *session* can actually complete: the
/// fountain index domain (`MAX_SEQUENCE_COUNT = 256`) caps a message at 256 parts,
/// so 200-byte parts top out at 51,200 B. `MULTIPART_PAYLOAD_MAX_LEN` (64 KiB) is the
/// buffer budget, not the session budget - a 64 KiB message would need 328 parts and
/// the encoder refuses it, which is the honest answer (B-7, 2026-11-15).
#[test]
fn p102_max_payload_session_within_budget() {
    // 250 parts x 200 B: the shell prefix and fragment rounding eat into the
    // 256-part domain, so leave a little headroom rather than sit exactly on it.
    let payload: std::vec::Vec<u8> = vec![0u8; 250 * 200];
    assert!(payload.len() <= MULTIPART_PAYLOAD_MAX_LEN);
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
