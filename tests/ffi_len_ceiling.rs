//! FFI graded audit (2026-11-19) — F-1/F-2 pins.
//!
//! **F-1**: a `c_uint` length is a claim, and `u32::MAX` exceeds `isize::MAX` on a
//! 32-bit target, which makes `slice::from_raw_parts(_mut)` a violated precondition
//! (UB) rather than an error. Every entry therefore bounds the claim **before** the
//! slice exists:
//!
//! - **capacity claims** (output buffers) are clamped to the entry's budget — the
//!   caller cannot get a wider write than the budget allows, and does not get an
//!   error for owning a bigger buffer than we need;
//! - **count claims** (input/output arrays the entry walks) are refused with the
//!   entry's capacity/kind code, because a count also decides how many elements are
//!   read or written.
//!
//! The host is 64-bit and cannot see the overflow itself; the structural guard for
//! the clamp is `scripts/check_ffi_raw_len.sh` (a red/green source gate), and these
//! tests pin the *behaviour* each entry promises around a bogus claim.
//!
//! **F-2**: `shlosilo_review_ffi` carves record storage out of the caller workspace;
//! the base address is caller-chosen, so alignment has to be established at runtime
//! (a `debug_assert!` disappears in release).
#![cfg(feature = "alloc-fallback")]

use core::mem::MaybeUninit;

use shlosilo::error::ShlosiloErrorCode;
use shlosilo::ffi::c_abi;
use shlosilo::ffi::c_abi::r3::{shlosilo_sign_session_ffi, shlosilo_ur_decode_new};
use shlosilo::ffi::error_code::ERR_UNKNOWN;
use shlosilo::types::key_session::KeySession;

const OK: i32 = 0;
const ERR_BUFFER_TOO_SMALL: i32 = ShlosiloErrorCode::BufferTooSmall as i32;
const ERR_INVALID_FORMAT: i32 = ShlosiloErrorCode::EncodingError as i32;

/// Wallet entropy (same fixture family as tests/key_session_ffi.rs).
const FIXTURE_ENTROPY: [u8; 16] = [
    0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29, 0x16,
];

/// Payload carried through the encoder fixture (any bytes: the encoder only frames them).
const PAYLOAD: [u8; 64] = [0x42u8; 64];

fn empty_record() -> shlosilo::business::sign::WalletKiRecord {
    shlosilo::business::sign::WalletKiRecord {
        transfer_idx: 0,
        wallet_fp: [0u8; 8],
        key_image: [0u8; 32],
        out_pub: [0u8; 32],
    }
}

fn place_session(slot: &mut MaybeUninit<KeySession>, entropy: &[u8]) -> *mut KeySession {
    let session = KeySession::from_entropy(entropy, b"").expect("session");
    let handle = slot.as_mut_ptr();
    unsafe { core::ptr::write(handle, session) };
    handle
}

/// Put a live encoder into a caller workspace (the caller-placement contract).
fn with_encoder<R>(
    f: impl FnOnce(*mut shlosilo::ur::ur_multipart::UrMultipartEncoder<'static>, &mut [u8]) -> R,
) -> R {
    let need = c_abi::shlosilo_ur_encode_ws_len() as usize;
    let mut ws = std::vec![0u8; need];
    let handle = unsafe {
        c_abi::r3::shlosilo_ur_encode_begin(
            c"bytes".as_ptr(),
            PAYLOAD.as_ptr(),
            PAYLOAD.len() as u32,
            200,
            ws.as_mut_ptr(),
            need as u32,
        )
    };
    assert!(!handle.is_null(), "encoder handle");
    let mut frame = std::vec![0u8; 1024];
    let out = f(handle, &mut frame);
    unsafe { c_abi::r3::shlosilo_ur_encode_free(handle) };
    out
}

#[test]
fn ur_encode_next_clamps_absurd_frame_capacity() {
    with_encoder(|handle, frame| {
        let mut actual: u32 = 0;
        let rc = unsafe {
            c_abi::r3::shlosilo_ur_encode_next(handle, frame.as_mut_ptr(), u32::MAX, &mut actual)
        };
        assert_eq!(
            rc, OK,
            "an oversized capacity claim is clamped, not refused"
        );
        let n = actual as usize;
        assert!(
            n > 0 && n < frame.len(),
            "frame length {n} outside the buffer"
        );
        assert_eq!(frame[n], 0, "the frame is NUL-terminated inside the buffer");
    });
}

#[test]
fn ur_encode_next_cyclic_clamps_absurd_frame_capacity() {
    with_encoder(|handle, frame| {
        let mut actual: u32 = 0;
        let rc = unsafe {
            c_abi::r3::shlosilo_ur_encode_next_cyclic(
                handle,
                frame.as_mut_ptr(),
                u32::MAX,
                &mut actual,
            )
        };
        assert_eq!(rc, OK);
        let n = actual as usize;
        assert!(n > 0 && n < frame.len());
        assert_eq!(frame[n], 0);
    });
}

#[test]
fn ur_decode_payload_absurd_capacity_keeps_the_normal_error_path() {
    let need = c_abi::shlosilo_ur_decode_ws_len() as usize;
    let mut ws = std::vec![0u8; need];
    let handle = unsafe { shlosilo_ur_decode_new(ws.as_mut_ptr(), need as u32) };
    assert!(!handle.is_null(), "decoder handle");
    let mut buf = std::vec![0u8; 64];
    let mut actual: u32 = 7;
    let rc = unsafe {
        c_abi::r3::shlosilo_ur_decode_payload(handle, buf.as_mut_ptr(), u32::MAX, &mut actual)
    };
    unsafe { c_abi::r3::shlosilo_ur_decode_free(handle) };
    // capacity is clamped, so the answer is the session's own state, not a slice-length error.
    // A2-15 (2026-11-20): that state is the documented ERR_UNKNOWN (-1); it used to be reported as
    // EncodingInvalidFormat, which made "no frames yet" indistinguishable from malformed input.
    assert_eq!(rc, ERR_UNKNOWN);
    assert_ne!(rc, ERR_INVALID_FORMAT);
    assert_eq!(actual, 0);
}

#[test]
fn export_payload_rejects_absurd_capacity() {
    let mut slot = MaybeUninit::<KeySession>::uninit();
    let session = place_session(&mut slot, &FIXTURE_ENTROPY);

    // T1-11 (2026-11-19 audit, closed 2026-11-20): OK plus a positive length does not prove that
    // anything was written or that the reported length is the real one. The buffer is poisoned, and the
    // absurd capacity claim is compared against a normal one: same bytes, same length, poison only
    // beyond the reported end.
    let run = |cap: u32| -> (i32, u32, std::vec::Vec<u8>) {
        let mut out = std::vec![0xAAu8; 4096];
        let mut actual: u32 = 0xDEAD_BEEF;
        let rc = unsafe {
            shlosilo::ffi::export_abi::shlosilo_export_format_payload_ffi(
                session,
                0,
                0,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                0,
                out.as_mut_ptr(),
                cap,
                &mut actual,
            )
        };
        (rc, actual, out)
    };

    let (rc_normal, n_normal, buf_normal) = run(4096);
    let (rc_absurd, n_absurd, buf_absurd) = run(u32::MAX);

    assert_eq!(rc_normal, OK, "the normal-capacity call must succeed");
    assert_eq!(
        rc_absurd, OK,
        "the capacity claim must be clamped to the export budget, not refused"
    );
    assert_eq!(
        n_absurd, n_normal,
        "the absurd claim must report the same length as the honest one"
    );
    assert!(n_normal > 0, "nothing was written");
    assert!(
        buf_normal[..n_normal as usize].iter().any(|&b| b != 0xAA),
        "the reported range is still poison, so no bytes were written"
    );
    assert_eq!(
        &buf_absurd[..n_absurd as usize],
        &buf_normal[..n_normal as usize],
        "the clamped call must produce the same bytes"
    );
    assert!(
        buf_normal[n_normal as usize..].iter().all(|&b| b == 0xAA),
        "the call wrote past its own reported length"
    );

    // the session storage is caller-owned: drop the value in place
    unsafe { core::ptr::drop_in_place(session) };
}

#[test]
fn sign_session_rejects_absurd_ki_records_count() {
    // T1-15 (2026-11-19 audit, closed 2026-11-20): the old version asserted only "not OK", and its
    // payload is not a valid eth-sign-request anyway - so a payload/content rejection would have
    // satisfied it without the record-count check ever running. Measured: the absurd count is refused
    // with the count/kind code (-2), while the same call with one record fails later on content (-21).
    // The pin is that difference, plus a zeroed out-param.
    const RECORDS_KIND_CODE: i32 = shlosilo::error::ShlosiloErrorCode::InvalidArgument as i32;

    let mut slot = MaybeUninit::<KeySession>::uninit();
    let session = place_session(&mut slot, &FIXTURE_ENTROPY);
    let need = c_abi::shlosilo_sign_ws_len();
    let mut ws = std::vec![0u8; need as usize];
    let mut out = std::vec![0u8; 512];
    let records = [empty_record()];

    let mut run = |records_count: u32| -> (i32, u32) {
        let mut actual: u32 = 0xDEAD_BEEF;
        let rc = unsafe {
            shlosilo_sign_session_ffi(
                session,
                c"eth-sign-request".as_ptr(),
                PAYLOAD.as_ptr(),
                PAYLOAD.len() as u32,
                core::ptr::null(),
                0,
                out.as_mut_ptr(),
                out.len() as u32,
                &mut actual,
                ws.as_mut_ptr(),
                need,
                records.as_ptr(),
                records_count,
            )
        };
        (rc, actual)
    };

    let (rc_absurd, actual_absurd) = run(u32::MAX);
    let (rc_one, _) = run(1);
    unsafe { core::ptr::drop_in_place(session) };

    assert_eq!(
        rc_absurd, RECORDS_KIND_CODE,
        "a 4 Gi-record array claim must be refused by the count validation"
    );
    assert_eq!(
        actual_absurd, 0,
        "a refused call must report no written length"
    );
    assert_ne!(
        rc_one, RECORDS_KIND_CODE,
        "the one-record control must fail on the payload, not on the count check"
    );
}

#[test]
fn ki_store_merge_rejects_absurd_counts() {
    let mut store = [empty_record(); 4];
    let incoming = [empty_record(); 1];
    let mut len: u32 = 0;

    let rc = unsafe {
        c_abi::r3::shlosilo_ki_store_merge_ffi(
            store.as_mut_ptr(),
            u32::MAX,
            &mut len,
            incoming.as_ptr(),
            incoming.len() as u32,
        )
    };
    assert_eq!(rc, ERR_BUFFER_TOO_SMALL, "store capacity claim is clamped");

    let rc = unsafe {
        c_abi::r3::shlosilo_ki_store_merge_ffi(
            store.as_mut_ptr(),
            store.len() as u32,
            &mut len,
            incoming.as_ptr(),
            u32::MAX,
        )
    };
    assert_eq!(rc, ERR_BUFFER_TOO_SMALL, "incoming count claim is clamped");
}

/// F-2: the review workspace is caller memory, so the record pool has to be
/// aligned at runtime. A deliberately odd base address must still produce a
/// view (before the fix the record span was carved straight off that base, which
/// a `debug_assert!` caught only in debug builds).
#[test]
fn review_ffi_accepts_misaligned_workspace() {
    use shlosilo::ffi::c_abi::shlosilo_review_ws_len;

    const PSBT: &[u8] = include_bytes!("fixtures/sparrow_signet_12k.psbt");
    let need = shlosilo_review_ws_len() as usize;

    // T1-12 (2026-11-19 audit, closed 2026-11-20): "count > 0" only shows the entry did not refuse the
    // address - it cannot see a misaligned carve producing garbage content. The same review is run twice,
    // from an aligned workspace and from a base shifted by one byte, and the complete output (line blob,
    // length, line count, flags, in/out counts) must be identical.
    let run = |shift: usize| -> (i32, std::vec::Vec<u8>, u32, u32, u32, u32) {
        let mut backing = std::vec![0u8; need + 8];
        let ws = &mut backing[shift..shift + need];
        let mut lines = std::vec![0u8; c_abi::REVIEW_LINES_BUF];
        let (mut used, mut count, mut flags, mut in_out) = (0u32, 0u32, 0u32, 0u32);
        let rc = unsafe {
            c_abi::shlosilo_review_ffi(
                c"crypto-psbt".as_ptr(),
                PSBT.as_ptr(),
                PSBT.len() as u32,
                1, // testnet
                core::ptr::null(),
                ws.as_mut_ptr(),
                ws.len() as u32,
                lines.as_mut_ptr(),
                lines.len() as u32,
                &mut used,
                &mut count,
                &mut flags,
                &mut in_out,
                core::ptr::null_mut(),
            )
        };
        lines.truncate(used as usize);
        (rc, lines, used, count, flags, in_out)
    };

    let aligned = run(0);
    let shifted = run(1);

    assert_eq!(aligned.0, OK, "the aligned control must succeed");
    assert_eq!(
        shifted.0, OK,
        "a misaligned workspace must still be accepted (the entry aligns the base itself)"
    );
    assert!(aligned.3 > 0, "the review produced no lines");
    assert!(
        aligned.1.iter().any(|&b| b != 0),
        "the aligned run produced an empty blob"
    );
    assert_eq!(
        aligned.1, shifted.1,
        "the misaligned run produced different line bytes"
    );
    assert_eq!(aligned.2, shifted.2, "used differs");
    assert_eq!(aligned.3, shifted.3, "line count differs");
    assert_eq!(aligned.4, shifted.4, "flags differ");
    assert_eq!(aligned.5, shifted.5, "in/out counts differ");
}
