//! QR transport limits (S2 / B-7): the two directions are not one number.
//!
//! ## What this pins
//!
//! 1. **Inbound** (wallet → device) is bounded by the fountain decoder's slot
//!    count, not by memory: it completes at `decoded_count >= sequence_count`
//!    with `UR_WS_DECODED_SLOTS = 256` slots and the sender's fragment length
//!    (~65 B of data for the 130-character fragments the Cake family sends),
//!    i.e. ~16 KiB. Raising that constant alone accepts frames that can never be
//!    assembled.
//! 2. **Outbound** (device → wallet) is ours to choose: 64 KiB, because we pick
//!    the fragment length and the wallet's decoder is the limit.
//! 3. The Rust caps and the firmware constants must agree - a mismatch shows up
//!    either as "collected but cannot buffer" or as a sign that succeeds into a
//!    buffer the carousel cannot carry.
//! 4. The outbound budget gate accepts a 64 KiB buffer and refuses one byte more
//!    without writing partial output.

use core::ffi::c_uint;
use std::ffi::CString;

const PRODUCT_TASK_C: &str = include_str!("../flux/forgebox/src/tasks/product_task.c");

const INBOUND: usize = 16 * 1024;
const OUTBOUND: usize = 64 * 1024 + 512;

fn hex_decode(s: &str) -> Vec<u8> {
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    clean
        .chunks(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16).unwrap();
            let lo = (p[1] as char).to_digit(16).unwrap();
            ((hi << 4) | lo) as u8
        })
        .collect()
}

/// Call the typed sign entry with a caller buffer of `out_len` bytes.
/// The mnemonic is deliberately invalid, so the call stops right after the
/// buffer-budget gate - which is the thing under test.
fn typed_sign_with_buffer(out_len: usize) -> (i32, c_uint) {
    // A minimal, well-formed request: the fixture only has to be large enough to
    // exist, since the budget check precedes parsing.
    let payload = hex_decode(
        "70736274ff01005e02000000013aee4d6b51da574900e56d173041115bd1e1d01d4697a845784cf716a10c9806\
         0000000000ffffffff0100190000000000002251202258f2d4637b2ca3fd27614868b33dee1a242b42582d5474\
         f51730005fa99ce800000000",
    );
    let tname = CString::new("crypto-psbt").unwrap();
    let idx: Vec<u16> = vec![0u16; 12];
    let passphrase: [u8; 0] = [];
    let mut out = vec![0u8; out_len];
    let mut actual: c_uint = 0;
    let mut ws = vec![0u8; shlosilo::ffi::c_abi::shlosilo_sign_ws_len() as usize];
    let rc = shlosilo::ffi::c_abi::r3::shlosilo_sign_typed_ffi(
        tname.as_ptr(),
        payload.as_ptr(),
        payload.len() as c_uint,
        idx.as_ptr(),
        12,
        passphrase.as_ptr(),
        0,
        0,
        core::ptr::null(),
        0,
        out.as_mut_ptr(),
        out.len() as c_uint,
        &mut actual,
        ws.as_mut_ptr(),
        ws.len() as c_uint,
    );
    (rc, actual)
}

/// 1. The inbound cap is the slot-derived one, and the firmware agrees with it.
#[test]
fn inbound_cap_is_the_slot_derived_value_on_both_sides() {
    // Rust side: the constant the FFI and XMR plaintext budgets derive from.
    let rust_inbound = shlosilo::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN;
    assert_eq!(
        rust_inbound, INBOUND,
        "inbound reassembly cap: 256 decode slots x ~65 B sender fragments"
    );
    // Firmware side.
    assert!(
        PRODUCT_TASK_C.contains("#define UR_PAYLOAD_MAX            (16 * 1024)"),
        "the firmware's inbound buffer must match the Rust cap (otherwise a payload \
         is collected that the signer then refuses)"
    );
}

/// 2. The outbound cap is 64 KiB + slack on both sides.
#[test]
fn outbound_cap_is_64k_on_both_sides() {
    assert!(
        PRODUCT_TASK_C.contains("#define SIGN_OUT_MAX              (64 * 1024 + 512)"),
        "the firmware's signed-artifact buffer must be the outbound cap"
    );
    // The FFI budget gate accepts exactly this many bytes (checked below); the
    // constant itself lives in caps.rs and is not exported, so the behavioural
    // test is what ties the two together.
    assert_eq!(OUTBOUND, 64 * 1024 + 512);
}

/// 3. The budget gate: a 64 KiB buffer reaches the mnemonic check (i.e. the
///    budget accepted it), one byte more is refused as a buffer problem.
#[test]
fn outbound_budget_accepts_64k_and_refuses_more() {
    let (rc_at, actual_at) = typed_sign_with_buffer(OUTBOUND);
    let (rc_over, actual_over) = typed_sign_with_buffer(OUTBOUND + 1);

    // Exact codes, not just "they differ": 64 KiB stops at the (deliberately
    // invalid) mnemonic, i.e. it passed the budget gate, while one byte more is
    // refused as a buffer problem.
    assert_eq!(
        rc_at,
        shlosilo::error::ShlosiloErrorCode::InvalidMnemonic as i32,
        "64 KiB must clear the buffer gate and fail on the placeholder mnemonic"
    );
    assert_eq!(
        rc_over,
        shlosilo::error::ShlosiloErrorCode::BufferTooSmall as i32,
        "64 KiB + 1 must be refused by the budget gate"
    );
    assert_eq!(
        actual_over, 0,
        "a refused buffer must not report a length (zero-partial-state rule)"
    );
    assert_eq!(
        actual_at, 0,
        "nothing is written when the mnemonic is invalid: no partial output"
    );
}

/// 4. The decoder's own limit is what makes the inbound cap structural: a
///    message needing more fragments than there are slots can never complete.
///    (Guards the reasoning in the caps module note, so a future slot-count
///    change has to revisit the cap deliberately.)
#[test]
fn inbound_cap_stays_within_what_the_slots_can_assemble() {
    // 65 B of data per part is what 130-character bytewords fragments carry.
    const SENDER_FRAGMENT: usize = 65;
    let slots = shlosilo::types::caps::UR_WS_DECODED_SLOTS;
    let reachable = slots * SENDER_FRAGMENT;
    assert!(
        INBOUND <= reachable,
        "the inbound cap ({INBOUND}) must stay under what {slots} slots can assemble \
         with {SENDER_FRAGMENT}-byte fragments ({reachable})"
    );
}
