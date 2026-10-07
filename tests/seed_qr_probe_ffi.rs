//! Task 5a tests — `shlosilo_seed_qr_probe_ffi`: the seed-QR scan-flow probe.
//!
//! Pins the C classification codes (0..5) over the full classification set and
//! the error side (NULL / over-budget). Test-vector convention
//! (tests/key_session_ffi.rs): fixed plaintext entropy fixtures, never real
//! seed material.

use shlosilo::ffi::c_abi::shlosilo_seed_qr_probe_ffi;

/// Classification codes (the probe's C contract).
const NOT_SEED: i32 = 0;
const STANDARD_12: i32 = 1;
const STANDARD_24: i32 = 2;
const COMPACT_12: i32 = 3;
const COMPACT_24: i32 = 4;
const UR_UNSUPPORTED: i32 = 5;
const ERR_NULL_POINTER: i32 = -2;
const ERR_ENCODING: i32 = -21;

fn probe(data: &[u8]) -> i32 {
    shlosilo_seed_qr_probe_ffi(data.as_ptr(), data.len() as core::ffi::c_uint)
}

fn digits(n: usize) -> alloc::vec::Vec<u8> {
    (0..n).map(|i| b'0' + (i % 10) as u8).collect()
}

extern crate alloc;

#[test]
fn compact_16_and_32_classify_by_word_count() {
    // classify is PURE: any 16/32 bytes are the compact length domain — no
    // checksum runs here (that is decode's job at session-open time).
    assert_eq!(probe(&[0x11u8; 16]), COMPACT_12);
    assert_eq!(probe(&[0xffu8; 16]), COMPACT_12);
    assert_eq!(probe(&[0x5au8; 32]), COMPACT_24);
    assert_eq!(probe(&[0x00u8; 32]), COMPACT_24);
}

#[test]
fn standard_48_and_96_digits_classify_by_word_count() {
    assert_eq!(probe(&digits(48)), STANDARD_12);
    assert_eq!(probe(&digits(96)), STANDARD_24);
}

#[test]
fn non_digit_48_and_96_are_not_seed() {
    assert_eq!(probe(&[b'a'; 48]), NOT_SEED);
    assert_eq!(probe(&[b'a'; 96]), NOT_SEED);
    // one noise byte inside the digit run disqualifies the payload
    let mut noisy = digits(48);
    noisy[7] = b'x';
    assert_eq!(probe(&noisy), NOT_SEED);
}

#[test]
fn ur_transport_is_its_own_class() {
    assert_eq!(probe(b"ur:"), UR_UNSUPPORTED);
    assert_eq!(probe(b"ur:crypto-seed/abc"), UR_UNSUPPORTED);
    assert_eq!(probe(b"UR:abc"), UR_UNSUPPORTED);
    // no colon → not UR; length outside the plate domains → not a seed
    assert_eq!(probe(b"ur"), NOT_SEED);
}

#[test]
fn empty_and_off_lengths_are_not_seed() {
    // empty scan: non-null pointer, zero length
    let dummy = 0u8;
    assert_eq!(
        shlosilo_seed_qr_probe_ffi(&dummy, 0),
        NOT_SEED,
        "empty payload is NotSeed"
    );
    for n in [1usize, 15, 17, 31, 33, 47, 97] {
        assert_eq!(probe(&alloc::vec![0x5au8; n]), NOT_SEED, "len {n}");
    }
}

#[test]
fn null_data_is_err_null_pointer() {
    assert_eq!(
        shlosilo_seed_qr_probe_ffi(core::ptr::null(), 16),
        ERR_NULL_POINTER
    );
    assert_eq!(
        shlosilo_seed_qr_probe_ffi(core::ptr::null(), 0),
        ERR_NULL_POINTER
    );
}

#[test]
fn over_budget_scan_payload_is_encoding_error() {
    // above the 4096-byte scan budget: rejected before classification
    let big = alloc::vec![b'0'; 4097];
    assert_eq!(probe(&big), ERR_ENCODING);
}
