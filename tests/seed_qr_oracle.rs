//! SeedQR / CompactSeedQR golden tests against the SeedSigner oracle.
//!
//! Golden provenance (NOT hand-derived): the real SeedSigner encoders
//! `seedsigner.models.encode_qr.SeedQrEncoder` / `CompactSeedQrEncoder`
//! (~/codebases/seedsigner @ encode_qr.py) driven with embit 0.8.0
//! `bip39.mnemonic_from_bytes`:
//!
//! ```text
//! entropy A = 11×16  -> baby mass dust captain baby mass dust captain baby mass dust casino
//!   indices 136 1092 546 273 136 1092 546 273 136 1092 546 283
//!   SeedQR       "013610920546027301361092054602730136109205460283"   (48 digits)
//!   CompactSeedQR 1111…11 (16 bytes) = 11111111111111111111111111111111
//! entropy B = 22×32  -> captain baby mass dust … captain baby mass fault
//!   indices (273 136 1092 546)×5 + 273 136 1092 671
//!   SeedQR       "0273013610920546…0273013610920671"                   (96 digits)
//!   CompactSeedQR 2222…22 (32 bytes)
//! ```
//!
//! The compact goldens equal the input entropy byte-for-byte — the expected
//! outcome of the SeedSigner bit layout (11-bit index stream, drop the trailing
//! 4/8 checksum bits, repack 8 bits at a time), independently confirmed by the
//! oracle rather than assumed.

use shlosilo::entropy::mnemonic::{Mnemonic, WordCount};
use shlosilo::entropy::seed_qr::{decode, encode_compact, encode_standard};
use shlosilo::error::ShlosiloErrorKind;

// ─── golden vectors (SeedSigner oracle output) ───────────────────────────────

const ENTROPY_A: [u8; 16] = [0x11; 16];
const GOLDEN_IDX_A: [u16; 12] = [
    136, 1092, 546, 273, 136, 1092, 546, 273, 136, 1092, 546, 283,
];
const GOLDEN_SEEDQR_A: &str = "013610920546027301361092054602730136109205460283";
const GOLDEN_COMPACT_A: [u8; 16] = [0x11; 16];

const ENTROPY_B: [u8; 32] = [0x22; 32];
const GOLDEN_IDX_B: [u16; 24] = [
    273, 136, 1092, 546, 273, 136, 1092, 546, 273, 136, 1092, 546, 273, 136, 1092, 546, 273, 136,
    1092, 546, 273, 136, 1092, 671,
];
const GOLDEN_SEEDQR_B: &str = "027301361092054602730136109205460273013610920546027301361092054602730136109205460273013610920671";
const GOLDEN_COMPACT_B: [u8; 32] = [0x22; 32];

// ─── encode: bit-exact against the oracle ────────────────────────────────────

#[test]
fn oracle_entropy_a_indices_match_embit() {
    // Our BIP-39 (from_entropy) must land on the embit word indices the oracle used.
    let m = Mnemonic::from_entropy(&ENTROPY_A).unwrap();
    assert_eq!(m.indices(), &GOLDEN_IDX_A);
}

#[test]
fn oracle_entropy_b_indices_match_embit() {
    let m = Mnemonic::from_entropy(&ENTROPY_B).unwrap();
    assert_eq!(m.indices(), &GOLDEN_IDX_B);
}

#[test]
fn encode_standard_entropy_a_matches_golden() {
    let m = Mnemonic::from_entropy(&ENTROPY_A).unwrap();
    assert_eq!(encode_standard(&m), GOLDEN_SEEDQR_A);
}

#[test]
fn encode_standard_entropy_b_matches_golden() {
    let m = Mnemonic::from_entropy(&ENTROPY_B).unwrap();
    assert_eq!(encode_standard(&m), GOLDEN_SEEDQR_B);
}

#[test]
fn encode_compact_entropy_a_matches_golden() {
    let m = Mnemonic::from_entropy(&ENTROPY_A).unwrap();
    assert_eq!(encode_compact(&m), GOLDEN_COMPACT_A.to_vec());
}

#[test]
fn encode_compact_entropy_b_matches_golden() {
    let m = Mnemonic::from_entropy(&ENTROPY_B).unwrap();
    assert_eq!(encode_compact(&m), GOLDEN_COMPACT_B.to_vec());
}

// ─── decode: golden payloads back to entropy ─────────────────────────────────

#[test]
fn decode_compact_entropy_a() {
    let s = decode(&GOLDEN_COMPACT_A).unwrap();
    assert_eq!(s.len(), 16);
    assert_eq!(s.expose(), &ENTROPY_A);
}

#[test]
fn decode_compact_entropy_b() {
    let s = decode(&GOLDEN_COMPACT_B).unwrap();
    assert_eq!(s.len(), 32);
    assert_eq!(s.expose(), &ENTROPY_B);
}

#[test]
fn decode_standard_entropy_a() {
    let s = decode(GOLDEN_SEEDQR_A.as_bytes()).unwrap();
    assert_eq!(s.len(), 16);
    assert_eq!(s.expose(), &ENTROPY_A);
}

#[test]
fn decode_standard_entropy_b() {
    let s = decode(GOLDEN_SEEDQR_B.as_bytes()).unwrap();
    assert_eq!(s.len(), 32);
    assert_eq!(s.expose(), &ENTROPY_B);
}

// ─── round-trip: encode → decode → identical entropy ─────────────────────────

#[test]
fn round_trip_compact_both_lengths() {
    for entropy in [ENTROPY_A.to_vec(), ENTROPY_B.to_vec()] {
        let m = Mnemonic::from_entropy(&entropy).unwrap();
        let s = decode(&encode_compact(&m)).unwrap();
        assert_eq!(s.expose(), &entropy[..]);
    }
}

#[test]
fn round_trip_standard_both_lengths() {
    for entropy in [ENTROPY_A.to_vec(), ENTROPY_B.to_vec()] {
        let m = Mnemonic::from_entropy(&entropy).unwrap();
        let s = decode(encode_standard(&m).as_bytes()).unwrap();
        assert_eq!(s.expose(), &entropy[..]);
    }
}

// ─── recognition / rejection ─────────────────────────────────────────────────

#[test]
fn decode_rejects_ur_payload() {
    // UR transport (crypto-seed) is a v2 concern; explicit FeatureNotImplemented.
    let err = decode(b"ur:crypto-seed/1-2/lpaxcywzvt90jyvs0zt0yxdq").unwrap_err();
    assert_eq!(err.kind, ShlosiloErrorKind::FeatureNotImplemented);
    // Short `ur:` payload must not slip through as compact entropy either.
    let err = decode(b"ur:xy").unwrap_err();
    assert_eq!(err.kind, ShlosiloErrorKind::FeatureNotImplemented);
}

#[test]
fn decode_rejects_nondigit_in_digit_domains() {
    // 48/96-length domains reserved for the %04d digit strings.
    let mut a = GOLDEN_SEEDQR_A.as_bytes().to_vec();
    a[7] = b'x';
    let err = decode(&a).unwrap_err();
    assert_eq!(err.kind, ShlosiloErrorKind::EncodingInvalidFormat);

    let mut b = GOLDEN_SEEDQR_B.as_bytes().to_vec();
    b[42] = b'-';
    let err = decode(&b).unwrap_err();
    assert_eq!(err.kind, ShlosiloErrorKind::EncodingInvalidFormat);
}

#[test]
fn decode_rejects_bad_byte_lengths() {
    // 15/17/33-byte streams: outside both the compact (16/32) and digit (48/96) domains.
    for bad in [15usize, 17, 33] {
        let data = vec![0x5au8; bad];
        let err = decode(&data).unwrap_err();
        assert_eq!(
            err.kind,
            ShlosiloErrorKind::EncodingInvalidFormat,
            "len {bad} must be rejected"
        );
    }
    // 15/18/21-word entropy lengths are valid BIP-39 but NOT in the
    // SeedSigner 12/24 steel-plate family — must be rejected all the same.
    for bad in [20usize, 24, 28] {
        let data = vec![0x5au8; bad];
        let err = decode(&data).unwrap_err();
        assert_eq!(
            err.kind,
            ShlosiloErrorKind::EncodingInvalidFormat,
            "len {bad} must be rejected (12/24 family only)"
        );
    }
}

#[test]
fn decode_rejects_out_of_range_index() {
    // 4 ASCII digits ≥ 2048 in an otherwise well-formed 48-digit string.
    let mut a = GOLDEN_SEEDQR_A.as_bytes().to_vec();
    a[0..4].copy_from_slice(b"2048");
    let err = decode(&a).unwrap_err();
    assert_eq!(err.kind, ShlosiloErrorKind::MnemonicInvalidWord);
}

#[test]
fn decode_rejects_bad_checksum_digits() {
    // Adjacent valid word swap (last index 0283 -> 0284) breaks the BIP-39 checksum.
    let mut a = GOLDEN_SEEDQR_A.as_bytes().to_vec();
    a[44..48].copy_from_slice(b"0284");
    let err = decode(&a).unwrap_err();
    assert_eq!(err.kind, ShlosiloErrorKind::MnemonicInvalidChecksum);
}

// ─── word-count fan-out: decode result feeds KeySession::from_entropy ────────

#[test]
fn decoded_entropy_matches_expected_word_count() {
    let a = decode(&GOLDEN_COMPACT_A).unwrap();
    assert_eq!(a.len(), WordCount::Words12.entropy_bytes());
    let b = decode(&GOLDEN_COMPACT_B).unwrap();
    assert_eq!(b.len(), WordCount::Words24.entropy_bytes());
}
