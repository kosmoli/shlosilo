//! BIP-340 / keystone cross-validation test module for shlosilo secp256k1 primitives
//!
//! ## Purpose (2026-08-22)
//! Validate shlosilo's `curve_primitive::secp256k1` against BIP-340 official test vectors
//! to catch any future curve arithmetic regressions. Before this module was added, shlosilo's
//! lib tests used `scalar_from_bytes(&[2u8; 32])` which is a HUGE scalar (32 × 0x02),
//! not scalar=2. This module exists so future devs don't reintroduce that confusion.
//!
//! ## BIP-340 official test vectors (https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv)
//! - priv = 0x000...001 → pub = G.x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
//! - priv = 0x000...002 → pub = 2G.x = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
//! - priv = 0x000...003 → pub = 3G.x = 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9
//!
//! ## Big-endian scalar byte order rule
//! secp256k1 private keys are 32 bytes big-endian. To get scalar value N (small integer),
//! use `{0;31, N}` (last byte = N), NOT `[N; 32]` (all 32 bytes = N — that's scalar(0xNNNN...NN)).

extern crate shlosilo;

/// Helper: build a 32-byte big-endian scalar from a small integer (1, 2, 3, ...)
#[inline]
fn small_scalar(n: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    bytes
}

// ============================================================================
// BIP-340 base point multiplication sanity tests
// ============================================================================

#[test]
fn bip340_priv1_matches_g() {
    use shlosilo::curve_primitive::secp256k1::{base_mul, point_to_compressed, scalar_from_bytes};
    let sk_bytes = small_scalar(1);
    let sk = scalar_from_bytes(&sk_bytes).unwrap();
    let pk = base_mul(&sk);
    let pk_compressed = point_to_compressed(&pk);
    assert_eq!(pk_compressed[0], 0x02, "G.y should be even");
    assert_eq!(
        &pk_compressed[1..33],
        &[
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98
        ][..]
    );
}

#[test]
fn bip340_priv2_matches_2g() {
    use shlosilo::curve_primitive::secp256k1::{base_mul, point_to_compressed, scalar_from_bytes};
    let sk_bytes = small_scalar(2);
    let sk = scalar_from_bytes(&sk_bytes).unwrap();
    let pk = base_mul(&sk);
    let pk_compressed = point_to_compressed(&pk);
    assert_eq!(
        &pk_compressed[..],
        &[
            0x02, 0xC6, 0x04, 0x7F, 0x94, 0x41, 0xED, 0x7D, 0x6D, 0x30, 0x45, 0x40, 0x6E, 0x95,
            0xC0, 0x7C, 0xD8, 0x5C, 0x77, 0x8E, 0x4B, 0x8C, 0xEF, 0x3C, 0xA7, 0xAB, 0xAC, 0x09,
            0xB9, 0x5C, 0x70, 0x9E, 0xE5
        ][..]
    );
}

#[test]
fn bip340_priv3_matches_3g() {
    use shlosilo::curve_primitive::secp256k1::{base_mul, point_to_compressed, scalar_from_bytes};
    let sk_bytes = small_scalar(3);
    let sk = scalar_from_bytes(&sk_bytes).unwrap();
    let pk = base_mul(&sk);
    let pk_compressed = point_to_compressed(&pk);
    assert_eq!(
        &pk_compressed[..],
        &[
            0x02, 0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10, 0x49, 0x34, 0x4F, 0x85, 0xF8,
            0x9D, 0x52, 0x29, 0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0, 0x86, 0x01, 0xF1,
            0x13, 0xBC, 0xE0, 0x36, 0xF9
        ][..]
    );
}

// ============================================================================
// scalar_from_bytes / scalar_to_bytes roundtrip
// ============================================================================

#[test]
fn scalar_roundtrip_small_values() {
    use shlosilo::curve_primitive::secp256k1::{scalar_from_bytes, scalar_to_bytes};
    for n in 0u8..=10 {
        let mut bytes = [0u8; 32];
        bytes[31] = n;
        let s = scalar_from_bytes(&bytes).unwrap();
        let back = scalar_to_bytes(&s);
        assert_eq!(back, bytes, "roundtrip failed for n={}", n);
    }
}

#[test]
fn scalar_roundtrip_rejects_all_0x02() {
    // Regression: old tests used [2u8; 32] thinking it was scalar=2, but it was
    // actually scalar(0x020202...02). Make sure we document the convention.
    use shlosilo::curve_primitive::secp256k1::{scalar_from_bytes, scalar_to_bytes};
    let bytes = [2u8; 32];
    let s = scalar_from_bytes(&bytes).unwrap();
    let back = scalar_to_bytes(&s);
    assert_eq!(
        back, bytes,
        "scalar(0x0202...02) roundtrip must preserve all bytes"
    );
    assert_eq!(back[31], 0x02);
    assert_eq!(back[0], 0x02);
}
