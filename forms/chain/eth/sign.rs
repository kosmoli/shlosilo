//! ETH shared sign utilities (Phase 5 v8)
//!
//! Provides what EIP-155 / EIP-2930 / EIP-1559 share:
//! - `compute_y_parity` — recover y_parity from (r, s, sighash, sk)
//! - `apply_low_s` — BIP-146 low-s enforcement
//! - `compute_y_parity_with_low_s` — one-stop: ECDSA sign → low-s → y_parity
//!
//! Business functions for all ETH tx types reuse this module to avoid code duplication.

use crate::curve_primitive::secp256k1::{base_mul, point_to_compressed, scalar_from_bytes};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::signature::ecdsa_secp256k1::{self as ecdsa};

/// Compute y_parity (recovery_id) — derive R.y parity from (r, s, sighash, sk)
///
/// Algorithm: try y_parity=0,1 with `VerifyingKey::recover_from_prehash(sighash, &sig, recid)`
/// and compare the recovered pubkey with the pubkey of sk to find the correct y_parity.
///
/// k256 0.14 `recover_from_prehash` accepts a 32-byte prehash (no Digest trait required)
fn compute_y_parity(
    sk: &crate::curve_primitive::secp256k1::Secp256k1Scalar,
    sighash: &[u8; 32],
    r_bytes: &[u8; 32],
    s_bytes: &[u8; 32],
) -> Result<u8> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    let mut sig_64 = [0u8; 64];
    sig_64[..32].copy_from_slice(r_bytes);
    sig_64[32..].copy_from_slice(s_bytes);
    let sig = Signature::from_slice(&sig_64)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    let pk_point = base_mul(sk);
    let pk_compressed = point_to_compressed(&pk_point);

    for y_parity in 0u8..=1u8 {
        let recid = RecoveryId::new(y_parity == 1, false);
        let recovered = VerifyingKey::recover_from_prehash(sighash, &sig, recid);
        if let Ok(recovered_pk) = recovered {
            let sec1_point = recovered_pk.to_sec1_point(true);
            let rec_bytes = sec1_point.as_bytes();
            if rec_bytes == &pk_compressed[..] {
                return Ok(y_parity);
            }
        }
    }

    Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))
}

/// BIP-146 / EIP-2 low-s enforcement helper
///
/// secp256k1 curve order n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
/// If s > n/2, flip s = n - s and return y_parity ^ 1; otherwise leave unchanged
pub fn apply_low_s(
    sighash: &[u8; 32],
    sk: &crate::curve_primitive::secp256k1::Secp256k1Scalar,
    r_bytes: &mut [u8; 32],
    s_bytes: &mut [u8; 32],
) -> Result<u8> {
    // 1. ECDSA sign_prehash
    let sig = ecdsa::sign(sk, sighash)?;
    let sig_bytes = sig.as_ref();
    r_bytes.copy_from_slice(&sig_bytes[..32]);
    s_bytes.copy_from_slice(&sig_bytes[32..]);

    // 2. compute y_parity with the original sig
    let y_parity_original = compute_y_parity(sk, sighash, r_bytes, s_bytes)?;

    // 3. check s > n/2
    let half_n_high: [u8; 16] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff,
    ];
    let half_n_low: [u8; 16] = [
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20,
        0xa0,
    ];
    let s_high = &s_bytes[..16];
    let s_low = &s_bytes[16..];
    let is_high_s = if s_high > half_n_high.as_slice() {
        true
    } else if s_high < half_n_high.as_slice() {
        false
    } else {
        s_low > half_n_low.as_slice()
    };

    if is_high_s {
        // flip s = n - s (256-bit subtraction)
        let n_bytes: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        let mut new_s = [0u8; 32];
        let mut borrow: u8 = 0;
        for i in (0..32).rev() {
            let a = n_bytes[i];
            let b = s_bytes[i];
            let (d, b1) = a.overflowing_sub(b);
            let (d2, b2) = d.overflowing_sub(borrow);
            new_s[i] = d2;
            borrow = (b1 || b2) as u8;
        }
        s_bytes.copy_from_slice(&new_s);
        // flip y_parity (R → -R, parity flips)
        Ok(y_parity_original ^ 1)
    } else {
        Ok(y_parity_original)
    }
}

/// Convert a 32-byte private key to a scalar
pub fn sk_from_pk(pk: &[u8; 32]) -> Result<crate::curve_primitive::secp256k1::Secp256k1Scalar> {
    scalar_from_bytes(pk)
}

/// ECDSA public key recovery (L1 pure verify)
///
/// Input: prehash + 65-byte signature (r || s || v), v = 27/28 meaning y_parity ∈ {0, 1}.
///
/// Output: 64-byte uncompressed public key (x || y, 32 + 32 bytes), Err on failure.
///
/// Used for EIP-191 personal_ecRecover; can later serve as a wallet-side verify tool.
pub fn ecdsa_recover(prehash: &[u8; 32], sig: &[u8; 65]) -> Result<[u8; 64]> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    // parse r || s
    let mut sig_64 = [0u8; 64];
    sig_64.copy_from_slice(&sig[..64]);
    let signature = Signature::from_slice(&sig_64)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    // v ∈ {27, 28} → y_parity ∈ {0, 1}
    let v = sig[64];
    if v != 27 && v != 28 {
        return Err(ShlosiloError::with_context(
            ShlosiloErrorKind::EncodingInvalidFormat,
            crate::error::ErrorContext::None,
        ));
    }
    let y_parity = v - 27;
    let recid = RecoveryId::new(y_parity == 1, false);

    // recover
    let recovered_pk = VerifyingKey::recover_from_prehash(prehash, &signature, recid)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    // convert to 65-byte uncompressed (0x04 || x || y)
    let encoded_point = recovered_pk.to_sec1_point(false);
    let bytes = encoded_point.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes[1..]);
    Ok(out)
}
