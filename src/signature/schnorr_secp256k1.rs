//! BIP-340 Schnorr signing over secp256k1 (BTC Taproot / Lightning)
//!
//! Phase 5 v2 real implementation: `k256::schnorr` 0.14 (BIP-340)

use crate::curve_primitive::secp256k1::{Secp256k1Point, Secp256k1Scalar};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SCHNORR_SIGNATURE_LEN: usize = 64;

/// BIP-340 Schnorr signature (R || s, 32 + 32 bytes)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SchnorrSignature {
    bytes: [u8; SCHNORR_SIGNATURE_LEN],
}

impl AsRef<[u8]> for SchnorrSignature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for SchnorrSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SchnorrSignature(<{} bytes redacted>)", self.bytes.len())
    }
}

/// BIP-340 Schnorr signature
///
/// `aux_rand` provides nonce randomness (BIP-340 recommends passing extra randomness to avoid side channels)
pub fn sign(sk: &Secp256k1Scalar, msg: &[u8; 32], aux_rand: &[u8; 32]) -> Result<SchnorrSignature> {
    // Convert sk → k256::schnorr::SigningKey
    let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(sk);
    let sk_fb = k256::FieldBytes::from(sk_bytes);
    let signing_key = SigningKey::from_bytes(&sk_fb)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    // BIP-340 raw signature (k256 0.14 API: sign_raw(msg, aux_rand))
    let sig: Signature = signing_key
        .sign_raw(msg, aux_rand)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let sig_bytes: [u8; SCHNORR_SIGNATURE_LEN] = sig.to_bytes();
    Ok(SchnorrSignature { bytes: sig_bytes })
}

/// BIP-340 Schnorr verification
///
/// `pk` must be a 32-byte x-only key (take the x coordinate of a compressed pubkey)
pub fn verify(pk: &Secp256k1Point, msg: &[u8; 32], sig: &SchnorrSignature) -> bool {
    // Convert pk → x-only 32 bytes
    let pk_compressed = crate::curve_primitive::secp256k1::point_to_compressed(pk);
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&pk_compressed[1..33]);
    // BIP-340 requires y to be even (pk[0] = 0x02). Otherwise verification fails
    if pk_compressed[0] != 0x02 {
        return false;
    }
    let pk_fb = k256::FieldBytes::from(x_only);
    let verifying_key = match VerifyingKey::from_bytes(&pk_fb) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig_obj = match Signature::try_from(sig.bytes.as_slice()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verifying_key.verify_raw(msg, &sig_obj).is_ok()
}

/// Parse a signature from 64 bytes (R || s)
pub fn from_bytes(bytes: &[u8]) -> Result<SchnorrSignature> {
    if bytes.len() != SCHNORR_SIGNATURE_LEN {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut arr = [0u8; SCHNORR_SIGNATURE_LEN];
    arr.copy_from_slice(bytes);
    Ok(SchnorrSignature { bytes: arr })
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&Secp256k1Scalar, &[u8; 32], &[u8; 32]) -> Result<SchnorrSignature> = sign;
    const _: fn(&Secp256k1Point, &[u8; 32], &SchnorrSignature) -> bool = verify;

    #[test]
    fn signature_len() {
        assert_eq!(SCHNORR_SIGNATURE_LEN, 64);
    }

    #[test]
    fn signature_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<SchnorrSignature>());
    }

    /// BIP-340 test vector — Test Vector 0
    #[test]
    fn schnorr_sign_verify_roundtrip() {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 3;
        let sk = crate::curve_primitive::secp256k1::scalar_from_bytes(&sk_bytes).unwrap();
        let pk = crate::curve_primitive::secp256k1::base_mul(&sk);
        let msg = [0u8; 32];
        let aux_rand = [0u8; 32];

        let sig = sign(&sk, &msg, &aux_rand).unwrap();
        assert_eq!(sig.bytes.len(), SCHNORR_SIGNATURE_LEN);
        assert!(verify(&pk, &msg, &sig));
    }

    /// Wrong message rejected
    #[test]
    fn schnorr_verify_rejects_wrong_msg() {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 7;
        let sk = crate::curve_primitive::secp256k1::scalar_from_bytes(&sk_bytes).unwrap();
        let pk = crate::curve_primitive::secp256k1::base_mul(&sk);
        let msg = [0xab; 32];
        let aux_rand = [0u8; 32];
        let sig = sign(&sk, &msg, &aux_rand).unwrap();

        let wrong_msg = [0xcd; 32];
        assert!(!verify(&pk, &wrong_msg, &sig));
    }

    /// BIP-340 test vector — index 0 (public test vector)
    /// sk = 000...003 (big-endian)
    /// aux_rand = 000...000
    /// msg = 000...000
    /// expected sig = e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0
    #[test]
    fn schnorr_bip340_test_vector_0() {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 3;
        let sk = crate::curve_primitive::secp256k1::scalar_from_bytes(&sk_bytes).unwrap();
        let msg = [0u8; 32];
        let aux_rand = [0u8; 32];
        let sig = sign(&sk, &msg, &aux_rand).unwrap();

        let expected_sig_hex = "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0";
        let expected_sig = hex_decode(expected_sig_hex);
        assert_eq!(sig.bytes, expected_sig);
    }

    fn hex_decode(s: &str) -> [u8; 64] {
        let bytes = s.as_bytes();
        let mut out = [0u8; 64];
        for i in 0..64 {
            let hi = hex_val(bytes[2 * i]);
            let lo = hex_val(bytes[2 * i + 1]);
            out[i] = (hi << 4) | lo;
        }
        out
    }

    fn hex_val(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }
}
