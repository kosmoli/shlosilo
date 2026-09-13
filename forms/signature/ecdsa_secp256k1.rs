//! ECDSA signatures over secp256k1 (BTC Legacy + segwit v0 + ETH + Cosmos)
//!
//! Phase 5 v2 real implementation: `k256::ecdsa` (RFC 6979 deterministic nonce)

use crate::curve_primitive::secp256k1::{Secp256k1Point, Secp256k1Scalar};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use k256::ecdsa::{
    signature::{hazmat::PrehashSigner, hazmat::PrehashVerifier},
    Signature, SigningKey, VerifyingKey,
};
use k256::FieldBytes;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ECDSA signature (r, s compact serialization)
///
/// Fixed byte length: 32 (r) + 32 (s) = 64 bytes
pub const ECDSA_SIGNATURE_LEN: usize = 64;

/// ECDSA signature wrapper
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdsaSignature {
    bytes: [u8; ECDSA_SIGNATURE_LEN],
}

impl AsRef<[u8]> for EcdsaSignature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for EcdsaSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // do not expose signature byte contents (prevents signature leakage into debug logs)
        write!(f, "EcdsaSignature(<{} bytes redacted>)", self.bytes.len())
    }
}

/// Extract bytes from a k256 Signature
fn sig_to_bytes(sig: &Signature) -> [u8; ECDSA_SIGNATURE_LEN] {
    sig.to_bytes().into()
}

/// ECDSA signing
///
/// Uses an RFC 6979 deterministic nonce (built into k256::SigningKey)
///
/// # Implementation
/// - Convert the shlosilo `Secp256k1Scalar` (32 bytes big-endian) → k256 `SigningKey`
/// - Call `signing_key.sign(msg_hash)` — internally RFC 6979 + SHA-256
/// - But k256 `sign()` **re-hashes** the msg with SHA-256 — that would **double-hash** our prehashed input!
///
/// Fix: use `sign_prehashed`, which directly accepts a 32-byte hash
pub fn sign(sk: &Secp256k1Scalar, msg_hash: &[u8; 32]) -> Result<EcdsaSignature> {
    // convert sk to k256::SigningKey
    let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(sk);
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_bytes);
    let signing_key = SigningKey::from_bytes(&sk_arr.into())
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    // use sign_prehashed (k256 internally accepts prehashed input directly)
    let z = FieldBytes::from(*msg_hash);
    let sig: Signature = signing_key
        .sign_prehash(&z)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    Ok(EcdsaSignature {
        bytes: sig_to_bytes(&sig),
    })
}

/// ECDSA verification
pub fn verify(pk: &Secp256k1Point, msg_hash: &[u8; 32], sig: &EcdsaSignature) -> bool {
    // convert pk to k256::VerifyingKey (using the compressed public key, SEC1 33 bytes)
    let pk_compressed = crate::curve_primitive::secp256k1::point_to_compressed(pk);
    let verifying_key = match VerifyingKey::from_sec1_bytes(&pk_compressed) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig_obj = match Signature::from_slice(&sig.bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let z = FieldBytes::from(*msg_hash);
    verifying_key.verify_prehash(&z, &sig_obj).is_ok()
}

/// Parse a signature from 64-byte (r || s) bytes
pub fn from_bytes(bytes: &[u8]) -> Result<EcdsaSignature> {
    if bytes.len() != ECDSA_SIGNATURE_LEN {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut arr = [0u8; ECDSA_SIGNATURE_LEN];
    arr.copy_from_slice(bytes);
    Ok(EcdsaSignature { bytes: arr })
}

/// Parse a signature from DER encoding (for importing from external sources)
pub fn from_der(der: &[u8]) -> Result<EcdsaSignature> {
    let sig = Signature::from_der(der)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    Ok(EcdsaSignature {
        bytes: sig_to_bytes(&sig),
    })
}

/// Serialize to DER encoding (for appending to the transaction witness in BTC sighash)
///
/// DER encoding format: 0x30 || total_len || 0x02 || r_len || r || 0x02 || s_len || s
/// Length 70-72 bytes (r/s variable)
pub fn to_der(sig: &EcdsaSignature) -> Result<heapless::Vec<u8, 72>> {
    // reassemble the internal 64 bytes (r || s) into a k256::Signature
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig.bytes.as_ref());
    let k256_sig = Signature::from_bytes(&sig_arr.into())
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let der = k256_sig.to_der();
    let der_bytes = der.as_bytes();
    let mut out: heapless::Vec<u8, 72> = heapless::Vec::new();
    out.extend_from_slice(der_bytes)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&Secp256k1Scalar, &[u8; 32]) -> Result<EcdsaSignature> = sign;
    const _: fn(&Secp256k1Point, &[u8; 32], &EcdsaSignature) -> bool = verify;
    const _: fn(&[u8]) -> Result<EcdsaSignature> = from_der;

    #[test]
    fn signature_len() {
        assert_eq!(ECDSA_SIGNATURE_LEN, 64);
    }

    #[test]
    fn signature_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<EcdsaSignature>());
    }

    /// Phase 5 v2 real implementation: ECDSA sign + verify round-trip
    #[test]
    fn sign_verify_roundtrip() {
        // big-endian encoding of 0xdeadbeef... (32 bytes)
        let mut sk_bytes = [0u8; 32];
        for (i, b) in sk_bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(0x13);
        }
        let sk = crate::curve_primitive::secp256k1::scalar_from_bytes(&sk_bytes).unwrap();
        let pk = crate::curve_primitive::secp256k1::base_mul(&sk);
        let msg_hash = [0xab; 32];

        let sig = sign(&sk, &msg_hash).unwrap();
        assert_eq!(sig.bytes.len(), ECDSA_SIGNATURE_LEN);

        // verify the signature
        assert!(verify(&pk, &msg_hash, &sig));
    }

    /// ECDSA verification rejects a wrong message
    #[test]
    fn verify_rejects_wrong_message() {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 42;
        let sk = crate::curve_primitive::secp256k1::scalar_from_bytes(&sk_bytes).unwrap();
        let pk = crate::curve_primitive::secp256k1::base_mul(&sk);
        let msg_hash = [0xab; 32];
        let sig = sign(&sk, &msg_hash).unwrap();

        let wrong_msg = [0xcd; 32];
        assert!(!verify(&pk, &wrong_msg, &sig));
    }

    /// RFC 6979 deterministic signing: same sk + msg produce the same signature every time
    #[test]
    fn signature_is_deterministic() {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 99;
        let sk = crate::curve_primitive::secp256k1::scalar_from_bytes(&sk_bytes).unwrap();
        let msg_hash = [0x42; 32];

        let sig1 = sign(&sk, &msg_hash).unwrap();
        let sig2 = sign(&sk, &msg_hash).unwrap();
        assert_eq!(sig1.bytes, sig2.bytes);
    }
}
