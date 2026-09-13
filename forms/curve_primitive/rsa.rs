//! RSA-4096 key primitive (Layer A / Arweave)
//!
//! Phase 2.1 stub: `unimplemented!()` + type definitions
//! Phase 4 real implementation: the `rsa` crate (PKCS#8 + RSA-PSS)
//!
//! **Security constraints**:
//! - `RsaPrivKey` forbids `Copy` and implements `Zeroize + ZeroizeOnDrop`
//! - `RsaPubKey` allows `Copy + Eq` (public keys are public material)

use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// RSA-4096 maximum signature length (512 bytes for a 4096-bit key + PSS overhead)
pub const RSA_SIGNATURE_MAX_LEN: usize = 512;

/// RSA-4096 private key
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RsaPrivKey(/* private fields */);

/// RSA-4096 public key
#[derive(Clone, PartialEq, Eq)]
pub struct RsaPubKey(/* private fields */);

// ============================================================================
// Free functions
// ============================================================================

/// Parse an RSA private key in PKCS#8 format
///
/// Phase 4 real implementation: `rsa::pkcs8::DecodePrivateKey::from_pkcs8_der(bytes)`
pub fn privkey_from_pkcs8_der(_bytes: &[u8]) -> Result<RsaPrivKey> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

/// Parse an RSA public key in SubjectPublicKeyInfo format
///
/// Phase 4 real implementation: `rsa::pkcs8::DecodePublicKey::from_public_key_der(bytes)`
pub fn pubkey_from_spki_der(_bytes: &[u8]) -> Result<RsaPubKey> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

/// RSA-PSS signing
///
/// Phase 4 real implementation: `rsa::pss::Signature::sign(rng, ...)`
///
/// Output: `heapless::Vec<u8, RSA_SIGNATURE_MAX_LEN>` (stack-allocated, fixed-size cap)
pub fn sign_pss(
    _sk: &RsaPrivKey,
    _msg: &[u8],
    _salt_len: usize,
) -> Result<heapless::Vec<u8, RSA_SIGNATURE_MAX_LEN>> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

/// RSA-PSS verification
pub fn verify_pss(_pk: &RsaPubKey, _msg: &[u8], _sig: &[u8], _salt_len: usize) -> bool {
    // P2-01: unimplemented!() panic → stable false (bool signature has no Err channel)
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&[u8]) -> Result<RsaPrivKey> = privkey_from_pkcs8_der;
    const _: fn(&[u8]) -> Result<RsaPubKey> = pubkey_from_spki_der;
    const _: fn(&RsaPrivKey, &[u8], usize) -> Result<heapless::Vec<u8, RSA_SIGNATURE_MAX_LEN>> =
        sign_pss;
    const _: fn(&RsaPubKey, &[u8], &[u8], usize) -> bool = verify_pss;

    #[test]
    fn privkey_not_copy() {
        assert!(core::mem::needs_drop::<RsaPrivKey>());
    }

    #[test]
    fn pubkey_is_not_drop() {
        // Copy will be derived in the Phase 4 real implementation — derive Clone is enough for the stub stage
        assert!(!core::mem::needs_drop::<RsaPubKey>());
    }

    #[test]
    fn stub_returns_feature_not_implemented() {
        // P2-01: stub no longer panics — returns a stable error code
        let e = privkey_from_pkcs8_der(&[]).err().expect("should err");
        assert_eq!(
            e.kind,
            crate::error::ShlosiloErrorKind::FeatureNotImplemented
        );
        let e = pubkey_from_spki_der(&[]).err().expect("should err");
        assert_eq!(
            e.kind,
            crate::error::ShlosiloErrorKind::FeatureNotImplemented
        );
    }
}
