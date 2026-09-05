//! EdDSA signatures over ed25519 (RFC 8032 / SOL + APT + SUI + NEAR + TON)

use crate::curve_primitive::ed25519::{Ed25519Point, Ed25519Scalar};
use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const EDDSA_SIGNATURE_LEN: usize = 64;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EddsaSignature {
    bytes: [u8; EDDSA_SIGNATURE_LEN],
}

impl AsRef<[u8]> for EddsaSignature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for EddsaSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EddsaSignature(<{} bytes redacted>)", self.bytes.len())
    }
}

/// RFC 8032 EdDSA signature
///
/// # Phase 4 implementation
/// `ed25519-dalek` crate's `SigningKey::sign(msg)`
pub fn sign(_sk: &Ed25519Scalar, _msg: &[u8]) -> Result<EddsaSignature> {
    // P2-01: original unimplemented!() panic → stable error code (Phase 4 integrates ed25519-dalek)
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

/// RFC 8032 EdDSA verification (unimplemented, always false — no panic)
pub fn verify(_pk: &Ed25519Point, _msg: &[u8], _sig: &EddsaSignature) -> bool {
    // P2-01: original unimplemented!() panic → stable false (bool signatures have no Err channel)
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&Ed25519Scalar, &[u8]) -> Result<EddsaSignature> = sign;
    const _: fn(&Ed25519Point, &[u8], &EddsaSignature) -> bool = verify;

    #[test]
    fn signature_len() {
        assert_eq!(EDDSA_SIGNATURE_LEN, 64);
    }

    #[test]
    fn signature_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<EddsaSignature>());
    }

    #[test]
    fn stub_returns_feature_not_implemented() {
        // P2-01: stubs no longer panic — sign returns a stable error code, verify is always false
        let sk = crate::curve_primitive::ed25519::scalar_zero();
        assert_eq!(
            sign(&sk, b"msg").unwrap_err().kind,
            crate::error::ShlosiloErrorKind::FeatureNotImplemented
        );
        // verify unimplemented, always false (passes if no panic) — EddsaSignature has no pub constructor,
        // build test values from zeroized bytes (avoids MaybeUninit UB)
        let sig: EddsaSignature = {
            let mut bytes = [0u8; EDDSA_SIGNATURE_LEN];
            let mut s: EddsaSignature = EddsaSignature {
                bytes: [0u8; EDDSA_SIGNATURE_LEN],
            };
            s.bytes = bytes;
            let _ = &mut bytes;
            s
        };
        assert!(!verify(
            &crate::curve_primitive::ed25519::generator(),
            b"msg",
            &sig
        ));
    }
}
