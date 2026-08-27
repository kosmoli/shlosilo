//! EdDSA 签名 over ed25519（RFC 8032 / SOL + APT + SUI + NEAR + TON）

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

/// RFC 8032 EdDSA 签名
///
/// # Phase 4 实现
/// `ed25519-dalek` crate 的 `SigningKey::sign(msg)`
pub fn sign(_sk: &Ed25519Scalar, _msg: &[u8]) -> Result<EddsaSignature> {
    unimplemented!("Phase 2.2 stub: eddsa_ed25519::sign 将在 Phase 4 接入 ed25519-dalek")
}

/// RFC 8032 EdDSA 验签
pub fn verify(_pk: &Ed25519Point, _msg: &[u8], _sig: &EddsaSignature) -> bool {
    unimplemented!("Phase 2.2 stub: eddsa_ed25519::verify 将在 Phase 4 接入 ed25519-dalek")
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
    fn stub_phase_documented() {
        let source = include_str!("eddsa_ed25519.rs");
        assert!(source.contains("unimplemented!"));
        assert!(source.contains("Phase 4"));
    }
}