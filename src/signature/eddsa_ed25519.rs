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
    // P2-01：原 unimplemented!() panic → 稳定错误码（Phase 4 接入 ed25519-dalek）
    Err(crate::error::ShlosiloError::new(crate::error::ShlosiloErrorKind::FeatureNotImplemented))
}

/// RFC 8032 EdDSA 验签（未实现，恒 false——不 panic）
pub fn verify(_pk: &Ed25519Point, _msg: &[u8], _sig: &EddsaSignature) -> bool {
    // P2-01：原 unimplemented!() panic → 稳定 false（bool 签名无 Err 通道）
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
        // P2-01：stub 不再 panic——sign 返回稳定错误码、verify 恒 false
        let sk = crate::curve_primitive::ed25519::scalar_zero();
        assert_eq!(
            sign(&sk, b"msg").unwrap_err().kind,
            crate::error::ShlosiloErrorKind::FeatureNotImplemented
        );
        // verify 未实现恒 false（无 panic 即通过）——EddsaSignature 无 pub 构造，
        // 用零化字节构造测试值（避免 MaybeUninit UB）
        let sig: EddsaSignature = {
            let mut bytes = [0u8; EDDSA_SIGNATURE_LEN];
            let mut s: EddsaSignature = EddsaSignature { bytes: [0u8; EDDSA_SIGNATURE_LEN] };
            s.bytes = bytes;
            let _ = &mut bytes;
            s
        };
        assert!(!verify(&crate::curve_primitive::ed25519::generator(), b"msg", &sig));
    }
}