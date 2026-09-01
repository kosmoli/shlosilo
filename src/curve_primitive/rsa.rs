//! RSA-4096 密钥原语（Layer A / Arweave）
//!
//! Phase 2.1 stub：`unimplemented!()` + 类型定义
//! Phase 4 真实实现：`rsa` crate（PKCS#8 + RSA-PSS）
//!
//! **安全约束**：
//! - `RsaPrivKey` 禁用 `Copy`，实现 `Zeroize + ZeroizeOnDrop`
//! - `RsaPubKey` 允许 `Copy + Eq`（公钥是公开材料）

use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// RSA-4096 签名最大长度（512 bytes for 4096-bit key + PSS overhead）
pub const RSA_SIGNATURE_MAX_LEN: usize = 512;

/// RSA-4096 私钥
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RsaPrivKey(/* private fields */);

/// RSA-4096 公钥
#[derive(Clone, PartialEq, Eq)]
pub struct RsaPubKey(/* private fields */);

// ============================================================================
// Free functions
// ============================================================================

/// 解析 PKCS#8 格式的 RSA 私钥
///
/// Phase 4 真实实现：`rsa::pkcs8::DecodePrivateKey::from_pkcs8_der(bytes)`
pub fn privkey_from_pkcs8_der(_bytes: &[u8]) -> Result<RsaPrivKey> {
    // P2-01: unimplemented!() panic → 稳定错误码
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

/// 解析 SubjectPublicKeyInfo 格式的 RSA 公钥
///
/// Phase 4 真实实现：`rsa::pkcs8::DecodePublicKey::from_public_key_der(bytes)`
pub fn pubkey_from_spki_der(_bytes: &[u8]) -> Result<RsaPubKey> {
    // P2-01: unimplemented!() panic → 稳定错误码
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

/// RSA-PSS 签名
///
/// Phase 4 真实实现：`rsa::pss::Signature::sign(rng, ...)`
///
/// 输出：`heapless::Vec<u8, RSA_SIGNATURE_MAX_LEN>`（栈分配，固定大小上限）
pub fn sign_pss(
    _sk: &RsaPrivKey,
    _msg: &[u8],
    _salt_len: usize,
) -> Result<heapless::Vec<u8, RSA_SIGNATURE_MAX_LEN>> {
    // P2-01: unimplemented!() panic → 稳定错误码
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

/// RSA-PSS 验签
pub fn verify_pss(_pk: &RsaPubKey, _msg: &[u8], _sig: &[u8], _salt_len: usize) -> bool {
    // P2-01: unimplemented!() panic → 稳定 false（bool 签名无 Err 通道）
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
        // Phase 4 真实实现时会 derive Copy——stub 阶段 derive Clone 已经够了
        assert!(!core::mem::needs_drop::<RsaPubKey>());
    }

    #[test]
    fn stub_returns_feature_not_implemented() {
        // P2-01：stub 不再 panic——返回稳定错误码
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
