//! ECDSA 签名 over secp256k1（BTC Legacy + segwit v0 + ETH + Cosmos）
//!
//! Phase 5 v2 真实实现：`k256::ecdsa` (RFC 6979 确定性 nonce)

use crate::curve_primitive::secp256k1::{Secp256k1Point, Secp256k1Scalar};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use k256::ecdsa::{
    signature::{hazmat::PrehashSigner, hazmat::PrehashVerifier},
    Signature, SigningKey, VerifyingKey,
};
use k256::FieldBytes;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ECDSA 签名（r, s 压缩序列化）
///
/// 字节长度固定：32 (r) + 32 (s) = 64 bytes
pub const ECDSA_SIGNATURE_LEN: usize = 64;

/// ECDSA 签名包装
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
        // 不暴露签名字节内容（防 signature 泄露给 debug 日志）
        write!(f, "EcdsaSignature(<{} bytes redacted>)", self.bytes.len())
    }
}

/// 从 k256 Signature 提取 bytes
fn sig_to_bytes(sig: &Signature) -> [u8; ECDSA_SIGNATURE_LEN] {
    sig.to_bytes().into()
}

/// ECDSA 签名
///
/// 使用 RFC 6979 确定性 nonce（k256::SigningKey 内置）
///
/// # 实现
/// - 将 shlosilo `Secp256k1Scalar` (32 bytes big-endian) → k256 `SigningKey`
/// - 调用 `signing_key.sign(msg_hash)` —— 内部使用 RFC 6979 + SHA-256
/// - 但 k256 `sign()` 会**重新**对 msg 做 SHA-256 digest——这跟我们的 prehashed 输入**双重 hash**！
///
/// 修正：使用 `sign_prehashed` 直接接受 32-byte hash
pub fn sign(sk: &Secp256k1Scalar, msg_hash: &[u8; 32]) -> Result<EcdsaSignature> {
    // 转换 sk 到 k256::SigningKey
    let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(sk);
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_bytes);
    let signing_key = SigningKey::from_bytes(&sk_arr.into()).map_err(|_| {
        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
    })?;

    // 使用 sign_prehashed（k256 内部直接接受 prehashed 输入）
    let z = FieldBytes::from(*msg_hash);
    let sig: Signature = signing_key.sign_prehash(&z).map_err(|_| {
        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
    })?;
    Ok(EcdsaSignature { bytes: sig_to_bytes(&sig) })
}

/// ECDSA 验签
pub fn verify(pk: &Secp256k1Point, msg_hash: &[u8; 32], sig: &EcdsaSignature) -> bool {
    // 转换 pk 到 k256::VerifyingKey（使用压缩公钥 SEC1 33 bytes）
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

/// 从 64-byte (r || s) bytes 解析签名
pub fn from_bytes(bytes: &[u8]) -> Result<EcdsaSignature> {
    if bytes.len() != ECDSA_SIGNATURE_LEN {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut arr = [0u8; ECDSA_SIGNATURE_LEN];
    arr.copy_from_slice(bytes);
    Ok(EcdsaSignature { bytes: arr })
}

/// 从 DER 编码解析签名（用于从外部导入）
pub fn from_der(der: &[u8]) -> Result<EcdsaSignature> {
    let sig = Signature::from_der(der).map_err(|_| {
        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
    })?;
    Ok(EcdsaSignature { bytes: sig_to_bytes(&sig) })
}

/// 序列化为 DER 编码（用于 BTC sighash 拼接到交易 witness）
///
/// DER 编码格式：0x30 || total_len || 0x02 || r_len || r || 0x02 || s_len || s
/// 长度 70-72 bytes（r/s 可变）
pub fn to_der(sig: &EcdsaSignature) -> Result<heapless::Vec<u8, 72>> {
    // 把内部 64 bytes (r || s) 重新组装为 k256::Signature
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig.bytes.as_ref());
    let k256_sig = Signature::from_bytes(&sig_arr.into()).map_err(|_| {
        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
    })?;
    let der = k256_sig.to_der();
    let der_bytes = der.as_bytes();
    let mut out: heapless::Vec<u8, 72> = heapless::Vec::new();
    out.extend_from_slice(der_bytes).map_err(|_| {
        ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow)
    })?;
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

    /// Phase 5 v2 真实实现：ECDSA sign + verify round-trip
    #[test]
    fn sign_verify_roundtrip() {
        // big-endian 编码 0xdeadbeef... (32 bytes)
        let mut sk_bytes = [0u8; 32];
        for (i, b) in sk_bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(0x13);
        }
        let sk = crate::curve_primitive::secp256k1::scalar_from_bytes(&sk_bytes).unwrap();
        let pk = crate::curve_primitive::secp256k1::base_mul(&sk);
        let msg_hash = [0xab; 32];

        let sig = sign(&sk, &msg_hash).unwrap();
        assert_eq!(sig.bytes.len(), ECDSA_SIGNATURE_LEN);

        // 验证签名
        assert!(verify(&pk, &msg_hash, &sig));
    }

    /// ECDSA 验签拒绝错消息
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

    /// RFC 6979 确定性签名：相同 sk + msg 每次产生相同签名
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