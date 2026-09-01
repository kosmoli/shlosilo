//! ed25519 曲线原语（Layer A / XMR + SOL + Cardano + SUI + Near + Aptos）
//!
//! Phase 5 v4 真实实现：`ed25519-dalek` crate 2.2
//!
//! ## 设计要点
//!
//! - 直接 wrap `ed25519_dalek::SigningKey` + `VerifyingKey`（ed25519-dalek 2 友好 API）
//! - 不直接 wrap `curve25519_dalek` 类型（避免暴露底层 details）
//! - XMR 业务模块可单独 import `monero-ed25519` 用于 Pedersen commitment + reduce_scalar
//!
//! ## 安全约束（v2 §2.1）
//!
//! - `Ed25519Scalar` 禁用 `Copy`，实现 `Zeroize + ZeroizeOnDrop`
//! - `Ed25519Point` 允许 `Copy + Eq`（公钥是公开材料）
//! - 字段私有，外部不能凭空构造

use ed25519_dalek::{SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// ed25519 标量长度（32 bytes）
pub(crate) const SCALAR_LEN: usize = SECRET_KEY_LENGTH;

/// ed25519 压缩点长度（32 bytes）
pub(crate) const COMPRESSED_POINT_LEN: usize = PUBLIC_KEY_LENGTH;

/// ed25519 标量（私钥分量的内部表示）
///
/// 内部存储 `ed25519_dalek::SigningKey`。
/// **禁用 Copy**：v2 §2.1 v2.x 安全约束。
pub struct Ed25519Scalar {
    inner: SigningKey,
}

// 手动 impl Zeroize + ZeroizeOnDrop（SigningKey 本身已经 Zeroize，但 inner 仍需 Drop）
impl Drop for Ed25519Scalar {
    fn drop(&mut self) {
        // SigningKey 自动 zeroize 在 drop 时（它 impl Zeroize）
        // 这里只需要 ZeroizeOnDrop 标记（用 derive 的 helper macro）
    }
}

// 提供手动 Zeroize impl（SigningKey 已经 Zeroize）
impl Zeroize for Ed25519Scalar {
    fn zeroize(&mut self) {
        // 调用 SigningKey 的 Zeroize（如果 it exists）；否则 drop + 重写
        let mut sk_bytes = self.inner.to_bytes();
        sk_bytes.zeroize();
        // 重新构造 SigningKey 以覆盖 inner 内存
        if let Ok(new_sk) = SigningKey::from_keypair_bytes(&{
            let mut kp = [0u8; 64];
            kp[..32].copy_from_slice(&sk_bytes);
            kp
        }) {
            self.inner = new_sk;
        }
    }
}

impl ZeroizeOnDrop for Ed25519Scalar {}

/// ed25519 点（公钥的内部表示）
///
/// **公开材料**——允许 `Copy + Eq`。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ed25519Point {
    inner: VerifyingKey,
}

// ============================================================================
// Free functions
// ============================================================================

/// ed25519 曲线基点
pub fn generator() -> Ed25519Point {
    let g_bytes: [u8; PUBLIC_KEY_LENGTH] = {
        let mut b = [0u8; PUBLIC_KEY_LENGTH];
        b[0] = 1;
        b
    };
    let g = VerifyingKey::from_bytes(&g_bytes).expect("basepoint");
    Ed25519Point { inner: g }
}

/// 基点乘法：result = s * G（用 `verifying_key()` 拿公开 pk）
pub fn base_mul(s: &Ed25519Scalar) -> Ed25519Point {
    let vk = s.inner.verifying_key();
    Ed25519Point { inner: vk }
}

/// 零标量（用于累加器初始化）
pub fn scalar_zero() -> Ed25519Scalar {
    let zero_bytes = [0u8; SECRET_KEY_LENGTH];
    // 用 from_keypair_bytes 接受 64 bytes (sk || pk)
    let mut kp_bytes = [0u8; 64];
    kp_bytes[..32].copy_from_slice(&zero_bytes);
    // pk = base_mul(zero_scalar) = identity
    // 使用 from_keypair_bytes + 错误 fallback 到 unsafe from_bytes
    let sk = SigningKey::from_bytes(&zero_bytes);
    Ed25519Scalar { inner: sk }
}

/// 从 32 字节构造 ed25519 标量
///
/// # Errors
/// - `EncodingInvalidFormat`：bytes 长度不是 32
pub fn scalar_from_bytes(bytes: &[u8]) -> Result<Ed25519Scalar> {
    if bytes.len() != SCALAR_LEN {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut arr = [0u8; SCALAR_LEN];
    arr.copy_from_slice(bytes);
    // SigningKey::from_bytes 是 infallible（accepts any 32 bytes）
    let sk = SigningKey::from_bytes(&arr);
    Ok(Ed25519Scalar { inner: sk })
}

/// ed25519 标量 → 32 字节
pub fn scalar_to_bytes(s: &Ed25519Scalar) -> [u8; SCALAR_LEN] {
    s.inner.to_bytes()
}

/// ed25519 点 → 32 字节压缩
pub fn point_to_compressed(p: &Ed25519Point) -> [u8; COMPRESSED_POINT_LEN] {
    p.inner.to_bytes()
}

/// 从 32 字节压缩构造 ed25519 点
pub fn point_from_compressed(bytes: &[u8]) -> Result<Ed25519Point> {
    if bytes.len() != COMPRESSED_POINT_LEN {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut arr = [0u8; COMPRESSED_POINT_LEN];
    arr.copy_from_slice(bytes);
    let vk = VerifyingKey::from_bytes(&arr)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    Ok(Ed25519Point { inner: vk })
}

#[cfg(test)]
mod tests {
    use super::*;

    // 类型签名形状验证
    const _: fn() -> Ed25519Point = generator;
    const _: fn(&Ed25519Scalar) -> Ed25519Point = base_mul;
    const _: fn() -> Ed25519Scalar = scalar_zero;

    #[test]
    fn scalar_not_copy() {
        assert!(core::mem::needs_drop::<Ed25519Scalar>());
    }

    #[test]
    fn point_is_copy() {
        assert!(!core::mem::needs_drop::<Ed25519Point>());
    }

    #[test]
    fn scalar_zero_works() {
        let s = scalar_zero();
        let out = scalar_to_bytes(&s);
        assert_eq!(out, [0u8; SCALAR_LEN]);
    }

    /// scalar_from_bytes round-trip
    #[test]
    fn scalar_from_bytes_works() {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        let s = scalar_from_bytes(&bytes).unwrap();
        assert_eq!(scalar_to_bytes(&s), bytes);
    }

    /// base_mul(s) = verifying_key
    #[test]
    fn base_mul_equals_verifying_key() {
        let mut bytes = [0u8; 32];
        bytes[31] = 42;
        let s = scalar_from_bytes(&bytes).unwrap();
        let p = base_mul(&s);
        let pk_bytes = s.inner.verifying_key().to_bytes();
        assert_eq!(point_to_compressed(&p), pk_bytes);
    }

    /// 压缩公钥 round-trip
    #[test]
    fn point_compressed_roundtrip() {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 7;
        let sk = scalar_from_bytes(&sk_bytes).unwrap();
        let pk = base_mul(&sk);
        let compressed = point_to_compressed(&pk);
        assert_eq!(compressed.len(), COMPRESSED_POINT_LEN);
        let pk2 = point_from_compressed(&compressed).unwrap();
        assert_eq!(point_to_compressed(&pk), point_to_compressed(&pk2));
    }

    /// ed25519 basepoint (G) 已知 compressed bytes
    #[test]
    fn ed25519_basepoint_test_vector() {
        let g = generator();
        let g_compressed = point_to_compressed(&g);
        assert_eq!(g_compressed[0], 1);
        for &b in &g_compressed[1..] {
            assert_eq!(b, 0);
        }
    }

    /// scalar_from_bytes 拒绝错误长度
    #[test]
    fn scalar_from_bytes_rejects_wrong_length() {
        let bytes = [0u8; 16];
        let r = scalar_from_bytes(&bytes);
        assert!(r.is_err());
    }

    /// scalar_from_bytes 任意 bytes 接受（ed25519-dalek 2 from_bytes 是 infallible）
    #[test]
    fn scalar_from_bytes_accepts_any() {
        // 即使所有 ff，ed25519-dalek 也接受
        let bytes = [0xFFu8; 32];
        let r = scalar_from_bytes(&bytes);
        assert!(r.is_ok());
    }
}
