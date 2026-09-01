//! secp256k1 曲线原语（Layer A / BTC + ETH + Cosmos 等）
//!
//! Phase 5 真实实现（v2 §2.3 决策）：`k256` crate 0.14
//!
//! ## 安全约束（v2 §2.1）
//!
//! - `Secp256k1Scalar` 禁用 `Copy`，实现 `Zeroize + ZeroizeOnDrop`
//! - `Secp256k1Point` 允许 `Copy + Eq`（公钥是公开材料）
//! - 字段私有，外部不能凭空构造 `Secp256k1Scalar`——必须通过本模块 free function 或派生模块
//! - Clone 在聚合结构场景下需要（v2 §2.7）

use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use primeorder::PrimeField;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// secp256k1 标量长度（32 bytes）
pub const SCALAR_LEN: usize = 32;

/// secp256k1 压缩公钥长度（33 bytes）
pub const COMPRESSED_POINT_LEN: usize = 33;

/// secp256k1 未压缩公钥长度（65 bytes，0x04 || X(32) || Y(32)）
pub const UNCOMPRESSED_POINT_LEN: usize = 65;

/// secp256k1 标量（私钥分量的内部表示）
///
/// 内部存储 `k256::Scalar`（在 `Zeroizing<Scalar>` 包装中保证 zeroize）。
/// 字段全部私有——外部只能通过 `&Secp256k1Scalar` 或 `&mut Secp256k1Scalar` 借用。
/// **禁用 Copy**：v2 §2.1 v2.x 安全约束。
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secp256k1Scalar {
    inner: Scalar,
}

/// secp256k1 点（公钥的内部表示）
///
/// **公开材料**——允许 `Copy + Eq`。
/// 字段私有不导出——保证 `Secp256k1Point` 永远代表曲线上有效点。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Secp256k1Point {
    inner: AffinePoint,
    // 不实现 Drop：Rust 禁止类型同时 derive Copy + impl Drop
    // AffinePoint 内部 X/Y 是公开材料，零拷贝保证安全
}

// ============================================================================
// Free functions（v2.2 删除 trait 决策：编译期由类型签名直接表达约束）
// ============================================================================

/// secp256k1 曲线生成元（generator point G）
pub fn generator() -> Secp256k1Point {
    let p = AffinePoint::GENERATOR;
    Secp256k1Point { inner: p }
}

/// 标量乘法：result = s * p
///
/// 接受 `&Secp256k1Scalar` + `&Secp256k1Point`，返回 owned `Secp256k1Point`
pub fn scalar_mul(s: &Secp256k1Scalar, p: &Secp256k1Point) -> Secp256k1Point {
    let proj = ProjectivePoint::from(&p.inner) * s.inner;
    let affine = proj.to_affine();
    Secp256k1Point { inner: affine }
}

/// 基点乘法：result = s * G（generator）
///
/// 业务模块最常用：派生公钥 pk = base_mul(sk)
pub fn base_mul(s: &Secp256k1Scalar) -> Secp256k1Point {
    scalar_mul(s, &generator())
}

/// 点加：result = a + b
pub fn point_add(a: &Secp256k1Point, b: &Secp256k1Point) -> Secp256k1Point {
    // 用 &a.inner / &b.inner 避免移动（AffinePoint 不是 Copy）
    let proj = ProjectivePoint::from(&a.inner) + ProjectivePoint::from(&b.inner);
    Secp256k1Point {
        inner: proj.to_affine(),
    }
}

/// 零标量（用于累加器初始化）
pub fn scalar_zero() -> Secp256k1Scalar {
    Secp256k1Scalar {
        inner: Scalar::ZERO,
    }
}

/// Scalar 加法（mod curve order）: result = a + b
pub fn scalar_add(a: &Secp256k1Scalar, b: &Secp256k1Scalar) -> Secp256k1Scalar {
    Secp256k1Scalar {
        inner: a.inner + b.inner,
    }
}

/// 标量乘法点: result = -p (point negation, 翻转 y)
pub fn point_negate(p: &Secp256k1Point) -> Secp256k1Point {
    Secp256k1Point { inner: -p.inner }
}

/// Scalar 否定 (mod curve order): -a = L - a
pub fn scalar_negate(a: &Secp256k1Scalar) -> Secp256k1Scalar {
    Secp256k1Scalar { inner: -a.inner }
}

/// Scalar multiplication mod curve order: result = a * b mod n
/// (k256::Scalar impl Add, Sub, Mul — Mul already does modular reduction)
pub fn scalar_mul_n(a: &Secp256k1Scalar, b: &Secp256k1Scalar) -> Secp256k1Scalar {
    Secp256k1Scalar {
        inner: a.inner * b.inner,
    }
}

/// 从 32 字节构造 secp256k1 标量
///
/// 使用 `primeorder::PrimeField::from_repr`（k256 0.14 Scalar 实现 PrimeField）
///
/// # Errors
/// - `EncodingInvalidFormat`：bytes 长度不是 32 或 bytes 解释为 scalar 超出曲线阶
pub fn scalar_from_bytes(bytes: &[u8]) -> Result<Secp256k1Scalar> {
    if bytes.len() != SCALAR_LEN {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut arr = [0u8; SCALAR_LEN];
    arr.copy_from_slice(bytes);
    let field_bytes = FieldBytes::from(arr);
    let ct = <Scalar as PrimeField>::from_repr(field_bytes);
    if bool::from(ct.is_some()) {
        Ok(Secp256k1Scalar { inner: ct.unwrap() })
    } else {
        Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))
    }
}

/// secp256k1 标量 → 32 字节（大端）
pub fn scalar_to_bytes(s: &Secp256k1Scalar) -> [u8; SCALAR_LEN] {
    let bytes = s.inner.to_bytes();
    let mut arr = [0u8; SCALAR_LEN];
    arr.copy_from_slice(&bytes);
    arr
}

/// secp256k1 标量 → 压缩公钥（33 bytes）
pub fn point_to_compressed(p: &Secp256k1Point) -> [u8; COMPRESSED_POINT_LEN] {
    use k256::elliptic_curve::sec1::ToSec1Point;
    let encoded = p.inner.to_sec1_point(true);
    let bytes = encoded.as_bytes();
    let mut arr = [0u8; COMPRESSED_POINT_LEN];
    arr.copy_from_slice(bytes);
    arr
}

/// secp256k1 标量 → 未压缩公钥（65 bytes）
pub fn point_to_uncompressed(p: &Secp256k1Point) -> [u8; UNCOMPRESSED_POINT_LEN] {
    use k256::elliptic_curve::sec1::ToSec1Point;
    let encoded = p.inner.to_sec1_point(false);
    let bytes = encoded.as_bytes();
    let mut arr = [0u8; UNCOMPRESSED_POINT_LEN];
    arr.copy_from_slice(bytes);
    arr
}

/// 从压缩公钥（33 bytes）构造 secp256k1 点
pub fn point_from_compressed(bytes: &[u8]) -> Result<Secp256k1Point> {
    use k256::elliptic_curve::sec1::FromSec1Point;
    if bytes.len() != COMPRESSED_POINT_LEN {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let encoded = k256::Sec1Point::from_bytes(bytes)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let affine = Option::from(AffinePoint::from_sec1_point(&encoded))
        .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    Ok(Secp256k1Point { inner: affine })
}

#[cfg(test)]
mod tests {
    use super::*;

    // 类型级断言（保留 Phase 2.1 stub 测试）：
    const _: fn() -> Secp256k1Point = generator;
    const _: fn(&Secp256k1Scalar, &Secp256k1Point) -> Secp256k1Point = scalar_mul;
    const _: fn(&Secp256k1Scalar) -> Secp256k1Point = base_mul;
    const _: fn(&Secp256k1Point, &Secp256k1Point) -> Secp256k1Point = point_add;
    const _: fn() -> Secp256k1Scalar = scalar_zero;

    #[test]
    fn scalar_not_copy() {
        assert!(core::mem::needs_drop::<Secp256k1Scalar>());
    }

    #[test]
    fn point_is_copy() {
        assert!(!core::mem::needs_drop::<Secp256k1Point>());
    }

    #[test]
    fn scalar_zero_works() {
        let s = scalar_zero();
        let out = scalar_to_bytes(&s);
        assert_eq!(out, [0u8; SCALAR_LEN]);
    }

    /// Phase 5 真实实现：scalar_from_bytes round-trip
    #[test]
    fn scalar_from_bytes_works() {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        let s = scalar_from_bytes(&bytes).unwrap();
        let out = scalar_to_bytes(&s);
        assert_eq!(out, bytes);
    }

    /// Phase 5 真实实现：scalar_from_bytes 拒绝超曲线阶
    #[test]
    fn scalar_from_bytes_rejects_overflow() {
        let bytes = [0xFFu8; 32];
        let r = scalar_from_bytes(&bytes);
        assert!(r.is_err());
    }

    /// Phase 5 真实实现：base_mul(G) = G
    #[test]
    fn base_mul_returns_generator_for_one() {
        let mut one_bytes = [0u8; 32];
        one_bytes[31] = 1;
        let one = scalar_from_bytes(&one_bytes).unwrap();
        let p = base_mul(&one);
        let g = generator();
        assert_eq!(point_to_compressed(&p), point_to_compressed(&g));
    }

    /// Phase 5 真实实现：G + G = 2G
    #[test]
    fn point_add_g_g_equals_2g() {
        let g = generator();
        let g_plus_g = point_add(&g, &g);
        let g_plus_g_compressed = point_to_compressed(&g_plus_g);

        let mut two_bytes = [0u8; 32];
        two_bytes[31] = 2;
        let two = scalar_from_bytes(&two_bytes).unwrap();
        let two_g = base_mul(&two);
        let two_g_compressed = point_to_compressed(&two_g);
        // Print values via assertion failure if not equal
        assert_eq!(hex_encode_pub(&g_plus_g), hex_encode_pub(&two_g));
        assert_eq!(g_plus_g_compressed, two_g_compressed);
    }

    fn hex_encode_pub(p: &Secp256k1Point) -> alloc::string::String {
        use super::point_to_compressed;
        let bytes = point_to_compressed(p);
        let mut s = alloc::string::String::new();
        for b in &bytes {
            s.push_str(&alloc::format!("{:02x}", b));
        }
        s
    }

    /// Phase 5 真实实现：压缩公钥 round-trip
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

    /// Phase 5 真实实现：BIP-340 / secp256k1 测试向量（生成器点）
    #[test]
    fn generator_point_bip340_test_vector() {
        let g = generator();
        let g_compressed = point_to_compressed(&g);
        // G.x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        let g_x: [u8; 32] = [
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98,
        ];
        assert_eq!(&g_compressed[1..33], &g_x);
        assert_eq!(g_compressed[0], 0x02); // y 是偶数
    }
}
