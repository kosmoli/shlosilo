//! NIST P-256 曲线原语（Layer A / 预留，未在 v1 使用）
//!
//! Phase 2.1 stub：`unimplemented!()` + 类型定义
//! Phase 4+ 真实实现：`p256` crate
//!
//! **状态**：v1 不使用，Phase 8+ 才会真实实现。

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct P256Scalar(/* private fields */);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct P256Point(/* private fields */);

pub fn generator() -> P256Point {
    unimplemented!("Phase 2.1 stub: p256::generator() 将在 Phase 4+ 接入 p256 crate")
}

pub fn scalar_mul(_s: &P256Scalar, _p: &P256Point) -> P256Point {
    unimplemented!("Phase 2.1 stub: scalar_mul 将在 Phase 4+ 接入 p256 crate")
}

pub fn base_mul(_s: &P256Scalar) -> P256Point {
    unimplemented!("Phase 2.1 stub: base_mul 将在 Phase 4+ 接入 p256 crate")
}

pub fn point_add(_a: &P256Point, _b: &P256Point) -> P256Point {
    unimplemented!("Phase 2.1 stub: point_add 将在 Phase 4+ 接入 p256 crate")
}

pub fn scalar_zero() -> P256Scalar {
    unimplemented!("Phase 2.1 stub: scalar_zero 将在 Phase 4+ 接入 p256 crate")
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn() -> P256Point = generator;
    const _: fn(&P256Scalar, &P256Point) -> P256Point = scalar_mul;
    const _: fn(&P256Scalar) -> P256Point = base_mul;
    const _: fn(&P256Point, &P256Point) -> P256Point = point_add;
    const _: fn() -> P256Scalar = scalar_zero;

    #[test]
    fn scalar_not_copy() {
        assert!(core::mem::needs_drop::<P256Scalar>());
    }

    #[test]
    fn point_is_copy() {
        assert!(!core::mem::needs_drop::<P256Point>());
    }

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("p256.rs");
        assert!(source.contains("unimplemented!"));
    }
}