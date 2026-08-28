//! NIST P-256 曲线原语（Layer A / 预留，未在 v1 使用）
//!
//! Phase 2.1 stub：`unimplemented!()` + 类型定义
//! Phase 4+ 真实实现：`p256` crate
//!
//! **状态**：v1 不使用，Phase 8+ 才会真实实现。

use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct P256Scalar(/* private fields */);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct P256Point(/* private fields */);

pub fn generator() -> Result<P256Point> {
    // P2-01: unimplemented!() panic → 稳定错误码
    Err(crate::error::ShlosiloError::new(crate::error::ShlosiloErrorKind::FeatureNotImplemented))
}

pub fn scalar_mul(_s: &P256Scalar, _p: &P256Point) -> Result<P256Point> {
    // P2-01: unimplemented!() panic → 稳定错误码
    Err(crate::error::ShlosiloError::new(crate::error::ShlosiloErrorKind::FeatureNotImplemented))
}

pub fn base_mul(_s: &P256Scalar) -> Result<P256Point> {
    // P2-01: unimplemented!() panic → 稳定错误码
    Err(crate::error::ShlosiloError::new(crate::error::ShlosiloErrorKind::FeatureNotImplemented))
}

pub fn point_add(_a: &P256Point, _b: &P256Point) -> Result<P256Point> {
    // P2-01: unimplemented!() panic → 稳定错误码
    Err(crate::error::ShlosiloError::new(crate::error::ShlosiloErrorKind::FeatureNotImplemented))
}

pub fn scalar_zero() -> Result<P256Scalar> {
    // P2-01: unimplemented!() panic → 稳定错误码
    Err(crate::error::ShlosiloError::new(crate::error::ShlosiloErrorKind::FeatureNotImplemented))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn() -> Result<P256Point> = generator;
    const _: fn(&P256Scalar, &P256Point) -> Result<P256Point> = scalar_mul;
    const _: fn(&P256Scalar) -> Result<P256Point> = base_mul;
    const _: fn(&P256Point, &P256Point) -> Result<P256Point> = point_add;
    const _: fn() -> Result<P256Scalar> = scalar_zero;

    #[test]
    fn scalar_not_copy() {
        assert!(core::mem::needs_drop::<P256Scalar>());
    }

    #[test]
    fn point_is_copy() {
        assert!(!core::mem::needs_drop::<P256Point>());
    }

    #[test]
    fn stub_returns_feature_not_implemented() {
        // P2-01：stub 不再 panic——返回稳定错误码
        // （P256Scalar 无 Debug，用 map_err 避开 unwrap_err 的 Debug 约束）
        let e0 = scalar_zero().err().expect("scalar_zero should err");
        assert_eq!(e0.kind, crate::error::ShlosiloErrorKind::FeatureNotImplemented);
        let e1 = generator().err().expect("generator should err");
        assert_eq!(e1.kind, crate::error::ShlosiloErrorKind::FeatureNotImplemented);
    }
}