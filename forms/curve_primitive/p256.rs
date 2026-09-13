//! NIST P-256 curve primitive (Layer A / reserved, unused in v1)
//!
//! Phase 2.1 stub: `unimplemented!()` + type definitions
//! Phase 4+ real implementation: the `p256` crate
//!
//! **Status**: unused in v1; a real implementation comes at Phase 8+.

use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct P256Scalar(/* private fields */);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct P256Point(/* private fields */);

pub fn generator() -> Result<P256Point> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

pub fn scalar_mul(_s: &P256Scalar, _p: &P256Point) -> Result<P256Point> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

pub fn base_mul(_s: &P256Scalar) -> Result<P256Point> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

pub fn point_add(_a: &P256Point, _b: &P256Point) -> Result<P256Point> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

pub fn scalar_zero() -> Result<P256Scalar> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
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
        // P2-01: the stub no longer panics — returns a stable error code
        // (P256Scalar has no Debug; use map_err to avoid unwrap_err\'s Debug bound)
        let e0 = scalar_zero().err().expect("scalar_zero should err");
        assert_eq!(
            e0.kind,
            crate::error::ShlosiloErrorKind::FeatureNotImplemented
        );
        let e1 = generator().err().expect("generator should err");
        assert_eq!(
            e1.kind,
            crate::error::ShlosiloErrorKind::FeatureNotImplemented
        );
    }
}
