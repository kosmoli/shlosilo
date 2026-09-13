//! TxExtract：signed tx → UR bytes

use crate::error::Result;

/// signed tx → UR bytes
///
/// **Phase 2.4 fake implementation**: returns a copy of the bytes directly
/// Phase 4 real implementation: chain-specific serialization + CBOR encoding + Fountain
pub fn from_signed(
    _chain_kind: crate::types::chain_kind::ChainKind,
    _signed_tx: &[u8],
) -> Result<heapless::Vec<u8, 2048>> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::chain_kind::ChainKind;

    const _: fn(ChainKind, &[u8]) -> Result<heapless::Vec<u8, 2048>> = from_signed;

    #[test]
    fn stub_returns_feature_not_implemented() {
        // P2-01: stubs no longer panic — return a stable error code
        let e = from_signed(ChainKind::Unknown, &[]).expect_err("should err");
        assert_eq!(
            e.kind,
            crate::error::ShlosiloErrorKind::FeatureNotImplemented
        );
    }
}
