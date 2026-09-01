//! TxExtract：signed tx → UR bytes

use crate::error::Result;

/// signed tx → UR bytes
///
/// **Phase 2.4 假实现**：直接返回 bytes 副本
/// Phase 4 真实实现：chain-specific 序列化 + CBOR 编码 + Fountain
pub fn from_signed(
    _chain_kind: crate::types::chain_kind::ChainKind,
    _signed_tx: &[u8],
) -> Result<heapless::Vec<u8, 2048>> {
    // P2-01: unimplemented!() panic → 稳定错误码
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
        // P2-01：stub 不再 panic——返回稳定错误码
        let e = from_signed(ChainKind::Unknown, &[]).expect_err("should err");
        assert_eq!(
            e.kind,
            crate::error::ShlosiloErrorKind::FeatureNotImplemented
        );
    }
}
