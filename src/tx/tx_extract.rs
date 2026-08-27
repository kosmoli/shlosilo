//! TxExtract：signed tx → UR bytes

use crate::error::Result;

/// signed tx → UR bytes
///
/// **Phase 2.4 假实现**：直接返回 bytes 副本
/// Phase 4 真实实现：chain-specific 序列化 + CBOR 编码 + Fountain
pub fn from_signed(_chain_kind: crate::types::chain_kind::ChainKind, _signed_tx: &[u8]) -> Result<heapless::Vec<u8, 2048>> {
    unimplemented!("Phase 2.4 stub: tx_extract::from_signed 将在 Phase 4 接入 chain-specific 序列化")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::chain_kind::ChainKind;

    const _: fn(ChainKind, &[u8]) -> Result<heapless::Vec<u8, 2048>> = from_signed;

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("tx_extract.rs");
        assert!(source.contains("unimplemented!"));
        assert!(source.contains("Phase 4"));
    }
}