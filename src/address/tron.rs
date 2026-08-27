//! TRON 地址编码（base58check + 0x41 前缀）

use crate::curve_primitive::secp256k1::Secp256k1Point;
use crate::error::Result;
use crate::network::Network;
use core::fmt;

/// TRON 地址（同 ETH 长度限制 + base58check）
pub type TronAddress = super::eth::EthAddress;

/// TRON 地址编码
///
/// # Phase 4 实现
/// - base58check(0x41 || keccak256(pubkey)[12..32])
/// - 0x41 是 TRON 主网地址前缀（testnet 0xa0）
pub fn encode(_pubkey: &Secp256k1Point, _network: Network) -> Result<TronAddress> {
    unimplemented!("Phase 2.3 stub: tron::encode 将在 Phase 4 接入 base58check")
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&Secp256k1Point, Network) -> Result<TronAddress> = encode;

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("tron.rs");
        assert!(source.contains("unimplemented!"));
        assert!(source.contains("Phase 4"));
    }
}