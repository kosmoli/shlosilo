//! TRON 地址编码（base58check + 0x41 前缀）

use crate::curve_primitive::secp256k1::Secp256k1Point;
use crate::error::Result;
use crate::network::Network;

/// TRON 地址（同 ETH 长度限制 + base58check）
pub type TronAddress = super::eth::EthAddress;

/// TRON 地址编码
///
/// # Phase 4 实现
/// - base58check(0x41 || keccak256(pubkey)[12..32])
/// - 0x41 是 TRON 主网地址前缀（testnet 0xa0）
pub fn encode(_pubkey: &Secp256k1Point, _network: Network) -> Result<TronAddress> {
    // P2-01: unimplemented!() panic → 稳定错误码
    Err(crate::error::ShlosiloError::new(crate::error::ShlosiloErrorKind::FeatureNotImplemented))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&Secp256k1Point, Network) -> Result<TronAddress> = encode;

    #[test]
    fn stub_no_panic_marker() {
        // P2-01：stub 已改为稳定错误码，不允许 panic 宏回归（跳过注释行）
        for line in include_str!("tron.rs").lines() {
            let t = line.trim_start();
            if t.starts_with("//") { continue; }
            assert!(!t.contains(concat!("unimplemented", "!(")), "panic macro regressed: {}", line);
        }
    }
}