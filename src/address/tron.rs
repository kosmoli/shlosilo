//! TRON address encoding (base58check + 0x41 prefix)

use crate::curve_primitive::secp256k1::Secp256k1Point;
use crate::error::Result;
use crate::network::Network;

/// TRON address (same length limit as ETH + base58check)
pub type TronAddress = super::eth::EthAddress;

/// TRON address encoding
///
/// # Phase 4 Implementation
/// - base58check(0x41 || keccak256(pubkey)[12..32])
/// - 0x41 is the TRON mainnet address prefix (testnet 0xa0)
pub fn encode(_pubkey: &Secp256k1Point, _network: Network) -> Result<TronAddress> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&Secp256k1Point, Network) -> Result<TronAddress> = encode;

    #[test]
    fn stub_no_panic_marker() {
        // P2-01: stubs have been switched to stable error codes; panic macros must not regress (skip comment lines)
        for line in include_str!("tron.rs").lines() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            assert!(
                !t.contains(concat!("unimplemented", "!(")),
                "panic macro regressed: {}",
                line
            );
        }
    }
}
