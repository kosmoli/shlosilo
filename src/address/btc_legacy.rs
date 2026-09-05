//! BTC legacy address encoding (P2PKH + P2SH, base58check)
//!
//! Phase 2.3 stub: `unimplemented!()` + type definitions
//! Phase 4 real implementation: `bitcoin` crate base58 + ripemd160/sha256 encoding primitives

use crate::curve_primitive::secp256k1::Secp256k1Point;
use crate::error::Result;
use crate::network::Network;

/// BTC legacy address (same as BtcAddress, using heapless::String<64>)
pub type BtcLegacyAddress = super::btc_segwit::BtcAddress;

/// BTC legacy address encoding
///
/// # Phase 4 implementation
/// - P2PKH: base58check(0x00 || ripemd160(sha256(pubkey)))
/// - P2SH:  base58check(0x05 || ripemd160(sha256(redeem_script)))
pub fn encode_p2pkh(_pubkey: &Secp256k1Point, _network: Network) -> Result<BtcLegacyAddress> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

pub fn encode_p2sh(_redeem_script_hash: &[u8; 20], _network: Network) -> Result<BtcLegacyAddress> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&Secp256k1Point, Network) -> Result<BtcLegacyAddress> = encode_p2pkh;
    const _: fn(&[u8; 20], Network) -> Result<BtcLegacyAddress> = encode_p2sh;

    #[test]
    fn stub_no_panic_marker() {
        // P2-01: stubs now return stable error codes; panic macros must not regress (skip comment lines)
        for line in include_str!("btc_legacy.rs").lines() {
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
