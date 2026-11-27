//! TRON address encoding (base58check + 0x41 prefix)
//! **NOT IMPLEMENTED** — this module is a stub: every entry point returns
//! `ShlosiloErrorKind::FeatureNotImplemented`. It must therefore never back a capability in
//! `capabilities/*.toml`: there, `true` means "the product path really uses this", and a stub is
//! the opposite of that ("a primitive that merely exists in the library is not a capability of
//! this chain" — chain-axis design §3.2). Real address encoders live in `forms/encoding/`
//! (base58 + base58check, bech32 + bech32m, base64, cbor); this file is the chain-specific
//! payload construction that has not been written yet.
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
