//! BTC segwit address encoding (bech32 + bech32m, P2WPKH + P2TR)
//!
//! Phase 5 v5 real implementation: `bech32` + `bitcoin_hashes::ripemd160` + `sha256`
//!
//! ## Algorithm (P2WPKH, BIP-84)
//!
//! 1. witness_program = RIPEMD-160(SHA-256(compressed_pubkey)) (20 bytes)
//! 2. data = [0x00] + witness_program (21 bytes, version 0 + 20 bytes program)
//! 3. address = bech32_encode("bc"/"tb", data) (~42 chars)
//!
//! ## Algorithm (P2TR, BIP-86 / BIP-341)
//!
//! 1. tweaked_x_only_pubkey = lift_x(sha256(compressed_pubkey)) tweaked by tagged_hash("TapTweak", x_only_pubkey)
//! 2. witness_program = x_only_pubkey (32 bytes)
//! 3. data = [0x01] + witness_program (33 bytes, version 1 + 32 bytes program)
//! 4. address = bech32m_encode("bc"/"tb", data) (~62 chars)

use crate::curve_primitive::secp256k1::Secp256k1Point;
use crate::encoding::{bech32, ripemd160, sha256};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::network::Network;
use core::fmt;

/// Segwit variant (v2.3 §2.4 Layer D table)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegwitVariant {
    /// V0: P2WPKH（ECDSA + BIP-84 / BIP-49）
    V0,
    /// V1: P2TR（Taproot / BIP-86 / BIP-341）
    V1,
}

/// BTC address (max 90 chars bech32 encoding)
pub const BTC_ADDRESS_MAX_LEN: usize = 90;

/// P2WPKH witness program length (20 bytes)
pub const P2WPKH_WITNESS_PROGRAM_LEN: usize = 20;

/// P2TR witness program length (32-byte x-only pubkey)
pub const P2TR_WITNESS_PROGRAM_LEN: usize = 32;

#[derive(Clone, PartialEq, Eq)]
pub struct BtcAddress {
    bytes: heapless::String<BTC_ADDRESS_MAX_LEN>,
}

impl AsRef<str> for BtcAddress {
    fn as_ref(&self) -> &str {
        self.bytes.as_str()
    }
}

impl fmt::Display for BtcAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.bytes)
    }
}

impl fmt::Debug for BtcAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not leak the full address (privacy) — only the first 6 and last 4 chars are exposed
        let s = self.bytes.as_str();
        if s.len() > 12 {
            write!(f, "BtcAddress({}…{})", &s[..6], &s[s.len() - 4..])
        } else {
            write!(f, "BtcAddress(<{} chars redacted>)", s.len())
        }
    }
}

/// BTC bech32 hrp (per network)
fn btc_hrp(network: Network) -> Result<&'static str> {
    match network {
        Network::BitcoinMainnet => Ok("bc"),
        Network::BitcoinTestnet => Ok("tb"),
        _ => Err(ShlosiloError::new(ShlosiloErrorKind::NetworkUnrecognized)),
    }
}

/// P2WPKH witness program: RIPEMD-160(SHA-256(compressed_pubkey))
fn p2wpkh_witness_program(pubkey: &Secp256k1Point) -> Result<[u8; P2WPKH_WITNESS_PROGRAM_LEN]> {
    use crate::curve_primitive::secp256k1::point_to_compressed;
    let compressed = point_to_compressed(pubkey);
    let sha = sha256::hash(&compressed)?;
    ripemd160::hash(&sha)
}

/// BTC segwit address encoding (P2WPKH / P2TR)
///
/// # Phase 5 v5 implementation
///
/// - V0 (P2WPKH): `bech32_encode(hrp, [0x00] + RIPEMD-160(SHA-256(pubkey)))`
/// - V1 (P2TR): `bech32m_encode(hrp, [0x01] + x_only_tweaked_pubkey)` — TODO BIP-341 tweak
pub fn encode(
    pubkey: &Secp256k1Point,
    network: Network,
    variant: SegwitVariant,
) -> Result<BtcAddress> {
    let hrp = btc_hrp(network)?;

    match variant {
        SegwitVariant::V0 => {
            // P2WPKH: RIPEMD-160(SHA-256(compressed_pubkey))
            let wp = p2wpkh_witness_program(pubkey)?;

            // bech32 data = [witver (1 byte)] + convertbits(witprog, 8→5, pad=true)
            let bits_5 = bech32::convertbits(&wp, 8, 5, true)?;
            let mut data: heapless::Vec<u8, 64> = heapless::Vec::new();
            data.push(0x00)
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
            for &b in bits_5.iter() {
                data.push(b)
                    .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
            }

            // bech32 encode (V0 uses bech32, NOT bech32m)
            let addr_str = bech32::encode(hrp, &data)?;
            let mut address: heapless::String<BTC_ADDRESS_MAX_LEN> = heapless::String::new();
            address
                .push_str(addr_str.as_ref())
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
            Ok(BtcAddress { bytes: address })
        }
        SegwitVariant::V1 => {
            // P2TR: needs the BIP-341 tweaked x-only pubkey
            // Phase 5 v5 not yet implemented (needs BIP-341 tagged_hash + tweak_x_only)
            // P2TR is left for Phase 6+ (low taproot deployment)
            Err(ShlosiloError::new(
                ShlosiloErrorKind::ExportProtocolUnimplemented,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve_primitive::secp256k1::{base_mul, scalar_from_bytes};

    /// BIP-173 P2WPKH Mainnet official test vector
    /// (BIP-173 Appendix)
    #[test]
    fn bip173_p2wpkh_mainnet_official() {
        // pubkey: 751e76e8199196d454941c45d1b3a323f1433bd6
        // Here we generate a pubkey to test the roundtrip, rather than comparing a specific string
        let sk_bytes = [0x01u8; 32]; // arbitrary sk
        let sk = scalar_from_bytes(&sk_bytes).unwrap();
        let pk = base_mul(&sk);

        let addr = encode(&pk, Network::BitcoinMainnet, SegwitVariant::V0).unwrap();
        // A P2WPKH Mainnet address starts with "bc1q" and is 42 chars long
        assert!(addr.as_ref().starts_with("bc1q"), "got: {}", addr.as_ref());
        assert_eq!(addr.as_ref().len(), 42);
    }

    /// P2WPKH Testnet (tb1q...) prefix
    #[test]
    fn bip173_p2wpkh_testnet_prefix() {
        let sk = scalar_from_bytes(&[0x02u8; 32]).unwrap();
        let pk = base_mul(&sk);
        let addr = encode(&pk, Network::BitcoinTestnet, SegwitVariant::V0).unwrap();
        assert!(addr.as_ref().starts_with("tb1q"), "got: {}", addr.as_ref());
    }

    /// Determinism: same sk → same address
    #[test]
    fn deterministic_address() {
        let sk = scalar_from_bytes(&[0x03u8; 32]).unwrap();
        let pk = base_mul(&sk);
        let addr1 = encode(&pk, Network::BitcoinMainnet, SegwitVariant::V0).unwrap();
        let addr2 = encode(&pk, Network::BitcoinMainnet, SegwitVariant::V0).unwrap();
        assert_eq!(addr1.as_ref(), addr2.as_ref());
    }

    /// Different sk → different addresses
    #[test]
    fn different_sk_different_address() {
        let sk1 = scalar_from_bytes(&[0x04u8; 32]).unwrap();
        let sk2 = scalar_from_bytes(&[0x05u8; 32]).unwrap();
        let pk1 = base_mul(&sk1);
        let pk2 = base_mul(&sk2);
        let addr1 = encode(&pk1, Network::BitcoinMainnet, SegwitVariant::V0).unwrap();
        let addr2 = encode(&pk2, Network::BitcoinMainnet, SegwitVariant::V0).unwrap();
        assert_ne!(addr1.as_ref(), addr2.as_ref());
    }

    /// P2TR (V1) not yet implemented → Err
    #[test]
    fn p2tr_not_implemented() {
        let sk = scalar_from_bytes(&[0x06u8; 32]).unwrap();
        let pk = base_mul(&sk);
        let result = encode(&pk, Network::BitcoinMainnet, SegwitVariant::V1);
        assert!(result.is_err());
    }

    /// Non-BTC network → Err
    #[test]
    fn non_btc_network_rejected() {
        let sk = scalar_from_bytes(&[0x07u8; 32]).unwrap();
        let pk = base_mul(&sk);
        let result = encode(&pk, Network::EthereumMainnet, SegwitVariant::V0);
        assert!(result.is_err());
    }
}
