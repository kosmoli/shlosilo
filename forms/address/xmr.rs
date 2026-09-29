//! XMR address encoding (base58 + Keccak256 checksum + network byte + spend_pub + view_pub)
//!
//! Phase 5 v4 real implementation: wraps `base58-monero 2.0` + `monero-ed25519`
//!
//! ## Algorithm (XMR standard address)
//!
//! 1. payload = 1 byte network + 32 bytes spend_pub + 32 bytes view_pub (65 bytes)
//! 2. checksum = Keccak256(payload)[:4]
//! 3. bytes_to_encode = payload || checksum (69 bytes)
//! 4. address = base58_monero_encode(bytes_to_encode) (~95 chars)
//!
//! **Note**:
//! - Keccak-256 is **not** SHA3-256 (different nonce), but tiny-keccak defaults to Keccak-256 ✓
//! - XMR base58 ≠ Bitcoin base58（8-byte blocks）
//!
//! ## Network bytes
//!
//! | Network | byte |
//! |---------|------|
//! | Mainnet | 0x12 |
//! | Stagenet | 0x18 |
//! | Testnet | 0x35 |
//!
//! ## v2.4 security fixes
//!
//! - Both `&Ed25519Point` are borrows, no clone copies
//! - The output XmrAddress is a `heapless::String<128>` (stack allocated)
//!
//! ## v2 §2.3 algorithm decisions
//!
//! ✅ **wrap base58-monero** (official monero-rs, audited multiple times; encode/decode class)

use crate::curve_primitive::ed25519::{point_to_compressed, Ed25519Point};
use crate::encoding::keccak256;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::network::Network;
use base58_monero::base58::{encode_block, ENCODED_BLOCK_SIZES, FULL_BLOCK_SIZE};
use core::fmt;

/// Maximum XMR address length (base58-encoding 69 bytes = 8-byte × 8 + 5-byte tail → 11×8 + 7 = 95 chars, safe margin below 128)
pub const XMR_ADDRESS_MAX_LEN: usize = 128;

/// XMR address payload length
const XMR_PAYLOAD_LEN: usize = 65; // 1 byte network + 32 spend_pub + 32 view_pub
/// XMR Keccak-256 checksum length
const XMR_CHECKSUM_LEN: usize = 4;

/// XMR network byte
fn xmr_network_byte(network: Network) -> Result<u8> {
    match network {
        Network::MoneroMainnet => Ok(0x12),
        Network::MoneroStagenet => Ok(0x18),
        Network::MoneroTestnet => Ok(0x35),
        _ => Err(ShlosiloError::new(ShlosiloErrorKind::NetworkUnrecognized)),
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct XmrAddress {
    bytes: heapless::String<XMR_ADDRESS_MAX_LEN>,
}

impl AsRef<str> for XmrAddress {
    fn as_ref(&self) -> &str {
        self.bytes.as_str()
    }
}

impl fmt::Display for XmrAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.bytes)
    }
}

impl fmt::Debug for XmrAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.bytes.as_str();
        if s.len() > 12 {
            write!(f, "XmrAddress({}…{})", &s[..8], &s[s.len() - 6..])
        } else {
            write!(f, "XmrAddress(<redacted>)")
        }
    }
}

/// Encode an XMR address
///
/// # Algorithm
///
/// 1. payload = network_byte || spend_pub || view_pub (65 bytes)
/// 2. checksum = Keccak256(payload)[:4]
/// 3. bytes = payload || checksum (69 bytes)
/// 4. address = base58_monero_encode(bytes) → 95 chars
///
/// # v2.4 security
///
/// Both `&Ed25519Point` are borrows, **no clone** — avoiding leaking spend_pk copies tied to the private key on the hot path.
///
/// # base58-monero encode_check known bug
///
/// `base58_monero::encode_check` simply appends the checksum to the payload and calls `encode`, which makes a Monero address
/// actually encode to 101 chars (not the canonical 95 chars). We use `encode` + hand-written checksum concatenation:
///
/// - 65 bytes payload → 8 full blocks (64 bytes) + 1 byte tail
/// - 1 byte tail + 4 checksum = 5 bytes ≤ 8 → 5-byte final block → 7 chars
/// - Total: 8 × 11 + 7 = **95 chars** ✓ (the official Monero length)
pub fn encode(
    spend_pub: &Ed25519Point,
    view_pub: &Ed25519Point,
    network: Network,
) -> Result<XmrAddress> {
    // 1. network byte
    let net_byte = xmr_network_byte(network)?;

    // 2. spend_pub + view_pub → 32 bytes each (compressed)
    let spend_bytes = point_to_compressed(spend_pub);
    let view_bytes = point_to_compressed(view_pub);

    // 3. payload = [net_byte, spend_bytes, view_bytes] (65 bytes)
    let mut payload: heapless::Vec<u8, XMR_PAYLOAD_LEN> = heapless::Vec::new();
    payload
        .push(net_byte)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    payload
        .extend_from_slice(&spend_bytes)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    payload
        .extend_from_slice(&view_bytes)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;

    // 4. checksum = Keccak256(payload)[:4]
    let checksum_full = keccak256::hash(&payload)?;
    let checksum = &checksum_full[..XMR_CHECKSUM_LEN];

    // 5-7. Correct encoding: 8 full blocks + 1 byte tail; last 1 payload byte
    // + 4 checksum bytes = 5 bytes → 7 chars. Z6 zero-heap: block-wise base58
    // via the vendored audited `encode_block` — byte-identical to
    // `base58_monero::encode`, without the intermediate String.
    fn encode_blocks_into(
        dst: &mut heapless::String<XMR_ADDRESS_MAX_LEN>,
        mut data: &[u8],
    ) -> Result<()> {
        while !data.is_empty() {
            let n = core::cmp::min(data.len(), FULL_BLOCK_SIZE);
            let block = encode_block(&data[..n])
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
            for c in block[..ENCODED_BLOCK_SIZES[n]].iter() {
                dst.push(*c)
                    .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
            }
            data = &data[n..];
        }
        Ok(())
    }

    let mut address: heapless::String<XMR_ADDRESS_MAX_LEN> = heapless::String::new();
    encode_blocks_into(&mut address, &payload[..XMR_PAYLOAD_LEN - 1])?; // 64 bytes → 88 chars

    // last 1 byte of payload + 4 checksum bytes = 5 bytes → 7 chars
    let mut tail_block: heapless::Vec<u8, 8> = heapless::Vec::new();
    tail_block
        .extend_from_slice(&payload[XMR_PAYLOAD_LEN - 1..])
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    tail_block
        .extend_from_slice(checksum)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    encode_blocks_into(&mut address, &tail_block)?;

    Ok(XmrAddress { bytes: address })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve_primitive::ed25519::{base_mul, scalar_from_bytes};

    /// XMR Mainnet address length = 95 chars
    #[test]
    fn address_length_mainnet() {
        let sk1 = scalar_from_bytes(&[1u8; 32]).unwrap();
        let sk2 = scalar_from_bytes(&[2u8; 32]).unwrap();
        let pk1 = base_mul(&sk1);
        let pk2 = base_mul(&sk2);
        let addr = encode(&pk1, &pk2, Network::MoneroMainnet).unwrap();
        assert_eq!(addr.as_ref().len(), 95);
    }

    /// XMR Stagenet / Testnet have different prefixes
    #[test]
    fn network_prefix_different() {
        let sk1 = scalar_from_bytes(&[1u8; 32]).unwrap();
        let sk2 = scalar_from_bytes(&[2u8; 32]).unwrap();
        let pk1 = base_mul(&sk1);
        let pk2 = base_mul(&sk2);

        let mainnet = encode(&pk1, &pk2, Network::MoneroMainnet).unwrap();
        let stagenet = encode(&pk1, &pk2, Network::MoneroStagenet).unwrap();
        let testnet = encode(&pk1, &pk2, Network::MoneroTestnet).unwrap();

        // An XMR Mainnet address usually starts with \'4\' (0x12 = 18; 18 = 0x12 → "4" is the 19th base58-monero char)
        // Stagenet usually \'7\' (0x18 = 24)
        // Testnet usually \'9\' or \'B\' (0x35 = 53)
        // Actual chars depend on the algorithm, but **the first two chars should differ**
        assert_ne!(&mainnet.as_ref()[..2], &stagenet.as_ref()[..2]);
        assert_ne!(&mainnet.as_ref()[..2], &testnet.as_ref()[..2]);
        assert_ne!(&stagenet.as_ref()[..2], &testnet.as_ref()[..2]);
    }

    /// Determinism: same sk + network → same address
    #[test]
    fn deterministic_encoding() {
        let sk1 = scalar_from_bytes(&[3u8; 32]).unwrap();
        let sk2 = scalar_from_bytes(&[4u8; 32]).unwrap();
        let pk1 = base_mul(&sk1);
        let pk2 = base_mul(&sk2);
        let addr1 = encode(&pk1, &pk2, Network::MoneroMainnet).unwrap();
        let addr2 = encode(&pk1, &pk2, Network::MoneroMainnet).unwrap();
        assert_eq!(addr1.as_ref(), addr2.as_ref());
    }

    /// Different sk → different addresses; same sk re-run base_mul → same address
    #[test]
    fn different_spend_pub_different_address() {
        let sk1 = scalar_from_bytes(&[5u8; 32]).unwrap();
        let sk2 = scalar_from_bytes(&[6u8; 32]).unwrap();
        let pk1 = base_mul(&sk1);
        let pk2 = base_mul(&sk2);

        // pk1 vs pk2 differ
        assert_ne!(point_to_compressed(&pk1), point_to_compressed(&pk2));

        // spend_pub differs → addresses differ
        let addr1 = encode(&pk1, &pk2, Network::MoneroMainnet).unwrap();
        let addr_swap = encode(&pk2, &pk1, Network::MoneroMainnet).unwrap();
        assert_ne!(addr1.as_ref(), addr_swap.as_ref());

        // Calling again with the same pk1 + pk2 → the same address (deterministic)
        let pk1_again = base_mul(&sk1);
        let pk2_again = base_mul(&sk2);
        let addr1_again = encode(&pk1_again, &pk2_again, Network::MoneroMainnet).unwrap();
        assert_eq!(addr1.as_ref(), addr1_again.as_ref());

        // Different network → different address
        let addr_testnet = encode(&pk1, &pk2, Network::MoneroTestnet).unwrap();
        assert_ne!(addr1.as_ref(), addr_testnet.as_ref());
    }

    /// Non-XMR network errors
    #[test]
    fn non_xmr_network_rejected() {
        let sk1 = scalar_from_bytes(&[7u8; 32]).unwrap();
        let sk2 = scalar_from_bytes(&[8u8; 32]).unwrap();
        let pk1 = base_mul(&sk1);
        let pk2 = base_mul(&sk2);
        let result = encode(&pk1, &pk2, Network::BitcoinMainnet);
        assert!(result.is_err());
    }

    /// XMR address prefix verification (the exact prefix depends on base58-monero 8-byte block encoding;
    /// we only need to verify that the three networks encode different addresses and the length is 95 chars):
    #[test]
    fn xmr_address_differs_by_network() {
        let sk = scalar_from_bytes(&[9u8; 32]).unwrap();
        let pk = base_mul(&sk);

        let mainnet = encode(&pk, &pk, Network::MoneroMainnet).unwrap();
        let stagenet = encode(&pk, &pk, Network::MoneroStagenet).unwrap();
        let testnet = encode(&pk, &pk, Network::MoneroTestnet).unwrap();

        // The XMR addresses of the three networks should be completely different
        assert_ne!(mainnet.as_ref(), stagenet.as_ref());
        assert_ne!(mainnet.as_ref(), testnet.as_ref());
        assert_ne!(stagenet.as_ref(), testnet.as_ref());

        // Lengths are all 95 chars (Monero standard)
        assert_eq!(mainnet.as_ref().len(), 95);
        assert_eq!(stagenet.as_ref().len(), 95);
        assert_eq!(testnet.as_ref().len(), 95);
    }
}
