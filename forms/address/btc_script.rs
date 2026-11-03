//! BTC scriptPubKey → address rendering (BCR-free: pure structure, no keys)
//!
//! The review screen has to show the wallet operator a recipient string they can
//! check; the existing `btc_segwit::encode` is the *other* direction (our own
//! pubkey → our own address) and cannot render a foreign script. This module is
//! a pure `scriptPubKey → address` conversion:
//!
//! | script | bytes | address |
//! |---|---|---|
//! | P2PKH | `76 a9 14 <20> 88 ac` | base58check(prefix ‖ hash160) |
//! | P2SH  | `a9 14 <20> 87` | base58check(prefix ‖ script hash) |
//! | P2WPKH | `00 14 <20>` | bech32(hrp, [0] ‖ 5-bit program) |
//! | P2WSH  | `00 20 <32>` | bech32(hrp, [0] ‖ 5-bit program) |
//! | P2TR   | `51 20 <32>` | bech32m(hrp, [1] ‖ 5-bit program) |
//!
//! Anything else (OP_RETURN, bare scripts, unknown witness versions, non-canonical
//! lengths) is **rejected** — a review screen must never invent an address for a
//! script it does not understand.
//!
//! Zero-heap: caller buffers + `heapless`, no allocation.

use crate::address::btc_segwit::{BtcAddress, BTC_ADDRESS_MAX_LEN};
use crate::encoding::{base58, bech32};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::network::Network;

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// bech32 human-readable part for the two networks we can render.
fn hrp(network: Network) -> Result<&'static str> {
    match network {
        Network::BitcoinMainnet => Ok("bc"),
        Network::BitcoinTestnet => Ok("tb"),
        _ => Err(err()),
    }
}

/// base58 version byte for P2PKH addresses (0x00 mainnet / 0x6f testnet).
fn p2pkh_version(network: Network) -> Result<u8> {
    match network {
        Network::BitcoinMainnet => Ok(0x00),
        Network::BitcoinTestnet => Ok(0x6f),
        _ => Err(err()),
    }
}

/// base58 version byte for P2SH addresses (0x05 mainnet / 0xc4 testnet).
fn p2sh_version(network: Network) -> Result<u8> {
    match network {
        Network::BitcoinMainnet => Ok(0x05),
        Network::BitcoinTestnet => Ok(0xc4),
        _ => Err(err()),
    }
}

/// Render a scriptPubKey as an address string.
pub fn render(script_pubkey: &[u8], network: Network) -> Result<BtcAddress> {
    match script_pubkey {
        // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        [0x76, 0xa9, 0x14, h @ .., 0x88, 0xac] if h.len() == 20 => {
            let mut payload = [0u8; 21];
            payload[0] = p2pkh_version(network)?;
            payload[1..].copy_from_slice(h);
            let mut out = [0u8; BTC_ADDRESS_MAX_LEN];
            let n = base58::encode_check_into(&payload, &mut out)?;
            let s = core::str::from_utf8(&out[..n]).map_err(|_| err())?;
            BtcAddress::from_encoder_output(s)
        }
        // P2SH: OP_HASH160 <20> OP_EQUAL
        [0xa9, 0x14, h @ .., 0x87] if h.len() == 20 => {
            let mut payload = [0u8; 21];
            payload[0] = p2sh_version(network)?;
            payload[1..].copy_from_slice(h);
            let mut out = [0u8; BTC_ADDRESS_MAX_LEN];
            let n = base58::encode_check_into(&payload, &mut out)?;
            let s = core::str::from_utf8(&out[..n]).map_err(|_| err())?;
            BtcAddress::from_encoder_output(s)
        }
        // Witness programs: <version opcode> <push len> <program>
        [version_op, len, program @ ..] if program.len() == usize::from(*len) => {
            let version = match version_op {
                0x00 => 0u8,
                b @ 0x51..=0x60 => b - 0x50,
                _ => return Err(err()),
            };
            // Only the three defined shapes are renderable: v0 20/32, v1 32.
            // A v1/20 or v2 program has no agreed address form — refuse rather
            // than emit a well-formed string for a script nobody can spend.
            if !matches!((version, program.len()), (0, 20) | (0, 32) | (1, 32)) {
                return Err(err());
            }
            let bits = bech32::convertbits(program, 8, 5, true)?;
            let mut data: heapless::Vec<u8, 64> = heapless::Vec::new();
            data.push(version).map_err(|_| err())?;
            for b in bits.iter() {
                data.push(*b).map_err(|_| err())?;
            }
            let encoded = if version == 0 {
                bech32::encode(hrp(network)?, &data)?
            } else {
                bech32::encode_m(hrp(network)?, &data)?
            };
            BtcAddress::from_encoder_output(encoded.as_ref())
        }
        _ => Err(err()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&[u8], Network) -> Result<BtcAddress> = render;

    /// 非 BTC 网络一律拒绝（地址前缀无从确定）
    #[test]
    fn rejects_non_btc_networks() {
        let spk = [
            0x00u8, 0x14, 0x61, 0x00, 0xfc, 0x63, 0x43, 0xed, 0xc8, 0xc8, 0x74, 0x49, 0x6c, 0xb2,
            0xf5, 0xbb, 0xfe, 0xc8, 0x8e, 0xa9, 0xb7, 0x7c,
        ];
        assert!(render(&spk, Network::EthereumMainnet).is_err());
    }
}
