//! RIPEMD-160 hash（BTC P2WPKH witness program 派生）
//!
//! witness_program = RIPEMD-160(SHA-256(compressed_pubkey)) (20 bytes)
//!
//! 用于：
//! - BTC P2WPKH 地址：bech32_encode("bc"/"tb", [0x00] + witness_program)
//! - BTC P2PKH 地址：base58check_encode([0x00] + witness_program + checksum)
//!
//! ## v2 §2.3 算法决策
//!
//! ✅ **wrap `bitcoin_hashes 0.14`**（rust-bitcoin 维护；密码学哈希）

use crate::error::Result;
use bitcoin_hashes::{ripemd160, Hash as _};

/// RIPEMD-160 输出长度
pub const RIPEMD160_OUTPUT_LEN: usize = 20;

/// RIPEMD-160 hash
///
/// # Phase 5 v5 真实实现
///
/// wrap `bitcoin_hashes::ripemd160::Hash::hash()`。
pub fn hash(data: &[u8]) -> Result<[u8; RIPEMD160_OUTPUT_LEN]> {
    let h = ripemd160::Hash::hash(data);
    let bytes = h.to_byte_array();
    let mut arr = [0u8; RIPEMD160_OUTPUT_LEN];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&[u8]) -> Result<[u8; RIPEMD160_OUTPUT_LEN]> = hash;

    /// 空输入 RIPEMD-160 输出已知
    /// (RFC 2286 test vector)
    #[test]
    fn ripemd160_empty() {
        let h = hash(&[]).unwrap();
        // 9c1185a5c5e9fc54612808977ee8f548b2258d31
        let expected = [
            0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28, 0x08, 0x97, 0x7e, 0xe8,
            0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31,
        ];
        assert_eq!(h, expected);
    }

    /// "abc" RIPEMD-160
    /// (RFC 2286 test vector)
    #[test]
    fn ripemd160_abc() {
        let h = hash(b"abc").unwrap();
        // 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
        let expected = [
            0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04, 0x4a, 0x8e, 0x98, 0xc6,
            0xb0, 0x87, 0xf1, 0x5a, 0x0b, 0xfc,
        ];
        assert_eq!(h, expected);
    }

    /// 输出长度
    #[test]
    fn output_length() {
        let h = hash(b"any input").unwrap();
        assert_eq!(h.len(), 20);
    }
}