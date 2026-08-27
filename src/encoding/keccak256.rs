//! Keccak-256 hash（ETH 地址构造 + XMR checksum）
//!
//! **重要区别**：Keccak-256 ≠ SHA3-256（nonce 不同）。ETH 用 Keccak-256。

use crate::error::Result;
use tiny_keccak::{Hasher, Keccak};

/// Keccak-256 输出长度
pub const KECCAK256_OUTPUT_LEN: usize = 32;

/// Keccak-256 hash
///
/// Phase 4 真实实现：`tiny_keccak::Keccak::v256()`
///
/// **v2.4 安全**：输入 borrow，输出 owned（hash 不携带 secret 信息）
pub fn hash(data: &[u8]) -> Result<[u8; KECCAK256_OUTPUT_LEN]> {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut output = [0u8; KECCAK256_OUTPUT_LEN];
    hasher.finalize(&mut output);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&[u8]) -> Result<[u8; KECCAK256_OUTPUT_LEN]> = hash;

    #[test]
    fn output_len() {
        assert_eq!(KECCAK256_OUTPUT_LEN, 32);
    }

    /// Keccak-256("") 标准测试向量
    /// https://github.com/ethereum/go-ethereum/blob/master/crypto/crypto.go
    #[test]
    fn hash_empty() {
        let h = hash(&[]).unwrap();
        let expected = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
        assert_eq!(hex::encode_to_string(&h), expected);
    }

    /// Keccak-256("abc") 标准测试向量
    #[test]
    fn hash_abc() {
        let h = hash(b"abc").unwrap();
        let expected = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45";
        assert_eq!(hex::encode_to_string(&h), expected);
    }
}

// 为 keccak256 测试添加 hex helper（独立模块）
#[cfg(test)]
mod hex {
    pub fn encode_to_string(bytes: &[u8]) -> alloc::string::String {
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        let mut s = alloc::string::String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }
}