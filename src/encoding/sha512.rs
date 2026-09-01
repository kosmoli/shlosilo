//! SHA-512 hash（PBKDF2-HMAC-SHA512 用，BIP-39 seed）

use crate::error::Result;
use sha2::{Digest, Sha512};

/// SHA-512 输出长度
pub const SHA512_OUTPUT_LEN: usize = 64;

/// SHA-512 hash
///
/// Phase 4 真实实现：`sha2::Sha512::digest(data)`
///
/// **v2.4 安全**：输入 borrow，输出 owned（hash 不携带 secret 信息）
pub fn hash(data: &[u8]) -> Result<[u8; SHA512_OUTPUT_LEN]> {
    let result = Sha512::digest(data);
    let bytes: [u8; SHA512_OUTPUT_LEN] = result.into();
    Ok(bytes)
}

/// HMAC-SHA512 (PBKDF2 building block)
///
/// 标准 HMAC: HMAC(K, m) = SHA512((K' xor opad) || SHA512((K' xor ipad) || m))
///
/// **Phase 4 真实实现**
pub fn hmac(key: &[u8], message: &[u8]) -> Result<[u8; SHA512_OUTPUT_LEN]> {
    const BLOCK_SIZE: usize = 128;

    // K' = K 若 K ≤ 128 bytes，否则 SHA512(K) 然后补 0 到 128 bytes
    let mut k_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = hash(key)?;
        k_block[..SHA512_OUTPUT_LEN].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    // ipad = K' xor 0x36
    let mut ipad = [0u8; BLOCK_SIZE];
    // opad = K' xor 0x5c
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = k_block[i] ^ 0x36;
        opad[i] = k_block[i] ^ 0x5c;
    }

    // inner = SHA512(ipad || message)
    let mut inner_input = [0u8; BLOCK_SIZE + 192]; // 128 + max message
    inner_input[..BLOCK_SIZE].copy_from_slice(&ipad);
    inner_input[BLOCK_SIZE..BLOCK_SIZE + message.len()].copy_from_slice(message);
    let inner = hash(&inner_input[..BLOCK_SIZE + message.len()])?;

    // outer = SHA512(opad || inner)
    let mut outer_input = [0u8; BLOCK_SIZE + SHA512_OUTPUT_LEN];
    outer_input[..BLOCK_SIZE].copy_from_slice(&opad);
    outer_input[BLOCK_SIZE..].copy_from_slice(&inner);
    hash(&outer_input)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// inline hex 编码（避免跨模块 cfg(test) 复杂性）
    fn hex_encode(bytes: &[u8]) -> alloc::string::String {
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        let mut s = alloc::string::String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }

    const _: fn(&[u8]) -> Result<[u8; SHA512_OUTPUT_LEN]> = hash;

    #[test]
    fn output_len() {
        assert_eq!(SHA512_OUTPUT_LEN, 64);
    }

    /// SHA-512("") 标准测试向量
    #[test]
    fn hash_empty() {
        let h = hash(&[]).unwrap();
        let expected = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                        47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        assert_eq!(hex_encode(&h), expected);
    }

    /// SHA-512("abc") 标准测试向量
    #[test]
    fn hash_abc() {
        let h = hash(b"abc").unwrap();
        let expected = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                        2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        assert_eq!(hex_encode(&h), expected);
    }

    /// HMAC-SHA512 简单测试（v0.4.0 Phase 4 baseline）
    #[test]
    fn hmac_basic() {
        let key = b"key";
        let msg = b"The quick brown fox jumps over the lazy dog";
        let mac = hmac(key, msg).unwrap();
        let expected = "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb\
                        82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a";
        assert_eq!(hex_encode(&mac), expected);
    }
}
