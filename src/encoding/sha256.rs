//! SHA-256 hash（BTC double-SHA256 用）

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use sha2::{Digest, Sha256};

/// SHA-256 输出长度
pub const SHA256_OUTPUT_LEN: usize = 32;

/// SHA-256 hash
///
/// Phase 4 真实实现：`sha2::Sha256::digest(data)`
///
/// **v2.4 安全**：输入 borrow，输出 owned（hash 不携带 secret 信息）
pub fn hash(data: &[u8]) -> Result<[u8; SHA256_OUTPUT_LEN]> {
    let result = Sha256::digest(data);
    let bytes: [u8; SHA256_OUTPUT_LEN] = result.into();
    Ok(bytes)
}

/// Bitcoin double-SHA256 = sha256(sha256(data))
///
/// BTC P2PKH 地址构造用：base58check(0x00 || ripemd160(double_sha256(pubkey)))
pub fn hash_twice(data: &[u8]) -> Result<[u8; SHA256_OUTPUT_LEN]> {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let bytes: [u8; SHA256_OUTPUT_LEN] = second.into();
    Ok(bytes)
}

/// 空 hash（用于不输入数据场景）
///
/// `Sha256::digest([])` 标准结果
pub fn empty_hash() -> [u8; SHA256_OUTPUT_LEN] {
    let result = Sha256::digest([]);
    result.into()
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

    const _: fn(&[u8]) -> Result<[u8; SHA256_OUTPUT_LEN]> = hash;
    const _: fn(&[u8]) -> Result<[u8; SHA256_OUTPUT_LEN]> = hash_twice;

    #[test]
    fn output_len() {
        assert_eq!(SHA256_OUTPUT_LEN, 32);
    }

    /// SHA-256("") 标准测试向量
    /// https://www.di-mgt.com.au/sha_testvectors.html
    #[test]
    fn hash_empty() {
        let h = hash(&[]).unwrap();
        assert_eq!(
            hex_encode(&h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// SHA-256("abc") 标准测试向量
    #[test]
    fn hash_abc() {
        let h = hash(b"abc").unwrap();
        assert_eq!(
            hex_encode(&h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// empty_hash 常量
    #[test]
    fn empty_hash_standard() {
        let h = empty_hash();
        assert_eq!(
            hex_encode(&h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Double-SHA-256("") 标准测试向量
    /// https://en.bitcoin.it/wiki/Protocol_documentation
    #[test]
    fn double_sha256_empty() {
        let h = hash_twice(&[]).unwrap();
        assert_eq!(
            hex_encode(&h),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }
}

// hex 模块：移到 encoding/mod.rs 让其他文件共享
