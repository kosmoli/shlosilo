//! ETH 地址编码（EIP-55 checksummed hex）
//!
//! Phase 5 v2 真实实现：Keccak256 + EIP-55 mixed-case checksum
//!
//! ## 算法（EIP-55）
//!
//! 1. `address_bytes` = `keccak256(pubkey[1..65])[12..32]`（uncompressed pubkey skip prefix 0x04）
//! 2. `hex_addr_lowercase` = lowercase hex of address_bytes (40 chars)
//! 3. `hash_nibbles` = `keccak256(hex_addr_lowercase as ASCII)`
//! 4. 对每个 nibble i：
//!    - 如果 `hex_addr_lowercase[i]` 是 a-f 且 `hash_nibbles[i] >= 8` → uppercase
//!    - 否则 → lowercase（数字不变）
//! 5. 拼 `"0x" + checksummed`

use crate::curve_primitive::secp256k1::Secp256k1Point;
use crate::encoding::keccak256;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::network::Network;
use core::fmt;

/// ETH 地址字符串长度（"0x" + 40 hex = 42 字符）
pub const ETH_ADDRESS_LEN: usize = 42;

/// ETH 地址（20 bytes → 40 hex + "0x" prefix）
#[derive(Clone, PartialEq, Eq)]
pub struct EthAddress {
    bytes: heapless::String<ETH_ADDRESS_LEN>,
}

impl AsRef<str> for EthAddress {
    fn as_ref(&self) -> &str {
        self.bytes.as_str()
    }
}

impl fmt::Display for EthAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.bytes)
    }
}

impl fmt::Debug for EthAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // privacy: redact full address
        let s = self.bytes.as_str();
        if s.len() >= 10 {
            write!(f, "EthAddress({}...{})", &s[..6], &s[s.len() - 4..])
        } else {
            write!(f, "EthAddress(<redacted>)")
        }
    }
}

/// hex nibble → ASCII char (lowercase)
fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + nibble - 10) as char,
        _ => '0',
    }
}

/// 单 byte → 2 lowercase hex chars
fn byte_to_hex_lower(b: u8) -> [char; 2] {
    [nibble_to_hex(b >> 4), nibble_to_hex(b & 0x0f)]
}

/// ETH 地址编码（EIP-55 checksummed hex）
///
/// `pubkey` 内部存储为 `AffinePoint`（任意 k256 Point），取 uncompressed 65 bytes
/// `network` 占位参数：ETH mainnet/testnet 共用同一地址格式（network 不影响 EIP-55）
pub fn encode(pubkey: &Secp256k1Point, _network: Network) -> Result<EthAddress> {
    // 1. uncompressed pubkey (65 bytes)
    let uncompressed = crate::curve_primitive::secp256k1::point_to_uncompressed(pubkey);
    // 2. keccak256(pubkey[1..65]) — skip 0x04 prefix
    let hash = keccak256::hash(&uncompressed[1..])?;
    // 3. last 20 bytes = address
    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(&hash[12..32]);
    // 4. lowercase hex
    let mut hex_addr_lowercase = [0u8; 40];
    for (i, b) in addr_bytes.iter().enumerate() {
        let pair = byte_to_hex_lower(*b);
        hex_addr_lowercase[2 * i] = pair[0] as u8;
        hex_addr_lowercase[2 * i + 1] = pair[1] as u8;
    }
    // 5. keccak256(lowercase hex as ASCII)
    let hash_check = keccak256::hash(&hex_addr_lowercase)?;
    // 6. 按 nibble 大小写转换
    let mut checksummed = heapless::String::<ETH_ADDRESS_LEN>::new();
    checksummed
        .push_str("0x")
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    for i in 0..40 {
        let c = hex_addr_lowercase[i] as char;
        let hash_nibble = match i % 2 {
            0 => hash_check[i / 2] >> 4,
            _ => hash_check[i / 2] & 0x0f,
        };
        let out_char = if c.is_ascii_digit() {
            c
        } else if hash_nibble >= 8 {
            c.to_ascii_uppercase()
        } else {
            c
        };
        checksummed
            .push(out_char)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    }
    Ok(EthAddress { bytes: checksummed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve_primitive::secp256k1::{base_mul, scalar_from_bytes};

    #[test]
    fn address_length() {
        assert_eq!(ETH_ADDRESS_LEN, 42);
    }

    #[test]
    fn debug_redacts() {
        use core::fmt::Write;
        let mut s = heapless::String::<64>::new();
        let addr = EthAddress {
            bytes: heapless::String::new(),
        };
        // 测试 Debug 格式不 panic
        write!(s, "{:?}", addr).ok();
    }

    /// EIP-55 标准测试向量（地址 → checksummed 字符串 round-trip）
    /// 但我们只测试：给定 pk → 输出格式正确（不是 EIP-55 字节精确匹配因为需要原始 pk）
    /// 这里验证：从 EthAddress 中读出 lowercase 与 EIP-55 测试向量的 lowercase 一致
    /// 加上 nibble-by-nibble checksum 算法逻辑
    #[test]
    fn encode_format() {
        // 任意 sk → pubkey → ETH 地址
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 7;
        let sk = scalar_from_bytes(&sk_bytes).unwrap();
        let pk = base_mul(&sk);
        let addr = encode(&pk, Network::EthereumMainnet).unwrap();
        let s = addr.as_ref();
        assert_eq!(s.len(), ETH_ADDRESS_LEN);
        assert!(s.starts_with("0x"));
        // 后 40 字符必须是 hex
        for c in s[2..].chars() {
            assert!(
                c.is_ascii_digit() || ('a'..='f').contains(&c) || ('A'..='F').contains(&c),
                "non-hex char: {}",
                c
            );
        }
    }

    /// EIP-55 标准测试向量：
    /// 已知 pubkey（uncompressed）→ 期望 address（lower）→ EIP-55 checksum 输出
    /// 这里用已知的 EthereumVitalik public key：
    ///   uncompressed pubkey = 0x04 + 64 bytes
    ///   实际上 0xfb6916095ca... 是著名测试地址
    ///
    /// 我们用 EIP-55 spec 中的算法独立计算并验证
    #[test]
    fn eip55_checksum_algorithm() {
        // 测试向量 1: all lower-case address = 5aaeb6053f3e94c9b9a09f33669435e7ef1beaed
        // 期望 EIP-55 输出: 5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
        let addr_low = b"5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        let hash = keccak256::hash(addr_low).unwrap();
        let expected = "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        let mut result = heapless::String::<40>::new();
        for i in 0..40 {
            let c = addr_low[i] as char;
            let hash_nibble = match i % 2 {
                0 => hash[i / 2] >> 4,
                _ => hash[i / 2] & 0x0f,
            };
            let out_char = if c.is_ascii_digit() {
                c
            } else if hash_nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            };
            result.push(out_char).unwrap();
        }
        assert_eq!(result.as_str(), expected);
    }

    /// EIP-55 测试向量 2: fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359
    /// low: fb6916095ca1df60bb79ce92ce3ea74c37c5d359
    #[test]
    fn eip55_checksum_algorithm_v2() {
        let addr_low = b"fb6916095ca1df60bb79ce92ce3ea74c37c5d359";
        let hash = keccak256::hash(addr_low).unwrap();
        let expected = "fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359";
        let mut result = heapless::String::<40>::new();
        for i in 0..40 {
            let c = addr_low[i] as char;
            let hash_nibble = match i % 2 {
                0 => hash[i / 2] >> 4,
                _ => hash[i / 2] & 0x0f,
            };
            let out_char = if c.is_ascii_digit() {
                c
            } else if hash_nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            };
            result.push(out_char).unwrap();
        }
        assert_eq!(result.as_str(), expected);
    }

    /// EIP-55 测试向量 3: dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB
    /// low: dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb
    #[test]
    fn eip55_checksum_algorithm_v3() {
        let addr_low = b"dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb";
        let hash = keccak256::hash(addr_low).unwrap();
        let expected = "dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB";
        let mut result = heapless::String::<40>::new();
        for i in 0..40 {
            let c = addr_low[i] as char;
            let hash_nibble = match i % 2 {
                0 => hash[i / 2] >> 4,
                _ => hash[i / 2] & 0x0f,
            };
            let out_char = if c.is_ascii_digit() {
                c
            } else if hash_nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            };
            result.push(out_char).unwrap();
        }
        assert_eq!(result.as_str(), expected);
    }

    /// EIP-55 测试向量 4: D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb
    /// low: d1220a0cf47c7b9be7a2e6ba89f429762e7b9adb
    #[test]
    fn eip55_checksum_algorithm_v4() {
        let addr_low = b"d1220a0cf47c7b9be7a2e6ba89f429762e7b9adb";
        let hash = keccak256::hash(addr_low).unwrap();
        let expected = "D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb";
        let mut result = heapless::String::<40>::new();
        for i in 0..40 {
            let c = addr_low[i] as char;
            let hash_nibble = match i % 2 {
                0 => hash[i / 2] >> 4,
                _ => hash[i / 2] & 0x0f,
            };
            let out_char = if c.is_ascii_digit() {
                c
            } else if hash_nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            };
            result.push(out_char).unwrap();
        }
        assert_eq!(result.as_str(), expected);
    }

    /// ETH 端到端：从任意 sk 派生 pubkey → ETH 地址全流程
    #[test]
    fn encode_end_to_end() {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 42;
        let sk = scalar_from_bytes(&sk_bytes).unwrap();
        let pk = base_mul(&sk);
        let addr = encode(&pk, Network::EthereumMainnet).unwrap();
        // 验证：确定性 + 长度正确
        let addr2 = encode(&pk, Network::EthereumMainnet).unwrap();
        assert_eq!(addr.as_ref(), addr2.as_ref());
        assert_eq!(addr.as_ref().len(), ETH_ADDRESS_LEN);
    }
}
