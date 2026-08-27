//! RLP 编码（Recursive Length Prefix）
//!
//! 用于 Ethereum 交易序列化、状态 trie、receipt 等。
//!
//! ## 算法
//!
//! - 编码单字节 `b`（0-127）：直接输出 `b`
//! - 编码 0-55 字节：[0x80 + len, ...bytes]
//! - 编码 >55 字节：[0xb7 + len_of_len, len_be, ...bytes]
//! - 编码 list [items...]：[0xc0 + payload_len, ...rlp(item)] for <= 55 bytes payload
//! - 编码 list >55 bytes：[0xf7 + len_of_len, payload_len_be, ...rlp(item)]
//!
//! ## v2 §2.3 决策
//!
//! ✅ **自实现 RLP**（Ethereum Yellow Paper 规范；编码类，不是密码学）
//!
//! 业务模块允许 alloc（`Vec<u8>` 生命周期 ≤ 函数调用）。

extern crate alloc;
use alloc::vec::Vec;

/// RLP 编码单值（bytes）
///
/// - 单字节 `0x00` → `0x80`（空字符串）
/// - 单字节 1-127：原样返回
/// - 0-55 字节：`[0x80 + len, ...bytes]`
/// - >55 字节：`[0xb7 + len_of_len, len_be, ...bytes]`
pub fn encode_bytes(b: &[u8]) -> Vec<u8> {
    // 单字节 0 → empty string (0x80)
    if b.len() == 1 && b[0] == 0x00 {
        return alloc::vec![0x80];
    }
    // 单字节 1-127：原样
    if b.len() == 1 && b[0] < 0x80 {
        return alloc::vec![b[0]];
    }
    if b.len() <= 55 {
        // 0x80 + len
        let mut out = Vec::with_capacity(1 + b.len());
        out.push(0x80 + b.len() as u8);
        out.extend_from_slice(b);
        out
    } else {
        // 0xb7 + len_of_len || len_be || bytes
        let n_bytes = (b.len() as u32).to_be_bytes();  // 4 bytes
        // find first non-zero byte (MSB)
        let mut leading_zeros = 0;
        while leading_zeros < 4 && n_bytes[leading_zeros] == 0 {
            leading_zeros += 1;
        }
        let len_of_len = (4 - leading_zeros) as u8;
        let mut out = Vec::with_capacity(1 + len_of_len as usize + b.len());
        out.push(0xb7 + len_of_len);
        out.extend_from_slice(&n_bytes[leading_zeros..]);
        out.extend_from_slice(b);
        out
    }
}

/// RLP 编码 uint256 / uint64（无符号整数）
///
/// 整数先转为 big-endian bytes（无前导 0），再 encode_bytes
pub fn encode_uint(n: u128) -> Vec<u8> {
    if n == 0 {
        return alloc::vec![0x80]; // RLP empty string (= 0)
    }
    // 计算有效字节数
    let bytes_needed = (128 - n.leading_zeros() + 7) / 8;
    let mut buf = [0u8; 16];
    let be = &n.to_be_bytes();
    let start = 16 - bytes_needed as usize;
    encode_bytes(&be[start..])
}

/// RLP 编码 uint256（32-byte big-endian big integer）
///
/// Strip leading zero bytes, then encode_bytes
pub fn encode_uint256(bytes: &[u8; 32]) -> Vec<u8> {
    let mut start = 0;
    while start < 32 && bytes[start] == 0 {
        start += 1;
    }
    if start == 32 {
        return alloc::vec![0x80]; // 0
    }
    encode_bytes(&bytes[start..])
}

/// RLP 编码 list（每个 item 已是 RLP-encoded bytes）
pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    // 先算 payload
    let payload_len: usize = items.iter().map(|i| i.len()).sum();
    let mut out = Vec::with_capacity(payload_len + 9);

    if payload_len <= 55 {
        out.push(0xc0 + payload_len as u8);
    } else {
        let n_bytes = (payload_len as u32).to_be_bytes();
        let mut leading_zeros = 0;
        while leading_zeros < 4 && n_bytes[leading_zeros] == 0 {
            leading_zeros += 1;
        }
        let len_of_len = (4 - leading_zeros) as u8;
        out.push(0xf7 + len_of_len);
        out.extend_from_slice(&n_bytes[leading_zeros..]);
    }

    for item in items {
        out.extend_from_slice(item);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RLP 官方测试向量：空字符串 → 0x80
    #[test]
    fn rlp_empty_string() {
        assert_eq!(encode_bytes(b""), alloc::vec![0x80]);
    }

    /// RLP 官方测试向量：单字节 0x7f → 0x7f
    #[test]
    fn rlp_single_byte_under_128() {
        assert_eq!(encode_bytes(&[0x7f]), alloc::vec![0x7f]);
    }

    /// RLP 官方测试向量：0x00 不直接返回，要编码为 0x80
    /// (因为 0 < 0x80 但在 RLP 规范里：单字节 < 0x80 直接返回，
    ///  但 0 是特殊情况 → b"" 编码 → 0x80)
    #[test]
    fn rlp_zero_byte() {
        // 0x00 = single byte 0 = b"" → 0x80 (RLP empty string)
        // 但 0x00 本身编码是 [0x00] = 1 byte value 0
        // 我们当前实现：b.len()==1 && b[0]<0x80 直接返回 b
        // 但 b"" 已经处理过了，b"\x00" 应该 encode_bytes(\b"\x00") = ?
        // 按官方规范：单字节值 < 0x80 → 直接返回该字节
        // 但 bytes_from_u128(0) = b"" (空), 然后 encode_bytes(b"") = [0x80]
        // 这里测试的是 encode_bytes 直接对 [0x00] 调用的行为
        // 实际上 [0x00] 视为单字节 0 → 应该直接返回 [0x00]
        // 但 RLP 规范把 0 当作 empty string — 让我们看官方测试
        // 官方测试 "0" → 0x80
        // 所以 encode_bytes(b"\x00") 应该是 [0x80]，不是 [0x00]
        // 这里我们的实现需要修正：单字节 0 当作 empty string
        assert_eq!(encode_bytes(&[0x00]), alloc::vec![0x80]);
    }

    /// RLP 官方测试向量：dog = 0x83 'd' 'o' 'g' (3 chars)
    #[test]
    fn rlp_dog() {
        let dog = b"dog";
        let encoded = encode_bytes(dog);
        assert_eq!(encoded, alloc::vec![0x83, b'd', b'o', b'g']);
    }

    /// RLP 官方测试向量：列表 ["cat", "dog"]
    #[test]
    fn rlp_list_cat_dog() {
        let cat = encode_bytes(b"cat");
        let dog = encode_bytes(b"dog");
        let list = encode_list(&[cat, dog]);
        // expected: 0xc8 0x83 'c' 'a' 't' 0x83 'd' 'o' 'g'
        assert_eq!(list, alloc::vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']);
    }

    /// RLP 官方测试向量：空列表 → 0xc0
    #[test]
    fn rlp_empty_list() {
        let list = encode_list(&[]);
        assert_eq!(list, alloc::vec![0xc0]);
    }

    /// RLP 官方测试向量：数字 0 → 0x80 (empty string)
    #[test]
    fn rlp_uint_zero() {
        assert_eq!(encode_uint(0), alloc::vec![0x80]);
    }

    /// RLP 官方测试向量：数字 15 → 0x0f
    #[test]
    fn rlp_uint_15() {
        assert_eq!(encode_uint(15), alloc::vec![0x0f]);
    }

    /// RLP 官方测试向量：数字 1024 → 0x82 0x04 0x00
    #[test]
    fn rlp_uint_1024() {
        assert_eq!(encode_uint(1024), alloc::vec![0x82, 0x04, 0x00]);
    }

    /// ETH 实际用例：chain_id=1 编码
    #[test]
    fn rlp_chain_id_1() {
        // 1 → 0x01
        assert_eq!(encode_uint(1), alloc::vec![0x01]);
    }

    /// ETH 实际用例：20-byte address → varstr
    #[test]
    fn rlp_address_20_bytes() {
        let addr = [0x35u8; 20];
        let encoded = encode_bytes(&addr);
        // 0x94 || 20 bytes (0x80 + 0x14 = 0x94)
        assert_eq!(encoded.len(), 21);
        assert_eq!(encoded[0], 0x94);
    }
}