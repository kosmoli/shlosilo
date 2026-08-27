//! base58 + base58check 编码（BTC legacy + XRP + SOL）
//!
//! **Phase 4 真实实现**（v2 §3.5 原则——L1 编码自己实现，不引入 alloc crate 依赖）：
//! - base58 算法核心 = 把 byte slice 当作大整数，连续除 58 取余
//! - base58check = base58(data || sha256(sha256(data))[:4])
//!
//! **为什么自己实现**：base58 是字符集转换 + 校验和算法，**不涉及密钥输入**，
//! 风险 = 字符串显示错（不会泄露密钥）。密码学原语（sha256/sha512/k256/ed25519-dalek）
//! 保留 crate 依赖；编码模块自己实现以严格遵守 v2 §3.5 零堆分配。

use crate::encoding::sha256;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// base58check 字符串最大长度
pub const BASE58_MAX_LEN: usize = 128;

/// base58 字符表（不含 0/I/O/l）
const BASE58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// 反查表（255 = invalid）
fn base58_inverse() -> [u8; 256] {
    let mut inv = [255u8; 256];
    for (i, &c) in BASE58_ALPHABET.iter().enumerate() {
        inv[c as usize] = i as u8;
    }
    inv
}

#[derive(Clone, PartialEq, Eq)]
pub struct Base58String {
    bytes: heapless::String<BASE58_MAX_LEN>,
}

impl AsRef<str> for Base58String {
    fn as_ref(&self) -> &str {
        self.bytes.as_str()
    }
}

impl core::fmt::Display for Base58String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.bytes)
    }
}

impl core::fmt::Debug for Base58String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = self.bytes.as_str();
        if s.len() > 12 {
            write!(f, "Base58String({}…{})", &s[..4], &s[s.len() - 4..])
        } else {
            write!(f, "Base58String(<redacted>)")
        }
    }
}

/// base58 编码（无 checksum）
///
/// 算法：
/// 1. 统计前导 0x00 byte 数量
/// 2. 把 input bytes 看作大整数，连续除以 58 → 反向输出字符
/// 3. 前导 0x00 byte → 前导 '1' 字符
///
/// **v0.4.0 实现**：参考 bitcoinjs-lib / bitcoin core 算法
pub fn encode(data: &[u8]) -> Result<Base58String> {
    // 1. 统计前导 0x00 byte 数量
    let mut leading_zeros = 0;
    for &b in data.iter() {
        if b == 0 {
            leading_zeros += 1;
        } else {
            break;
        }
    }

    // 2. 大整数除 58（用 heapless::Vec<u8, 256> 作工作空间）
    let mut working = heapless::Vec::<u8, 256>::new();
    working
        .extend_from_slice(data)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;

    let mut result_bytes: heapless::Vec<u8, BASE58_MAX_LEN> = heapless::Vec::new();

    // 计算需要输出的字符数 = leading_zeros + log58(data) ≈ leading_zeros + log58(max_value)
    // 简单做法：while working 不全 0 时除 58
    loop {
        // 检查是否全 0
        let mut all_zero = true;
        for &b in working.iter() {
            if b != 0 {
                all_zero = false;
                break;
            }
        }
        if all_zero {
            // 输出 leading_zeros 个 '1'（BASE58_ALPHABET[0]）
            for _ in 0..leading_zeros {
                result_bytes
                    .push(BASE58_ALPHABET[0])
                    .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
            }
            break;
        }

        // 大整数除 58
        let mut remainder: usize = 0;
        let mut new_working = heapless::Vec::<u8, 256>::new();
        for &b in working.iter() {
            let acc = remainder * 256 + b as usize;
            let q = acc / 58;
            remainder = acc % 58;
            if !(new_working.is_empty() && q == 0) {
                new_working
                    .push(q as u8)
                    .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
            }
            // carry 不变（acc 已经分散到 q 和 remainder）
            let _ = remainder;
        }
        result_bytes
            .push(BASE58_ALPHABET[remainder])
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
        working = new_working;
    }

    // 3. 反向 result_bytes → 输出
    let mut out = heapless::String::<BASE58_MAX_LEN>::new();
    for &b in result_bytes.iter().rev() {
        out.push(b as char)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }

    Ok(Base58String { bytes: out })
}

/// base58check 编码（带 sha256d 校验和）
///
/// `base58(data || sha256(sha256(data))[:4])`
pub fn encode_check(data: &[u8]) -> Result<Base58String> {
    let double_hash = sha256::hash_twice(data)?;
    let checksum = &double_hash[..4];

    let mut with_checksum = heapless::Vec::<u8, 256>::new();
    with_checksum
        .extend_from_slice(data)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    with_checksum
        .extend_from_slice(checksum)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;

    encode(&with_checksum)
}

/// base58 解码
///
/// 算法：把字符串视为 base58 数字，working（low byte 在前）= working * 58 + n
pub fn decode(s: &str) -> Result<heapless::Vec<u8, 192>> {
    let inv = base58_inverse();

    let mut leading_ones = 0;
    let mut working = heapless::Vec::<u8, 192>::new();
    let mut started = false;

    for c in s.bytes() {
        if c == b'1' && !started {
            leading_ones += 1;
            continue;
        }
        started = true;
        let n = inv[c as usize];
        if n == 255 {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }

        // working = working * 58 + n (单遍算法)
        let mut carry: usize = n as usize;
        for i in 0..working.len() {
            let acc = carry + (working[i] as usize) * 58;
            working[i] = (acc % 256) as u8;
            carry = acc / 256;
        }
        while carry > 0 {
            working
                .push((carry % 256) as u8)
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
            carry /= 256;
        }
    }

    // 输出：leading_ones 个 0x00 byte + working 反向（小端→大端 = 原字节序）
    let mut result = heapless::Vec::<u8, 192>::new();
    for _ in 0..leading_ones {
        result
            .push(0)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }
    for &b in working.iter().rev() {
        result
            .push(b)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }

    Ok(result)
}


/// base58check 解码（验证 checksum）
pub fn decode_check(s: &str) -> Result<heapless::Vec<u8, 128>> {
    let decoded = decode(s)?;
    if decoded.len() < 4 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    let split = decoded.len() - 4;
    let (data, checksum) = decoded.split_at(split);

    let expected = sha256::hash_twice(data)?;
    if &expected[..4] != checksum {
        return Err(ShlosiloError::new(
            ShlosiloErrorKind::EncodingInvalidChecksum,
        ));
    }

    let mut result = heapless::Vec::<u8, 128>::new();
    result
        .extend_from_slice(data)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BTC P2PKH 地址 base58check 标准测试向量
    /// Pubkey hash: 010966776006953D5567439E5E39F86A0D273BEE
    /// Version: 0x00 (mainnet P2PKH)
    /// Expected: 16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM
    #[test]
    fn encode_check_p2pkh() {
        let data = [
            0x00u8, 0x01, 0x09, 0x66, 0x77, 0x60, 0x06, 0x95, 0x3d, 0x55, 0x67, 0x43, 0x9e, 0x5e,
            0x39, 0xf8, 0x6a, 0x0d, 0x27, 0x3b, 0xee,
        ];
        let result = encode_check(&data).unwrap();
        assert_eq!(result.as_ref(), "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM");
    }

    /// decode_check round-trip
    #[test]
    fn decode_check_round_trip() {
        let original = [
            0x00u8, 0x01, 0x09, 0x66, 0x77, 0x60, 0x06, 0x95, 0x3d, 0x55, 0x67, 0x43, 0x9e, 0x5e,
            0x39, 0xf8, 0x6a, 0x0d, 0x27, 0x3b, 0xee,
        ];
        let encoded = encode_check(&original).unwrap();
        let decoded = decode_check(encoded.as_ref()).unwrap();
        assert_eq!(decoded.as_slice(), &original[..]);
    }

    /// checksum 错误 → 返回错误
    #[test]
    fn decode_check_wrong_checksum_rejected() {
        let data = [
            0x00u8, 0x01, 0x09, 0x66, 0x77, 0x60, 0x06, 0x95, 0x3d, 0x55, 0x67, 0x43, 0x9e, 0x5e,
            0x39, 0xf8, 0x6a, 0x0d, 0x27, 0x3b, 0xee,
        ];
        let encoded = encode_check(&data).unwrap();
        let encoded_str = encoded.as_ref();
        let last_char = encoded_str.chars().last().unwrap();
        let bad_last = if last_char == 'A' { 'B' } else { 'A' };
        let mut bad_chars: heapless::String<BASE58_MAX_LEN> = heapless::String::new();
        for (i, c) in encoded_str.chars().enumerate() {
            if i == encoded_str.len() - 1 {
                bad_chars.push(bad_last).unwrap();
            } else {
                bad_chars.push(c).unwrap();
            }
        }
        let result = decode_check(bad_chars.as_str());
        assert!(result.is_err());
    }

    /// base58 编码空输入 → 空字符串
    #[test]
    fn encode_empty() {
        let result = encode(&[]).unwrap();
        assert_eq!(result.as_ref(), "");
    }

    /// base58 编码单个 0x00 byte → "1"
    #[test]
    fn encode_single_zero() {
        let result = encode(&[0x00]).unwrap();
        assert_eq!(result.as_ref(), "1");
    }

    /// base58 编码多个前导 0x00 → 多个 '1'
    #[test]
    fn encode_multiple_leading_zeros() {
        let result = encode(&[0x00, 0x00, 0x00]).unwrap();
        assert_eq!(result.as_ref(), "111");
    }

    /// base58 decode + encode round-trip
    #[test]
    fn decode_encode_round_trip() {
        let original = b"hello world";
        let encoded = encode(original).unwrap();
        let decoded = decode(encoded.as_ref()).unwrap();
        assert_eq!(decoded.as_slice(), original);
    }

/// 错误字符 → 返回错误
    #[test]
    fn decode_invalid_char_rejected() {
        // '0' 不在 base58 字符集
        let r = decode("0ab");
        assert!(r.is_err());
    }
}