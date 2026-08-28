//! base64 + base64url 编码（Arweave address + UR payload）

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// base64 字符串最大长度
pub const BASE64_MAX_LEN: usize = 256;

#[derive(Clone, PartialEq, Eq)]
pub struct Base64String {
    bytes: heapless::String<BASE64_MAX_LEN>,
}

impl AsRef<str> for Base64String {
    fn as_ref(&self) -> &str {
        self.bytes.as_str()
    }
}

impl core::fmt::Display for Base64String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.bytes)
    }
}

impl core::fmt::Debug for Base64String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = self.bytes.as_str();
        if s.len() > 12 {
            write!(f, "Base64String({}…{})", &s[..4], &s[s.len() - 4..])
        } else {
            write!(f, "Base64String(<redacted>)")
        }
    }
}

/// base64 标准编码（含 `+` / `/` / `=` padding）
///
/// **Phase 4 真实实现**：手工实现（避免 base64 crate 引入 std）
///
/// 字符表：A-Z a-z 0-9 + /
const BASE64_STD_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// base64url 字符表（A-Z a-z 0-9 - _）
const BASE64_URL_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode_table(data: &[u8], table: &[u8; 64]) -> heapless::String<BASE64_MAX_LEN> {
    let mut out = heapless::String::<BASE64_MAX_LEN>::new();
    let mut i = 0;
    while i + 2 < data.len() {
        // 3 bytes → 4 chars
        let b0 = data[i];
        let b1 = data[i + 1];
        let b2 = data[i + 2];
        let _ = out.push(table[(b0 >> 2) as usize] as char);
        let _ = out.push(table[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        let _ = out.push(table[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        let _ = out.push(table[(b2 & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let b0 = data[i];
        let _ = out.push(table[(b0 >> 2) as usize] as char);
        let _ = out.push(table[((b0 & 0x03) << 4) as usize] as char);
        let _ = out.push('=');
        let _ = out.push('=');
    } else if rem == 2 {
        let b0 = data[i];
        let b1 = data[i + 1];
        let _ = out.push(table[(b0 >> 2) as usize] as char);
        let _ = out.push(table[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        let _ = out.push(table[((b1 & 0x0f) << 2) as usize] as char);
        let _ = out.push('=');
    }
    out
}

fn decode_table(s: &str, table: &[u8; 64]) -> Result<heapless::Vec<u8, 192>> {
    let mut out = heapless::Vec::<u8, 192>::new();
    // 反查表
    let mut inv = [0xffu8; 256];
    for (i, &c) in table.iter().enumerate() {
        inv[c as usize] = i as u8;
    }

    let chars: heapless::Vec<u8, BASE64_MAX_LEN> = s.bytes().collect();
    if !chars.len().is_multiple_of(4) {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    let mut i = 0;
    while i < chars.len() {
        let c0 = chars[i];
        let c1 = chars[i + 1];
        let c2 = chars[i + 2];
        let c3 = chars[i + 3];

        if c0 == b'=' || c1 == b'=' {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }

        let n0 = inv[c0 as usize];
        let n1 = inv[c1 as usize];
        let n2 = if c2 == b'=' { 0 } else { inv[c2 as usize] };
        let n3 = if c3 == b'=' { 0 } else { inv[c3 as usize] };

        if n0 == 0xff || n1 == 0xff || (c2 != b'=' && n2 == 0xff) || (c3 != b'=' && n3 == 0xff) {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }

        let _ = out.push((n0 << 2) | (n1 >> 4));
        if c2 != b'=' {
            let _ = out.push(((n1 & 0x0f) << 4) | (n2 >> 2));
        }
        if c3 != b'=' {
            let _ = out.push(((n2 & 0x03) << 6) | n3);
        }
        i += 4;
    }
    Ok(out)
}

/// base64 标准编码（含 padding）
pub fn encode_std(data: &[u8]) -> Result<Base64String> {
    let s = encode_table(data, BASE64_STD_TABLE);
    Ok(Base64String { bytes: s })
}

/// base64url 编码（无 padding，用 `-` `_` 替代 `+` `/`）
pub fn encode_url_safe(data: &[u8]) -> Result<Base64String> {
    let s = encode_table(data, BASE64_URL_TABLE);
    Ok(Base64String { bytes: s })
}

/// base64 解码
pub fn decode_std(s: &str) -> Result<heapless::Vec<u8, 192>> {
    decode_table(s, BASE64_STD_TABLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// base64("") = ""
    #[test]
    fn encode_empty() {
        let s = encode_std(&[]).unwrap();
        assert_eq!(s.as_ref(), "");
    }

    /// base64("f") = "Zg=="
    #[test]
    fn encode_one_byte() {
        let s = encode_std(b"f").unwrap();
        assert_eq!(s.as_ref(), "Zg==");
    }

    /// base64("fo") = "Zm8="
    #[test]
    fn encode_two_bytes() {
        let s = encode_std(b"fo").unwrap();
        assert_eq!(s.as_ref(), "Zm8=");
    }

    /// base64("foo") = "Zm9v"
    #[test]
    fn encode_three_bytes() {
        let s = encode_std(b"foo").unwrap();
        assert_eq!(s.as_ref(), "Zm9v");
    }

    /// base64("foobar") = "Zm9vYmFy"
    #[test]
    fn encode_six_bytes() {
        let s = encode_std(b"foobar").unwrap();
        assert_eq!(s.as_ref(), "Zm9vYmFy");
    }

    /// base64url 字符表不含 `+` `/`（用 `-` `_` 替代）
    #[test]
    fn encode_url_safe_no_special_chars() {
        // 4 bytes 数据会触发 padding '='
        let s = encode_url_safe(b"\xff\xfe\xfd\xfc").unwrap();
        assert!(!s.as_ref().contains('+'));
        assert!(!s.as_ref().contains('/'));
        assert!(s.as_ref().contains('='));
    }

    /// decode round-trip
    #[test]
    fn decode_round_trip() {
        let original = b"hello world!";
        let encoded = encode_std(original).unwrap();
        let decoded = decode_std(encoded.as_ref()).unwrap();
        assert_eq!(decoded.as_slice(), original);
    }
}