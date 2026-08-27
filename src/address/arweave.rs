//! Arweave 地址编码（base64url + SHA-256 digest）

use crate::curve_primitive::rsa::RsaPubKey;
use crate::error::Result;
use crate::network::Network;
use core::fmt;

/// Arweave 地址长度（base64url 编码 512-bit SHA-256 digest = 43 字符）
pub const ARWEAVE_ADDRESS_MAX_LEN: usize = 64;

#[derive(Clone, PartialEq, Eq)]
pub struct ArweaveAddress {
    bytes: heapless::String<ARWEAVE_ADDRESS_MAX_LEN>,
}

impl AsRef<str> for ArweaveAddress {
    fn as_ref(&self) -> &str {
        self.bytes.as_str()
    }
}

impl fmt::Display for ArweaveAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.bytes)
    }
}

impl fmt::Debug for ArweaveAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.bytes.as_str();
        if s.len() > 12 {
            write!(f, "ArweaveAddress({}…{})", &s[..8], &s[s.len() - 6..])
        } else {
            write!(f, "ArweaveAddress(<redacted>)")
        }
    }
}

/// Arweave 地址编码
///
/// # Phase 4 实现
/// - sha256(modulus_bytes) → 32-byte digest → base64url（43 字符）
pub fn encode(_pubkey: &RsaPubKey, _network: Network) -> Result<ArweaveAddress> {
    unimplemented!("Phase 2.3 stub: arweave::encode 将在 Phase 4 接入 sha256 + base64url")
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&RsaPubKey, Network) -> Result<ArweaveAddress> = encode;

    #[test]
    fn address_length() {
        assert_eq!(ARWEAVE_ADDRESS_MAX_LEN, 64);
    }

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("arweave.rs");
        assert!(source.contains("unimplemented!"));
        assert!(source.contains("Phase 4"));
        assert!(source.contains("sha256"));
    }
}