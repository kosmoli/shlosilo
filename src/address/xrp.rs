//! XRP 地址编码（classic + X-address，base58 + ripple alphabet）

use crate::curve_primitive::secp256k1::Secp256k1Point;
use crate::error::Result;
use crate::network::Network;
use core::fmt;

/// XRP 地址（classic base58 编码，最长 ~35 字符）
pub const XRP_ADDRESS_MAX_LEN: usize = 64;

#[derive(Clone, PartialEq, Eq)]
pub struct XrpAddress {
    bytes: heapless::String<XRP_ADDRESS_MAX_LEN>,
}

impl AsRef<str> for XrpAddress {
    fn as_ref(&self) -> &str {
        self.bytes.as_str()
    }
}

impl fmt::Display for XrpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.bytes)
    }
}

impl fmt::Debug for XrpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.bytes.as_str();
        if s.len() > 12 {
            write!(f, "XrpAddress({}…{})", &s[..4], &s[s.len() - 4..])
        } else {
            write!(f, "XrpAddress(<redacted>)")
        }
    }
}

/// XRP classic 地址（`r...` 前缀）
///
/// # Phase 4 实现
/// - base58(0x00 || ripemd160(sha256(pubkey)))
pub fn encode_classic(_pubkey: &Secp256k1Point, _network: Network) -> Result<XrpAddress> {
    unimplemented!("Phase 2.3 stub: xrp::encode_classic 将在 Phase 4 接入 base58")
}

/// XRP X-address（带 destination tag，`X...` 前缀）
pub fn encode_x_address(
    _pubkey: &Secp256k1Point,
    _network: Network,
    _tag: u32,
) -> Result<XrpAddress> {
    unimplemented!("Phase 2.3 stub: xrp::encode_x_address 将在 Phase 4 接入 base58 + tag")
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&Secp256k1Point, Network) -> Result<XrpAddress> = encode_classic;
    const _: fn(&Secp256k1Point, Network, u32) -> Result<XrpAddress> = encode_x_address;

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("xrp.rs");
        assert!(source.contains("unimplemented!"));
        assert!(source.contains("Phase 4"));
    }
}