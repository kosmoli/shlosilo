//! APT / SUI 地址编码（hex 0x + 32-byte pubkey）
//!
//! Phase 2.3 stub
//! Phase 4 真实实现：hex(0x || pubkey.to_bytes())

use crate::curve_primitive::ed25519::Ed25519Point;
use crate::error::Result;
use crate::network::Network;
use core::fmt;

/// APT 地址长度（"0x" + 64 hex = 66 字符）
pub const APTOS_ADDRESS_LEN: usize = 66;
pub const SUI_ADDRESS_LEN: usize = 66;

#[derive(Clone, PartialEq, Eq)]
pub struct AptosAddress {
    bytes: heapless::String<APTOS_ADDRESS_LEN>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SuiAddress {
    bytes: heapless::String<SUI_ADDRESS_LEN>,
}

macro_rules! impl_address_traits {
    ($name:ident, $len:ident) => {
        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.bytes.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.bytes)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let s = self.bytes.as_str();
                if s.len() > 12 {
                    write!(f, "{}({}…{})", stringify!($name), &s[..6], &s[s.len() - 4..])
                } else {
                    write!(f, "{}(<redacted>)", stringify!($name))
                }
            }
        }
    };
}

impl_address_traits!(AptosAddress, APTOS_ADDRESS_LEN);
impl_address_traits!(SuiAddress, SUI_ADDRESS_LEN);

/// APT 地址编码
///
/// # Phase 4 实现
/// - hex("0x" || pubkey.to_bytes()) — Aptos 直接用 32-byte ed25519 pubkey
pub fn encode_aptos(_pubkey: &Ed25519Point, _network: Network) -> Result<AptosAddress> {
    unimplemented!("Phase 2.3 stub: aptos_sui::encode_aptos 将在 Phase 4 接入 hex")
}

/// SUI 地址编码
///
/// # Phase 4 实现
/// - hex("0x" || pubkey.to_bytes()) — Sui 用 ed25519 scheme flag + pubkey（实际 hex 前缀 + 64 chars）
pub fn encode_sui(_pubkey: &Ed25519Point, _network: Network) -> Result<SuiAddress> {
    unimplemented!("Phase 2.3 stub: aptos_sui::encode_sui 将在 Phase 4 接入 hex + scheme flag")
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&Ed25519Point, Network) -> Result<AptosAddress> = encode_aptos;
    const _: fn(&Ed25519Point, Network) -> Result<SuiAddress> = encode_sui;

    #[test]
    fn aptos_address_len() {
        assert_eq!(APTOS_ADDRESS_LEN, 66);
    }

    #[test]
    fn sui_address_len() {
        assert_eq!(SUI_ADDRESS_LEN, 66);
    }

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("aptos_sui.rs");
        assert!(source.contains("unimplemented!"));
        assert!(source.contains("Phase 4"));
    }
}