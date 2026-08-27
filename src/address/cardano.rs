//! Cardano Shelley 地址编码（bech32 + Shelley multi-credential）

use crate::curve_primitive::ed25519::Ed25519Point;
use crate::error::Result;
use crate::network::Network;
use core::fmt;

/// Cardano 地址长度（bech32，最长 ~100 字符）
pub const CARDANO_ADDRESS_MAX_LEN: usize = 120;

#[derive(Clone, PartialEq, Eq)]
pub struct CardanoAddress {
    bytes: heapless::String<CARDANO_ADDRESS_MAX_LEN>,
}

impl AsRef<str> for CardanoAddress {
    fn as_ref(&self) -> &str {
        self.bytes.as_str()
    }
}

impl fmt::Display for CardanoAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.bytes)
    }
}

impl fmt::Debug for CardanoAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.bytes.as_str();
        if s.len() > 12 {
            write!(f, "CardanoAddress({}…{})", &s[..8], &s[s.len() - 6..])
        } else {
            write!(f, "CardanoAddress(<redacted>)")
        }
    }
}

/// Cardano Shelley 地址编码
///
/// # Phase 4 实现
/// - bech32(addr_header || network_id || payment_cred || stake_cred || ...)
/// - cardano_serialization_lib::Address
pub fn encode(
    _payment_pubkey: &Ed25519Point,
    _stake_pubkey: Option<&Ed25519Point>,
    _network: Network,
) -> Result<CardanoAddress> {
    unimplemented!(
        "Phase 2.3 stub: cardano::encode 将在 Phase 4 接入 cardano_serialization_lib"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&Ed25519Point, Option<&Ed25519Point>, Network) -> Result<CardanoAddress> = encode;

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("cardano.rs");
        assert!(source.contains("unimplemented!"));
        assert!(source.contains("Phase 4"));
    }
}