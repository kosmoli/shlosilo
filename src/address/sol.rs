//! SOL address encoding (base58 + ed25519 pubkey)
//!
//! Phase 2.3 stub
//! Phase 4 real implementation: `solana-program` or `ed25519-dalek` pubkey + base58

use crate::curve_primitive::ed25519::Ed25519Point;
use crate::error::Result;
use crate::network::Network;
use core::fmt;

/// SOL address length (base58-encoded 32-byte pubkey, roughly 32-44 characters)
pub const SOL_ADDRESS_MAX_LEN: usize = 64;

#[derive(Clone, PartialEq, Eq)]
pub struct SolAddress {
    bytes: heapless::String<SOL_ADDRESS_MAX_LEN>,
}

impl AsRef<str> for SolAddress {
    fn as_ref(&self) -> &str {
        self.bytes.as_str()
    }
}

impl fmt::Display for SolAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.bytes)
    }
}

impl fmt::Debug for SolAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.bytes.as_str();
        if s.len() > 12 {
            write!(f, "SolAddress({}…{})", &s[..4], &s[s.len() - 4..])
        } else {
            write!(f, "SolAddress(<redacted>)")
        }
    }
}

/// SOL address encoding
///
/// # Phase 4 Implementation
/// - base58(pubkey_32_bytes) — Solana uses the ed25519 32-byte pubkey directly as the address
pub fn encode(_pubkey: &Ed25519Point, _network: Network) -> Result<SolAddress> {
    // P2-01: unimplemented!() panic -> stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&Ed25519Point, Network) -> Result<SolAddress> = encode;

    #[test]
    fn stub_no_panic_marker() {
        // P2-01: stubs have been switched to stable error codes; panic macros must not regress (skip comment lines)
        for line in include_str!("sol.rs").lines() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            assert!(
                !t.contains(concat!("unimplemented", "!(")),
                "panic macro regressed: {}",
                line
            );
        }
    }
}
