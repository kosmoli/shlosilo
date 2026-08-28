//! SOL 地址编码（base58 + ed25519 pubkey）
//!
//! Phase 2.3 stub
//! Phase 4 真实实现：`solana-program` 或 `ed25519-dalek` pubkey + base58

use crate::curve_primitive::ed25519::Ed25519Point;
use crate::error::Result;
use crate::network::Network;
use core::fmt;

/// SOL 地址长度（base58 编码 32-byte pubkey，约 32-44 字符）
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

/// SOL 地址编码
///
/// # Phase 4 实现
/// - base58(pubkey_32_bytes) — Solana 直接用 ed25519 32-byte pubkey 作为地址
pub fn encode(_pubkey: &Ed25519Point, _network: Network) -> Result<SolAddress> {
    // P2-01: unimplemented!() panic → 稳定错误码
    Err(crate::error::ShlosiloError::new(crate::error::ShlosiloErrorKind::FeatureNotImplemented))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&Ed25519Point, Network) -> Result<SolAddress> = encode;

    #[test]
    fn stub_no_panic_marker() {
        // P2-01：stub 已改为稳定错误码，不允许 panic 宏回归（跳过注释行）
        for line in include_str!("sol.rs").lines() {
            let t = line.trim_start();
            if t.starts_with("//") { continue; }
            assert!(!t.contains(concat!("unimplemented", "!(")), "panic macro regressed: {}", line);
        }
    }
}