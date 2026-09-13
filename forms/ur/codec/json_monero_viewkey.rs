//! json-monero-viewkey UR codec（Feather Wallet / Monero GUI compatible）
//!
//! Unlike BC-UR — this is a JSON-encoded XMR view key export format
//! v2 §2.5 Layer E table: `ur::codec::json_monero_viewkey` (not BC-UR)

use crate::address::xmr::XmrAddress;
use crate::curve_primitive::ed25519::Ed25519Scalar;
use crate::error::Result;

/// JSON-encoded view key string (Feather Wallet compatible, max ~256 characters)
pub const JSON_MONERO_VIEWKEY_MAX_LEN: usize = 512;

#[derive(Clone, PartialEq, Eq)]
pub struct JsonMoneroViewkey {
    bytes: heapless::String<JSON_MONERO_VIEWKEY_MAX_LEN>,
}

impl AsRef<str> for JsonMoneroViewkey {
    fn as_ref(&self) -> &str {
        self.bytes.as_str()
    }
}

impl core::fmt::Debug for JsonMoneroViewkey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = self.bytes.as_str();
        if s.len() > 12 {
            write!(f, "JsonMoneroViewkey({}…{})", &s[..8], &s[s.len() - 6..])
        } else {
            write!(f, "JsonMoneroViewkey(<redacted>)")
        }
    }
}

/// JSON view key encoding
///
/// # Phase 4 implementation
/// - JSON `{"address": "...", "viewkey": "...", "restore_height": N}`
/// - Phase 8+ wownero reuse
///
/// **v2.4 security**: view_priv is lent out via `&Ed25519Scalar`, no cloned copies.
pub fn encode(
    _address: &XmrAddress,
    _view_priv: &Ed25519Scalar,
    _restore_height: u64,
) -> Result<JsonMoneroViewkey> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&XmrAddress, &Ed25519Scalar, u64) -> Result<JsonMoneroViewkey> = encode;

    #[test]
    fn json_len() {
        assert_eq!(JSON_MONERO_VIEWKEY_MAX_LEN, 512);
    }

    #[test]
    fn stub_no_panic_marker() {
        // P2-01: stubs now return stable error codes; panic macros must not regress (skip comment lines)
        for line in include_str!("json_monero_viewkey.rs").lines() {
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
