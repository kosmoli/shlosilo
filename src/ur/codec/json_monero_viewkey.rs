//! json-monero-viewkey UR codec（Feather Wallet / Monero GUI compatible）
//!
//! 与 BC-UR 不同——这是 JSON 编码的 XMR view key 导出格式
//! v2 §2.5 Layer E 表：`ur::codec::json_monero_viewkey`（非 BC-UR）

use crate::address::xmr::XmrAddress;
use crate::curve_primitive::ed25519::Ed25519Scalar;
use crate::error::Result;

/// JSON 编码的 view key 字符串（Feather Wallet 兼容，最长 ~256 字符）
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

/// JSON view key 编码
///
/// # Phase 4 实现
/// - JSON `{"address": "...", "viewkey": "...", "restore_height": N}`
/// - Phase 8+ wownero 复用
///
/// **v2.4 安全**：view_priv 通过 `&Ed25519Scalar` 借出，不 clone 副本。
pub fn encode(
    _address: &XmrAddress,
    _view_priv: &Ed25519Scalar,
    _restore_height: u64,
) -> Result<JsonMoneroViewkey> {
    unimplemented!("Phase 2.3 stub: json_monero_viewkey::encode 将在 Phase 4 接入 JSON 序列化")
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
    fn stub_phase_documented() {
        let source = include_str!("json_monero_viewkey.rs");
        assert!(source.contains("unimplemented!"));
        assert!(source.contains("Phase 4"));
        assert!(source.contains("Feather"));
    }
}