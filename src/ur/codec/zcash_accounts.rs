//! zcash-accounts UR codec（Phase 4 占位，v1 不实现 Zcash）

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// zcash-accounts UR codec encode
///
/// v1 不实现 Zcash（v2 §2.8 Zcash 暂缓说明），返回 `ExportProtocolUnimplemented`
pub fn encode(_account_data: &[u8]) -> Result<heapless::Vec<u8, 2048>> {
    Err(ShlosiloError::new(ShlosiloErrorKind::ExportProtocolUnimplemented))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&[u8]) -> Result<heapless::Vec<u8, 2048>> = encode;

    #[test]
    fn v1_returns_unsupported() {
        let result = encode(&[]);
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::ExportProtocolUnimplemented
        );
    }

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("zcash_accounts.rs");
        // v1 不实现 Zcash → 返回错误码（不是 unimplemented!）
        assert!(source.contains("ExportProtocolUnimplemented"));
        assert!(source.contains("Phase 4") || source.contains("v2"));
    }
}