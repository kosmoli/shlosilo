//! zcash-accounts UR codec (Phase 4 placeholder; Zcash not implemented in v1)

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// zcash-accounts UR codec encode
///
/// Zcash is not implemented in v1 (v2 §2.8 Zcash deferral note), returns `ExportProtocolUnimplemented`
pub fn encode(_account_data: &[u8]) -> Result<heapless::Vec<u8, 2048>> {
    Err(ShlosiloError::new(
        ShlosiloErrorKind::ExportProtocolUnimplemented,
    ))
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
        // v1 does not implement Zcash → return an error code (not unimplemented!)
        assert!(source.contains("ExportProtocolUnimplemented"));
        assert!(source.contains("Phase 4") || source.contains("v2"));
    }
}
