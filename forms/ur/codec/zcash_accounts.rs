//! zcash-accounts UR codec (Phase 4 placeholder; Zcash not implemented in v1)

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// zcash-accounts UR codec encode
///
/// Zcash is not implemented in v1 (v2 §2.8 Zcash deferral note), returns `ExportProtocolUnimplemented`
/// Z3.4 (T-05 frozen shape): v1 stub — the public shape is `&[u8] in,
/// &mut [u8] out` from day one (unimplemented until the zcash-accounts
/// export lands).
pub fn encode(_account_data: &[u8], _out: &mut [u8]) -> Result<usize> {
    Err(ShlosiloError::new(
        ShlosiloErrorKind::ExportProtocolUnimplemented,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&[u8], &mut [u8]) -> Result<usize> = encode;

    #[test]
    fn v1_returns_unsupported() {
        let result = encode(&[], &mut []);
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
