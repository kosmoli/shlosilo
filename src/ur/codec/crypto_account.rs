//! crypto-account UR codec（UR standard for single-account export）

use crate::derivation::path::DerivationPath;
use crate::error::Result;
use super::crypto_hd_key::Bip32XPub;

/// crypto-account UR codec encode
///
/// # Phase 4 实现
/// - CBOR map { "xfp": fingerprint, "key": xpub, "path": path }
pub fn encode(_master_fingerprint: &[u8; 4], _xpub: &Bip32XPub, _path: &DerivationPath) -> Result<crate::ur::ur_encode::UrEncoded> {
    unimplemented!("Phase 2.3 stub: crypto_account::encode 将在 Phase 4 接入 CBOR")
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&[u8; 4], &Bip32XPub, &DerivationPath) -> Result<crate::ur::ur_encode::UrEncoded> = encode;

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("crypto_account.rs");
        assert!(source.contains("unimplemented!"));
        assert!(source.contains("Phase 4"));
    }
}