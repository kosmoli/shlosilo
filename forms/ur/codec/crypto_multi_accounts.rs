//! crypto-multi-accounts UR codec（UR standard for multi-account export）

use super::crypto_hd_key::Bip32XPub;
use crate::derivation::path::DerivationPath;
use crate::error::Result;

/// Multi-account export input
#[derive(Clone, Debug)]
pub struct MultiAccountsInput<'a> {
    pub master_fingerprint: [u8; 4],
    pub xpubs: &'a [Bip32XPub],
    pub paths: &'a [DerivationPath],
    /// v2.4 security: the path slice holds no owned DerivationPath — business modules pass borrows
    pub chain_kind: u8, // ChainKind::as_u8()
}

/// crypto-multi-accounts UR codec encode
///
/// # Phase 4 implementation
/// - CBOR map { "xfp", "keys": [xpub,...], "paths": [[path,...],...] }
pub fn encode(_input: &MultiAccountsInput<'_>) -> Result<crate::ur::ur_encode::UrEncoded> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&MultiAccountsInput<'_>) -> Result<crate::ur::ur_encode::UrEncoded> = encode;

    #[test]
    fn stub_no_panic_marker() {
        // P2-01: the stub was changed to a stable error code; no panic-macro regression allowed (comment lines skipped)
        for line in include_str!("crypto_multi_accounts.rs").lines() {
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
