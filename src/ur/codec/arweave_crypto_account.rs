//! arweave-crypto-account UR codec（UR standard for Arweave wallet export）

use crate::curve_primitive::rsa::RsaPubKey;
use crate::derivation::path::DerivationPath;
use crate::error::Result;

/// arweave-crypto-account UR codec encode
///
/// # Phase 4 implementation
/// - CBOR map { "pubkey": rsa_der, "path": derivation_path }
pub fn encode(
    _pubkey: &RsaPubKey,
    _path: &DerivationPath,
) -> Result<crate::ur::ur_encode::UrEncoded> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&RsaPubKey, &DerivationPath) -> Result<crate::ur::ur_encode::UrEncoded> = encode;

    #[test]
    fn stub_no_panic_marker() {
        // P2-01: stubs now return stable error codes; panic macros must not regress (skip comment lines)
        for line in include_str!("arweave_crypto_account.rs").lines() {
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
