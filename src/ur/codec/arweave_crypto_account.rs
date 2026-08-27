//! arweave-crypto-account UR codec（UR standard for Arweave wallet export）

use crate::curve_primitive::rsa::RsaPubKey;
use crate::derivation::path::DerivationPath;
use crate::error::Result;

/// arweave-crypto-account UR codec encode
///
/// # Phase 4 实现
/// - CBOR map { "pubkey": rsa_der, "path": derivation_path }
pub fn encode(_pubkey: &RsaPubKey, _path: &DerivationPath) -> Result<crate::ur::ur_encode::UrEncoded> {
    unimplemented!("Phase 2.3 stub: arweave_crypto_account::encode 将在 Phase 4 接入 CBOR + RSA DER")
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&RsaPubKey, &DerivationPath) -> Result<crate::ur::ur_encode::UrEncoded> = encode;

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("arweave_crypto_account.rs");
        assert!(source.contains("unimplemented!"));
        assert!(source.contains("Phase 4"));
    }
}