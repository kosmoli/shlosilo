//! arweave-crypto-account UR codec（UR standard for Arweave wallet export）

use crate::curve_primitive::rsa::RsaPubKey;
use crate::derivation::path::DerivationPath;
use crate::error::Result;

/// arweave-crypto-account UR codec encode
///
/// # Phase 4 实现
/// - CBOR map { "pubkey": rsa_der, "path": derivation_path }
pub fn encode(
    _pubkey: &RsaPubKey,
    _path: &DerivationPath,
) -> Result<crate::ur::ur_encode::UrEncoded> {
    // P2-01: unimplemented!() panic → 稳定错误码
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
        // P2-01：stub 已改为稳定错误码，不允许 panic 宏回归（跳过注释行）
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
