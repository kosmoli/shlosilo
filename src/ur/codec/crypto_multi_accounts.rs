//! crypto-multi-accounts UR codec（UR standard for multi-account export）

use crate::derivation::path::DerivationPath;
use crate::error::Result;
use super::crypto_hd_key::Bip32XPub;

/// 多账户导出输入
#[derive(Clone, Debug)]
pub struct MultiAccountsInput<'a> {
    pub master_fingerprint: [u8; 4],
    pub xpubs: &'a [Bip32XPub],
    pub paths: &'a [DerivationPath],
    /// v2.4 安全：path 切片不持有 owned DerivationPath——业务模块用 borrow 传入
    pub chain_kind: u8,  // ChainKind::as_u8()
}

/// crypto-multi-accounts UR codec encode
///
/// # Phase 4 实现
/// - CBOR map { "xfp", "keys": [xpub,...], "paths": [[path,...],...] }
pub fn encode(_input: &MultiAccountsInput<'_>) -> Result<crate::ur::ur_encode::UrEncoded> {
    // P2-01: unimplemented!() panic → 稳定错误码
    Err(crate::error::ShlosiloError::new(crate::error::ShlosiloErrorKind::FeatureNotImplemented))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&MultiAccountsInput<'_>) -> Result<crate::ur::ur_encode::UrEncoded> = encode;

    #[test]
    fn stub_no_panic_marker() {
        // P2-01：stub 已改为稳定错误码，不允许 panic 宏回归（跳过注释行）
        for line in include_str!("crypto_multi_accounts.rs").lines() {
            let t = line.trim_start();
            if t.starts_with("//") { continue; }
            assert!(!t.contains(concat!("unimplemented", "!(")), "panic macro regressed: {}", line);
        }
    }
}