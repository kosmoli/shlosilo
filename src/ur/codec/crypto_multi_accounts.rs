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
    unimplemented!("Phase 2.3 stub: crypto_multi_accounts::encode 将在 Phase 4 接入 CBOR")
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&MultiAccountsInput<'_>) -> Result<crate::ur::ur_encode::UrEncoded> = encode;

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("crypto_multi_accounts.rs");
        assert!(source.contains("unimplemented!"));
        assert!(source.contains("Phase 4"));
    }
}