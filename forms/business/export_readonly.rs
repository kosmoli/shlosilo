//! Business 2: export read-only credentials (v2 §1.2 + §4.3 + v2.3 §13)
//!
//! **Phase 2.4 stub implementation**: dispatches by ExportProtocol to the corresponding codec; the call chain is legal but no actual encoding happens.

use crate::derivation::path::DerivationPath;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::network::Network;
use crate::ur::codec;

/// Export protocols (v2.3 §13)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportProtocol {
    /// BTC segwit single-key xpub
    CryptoHdKey,
    /// BTC BIP44 account export
    CryptoAccount,
    /// BTC + ETH multi-path
    CryptoMultiAccounts,
    /// XMR view key JSON (Feather Wallet compatible)
    JsonMoneroViewkey,
    /// Arweave public key + derivation path
    ArweaveCryptoAccount,
    /// Placeholder; not implemented in v1
    ZcashAccounts,
}

/// Business entry for exporting read-only credentials
///
/// **Phase 2.4 stub implementation**:
/// 1. `seed -> xpub`（Layer C bip32_secp256k1 stub）
/// 2. match ExportProtocol → the corresponding codec encode (Layer E codec stub)
/// 3. Returns stub_length (the actual UR payload length)
///
/// **v2.4 security**: `seed: &[u8]` borrow; paths: &[DerivationPath] borrow.
pub fn export_readonly(
    protocol: ExportProtocol,
    seed: &[u8],
    _network: Network,
    paths: &[DerivationPath],
    output_buf: &mut [u8],
) -> Result<usize> {
    match protocol {
        ExportProtocol::ZcashAccounts => Err(ShlosiloError::new(
            ShlosiloErrorKind::ExportProtocolUnimplemented,
        )),
        ExportProtocol::CryptoHdKey => {
            // P2-05: the crypto-hdkey UR's xpub field is fixed to the mainnet version (0x0488B21E).
            // testnet needs tpub (0x043587CF) — v1 keeps it simple: mainnet only,
            // other networks rejected explicitly (avoids exporting with wrong version bytes).
            if _network != Network::BitcoinMainnet {
                return Err(ShlosiloError::new(ShlosiloErrorKind::NetworkUnrecognized));
            }
            let path = paths.first().ok_or_else(|| {
                ShlosiloError::new(ShlosiloErrorKind::DerivationPathInvalidSyntax)
            })?;
            let xpub = crate::derivation::bip32_secp256k1::xpub_from_seed(seed, path)?;
            // The origin keypath's source_fingerprint is the ROOT fingerprint
            // (not derivable from an account-level xpub): the keystone SDK
            // refuses a crypto-hdkey whose keypath lacks it.
            let master_fingerprint =
                crate::derivation::bip32_secp256k1::master_fingerprint_from_seed(seed)?;
            let ur = codec::crypto_hd_key::encode(&xpub, &master_fingerprint, Some(path))?;
            let bytes = ur.as_str().as_bytes();
            if output_buf.len() < bytes.len() {
                return Err(ShlosiloError::with_context(
                    ShlosiloErrorKind::BufferTooSmall,
                    crate::error::ErrorContext::RequiredLength(bytes.len()),
                ));
            }
            output_buf[..bytes.len()].copy_from_slice(bytes);
            Ok(bytes.len())
        }
        ExportProtocol::CryptoAccount => {
            // BTC account sync (keystone wallet-side contract): one crypto-account
            // UR carrying one crypto-output per account path. Mainnet only, same
            // P2-05 reason as the hdkey arm above (tpub version bytes are not
            // implemented, so a testnet export would lie about the network).
            if _network != Network::BitcoinMainnet {
                return Err(ShlosiloError::new(ShlosiloErrorKind::NetworkUnrecognized));
            }
            // keystone's own set is four outputs (84/49/44/86); more than that
            // is outside the codec's buffer budget → explicit rejection.
            const MAX_OUTPUTS: usize = 4;
            if paths.is_empty() || paths.len() > MAX_OUTPUTS {
                return Err(ShlosiloError::new(
                    ShlosiloErrorKind::DerivationPathInvalidSyntax,
                ));
            }
            let master_fingerprint =
                crate::derivation::bip32_secp256k1::master_fingerprint_from_seed(seed)?;

            let mut xpubs = [[0u8; 78]; MAX_OUTPUTS];
            for (i, path) in paths.iter().enumerate() {
                xpubs[i] = crate::derivation::bip32_secp256k1::xpub_from_seed(seed, path)?;
            }
            let mut outputs: heapless::Vec<codec::crypto_account::AccountOutput<'_>, MAX_OUTPUTS> =
                heapless::Vec::new();
            for (i, path) in paths.iter().enumerate() {
                let purpose = path
                    .as_slice()
                    .first()
                    .ok_or_else(|| {
                        ShlosiloError::new(ShlosiloErrorKind::DerivationPathInvalidSyntax)
                    })?
                    .value();
                let script_expressions = codec::crypto_account::btc_script_expressions(purpose)?;
                outputs
                    .push(codec::crypto_account::AccountOutput {
                        xpub: &xpubs[i],
                        path,
                        script_expressions,
                    })
                    .map_err(|_| {
                        ShlosiloError::new(ShlosiloErrorKind::DerivationPathInvalidSyntax)
                    })?;
            }

            let ur = codec::crypto_account::encode(&master_fingerprint, &outputs)?;
            let bytes = ur.as_str().as_bytes();
            if output_buf.len() < bytes.len() {
                return Err(ShlosiloError::with_context(
                    ShlosiloErrorKind::BufferTooSmall,
                    crate::error::ErrorContext::RequiredLength(bytes.len()),
                ));
            }
            output_buf[..bytes.len()].copy_from_slice(bytes);
            Ok(bytes.len())
        }
        _ => {
            // P0-02 audit remediation: protocols not really implemented must be rejected explicitly —
            // never return stub_len (stale caller buffer contents would leak as an export result)
            Err(ShlosiloError::new(
                ShlosiloErrorKind::ExportProtocolUnimplemented,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_paths() -> heapless::Vec<DerivationPath, 8> {
        let mut v = heapless::Vec::new();
        v.push(DerivationPath::parse("m/44'/0'/0'/0/0").unwrap())
            .ok();
        v
    }

    #[test]
    fn export_btc_xpub_returns_ok() {
        let seed = [0u8; 64];
        let paths = test_paths();
        let mut output_buf = [0u8; 2048];
        let result = export_readonly(
            ExportProtocol::CryptoHdKey,
            &seed,
            Network::BitcoinMainnet,
            &paths,
            &mut output_buf,
        );
        let n = result.unwrap();
        let uri = core::str::from_utf8(&output_buf[..n]).unwrap();
        assert!(uri.starts_with("ur:crypto-hdkey/"));
    }

    /// P2-05: CryptoHdKey supports mainnet only — testnet rejected explicitly
    /// (the xpub version is fixed to mainnet bytes; testnet needs tpub — not done in v1)
    #[test]
    fn export_crypto_hdkey_rejects_testnet() {
        let seed = [0u8; 64];
        let paths = test_paths();
        let mut output_buf = [0xA5u8; 2048];
        let result = export_readonly(
            ExportProtocol::CryptoHdKey,
            &seed,
            Network::BitcoinTestnet,
            &paths,
            &mut output_buf,
        );
        let err = result.expect_err("testnet must be rejected for CryptoHdKey");
        assert_eq!(err.kind, ShlosiloErrorKind::NetworkUnrecognized);
        // Failure paths must not write the buffer
        assert!(output_buf.iter().all(|&b| b == 0xA5));
    }

    /// P2-05: ETH mainnet is likewise rejected (CryptoHdKey is a BTC-only export protocol)
    #[test]
    fn export_crypto_hdkey_rejects_non_btc_network() {
        let seed = [0u8; 64];
        let paths = test_paths();
        let mut output_buf = [0xA5u8; 2048];
        let result = export_readonly(
            ExportProtocol::CryptoHdKey,
            &seed,
            Network::EthereumMainnet,
            &paths,
            &mut output_buf,
        );
        assert_eq!(
            result.expect_err("non-BTC network must be rejected").kind,
            ShlosiloErrorKind::NetworkUnrecognized
        );
    }

    #[test]
    fn export_multisig_returns_unsupported() {
        let seed = [0u8; 64];
        let paths = test_paths();
        let mut output_buf = [0u8; 256];
        let result = export_readonly(
            ExportProtocol::ZcashAccounts,
            &seed,
            Network::BitcoinMainnet,
            &paths,
            &mut output_buf,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::ExportProtocolUnimplemented
        );
    }

    #[test]
    fn export_buffer_too_small() {
        let seed = [0u8; 64];
        let paths = test_paths();
        let mut output_buf = [0u8; 32]; // too small
        let result = export_readonly(
            ExportProtocol::CryptoHdKey,
            &seed,
            Network::BitcoinMainnet,
            &paths,
            &mut output_buf,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, ShlosiloErrorKind::BufferTooSmall);
    }

    /// keystone 的 BTC 账户集：84/49/44/86 四条 account 级路径
    fn account_paths() -> heapless::Vec<DerivationPath, 8> {
        let mut v = heapless::Vec::new();
        for p in ["m/84'/0'/0'", "m/49'/0'/0'", "m/44'/0'/0'", "m/86'/0'/0'"] {
            v.push(DerivationPath::parse(p).unwrap()).ok();
        }
        v
    }

    #[test]
    fn export_btc_account_returns_ok() {
        let seed = [0x42u8; 64];
        let paths = account_paths();
        let mut output_buf = [0u8; 4096];
        let n = export_readonly(
            ExportProtocol::CryptoAccount,
            &seed,
            Network::BitcoinMainnet,
            &paths,
            &mut output_buf,
        )
        .expect("crypto-account export");
        let uri = core::str::from_utf8(&output_buf[..n]).unwrap();
        assert!(uri.starts_with("ur:crypto-account/"), "got {uri}");
        // 形状由 tests/ur_crypto_hdkey_registry_shape.rs 用独立 CBOR 走查器钉死；
        // 这里只保证产品入口把它接了出来。
    }

    #[test]
    fn export_btc_account_rejects_testnet() {
        let seed = [0x42u8; 64];
        let paths = account_paths();
        let mut output_buf = [0xA5u8; 4096];
        let err = export_readonly(
            ExportProtocol::CryptoAccount,
            &seed,
            Network::BitcoinTestnet,
            &paths,
            &mut output_buf,
        )
        .expect_err("testnet account export must be rejected");
        assert_eq!(err.kind, ShlosiloErrorKind::NetworkUnrecognized);
        assert!(output_buf.iter().all(|&b| b == 0xA5), "失败路径不得写缓冲");
    }

    #[test]
    fn export_btc_account_rejects_unknown_purpose() {
        let seed = [0x42u8; 64];
        let mut paths = heapless::Vec::<DerivationPath, 8>::new();
        paths
            .push(DerivationPath::parse("m/45'/0'/0'").unwrap())
            .ok();
        let mut output_buf = [0xA5u8; 4096];
        let err = export_readonly(
            ExportProtocol::CryptoAccount,
            &seed,
            Network::BitcoinMainnet,
            &paths,
            &mut output_buf,
        )
        .expect_err("unknown purpose must be rejected, never guessed");
        assert_eq!(err.kind, ShlosiloErrorKind::ExportProtocolUnimplemented);
        assert!(output_buf.iter().all(|&b| b == 0xA5));
    }

    #[test]
    fn export_btc_account_rejects_too_many_outputs() {
        let seed = [0x42u8; 64];
        let mut paths = heapless::Vec::<DerivationPath, 8>::new();
        for p in ["m/84'/0'/0'", "m/49'/0'/0'", "m/44'/0'/0'", "m/86'/0'/0'"] {
            paths.push(DerivationPath::parse(p).unwrap()).ok();
        }
        // 第五条：超出 keystone 集合与 codec 缓冲预算 → 显式拒绝（不截断）
        paths
            .push(DerivationPath::parse("m/84'/0'/1'").unwrap())
            .ok();
        let mut output_buf = [0xA5u8; 4096];
        let err = export_readonly(
            ExportProtocol::CryptoAccount,
            &seed,
            Network::BitcoinMainnet,
            &paths,
            &mut output_buf,
        )
        .expect_err("five outputs must be rejected");
        assert_eq!(err.kind, ShlosiloErrorKind::DerivationPathInvalidSyntax);
        assert!(output_buf.iter().all(|&b| b == 0xA5));
    }
}
