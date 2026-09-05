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
            let ur = codec::crypto_hd_key::encode(&xpub, Some(path))?;
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
}
