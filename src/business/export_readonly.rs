//! 业务 2：导出只读凭证（v2 §1.2 + §4.3 + v2.3 §13）
//!
//! **Phase 2.4 假实现**：按 ExportProtocol dispatch 到对应 codec，调用链合法但不实际编码。

use crate::derivation::path::DerivationPath;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::network::Network;
use crate::ur::codec;

/// 导出协议（v2.3 §13）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportProtocol {
    /// BTC segwit single-key xpub
    CryptoHdKey,
    /// BTC BIP44 账户导出
    CryptoAccount,
    /// BTC + ETH 多路径
    CryptoMultiAccounts,
    /// XMR view key JSON（Feather Wallet 兼容）
    JsonMoneroViewkey,
    /// Arweave 公钥 + 派生路径
    ArweaveCryptoAccount,
    /// 占位，v1 不实现
    ZcashAccounts,
}

/// 导出只读凭证业务入口
///
/// **Phase 2.4 假实现**：
/// 1. `seed -> xpub`（Layer C bip32_secp256k1 stub）
/// 2. match ExportProtocol → 对应 codec encode（Layer E codec stub）
/// 3. 返回 stub_length（实际 UR payload 长度）
///
/// **v2.4 安全**：`seed: &[u8]` borrow，paths: &[DerivationPath] borrow。
pub fn export_readonly(
    protocol: ExportProtocol,
    seed: &[u8],
    _network: Network,
    paths: &[DerivationPath],
    output_buf: &mut [u8],
) -> Result<usize> {
    match protocol {
        ExportProtocol::ZcashAccounts => {
            return Err(ShlosiloError::new(
                ShlosiloErrorKind::ExportProtocolUnimplemented,
            ));
        }
        ExportProtocol::CryptoHdKey => {
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
            return Ok(bytes.len());
        }
        _ => {
            // P0-02 审计整改：未真实实现的协议必须显式拒绝——
            // 不得返回 stub_len（调用者缓冲区旧内容会被当导出结果泄露）
            return Err(ShlosiloError::new(
                ShlosiloErrorKind::ExportProtocolUnimplemented,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_paths() -> heapless::Vec<DerivationPath, 8> {
        let mut v = heapless::Vec::new();
        v.push(DerivationPath::parse("m/44'/0'/0'/0/0").unwrap()).ok();
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
        let mut output_buf = [0u8; 32];  // 太小
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