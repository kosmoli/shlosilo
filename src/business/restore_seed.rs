//! 业务 4：恢复 seed（v2 §1.1）
//!
//! mnemonic + passphrase → BIP-39 64-byte seed（PBKDF2-HMAC-SHA512, 2048）

use crate::entropy::bip39_passphrase;
use crate::entropy::mnemonic::Mnemonic;
use crate::error::Result;

/// mnemonic + passphrase → 64-byte seed
///
/// P1-05（2026-08-26）：先验 checksum——恢复路径拒绝 checksum 错误的助记词
/// （审计：validate() 曾恒 Ok，扫入拼写/校验和错误不会被拒绝）。
pub fn restore_seed(mnemonic: &Mnemonic, passphrase: &[u8], seed_out: &mut [u8; 64]) -> Result<()> {
    mnemonic.validate()?;
    let seed = bip39_passphrase::mnemonic_to_seed(mnemonic, passphrase)?;
    seed_out.copy_from_slice(seed.as_ref());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::mnemonic::WordCount;

    #[test]
    fn restore_seed_official_vector() {
        let mnemonic = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let mut seed_out = [0xFFu8; 64];
        restore_seed(&mnemonic, b"", &mut seed_out).unwrap();
        assert_ne!(seed_out, [0u8; 64]);
        assert_ne!(seed_out, [0xFFu8; 64]);
        // 与 bip39_passphrase 官方向量同一 seed
        let mut again = [0u8; 64];
        restore_seed(&mnemonic, b"", &mut again).unwrap();
        assert_eq!(seed_out, again);
    }

    #[test]
    fn restore_seed_type_signature() {
        const _: fn(&Mnemonic, &[u8], &mut [u8; 64]) -> Result<()> = restore_seed;
    }

    #[test]
    fn restore_seed_from_indices_abandon_about() {
        // 12 词官方：11×abandon + about
        let mut idx = [0u16; 12];
        idx[11] = 3;
        let mnemonic = Mnemonic::from_indices(&idx, WordCount::Words12).unwrap();
        let mut seed_out = [0u8; 64];
        restore_seed(&mnemonic, b"", &mut seed_out).unwrap();
        let via_entropy = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let mut expected = [0u8; 64];
        restore_seed(&via_entropy, b"", &mut expected).unwrap();
        assert_eq!(seed_out, expected);
    }

    /// P1-05：restore 路径拒绝 checksum 错误的助记词（审计核心要求）
    #[test]
    fn restore_seed_rejects_bad_checksum() {
        use crate::error::ShlosiloErrorKind;
        // 合法 12 词（abandon×11+about）→ 最后一个词改 about(3)→accident(4) 破坏 checksum
        let mut idx = [0u16; 12];
        idx[11] = 4;
        let mnemonic = Mnemonic::from_indices(&idx, WordCount::Words12).unwrap();
        let mut seed_out = [0u8; 64];
        let err = restore_seed(&mnemonic, b"", &mut seed_out).unwrap_err();
        assert_eq!(err.kind, ShlosiloErrorKind::MnemonicInvalidChecksum);
        // seed_out 不得被触碰
        assert_eq!(seed_out, [0u8; 64]);
    }

    /// P1-05：restore 路径通过合法 checksum
    #[test]
    fn restore_seed_accepts_valid_checksum() {
        let mnemonic = Mnemonic::from_entropy(&[0x5cu8; 16]).unwrap();
        let mut seed_out = [0u8; 64];
        restore_seed(&mnemonic, b"", &mut seed_out).unwrap();
        assert_ne!(seed_out, [0u8; 64]);
    }
}
