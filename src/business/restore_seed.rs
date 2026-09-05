//! Business 4: restore seed (v2 §1.1)
//!
//! mnemonic + passphrase → BIP-39 64-byte seed（PBKDF2-HMAC-SHA512, 2048）

use crate::entropy::bip39_passphrase;
use crate::entropy::mnemonic::Mnemonic;
use crate::error::Result;

/// mnemonic + passphrase → 64-byte seed
///
/// P1-05 (2026-08-26): checksum checked first — the restore path rejects mnemonics with a bad checksum
/// (Audit: validate() used to always return Ok, so scanned spelling/checksum errors were never rejected).
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
        // The same seed as the bip39_passphrase official vector
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
        // Official 12 words: 11×abandon + about
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

    /// P1-05: the restore path rejects mnemonics with a bad checksum (a core audit requirement)
    #[test]
    fn restore_seed_rejects_bad_checksum() {
        use crate::error::ShlosiloErrorKind;
        // Legal 12 words (abandon×11+about) → change the last word about(3)→accident(4) to break the checksum
        let mut idx = [0u16; 12];
        idx[11] = 4;
        let mnemonic = Mnemonic::from_indices(&idx, WordCount::Words12).unwrap();
        let mut seed_out = [0u8; 64];
        let err = restore_seed(&mnemonic, b"", &mut seed_out).unwrap_err();
        assert_eq!(err.kind, ShlosiloErrorKind::MnemonicInvalidChecksum);
        // seed_out must not be touched
        assert_eq!(seed_out, [0u8; 64]);
    }

    /// P1-05: the restore path passes with a legal checksum
    #[test]
    fn restore_seed_accepts_valid_checksum() {
        let mnemonic = Mnemonic::from_entropy(&[0x5cu8; 16]).unwrap();
        let mut seed_out = [0u8; 64];
        restore_seed(&mnemonic, b"", &mut seed_out).unwrap();
        assert_ne!(seed_out, [0u8; 64]);
    }
}
