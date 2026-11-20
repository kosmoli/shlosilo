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

    /// A2-16 (2026-11-19 audit): this test was called "official_vector" but computed the value twice
    /// with the same function, so it only proved determinism. It now compares against the published
    /// BIP-39 vector for `abandon x11 about` with an EMPTY passphrase:
    /// seed = PBKDF2-HMAC-SHA512(NFKD(mnemonic), "mnemonic" + "", 2048, 64).
    /// Recomputed independently with Python's hashlib (the same script reproduces the BIP-39
    /// "TREZOR" vector c55257c3…, which is how the derivation was checked before pinning).
    #[test]
    fn restore_seed_official_vector() {
        const EXPECTED: [u8; 64] = [
            0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55,
            0x56, 0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6,
            0xf6, 0xda, 0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86,
            0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
            0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4,
        ];
        let mnemonic = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let mut seed_out = [0xFFu8; 64];
        restore_seed(&mnemonic, b"", &mut seed_out).unwrap();
        assert_eq!(
            seed_out, EXPECTED,
            "restored seed must equal the published BIP-39 vector for abandon x11 about (empty passphrase)"
        );
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
