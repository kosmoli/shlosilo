//! BIP-39 passphrase：mnemonic + passphrase → 64-byte seed
//!
//! PBKDF2-HMAC-SHA512(mnemonic_sentence, "mnemonic" + passphrase, 2048)

extern crate alloc;

use alloc::string::String;

use crate::entropy::bip39_words;
use crate::entropy::mnemonic::Mnemonic;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// BIP-39 seed length (64 bytes)
pub const BIP39_SEED_LEN: usize = 64;

// P1-03: Clone forbidden — each clone adds one more active seed in RAM (v2-security §2)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Bip39Seed {
    bytes: [u8; BIP39_SEED_LEN],
}

impl AsRef<[u8]> for Bip39Seed {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Bip39Seed {
    pub fn into_bytes(self) -> [u8; BIP39_SEED_LEN] {
        self.bytes
    }
}

impl core::fmt::Debug for Bip39Seed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Bip39Seed(<64 bytes redacted>)")
    }
}

/// mnemonic + passphrase → 64-byte seed
pub fn mnemonic_to_seed(mnemonic: &Mnemonic, passphrase: &[u8]) -> Result<Bip39Seed> {
    let mut sentence = String::new();
    for (i, &idx) in mnemonic.indices().iter().enumerate() {
        let w = bip39_words::get_word_by_index(idx)
            .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::MnemonicInvalidWord))?;
        if i > 0 {
            sentence.push(' ');
        }
        sentence.push_str(w);
    }
    let mut salt = String::from("mnemonic");
    // The BIP-39 passphrase is a UTF-8 string and the standard requires NFKD normalization.
    // Firmware (no_std) does not implement NFKD — P1-05 audit remediation (2026-08-26):
    // explicitly support ASCII passphrases only; non-UTF-8 / non-ASCII is always rejected,
    // never silently treated as empty (silently treating as empty = a different seed from standard wallets = seemingly lost funds).
    let p = core::str::from_utf8(passphrase)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    if !p.is_ascii() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    salt.push_str(p);
    let mut bytes = [0u8; BIP39_SEED_LEN];
    pbkdf2_hmac::<Sha512>(sentence.as_bytes(), salt.as_bytes(), 2048, &mut bytes);
    sentence.zeroize();
    salt.zeroize();
    Ok(Bip39Seed { bytes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::mnemonic::WordCount;

    const _: fn(&Mnemonic, &[u8]) -> Result<Bip39Seed> = mnemonic_to_seed;

    #[test]
    fn seed_len() {
        assert_eq!(BIP39_SEED_LEN, 64);
    }

    #[test]
    fn seed_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<Bip39Seed>());
    }

    #[test]
    fn mnemonic_can_be_constructed() {
        let _m = Mnemonic::from_indices(&[0u16; 12], WordCount::Words12);
    }

    /// BIP-39 official vector: entropy=16×0 → abandon×11 + about; seed with an empty passphrase
    #[test]
    fn bip39_official_abandon_about() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert_eq!(m.indices()[0], 0);
        assert_eq!(m.indices()[11], 3); // about
        let seed = mnemonic_to_seed(&m, b"").unwrap();
        let expected = hex(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        );
        assert_eq!(seed.as_ref(), expected.as_slice());
    }

    fn hex(s: &str) -> alloc::vec::Vec<u8> {
        let s: alloc::string::String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// P1-05: non-UTF-8 passphrase errors explicitly (no longer silently treated as empty)
    #[test]
    fn non_utf8_passphrase_rejected() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let bad = [0xffu8, 0xfe, 0xfd]; // invalid UTF-8
        let err = mnemonic_to_seed(&m, &bad).unwrap_err();
        assert_eq!(err.kind, ShlosiloErrorKind::EncodingInvalidFormat);
    }

    /// P1-05: non-ASCII (including non-ASCII UTF-8) passphrase explicitly rejected — firmware supports ASCII only
    #[test]
    fn non_ascii_passphrase_rejected() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let bad = "测试".as_bytes(); // valid UTF-8 but non-ASCII (test data)
        let err = mnemonic_to_seed(&m, bad).unwrap_err();
        assert_eq!(err.kind, ShlosiloErrorKind::EncodingInvalidFormat);
    }

    /// P1-05: ASCII passphrase works (Trezor official vector: 128-bit all-zero entropy + "TREZOR")
    #[test]
    fn ascii_passphrase_accepted() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let seed = mnemonic_to_seed(&m, b"TREZOR").unwrap();
        // Trezor BIP-39 test vectors (independently computed cross-check with python-mnemonic vectors.json)
        let expected = hex(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        );
        assert_eq!(seed.as_ref(), expected.as_slice());
    }
}
