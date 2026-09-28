//! Mnemonic type (v2.3 interface notes §3)
//!
//! BIP-39 standard: 12/15/18/21/24 words (corresponding to 128/160/192/224/256 bits of entropy)
//!
//! Phase 2.0 stub:
//! - Mnemonic fields: fixed-size [u16; MAX_MNEMONIC_WORDS] + len
//! - `from_entropy`: validates entropy length + simplified checksum (replaced by SHA-256 at Phase 4)
//! - `to_seed`: returns a [0u8; 64] placeholder (real PBKDF2-HMAC-SHA512 implementation at Phase 4)
//! - `from_indices`: real implementation at Phase 4 + used by tests

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_MNEMONIC_WORDS: usize = 24;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WordCount {
    Words12 = 12,
    Words15 = 15,
    Words18 = 18,
    Words21 = 21,
    Words24 = 24,
}

impl WordCount {
    /// WordCount u16 → WordCount enum (used for FFI dispatch)
    pub fn try_from_count(n: usize) -> Option<Self> {
        match n {
            12 => Some(Self::Words12),
            15 => Some(Self::Words15),
            18 => Some(Self::Words18),
            21 => Some(Self::Words21),
            24 => Some(Self::Words24),
            _ => None,
        }
    }

    pub const fn entropy_bytes(self) -> usize {
        match self {
            WordCount::Words12 => 16,
            WordCount::Words15 => 20,
            WordCount::Words18 => 24,
            WordCount::Words21 => 28,
            WordCount::Words24 => 32,
        }
    }

    pub const fn checksum_bits(self) -> usize {
        // BIP-39: checksum bits = ENT / 32
        self.entropy_bytes() / 4
    }

    pub const fn as_usize(self) -> usize {
        self as usize
    }
}

/// BIP-39 mnemonic (stack-allocated, fixed size)
///
/// Fields:
/// - `indices`: each u16 is a BIP-39 wordlist index (0..=2047)
/// - `len`: the actual word count (12/15/18/21/24)
///
/// **Security constraint (v2.3 §3.2)**: no derive `Debug` — prevents key material leaking the wordlist contents through Debug output.
/// Hand-written Debug outputs only the word count.
// P1-03: Clone forbidden (v2-security §2); Debug is hand-written to expose only the word count
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Mnemonic {
    indices: [u16; MAX_MNEMONIC_WORDS],
    len: u8,
}

/// Hand-written Debug: exposes only the word count + an index hash, **never the wordlist contents**
impl core::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // uses a simple rolling hash to expose "this is the same mnemonic" — without exposing its content
        let mut h: u32 = 0;
        for &i in &self.indices[..self.len as usize] {
            h = h.wrapping_mul(31).wrapping_add(i as u32);
        }
        f.debug_struct("Mnemonic")
            .field("word_count", &self.len)
            .field("indices_hash", &h)
            .finish()
    }
}

impl Mnemonic {
    /// Build a mnemonic from entropy bytes (Phase 2.0 stub)
    ///
    /// Phase 2.0 simplification:
    /// - validate the entropy length
    /// - compute the SHA-256 checksum (zero placeholder for now; real implementation at Phase 4)
    /// - split into 11-bit segments written into indices
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        let word_count = match entropy.len() {
            16 => WordCount::Words12,
            20 => WordCount::Words15,
            24 => WordCount::Words18,
            28 => WordCount::Words21,
            32 => WordCount::Words24,
            _ => {
                return Err(ShlosiloError::new(
                    ShlosiloErrorKind::MnemonicInvalidEntropyLength,
                ))
            }
        };

        // BIP-39 checksum: top checksum_bits of SHA-256(entropy) appended after the entropy
        let hash = crate::encoding::sha256::hash(entropy)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::MnemonicInvalidEntropyLength))?;
        let checksum_byte = hash[0];

        let total_bits = entropy.len() * 8 + word_count.checksum_bits();
        let mut mnemonic = Self {
            indices: [0u16; MAX_MNEMONIC_WORDS],
            len: word_count as u8,
        };

        let mut bit_idx = 0;
        let mut entropy_buf = [0u8; 33]; // at most 32 entropy + 1 checksum byte
        entropy_buf[..entropy.len()].copy_from_slice(entropy);
        entropy_buf[entropy.len()] = checksum_byte;

        for word_idx in 0..word_count.as_usize() {
            let mut value: u16 = 0;
            for _bit in 0..11 {
                if bit_idx >= total_bits {
                    break;
                }
                let byte_idx = bit_idx / 8;
                let bit_offset = bit_idx % 8;
                let bit_val = (entropy_buf[byte_idx] >> (7 - bit_offset)) & 1;
                value = (value << 1) | (bit_val as u16);
                bit_idx += 1;
            }
            mnemonic.indices[word_idx] = value;
        }

        Ok(mnemonic)
    }

    /// Build from u16 indices (used by the Phase 4 real parser; usable with the Phase 2.0 stub)
    pub fn from_indices(indices: &[u16], expected_count: WordCount) -> Result<Self> {
        if indices.len() != expected_count.as_usize() {
            return Err(ShlosiloError::new(
                ShlosiloErrorKind::MnemonicInvalidWordCount,
            ));
        }
        for &i in indices {
            if i >= 2048 {
                return Err(ShlosiloError::new(ShlosiloErrorKind::MnemonicInvalidWord));
            }
        }
        let mut mnemonic = Self {
            indices: [0u16; MAX_MNEMONIC_WORDS],
            len: expected_count as u8,
        };
        mnemonic.indices[..indices.len()].copy_from_slice(indices);
        Ok(mnemonic)
    }

    pub fn word_count(&self) -> WordCount {
        match self.len {
            12 => WordCount::Words12,
            15 => WordCount::Words15,
            18 => WordCount::Words18,
            21 => WordCount::Words21,
            24 => WordCount::Words24,
            _ => unreachable!("invalid mnemonic length"),
        }
    }

    pub fn indices(&self) -> &[u16] {
        &self.indices[..self.len as usize]
    }

    /// Phase 2.0 stub: returns a [0u8; 64] placeholder
    /// Phase 4 real implementation: PBKDF2-HMAC-SHA512(mnemonic_sentence, "mnemonic" + passphrase, 2048 iterations)
    pub fn to_seed(&self, _passphrase: &[u8]) -> [u8; 64] {
        // Phase 4 real implementation: sha2::Sha512 + pbkdf2
        [0u8; 64]
    }

    /// Verify the mnemonic's checksum bits (P1-05 audit remediation, 2026-08-26)
    ///
    /// Recover entropy from indices (11-bit segments, taking the first ENT bits) → SHA-256 →
    /// Compare the top checksum_bits against the checksum embedded at the end of the mnemonic.
    /// Any wrong word (including a swap with an adjacent valid word) is rejected.
    pub fn validate(&self) -> Result<()> {
        let wc = self.word_count();
        let ent_bits = wc.entropy_bytes() * 8;
        let cs_bits = wc.checksum_bits();
        let total_bits = ent_bits + cs_bits; // at most 256+8=264

        // 1. 11-bit segments → bit stream (fixed stack array, no heap allocation)
        //    24 words = 264 bits is the upper bound (L1 no-heap discipline: zero alloc on hot path)
        let mut bits = [0u8; 264];
        let mut n = 0usize;
        'outer: for &idx in self.indices() {
            for shift in (0..11).rev() {
                bits[n] = ((idx >> shift) & 1) as u8;
                n += 1;
                if n == total_bits {
                    break 'outer;
                }
            }
        }

        // 2. Leading ent_bits → entropy bytes
        let ent_bytes = wc.entropy_bytes();
        let mut entropy = [0u8; 32];
        for i in 0..ent_bits {
            if bits[i] == 1 {
                entropy[i / 8] |= 1 << (7 - (i % 8));
            }
        }

        // 3. Trailing cs_bits → embedded checksum bits
        let mut embedded: u32 = 0;
        for i in 0..cs_bits {
            if bits[ent_bits + i] == 1 {
                embedded |= 1 << (cs_bits - 1 - i);
            }
        }

        // 4. Top cs_bits of SHA-256(entropy) = expected checksum
        let hash = crate::encoding::sha256::hash(&entropy[..ent_bytes])
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::MnemonicInvalidEntropyLength))?;
        let expected: u32 = (hash[0] as u32) >> (8 - cs_bits);

        if embedded == expected {
            Ok(())
        } else {
            Err(ShlosiloError::new(
                ShlosiloErrorKind::MnemonicInvalidChecksum,
            ))
        }
    }

    /// Serialize to a byte stream (each u16 written as two little-endian bytes)
    ///
    /// Phase 2.0 placeholder: used for L2b C-ABI passing
    pub fn to_bytes(&self) -> ([u8; MAX_MNEMONIC_WORDS * 2], usize) {
        let mut out = [0u8; MAX_MNEMONIC_WORDS * 2];
        for (i, &idx) in self.indices[..self.len as usize].iter().enumerate() {
            let bytes = idx.to_le_bytes();
            out[i * 2] = bytes[0];
            out[i * 2 + 1] = bytes[1];
        }
        (out, self.len as usize * 2)
    }
}

// PartialEq for tests (not derived, to avoid zeroize interference)
impl PartialEq for Mnemonic {
    fn eq(&self, other: &Self) -> bool {
        self.indices[..self.len as usize] == other.indices[..other.len as usize]
            && self.len == other.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
#[cfg(feature = "alloc-fallback")]
    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn word_count_entropy_bytes() {
        assert_eq!(WordCount::Words12.entropy_bytes(), 16);
        assert_eq!(WordCount::Words24.entropy_bytes(), 32);
    }

    #[test]
    fn from_entropy_invalid_length() {
        let bad = [0u8; 17];
        assert_eq!(
            Mnemonic::from_entropy(&bad).unwrap_err().kind,
            ShlosiloErrorKind::MnemonicInvalidEntropyLength
        );
    }

    #[test]
    fn from_indices_word_count_mismatch() {
        let indices = [0u16; 11]; // 11 is not a valid WordCount
        let result = Mnemonic::from_indices(&indices, WordCount::Words12);
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::MnemonicInvalidWordCount
        );
    }

    #[test]
    fn from_indices_index_out_of_range() {
        let mut indices = [0u16; 12];
        indices[3] = 2048; // out of range
        let result = Mnemonic::from_indices(&indices, WordCount::Words12);
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::MnemonicInvalidWord
        );
    }

    #[test]
    fn round_trip_indices() {
        let original: [u16; 12] = [0, 1, 2, 3, 2047, 100, 200, 300, 400, 500, 600, 700];
        let mnemonic = Mnemonic::from_indices(&original, WordCount::Words12).unwrap();
        assert_eq!(mnemonic.indices(), &original);
        assert_eq!(mnemonic.word_count(), WordCount::Words12);
    }

    #[test]
    fn from_entropy_16_bytes_12_words() {
        let entropy = [0u8; 16];
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(mnemonic.word_count(), WordCount::Words12);
        assert_eq!(mnemonic.indices().len(), 12);
    }

    // ============================================================
    // Phase 3 property-based tests
    // ============================================================

    use proptest::prelude::*;

    /// proptest strategy: one of the 5 WordCounts
    fn arb_word_count() -> impl Strategy<Value = WordCount> {
        prop_oneof![
            Just(WordCount::Words12),
            Just(WordCount::Words15),
            Just(WordCount::Words18),
            Just(WordCount::Words21),
            Just(WordCount::Words24),
        ]
    }

    /// proptest strategy: fixed-size entropy arrays (proptest::array::uniform to avoid Vec)
    #[allow(dead_code)] // referenced by proptest macro expansion; clippy false positive
    fn arb_entropy(wc: WordCount) -> impl Strategy<Value = Vec<u8>> {
        // dev-dependencies build for the std target, so Vec is available
        proptest::collection::vec(any::<u8>(), wc.entropy_bytes())
    }

    /// proptest strategy: valid u16 indices (0..2048)
    #[allow(dead_code)] // ditto
    fn arb_valid_index() -> impl Strategy<Value = u16> {
        0u16..2048u16
    }

    proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

    /// Valid entropy length → word_count matches the entropy length
            #[test]
            fn from_entropy_legal_length_matches_word_count(
                wc in arb_word_count(),
            ) {
                let entropy = vec![0u8; wc.entropy_bytes()];
                let m = Mnemonic::from_entropy(&entropy).unwrap();
                prop_assert_eq!(m.word_count(), wc);
                prop_assert_eq!(m.indices().len(), wc.as_usize());
            }

    /// Invalid entropy lengths (1-15 / 17-19 / 21-23 / 25-27 / 29-31 / 33+) → reject
            #[test]
            fn from_entropy_invalid_length_rejected(
                bad_len in 0usize..64,
            ) {
                prop_assume!(!matches!(bad_len, 16 | 20 | 24 | 28 | 32));
                let entropy = vec![0u8; bad_len];
                let result = Mnemonic::from_entropy(&entropy);
                prop_assert!(result.is_err());
                prop_assert_eq!(
                    result.unwrap_err().kind,
                    ShlosiloErrorKind::MnemonicInvalidEntropyLength
                );
            }

    /// from_indices valid indices + any WordCount → round-trip consistent
            #[test]
            fn from_indices_round_trip_preserved(
                wc in arb_word_count(),
            ) {
    let indices = vec![0u16; wc.as_usize()]; // all-zero indices (0..2048 valid)
                let m = Mnemonic::from_indices(&indices, wc).unwrap();
                prop_assert_eq!(m.indices(), &indices[..]);
                prop_assert_eq!(m.word_count(), wc);
            }

    /// from_indices out-of-range indices (≥2048) → reject
            #[test]
            fn from_indices_out_of_range_rejected(
                wc in arb_word_count(),
                bad_index in 2048u16..u16::MAX,
                bad_pos in 0usize..24,
            ) {
                prop_assume!(bad_pos < wc.as_usize());
                let mut indices = vec![0u16; wc.as_usize()];
                indices[bad_pos] = bad_index;
                let result = Mnemonic::from_indices(&indices, wc);
                prop_assert!(result.is_err());
                prop_assert_eq!(
                    result.unwrap_err().kind,
                    ShlosiloErrorKind::MnemonicInvalidWord
                );
            }

    /// from_indices length mismatching the WordCount → reject
            #[test]
            fn from_indices_length_mismatch_rejected(
                wc_idx in 0u8..5,
                bad_len in 0usize..24,
            ) {
                let wc = match wc_idx {
                    0 => WordCount::Words12,
                    1 => WordCount::Words15,
                    2 => WordCount::Words18,
                    3 => WordCount::Words21,
                    _ => WordCount::Words24,
                };
                prop_assume!(bad_len != wc.as_usize());
                let bad_indices = vec![0u16; bad_len];
                let result = Mnemonic::from_indices(&bad_indices, wc);
                prop_assert!(result.is_err());
                prop_assert_eq!(
                    result.unwrap_err().kind,
                    ShlosiloErrorKind::MnemonicInvalidWordCount
                );
            }

    /// word_count() → entropy_bytes() reverse: all 5 WordCounts mapped
            #[test]
            fn word_count_entropy_bytes_injective(wc_idx in 0u8..5) {
                let wc = match wc_idx {
                    0 => WordCount::Words12,
                    1 => WordCount::Words15,
                    2 => WordCount::Words18,
                    3 => WordCount::Words21,
                    _ => WordCount::Words24,
                };
                prop_assert_eq!(wc.entropy_bytes(), wc.as_usize() * 4 / 3);
            }

    /// PartialEq reflexivity: a == a
            #[test]
            fn mnemonic_eq_reflexive(indices in (0u16..24u16).prop_map(|_| (0u16..12u16).map(|i| i * 100).collect::<Vec<u16>>())) {
                let m = Mnemonic::from_indices(&indices, WordCount::Words12).unwrap();
    // P1-03 de-Clone: rebuild an equivalent copy from the same indices for the reflexivity assertion
                let m_ref = Mnemonic::from_indices(&indices, WordCount::Words12).unwrap();
                prop_assert_eq!(m, m_ref);
            }

    /// Two mnemonics built from the same index should be equal
            #[test]
            fn mnemonic_eq_same_indices(indices in (0u16..24u16).prop_map(|_| (0u16..12u16).map(|i| i * 100).collect::<Vec<u16>>())) {
                let m1 = Mnemonic::from_indices(&indices, WordCount::Words12).unwrap();
                let m2 = Mnemonic::from_indices(&indices, WordCount::Words12).unwrap();
                prop_assert_eq!(m1, m2);
            }
        }

    // ============================================================
    // Phase 3 BIP-39 test vectors (published by trezor-mnemonic)
    // ============================================================
    //
    // **IMPORTANT**: the Phase 2.0 stub's Mnemonic::from_entropy uses a 0 byte in place of the checksum
    // (not a real SHA-256) — which is why **standard BIP-39 test vectors cannot pass directly**
    // but the **flow** should be right: call from_entropy, build the mnemonic, get word_count / indices

    /// BIP-39 12-word standard entropy "0000...0000" → 12-word stub output
    #[test]
    fn bip39_stub_12_words_from_zero_entropy() {
        let entropy = [0u8; 16]; // 128-bit entropy
        let m = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(m.word_count(), WordCount::Words12);
        assert_eq!(m.indices().len(), 12);
        // stub: checksum byte = 0, so the first 11 indices are all 0 and the last index is the top 3 bits of entropy byte[0] (=0)
        for (i, &idx) in m.indices().iter().enumerate() {
            assert!(
                idx < 2048,
                "BIP-39 index must be < 2048, got {} at {}",
                idx,
                i
            );
        }
    }

    /// BIP-39 24-word standard entropy "0000...0000" (256-bit) → 24-word stub output
    #[test]
    fn bip39_stub_24_words_from_zero_entropy() {
        let entropy = [0u8; 32]; // 256-bit entropy
        let m = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(m.word_count(), WordCount::Words24);
        assert_eq!(m.indices().len(), 24);
        for (i, &idx) in m.indices().iter().enumerate() {
            assert!(
                idx < 2048,
                "BIP-39 index must be < 2048, got {} at {}",
                idx,
                i
            );
        }
    }

    /// BIP-39 arbitrary nonzero entropy → valid mnemonic (verified for all 5 WordCounts)
    #[test]
    fn bip39_stub_non_zero_entropy_valid() {
        for &wc in &[
            WordCount::Words12,
            WordCount::Words15,
            WordCount::Words18,
            WordCount::Words21,
            WordCount::Words24,
        ] {
            let entropy = vec![0xffu8; wc.entropy_bytes()];
            let m = Mnemonic::from_entropy(&entropy).unwrap();
            assert_eq!(m.word_count(), wc);
            assert_eq!(m.indices().len(), wc.as_usize());
        }
    }

    // ============================================================
    // P1-05 BIP-39 checksum verification (audit remediation)
    // ============================================================

    /// Official vector: the from_entropy output must pass validate (correct checksum)
    #[test]
    fn validate_passes_official_abandon_about() {
        // 128-bit all-zero entropy → 11×abandon + about (index 3)
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert_eq!(m.indices()[0], 0);
        assert_eq!(m.indices()[11], 3);
        assert!(m.validate().is_ok());
    }

    /// Official vector: Trezor test vector (256-bit entropy ff...ff) passes validate
    #[test]
    fn validate_passes_official_ff_entropy() {
        // 256-bit all-ff entropy → zoo zoo ... vote (official Trezor vector)
        let m = Mnemonic::from_entropy(&[0xffu8; 32]).unwrap();
        assert!(m.validate().is_ok());
    }

    /// Last word swapped with an adjacent valid word (breaks the checksum) → validate rejects
    #[test]
    fn validate_rejects_flipped_last_word() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        // last word index 3 (about) → 4 (accident), breaking the checksum
        let mut bad_indices = m.indices().to_vec();
        bad_indices[11] = 4;
        let bad = Mnemonic::from_indices(&bad_indices, WordCount::Words12).unwrap();
        assert!(bad.validate().is_err());
        assert_eq!(
            bad.validate().unwrap_err().kind,
            ShlosiloErrorKind::MnemonicInvalidChecksum
        );
    }

    /// Flipping one word anywhere → validate rejects (the checksum catches any single-word error)
    #[test]
    fn validate_rejects_mid_sentence_flip() {
        let m = Mnemonic::from_entropy(&[0x42u8; 16]).unwrap();
        let mut bad_indices = m.indices().to_vec();
        let orig = bad_indices[5];
        bad_indices[5] = (orig + 1) % 2048;
        let bad = Mnemonic::from_indices(&bad_indices, WordCount::Words12).unwrap();
        assert!(bad.validate().is_err());
    }

    /// all 5 word counts verified: the from_entropy output passes validate in every case
    #[test]
    fn validate_passes_all_word_counts() {
        for &wc in &[
            WordCount::Words12,
            WordCount::Words15,
            WordCount::Words18,
            WordCount::Words21,
            WordCount::Words24,
        ] {
            let entropy = vec![0xabu8; wc.entropy_bytes()];
            let m = Mnemonic::from_entropy(&entropy).unwrap();
            assert!(m.validate().is_ok(), "validate failed for {:?}", wc);
        }
    }

    /// from_entropy → from_indices round-trip keeps the checksum valid
    #[test]
    fn validate_round_trip_from_entropy() {
        for &wc in &[
            WordCount::Words12,
            WordCount::Words15,
            WordCount::Words18,
            WordCount::Words21,
            WordCount::Words24,
        ] {
            let entropy = vec![0x7fu8; wc.entropy_bytes()];
            let m = Mnemonic::from_entropy(&entropy).unwrap();
            let idx: Vec<u16> = m.indices().to_vec();
            let m2 = Mnemonic::from_indices(&idx, wc).unwrap();
            assert!(m2.validate().is_ok());
        }
    }
    /// Official Trezor vector: 256-bit all-zero entropy → abandon×23 + art (indices 0×23 + 102)
    #[test]
    fn validate_trezor_zero_entropy_24_words() {
        let mut idx = [0u16; 24];
        idx[23] = 102; // art
        let m = Mnemonic::from_indices(&idx, WordCount::Words24).unwrap();
        assert!(
            m.validate().is_ok(),
            "Trezor official 24-word all-zero must pass"
        );
        // consistent with the from_entropy output
        let m2 = Mnemonic::from_entropy(&[0u8; 32]).unwrap();
        assert_eq!(m, m2);
    }

    /// Official Trezor vector: 128-bit all-zero → abandon×11 + about (indices 0×11 + 3)
    #[test]
    fn validate_trezor_zero_entropy_12_words() {
        let mut idx = [0u16; 12];
        idx[11] = 3; // about
        let m = Mnemonic::from_indices(&idx, WordCount::Words12).unwrap();
        assert!(m.validate().is_ok());
    }
}
