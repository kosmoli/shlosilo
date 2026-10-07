//! SeedQR / CompactSeedQR — steel-plate seed codecs (SeedSigner family).
//!
//! Two on-plate representations of BIP-39 seed entropy:
//! - **SeedQR (standard)**: the word indices, each zero-padded to 4 decimal
//!   digits (`%04d`), concatenated — 48 digits (12 words) / 96 digits (24 words).
//! - **CompactSeedQR**: the raw entropy bytes — 16 bytes (12 words) /
//!   32 bytes (24 words). Bit layout: the 11-bit word-index stream (MSB first)
//!   with the trailing checksum bits dropped (12 words: 4 bits, 24 words: 8
//!   bits), repacked 8 bits at a time.
//!
//! Oracle conformance: the bit layout and digit format are pinned bit-exact
//! against the real SeedSigner encoders
//! (`seedsigner.models.encode_qr.SeedQrEncoder` / `CompactSeedQrEncoder`) in
//! `tests/seed_qr_oracle.rs`. Where this doc and the oracle could ever
//! disagree, the oracle wins.
//!
//! Scope: the SeedSigner steel-plate family is a hard 12/24-word interop limit
//! (interface detail decision §1, same as `KeySession::from_entropy`), so
//! [`decode`] only returns [`SeedEntropy::W12`] / [`SeedEntropy::W24`].
//! 15/18/21-word mnemonics have no plate representation and are rejected.
//!
//! UR transport (`ur:crypto-seed/…`) is explicitly not handled here — that is
//! a v2 concern (see [`decode`]).
//!
//! L1 discipline: pure functions, no I/O, no global state; seed material flows
//! through [`SecretBytes`] and errors through [`ShlosiloError`].

#[cfg(feature = "alloc-fallback")]
extern crate alloc;

use crate::entropy::mnemonic::{Mnemonic, WordCount};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::types::SecretBytes;
#[cfg(feature = "alloc-fallback")]
use alloc::string::String;
#[cfg(feature = "alloc-fallback")]
use alloc::vec::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Seed entropy as carried on a steel plate / QR. 12/24 words only
/// (SeedSigner family hard limit) — the two `SecretBytes` payloads are the
/// raw BIP-39 entropy, ready to feed `KeySession::from_entropy`.
//
// No Clone/Copy (v2-security §2): each clone doubles the live entropy.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum SeedEntropy {
    /// 16 bytes of entropy = 12-word mnemonic
    W12(SecretBytes<16>),
    /// 32 bytes of entropy = 24-word mnemonic
    W24(SecretBytes<32>),
}

// Redacted Debug (KeySession style): variant + length stay visible for
// diagnostics, entropy contents never print.
impl core::fmt::Debug for SeedEntropy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (variant, len) = match self {
            Self::W12(_) => ("W12", 16usize),
            Self::W24(_) => ("W24", 32usize),
        };
        f.debug_struct("SeedEntropy")
            .field("variant", &variant)
            .field("len", &len)
            .field("entropy", &"<redacted>")
            .finish()
    }
}

impl SeedEntropy {
    /// Wrap raw entropy bytes (16 = 12 words, 32 = 24 words); any other length
    /// is outside the steel-plate family and is rejected.
    ///
    /// Copies into the `SecretBytes` payload; zeroizing the caller's buffer is
    /// the caller's responsibility (`SecretBytes::take` covers fixed arrays).
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        match entropy.len() {
            16 => {
                let mut buf = [0u8; 16];
                buf.copy_from_slice(entropy);
                Ok(Self::W12(SecretBytes::take(&mut buf)))
            }
            32 => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(entropy);
                Ok(Self::W24(SecretBytes::take(&mut buf)))
            }
            _ => Err(ShlosiloError::new(
                ShlosiloErrorKind::MnemonicInvalidEntropyLength,
            )),
        }
    }

    /// Borrow the plaintext entropy — feeds `KeySession::from_entropy` directly.
    pub fn expose(&self) -> &[u8] {
        match self {
            Self::W12(s) => s.expose(),
            Self::W24(s) => s.expose(),
        }
    }

    /// Entropy length in bytes (16 or 32).
    pub fn len(&self) -> usize {
        match self {
            Self::W12(_) => 16,
            Self::W24(_) => 32,
        }
    }

    /// Never empty — kept for the `len`/`is_empty` API convention.
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// CompactSeedQR: word indices → 11-bit stream → drop trailing checksum bits
/// (12 words: 4, 24 words: 8 — BIP-39 gives ENT/32 in general) → 8-bit groups.
///
/// Returns the raw entropy bytes: 16 (12 words) / 32 (24 words).
///
/// **Interop honesty**: only 12/24-word phrases are byte-compatible with
/// SeedSigner's `CompactSeedQrEncoder`, which strips the checksum bits for
/// exactly 12/24 words and *ceil-packs the full 11-bit stream otherwise*
/// (15/18/21 words → 21/25/29 bytes). For non-12/24 phrases this function
/// instead drops the checksum bits and yields BIP-39 entropy 20/24/28 bytes —
/// **NOT byte-compatible with SeedSigner's ceil-packed compact format** — and
/// [`decode`] has no plate representation for them anyway. The
/// `debug_assert!` below pins the supported 12/24 steel-plate family (same
/// interop limit as `KeySession::from_entropy`).
///
/// **Secret hygiene**: the output is the plaintext equivalent of the mnemonic
/// (raw BIP-39 entropy). Never log or `Debug`-print it — the `Vec<u8> Debug`
/// would dump every byte, unlike [`SecretBytes`]/[`Mnemonic`], which redact.
/// Wrap in `zeroize::Zeroizing` and drop it as soon as the consumer is done.
///
/// Availability: `alloc-fallback` builds only (returns `Vec<u8>`); the
/// zero-alloc device builds use the stack-buffer form introduced for the
/// engraving flow (Task 8) — `decode` and `indices_to_entropy` stay no-alloc.
#[cfg(feature = "alloc-fallback")]
pub fn encode_compact(m: &Mnemonic) -> Vec<u8> {
    debug_assert!(
        matches!(m.word_count(), WordCount::Words12 | WordCount::Words24),
        "encode_compact: only the 12/24 steel-plate family is SeedSigner-compatible"
    );
    let mut out = alloc::vec![0u8; m.word_count().entropy_bytes()];
    indices_to_entropy(m.indices(), &mut out);
    out
}

/// SeedQR (standard): each word index as `%04d`, concatenated.
/// 48 digits (12 words) / 96 digits (24 words).
///
/// The digit format itself is word-count-agnostic (SeedSigner writes `%04d`
/// per index regardless), but the plate family is a hard 12/24 interop limit
/// (see [`encode_compact`]); the `debug_assert!` below pins it.
///
/// **Secret hygiene**: the digit string encodes the complete word-index
/// stream — the plaintext equivalent of the mnemonic. Never log or
/// `Debug`-print it; drop it as soon as the consumer is done.
///
/// Availability: `alloc-fallback` builds only (returns `String`) — same gate
/// as [`encode_compact`].
#[cfg(feature = "alloc-fallback")]
pub fn encode_standard(m: &Mnemonic) -> String {
    debug_assert!(
        matches!(m.word_count(), WordCount::Words12 | WordCount::Words24),
        "encode_standard: only the 12/24 steel-plate family is in scope"
    );
    use core::fmt::Write as _;
    let mut s = String::with_capacity(m.indices().len() * 4);
    for &idx in m.indices() {
        // indices are < 2048 → always fits 4 digits; write! never fails on String
        let _ = write!(s, "{:04}", idx);
    }
    s
}

/// Recognize and decode a steel-plate payload back to seed entropy.
///
/// Recognition order:
/// 1. `ur:` prefix (case-insensitive) → `FeatureNotImplemented`: UR transport
///    (`crypto-seed`) is a v2 concern and must never be silently misread as
///    plate data. Checked first so short `ur:` payloads cannot land in the
///    compact (16/32-byte) domain by accident.
/// 2. 16/32 bytes → CompactSeedQR (re-derive the mnemonic, re-verify the
///    BIP-39 checksum as belt-and-braces).
/// 3. 48/96 bytes, all ASCII digits → SeedQR standard (`%04d` index groups →
///    `Mnemonic::from_indices` range-checks, `validate` re-verifies the
///    checksum, then the index stream is collapsed back to entropy with the
///    same helper `encode_compact` uses).
/// 4. Anything else → `EncodingInvalidFormat`.
///
/// The compact (16/32) and digit (48/96) length domains are disjoint, so no
/// payload can be read both ways.
pub fn decode(data: &[u8]) -> Result<SeedEntropy> {
    // 1. UR transport guard
    if data.len() >= 3 && (data[0] | 0x20) == b'u' && (data[1] | 0x20) == b'r' && data[2] == b':' {
        return Err(ShlosiloError::new(ShlosiloErrorKind::FeatureNotImplemented));
    }

    match data.len() {
        // 2. CompactSeedQR: raw entropy
        16 | 32 => {
            // Belt-and-braces: entropy-derived mnemonics always carry a valid
            // checksum, so this can only fail if construction semantics change.
            let m = Mnemonic::from_entropy(data)?;
            m.validate()?;
            SeedEntropy::from_entropy(data)
        }
        // 3. SeedQR standard: %04d digit groups
        48 | 96 => {
            if !data.iter().all(u8::is_ascii_digit) {
                return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            let wc = if data.len() == 48 {
                WordCount::Words12
            } else {
                WordCount::Words24
            };
            let mut indices = [0u16; MAX_PLATE_WORDS];
            let (groups, _) = data.as_chunks::<4>();
            for (i, chunk) in groups.iter().enumerate() {
                let mut v: u16 = 0;
                for &b in chunk {
                    v = v * 10 + u16::from(b - b'0');
                }
                indices[i] = v;
            }
            // Range-checks every index (< 2048) and the count.
            let m = Mnemonic::from_indices(&indices[..wc.as_usize()], wc)?;
            // Re-verify the BIP-39 checksum: rejects swapped/adjacent words.
            m.validate()?;
            // Index stream → entropy (shared helper with encode_compact).
            let mut ent = [0u8; 32];
            indices_to_entropy(m.indices(), &mut ent[..wc.entropy_bytes()]);
            let out = SeedEntropy::from_entropy(&ent[..wc.entropy_bytes()]);
            ent.zeroize();
            // Plaintext index copy dies here too (SecretBytes hygiene: no
            // lingering mnemonic-equivalent material after use).
            indices.zeroize();
            out
        }
        // 4. everything else
        _ => Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)),
    }
}

/// Largest word count that fits on a plate (24 words).
const MAX_PLATE_WORDS: usize = 24;

/// Collapse an 11-bit word-index stream to entropy: concatenate the indices
/// MSB-first, keep the leading `out.len() * 8` bits, drop the trailing
/// BIP-39 checksum bits (12 words: 4 bits, 24 words: 8 bits).
///
/// Shared by [`encode_compact`] and [`decode`] (standard path) — the two must
/// never disagree on the bit layout.
fn indices_to_entropy(indices: &[u16], out: &mut [u8]) {
    let ent_bits = out.len() * 8;
    let mut n = 0usize;
    'outer: for &idx in indices {
        for shift in (0..11).rev() {
            if n == ent_bits {
                break 'outer;
            }
            if (idx >> shift) & 1 == 1 {
                out[n / 8] |= 1 << (7 - (n % 8));
            }
            n += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc-fallback")]
    extern crate alloc;
    use alloc::format;

    #[test]
    fn debug_is_redacted() {
        let s = SeedEntropy::from_entropy(&[0x11u8; 16]).unwrap();
        let dbg = format!("{:?}", s);
        assert!(dbg.contains("<redacted>"), "Debug must redact: {dbg}");
        assert!(!dbg.contains("17"), "no entropy byte may leak: {dbg}");
    }

    #[test]
    fn len_matches_variant() {
        assert_eq!(SeedEntropy::from_entropy(&[0u8; 16]).unwrap().len(), 16);
        assert_eq!(SeedEntropy::from_entropy(&[0u8; 32]).unwrap().len(), 32);
        assert!(!SeedEntropy::from_entropy(&[0u8; 16]).unwrap().is_empty());
    }

    #[test]
    fn from_entropy_rejects_plate_foreign_lengths() {
        for bad in [0usize, 15, 17, 20, 24, 28, 33] {
            let data = [0x5au8; 33];
            let err = SeedEntropy::from_entropy(&data[..bad]).unwrap_err();
            assert_eq!(err.kind, ShlosiloErrorKind::MnemonicInvalidEntropyLength);
        }
    }

    #[test]
    fn helper_matches_expected_bit_layout_12() {
        // 12 words: 132 stream bits, drop the trailing 4 → 128 entropy bits.
        // Indices 0b000_0000_0001 repeated: stream = 00000000001 …
        let indices = [1u16; 12];
        let mut out = [0u8; 16];
        indices_to_entropy(&indices, &mut out);
        // Hand-checkable: bit i of the stream is 1 iff i % 11 == 10.
        for i in 0..128 {
            let expected = if i % 11 == 10 { 1 } else { 0 };
            let got = (out[i / 8] >> (7 - (i % 8))) & 1;
            assert_eq!(got, expected, "stream bit {i}");
        }
    }
}
