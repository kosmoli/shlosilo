//! §B.5 RNG injection decision (2026-08-28): entropy injection + a mature CSPRNG.
//!
//! Layered contract:
//! - L3 is responsible for entropy acquisition (TRNG / getrandom() / dice / camera) and commits to a source and a minimum
//!   min-entropy (≥128 bit recommended). This module does not verify entropy quality; the length check is only a misuse guard.
//! - L2 uses HKDF-SHA256 to derive an independent RNG seed per [`RngPurpose`] sub-domain.
//! - The L1 chain layer only consumes `RngCore + CryptoRng` and is unaware of the entropy source.
//!
//! Security roles (§B.5 bolded decision):
//! - **entropy provides unpredictability** (the root of security);
//! - **the tx digest is context/domain separation and does not count toward entropy bits** — the attacker knows
//!   the construction data, so low-entropy entropy remains enumerable; mixing in a hash adds no entropy.
//!
//! All construction uses mature, audited crates — zero homemade DRBGs:
//! `HKDF-SHA256(ikm=entropy, info=label‖context) → 32B seed → ChaCha20Rng`。
//!
//! Same entropy + same construction → same signature stream: a **feature** (deterministic retry
//! property); r only serves this transaction's outputs, with no cross-transaction collision.
//!
//! **Defense in depth (Z2.4d-3)**: L2 derives every stream from a per-message context, so
//! different transactions can never share a nonce/k EVEN IF the same entropy is fed twice
//! (L3 mis-call, retry, state recovery). The L3 fresh-entropy-per-operation contract stays
//! mandatory as the first wall — L1/L2 must never treat upstream uniqueness as the sole
//! precondition for nonce safety (TRNG acquisition is decoupled from core logic by design).

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use zeroize::Zeroize;

use hkdf::Hkdf;

/// Entropy length lower bound (a misuse guard, not an entropy-quality check — see the module docs).
pub const ENTROPY_MIN_LEN: usize = 16;

/// RNG purpose sub-domains. Each purpose gets an independent KDF derivation; they share no byte stream —
/// refactoring the internal RNG consumption order in sign no longer breaks deterministic vectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RngPurpose {
    /// Transaction ephemeral key r (tx public key R = rG, standard notation; the subaddress special case is noted separately)
    TxKey,
    /// Bulletproof+ blinding
    BulletproofPlus,
    /// CLSAG signatures, isolated per input index
    Clsag(usize),
    /// Export-envelope encryption: ChaCha nonce + Monero Schnorr k (the signature
    /// over keccak256(nonce‖ciphertext)). Z2.4d-3: dedicated domain — this stream
    /// previously rode the BulletproofPlus label with a CONSTANT context, so two
    /// different transactions signed under the same entropy reused the same nonce
    /// AND the same k (two-time pad + Schnorr k-reuse → view_sk recovery).
    ExportEncrypt,
}

impl RngPurpose {
    /// info domain label (first half of the label ‖ 32B context concatenation)
    fn label(&self) -> &'static str {
        match self {
            RngPurpose::TxKey => "shlosilo/xmr/tx-key",
            RngPurpose::BulletproofPlus => "shlosilo/xmr/bulletproof+",
            // the clsag index is encoded into the second half of info; see purpose_rng
            RngPurpose::Clsag(_) => "shlosilo/xmr/clsag",
            RngPurpose::ExportEncrypt => "shlosilo/xmr/export-encrypt",
        }
    }
}

/// Per-export RNG context: Keccak(domain-tag ‖ plaintext stream), where the
/// plaintext is absorbed through the sponge (never materialized). The domain tag
/// carries a format version, so a future v2 container never shares a derivation
/// domain with v1 even on bytewise-identical payloads.
pub const EXPORT_CTX_DOMAIN: &[u8] = b"shlosilo/xmr/export-encrypt/ctx-v1";

/// Z2.4d-3: the sanctioned derivation for export-envelope randomness. Use this
/// (not a hand-rolled `purpose_rng` call) so the domain label and context binding
/// cannot drift apart again.
pub fn export_encrypt_rng(entropy: &[u8], ctx: &[u8; 32]) -> Result<ChaCha20Rng, RngSeedError> {
    purpose_rng(entropy, RngPurpose::ExportEncrypt, ctx)
}

/// Entropy injection error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RngSeedError {
    /// entropy empty or shorter than [`ENTROPY_MIN_LEN`] (API misuse guard)
    EntropyTooShort(usize),
}

impl From<RngSeedError> for crate::error::ShlosiloError {
    fn from(e: RngSeedError) -> Self {
        match e {
            RngSeedError::EntropyTooShort(n) => crate::error::ShlosiloError::with_context(
                crate::error::ShlosiloErrorKind::EntropyInjectionInvalid,
                crate::error::ErrorContext::ActualLength(n),
            ),
        }
    }
}

/// Derive the deterministic RNG for the given purpose.
///
/// `context` = digest of the tx construction data (domain separation; not counted as entropy).
/// The same (entropy, purpose, context) triple always produces the same random stream — the purity of the test model
/// `F(keys, tx, entropy) → signed_tx` is guaranteed by this function.
///
/// info = label ‖ context ‖ purpose_index (u32 LE; the clsag input index also lives in this segment),
/// with non-overlapping semantics per purpose.
pub fn purpose_rng(
    entropy: &[u8],
    purpose: RngPurpose,
    context: &[u8; 32],
) -> Result<ChaCha20Rng, RngSeedError> {
    if entropy.len() < ENTROPY_MIN_LEN {
        return Err(RngSeedError::EntropyTooShort(entropy.len()));
    }
    // purpose_index: TxKey=0, BulletproofPlus=1, Clsag(i)=2 (i encoded into the following 4B)
    let (purpose_index, sub_index): (u32, u32) = match purpose {
        RngPurpose::TxKey => (0, 0),
        RngPurpose::BulletproofPlus => (1, 0),
        RngPurpose::Clsag(i) => (2, i as u32),
        RngPurpose::ExportEncrypt => (3, 0),
    };
    // info = label ‖ context(32) ‖ purpose_index(4 LE) ‖ sub_index(4 LE)
    let mut info = [0u8; 80];
    let label = purpose.label();
    let mut off = 0usize;
    info[..label.len()].copy_from_slice(label.as_bytes());
    off += label.len();
    info[off..off + 32].copy_from_slice(context);
    off += 32;
    info[off..off + 4].copy_from_slice(&purpose_index.to_le_bytes());
    off += 4;
    info[off..off + 4].copy_from_slice(&sub_index.to_le_bytes());
    off += 4;

    let hk = Hkdf::<Sha256>::new(None, entropy);
    let mut seed = [0u8; 32];
    // 32B OKM always succeeds for HKDF-SHA256; unwrap is safe
    hk.expand(&info[..off], &mut seed).unwrap();
    let rng = ChaCha20Rng::from_seed(seed); // from_seed copies into the internal state
    seed.zeroize(); // intermediate seed zeroed right after use
    Ok(rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::RngCore;

    const CTX_A: [u8; 32] = [1u8; 32];
    const CTX_B: [u8; 32] = [2u8; 32];

    fn entropy() -> [u8; 32] {
        let mut e = [0u8; 32];
        for (i, b) in e.iter_mut().enumerate() {
            *b = i as u8;
        }
        e
    }

    fn stream(rng: &mut ChaCha20Rng) -> [u8; 64] {
        let mut out = [0u8; 64];
        rng.fill_bytes(&mut out);
        out
    }

    /// Fixed (entropy, purpose, context) → deterministic output (deterministic retry property)
    #[test]
    fn deterministic_same_inputs_same_stream() {
        let e = entropy();
        let x = stream(&mut purpose_rng(&e, RngPurpose::TxKey, &CTX_A).unwrap());
        let y = stream(&mut purpose_rng(&e, RngPurpose::TxKey, &CTX_A).unwrap());
        assert_eq!(x, y);
    }

    /// Different context (= different tx construction data) → different stream (domain separation)
    #[test]
    fn different_context_different_stream() {
        let e = entropy();
        let x = stream(&mut purpose_rng(&e, RngPurpose::TxKey, &CTX_A).unwrap());
        let y = stream(&mut purpose_rng(&e, RngPurpose::TxKey, &CTX_B).unwrap());
        assert_ne!(x, y);
    }

    /// Different entropy → different stream (the root of unpredictability)
    #[test]
    fn different_entropy_different_stream() {
        let mut e = entropy();
        e[0] ^= 1;
        let x = stream(&mut purpose_rng(&entropy(), RngPurpose::TxKey, &CTX_A).unwrap());
        let y = stream(&mut purpose_rng(&e, RngPurpose::TxKey, &CTX_A).unwrap());
        assert_ne!(x, y);
    }

    /// Purpose sub-domains are mutually independent (tx-key ≠ bp+ ≠ clsag(i), including clsag index distinction)
    #[test]
    fn purposes_are_domain_separated() {
        let e = entropy();
        let mut streams = [
            stream(&mut purpose_rng(&e, RngPurpose::TxKey, &CTX_A).unwrap()),
            stream(&mut purpose_rng(&e, RngPurpose::BulletproofPlus, &CTX_A).unwrap()),
            stream(&mut purpose_rng(&e, RngPurpose::Clsag(0), &CTX_A).unwrap()),
            stream(&mut purpose_rng(&e, RngPurpose::Clsag(1), &CTX_A).unwrap()),
        ];
        for i in 0..4 {
            for j in i + 1..4 {
                assert_ne!(streams[i], streams[j], "purpose {} == purpose {}", i, j);
            }
        }
        let _ = &mut streams; // silence unused assign in release
    }

    /// Misuse guard: <16B entropy rejected; 16B passes exactly
    #[test]
    fn short_entropy_rejected() {
        let e = [0u8; 15];
        assert_eq!(
            purpose_rng(&e, RngPurpose::TxKey, &CTX_A).unwrap_err(),
            RngSeedError::EntropyTooShort(15)
        );
        let e16 = [0u8; 16];
        assert!(purpose_rng(&e16, RngPurpose::TxKey, &CTX_A).is_ok());
    }

    /// Cross-validate HKDF-SHA256 correctness against RFC 5869 official Test Case 1
    /// （IKM=0x0b×22, salt=0x000102..., info=0xf0f1..., L=42）
    #[test]
    fn hkdf_rfc5869_test_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        let expect: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        assert_eq!(okm, expect);
    }

    /// Z2.4d-3 permanent nail: EVERY RngPurpose owns a disjoint stream even under an
    /// identical (entropy, context). The export stream once rode the BulletproofPlus
    /// label — the collision that let one entropy signing two transactions reuse the
    /// same ChaCha nonce AND Schnorr k. All-pairs comparison so any future purpose
    /// joining this list is automatically covered.
    #[test]
    fn all_purpose_streams_disjoint_under_same_ctx() {
        let e = [7u8; 32];
        let ctx = [9u8; 32];
        let purposes: [(RngPurpose, &str); 5] = [
            (RngPurpose::TxKey, "TxKey"),
            (RngPurpose::BulletproofPlus, "BulletproofPlus"),
            (RngPurpose::Clsag(0), "Clsag(0)"),
            (RngPurpose::Clsag(1), "Clsag(1)"),
            (RngPurpose::ExportEncrypt, "ExportEncrypt"),
        ];
        let mut streams = [[0u8; 64]; 5];
        for (i, (p, _)) in purposes.iter().enumerate() {
            purpose_rng(&e, *p, &ctx)
                .unwrap()
                .fill_bytes(&mut streams[i]);
        }
        for i in 0..streams.len() {
            for j in (i + 1)..streams.len() {
                assert_ne!(
                    streams[i], streams[j],
                    "purpose stream collision: {} vs {} (same ctx)",
                    purposes[i].1, purposes[j].1
                );
            }
        }
    }
}
