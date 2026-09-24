//! Monero RingCT signing (Phase 5 v9.5 Phase B)
//!
//! Implements RctSig (Ring Confidential Transactions) — the amount-hiding signature scheme.
//! shlosilo integration:
//! - RctSigBase (type=2/3, fee, pseudo_outs)
//! - RctSigPrunable (commitments + encrypted_amounts + bulletproofs + clsag_sigs)
//! - Bulletproofs+ range proofs (monero-bulletproofs crate)
//! - CLSAG ring signatures (monero-clsag crate, reused from v8)
//!
//! ## Algorithm (RingCTType 2/3 = Bulletproofs+)
//!
//! ```text
//! RctSig {
//!   Base {
//!     type: RingCTType (2 = BP per-output, 3 = BP aggregated, post-fork 1788000),
//!     fee: u64,
//!     pseudo_outs: Vec<[u8; 32]>,  // one pseudo output commitment per input
//!   },
//!   Prunable {
//!     commitments: Vec<[u8; 32]>,  // one commitment per output (C_i = mask_i * G + amount_i * H)
//!     encrypted_amounts: Vec<[u8; 8]>,  // 8 bytes ecdh encrypted amount per output
//!     bulletproofs: Vec<Bulletproof>,  // range proofs (BP+ aggregated for type=3)
//!     clsag_sigs: Vec<ClsagProof>,     // one CLSAG per input
//!   },
//! }
//! ```
//!
//! **Not implemented (Phase C follow-up)**:
//! - Full extra field generation (tx_pub_key derivation)
//! - End-to-end "inputs → outputs → sign → serialize → verify"
//!
//! **References**:
//! - <https://github.com/monero-project/monero/blob/master/src/ringct/rctSigs.cpp>
//! - <https://github.com/monero-project/monero/blob/master/src/ringct/rctTypes.h>

use crate::chain::xmr::clsag::ClsagProof;
extern crate alloc;
use alloc::vec::Vec;

use monero_bulletproofs::{Bulletproof, MAX_COMMITMENTS};
use monero_ed25519::{Commitment as MoneroCommitment, CompressedPoint, Scalar};
use rand_core::{CryptoRng, RngCore};

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::types::SliceVec;

/// RingCTType (BIP-compatible with XMR consensus)
pub mod rct_type {
    /// Type 0: full borromean (pre-fork, deprecated)
    pub const FULL: u8 = 0;
    /// Type 1: simple borromean (deprecated)
    pub const SIMPLE: u8 = 1;
    /// Type 2: bulletproofs (per-output BP+ range proof)
    pub const BULLETPROOFS: u8 = 2;
    /// Type 3: bulletproofs2 (aggregated BP+, post-fork 1788000)
    pub const BULLETPROOFS_PLUS: u8 = 3;
}

/// Z2.3 C3b-2: caller storage bundle for the RCT collections (consumed by value).
/// `commitment_points` holds the masked openings for BP+ proving (secret-adjacent);
/// the wire bytes live in the separate `commitments` pool.
pub struct RctPools<'a> {
    pub pseudo_outs: &'a mut [[u8; 32]],
    pub commitment_points: &'a mut [Option<MoneroCommitment>],
    pub commitments: &'a mut [[u8; 32]],
    pub encrypted_amounts: &'a mut [[u8; 8]],
    pub bulletproofs: &'a mut [Option<Bulletproof>],
    pub clsag_sigs: &'a mut [ClsagProof],
}

/// RctSigBase — the fixed part (independent of ring members; serializable early)
/// Z2.3 C3b-2 (2026-09-24, option 2): `pseudo_outs` is a caller-storage SliceVec.
pub struct RctSigBase<'a> {
    /// RingCT type (only 2 or 3 supported in shlosilo)
    pub rct_type: u8,
    /// tx fee (public)
    pub fee: u64,
    /// pseudo output commitments (one per input, 32 bytes)
    /// pseudo_outs[i] = Commitment(pseudo_mask_i, 0).commit()
    /// (Bull 0 range + 0 amount — makes sum_input_commitments = sum_output_commitments + fee*G)
    pub pseudo_outs: SliceVec<'a, [u8; 32]>,
}

// ─── Z2.4d serialize_into adapters (vendor `Bulletproof::write(impl io::Write)`) ──

/// Counts bytes without storing them (length pre-pass for the BP block).
struct LenCounter(usize);

impl std_shims::io::Write for LenCounter {
    fn write(&mut self, buf: &[u8]) -> std_shims::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
}

/// Writes into a caller buffer at a cursor position.
struct SliceWriter<'b> {
    out: &'b mut [u8],
    n: &'b mut usize,
}

impl<'b> std_shims::io::Write for SliceWriter<'b> {
    fn write(&mut self, buf: &[u8]) -> std_shims::io::Result<usize> {
        crate::types::push::push_slice(self.out, self.n, buf)
            .map_err(|_| std_shims::io::Error::other("serialize buffer too small"))?;
        Ok(buf.len())
    }
}

impl<'a> RctSigBase<'a> {
    pub fn new(rct_type: u8, fee: u64, pseudo_outs: SliceVec<'a, [u8; 32]>) -> Self {
        RctSigBase {
            rct_type,
            fee,
            pseudo_outs,
        }
    }

    /// Serialize base into a caller buffer (Z2.4d C-class). Byte-identical to `serialize`.
    pub fn serialize_into(&self, out: &mut [u8], n: &mut usize) -> Result<()> {
        use crate::chain::xmr::transaction::monero_encode_varint_at;
        use crate::types::push::{push_byte, push_slice};
        push_byte(out, n, self.rct_type)?;
        monero_encode_varint_at(out, n, self.fee)?;
        monero_encode_varint_at(out, n, self.pseudo_outs.len() as u64)?;
        for p in self.pseudo_outs.iter() {
            push_slice(out, n, p)?;
        }
        Ok(())
    }

    /// Test/legacy convenience (allocates). Production writes through `serialize_into`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.rct_type);
        // fee (varint)
        crate::chain::xmr::transaction::monero_encode_varint(&mut out, self.fee);
        // pseudo_outs_count (varint)
        crate::chain::xmr::transaction::monero_encode_varint(
            &mut out,
            self.pseudo_outs.len() as u64,
        );
        for p in self.pseudo_outs.iter() {
            out.extend_from_slice(p);
        }
        out
    }
}

/// RctSigPrunable — the prunable part (depends on ring members, large, trimmable)
/// Z2.3 C3b-2 (2026-09-24, option 2): all four lists are caller-storage SliceVecs.
/// `bulletproofs` slots are `Option` because the vendored `Bulletproof` type has no
/// `Default` placeholder (None = empty slot).
pub struct RctSigPrunable<'a> {
    /// output commitments (one per output, 32-byte Ed25519 point)
    /// commitments[i] = Commitment(mask_i, amount_i).commit()
    pub commitments: SliceVec<'a, [u8; 32]>,
    /// encrypted amounts per output (8 bytes ecdh-encrypted amount)
    pub encrypted_amounts: SliceVec<'a, [u8; 8]>,
    /// Bulletproofs (type=2: one BP per output; type=3: one aggregated BP)
    pub bulletproofs: SliceVec<'a, Option<Bulletproof>>,
    /// CLSAG signatures per input
    pub clsag_sigs: SliceVec<'a, ClsagProof>,
}

impl<'a> RctSigPrunable<'a> {
    pub fn new(
        commitments: SliceVec<'a, [u8; 32]>,
        encrypted_amounts: SliceVec<'a, [u8; 8]>,
        bulletproofs: SliceVec<'a, Option<Bulletproof>>,
        clsag_sigs: SliceVec<'a, ClsagProof>,
    ) -> Self {
        RctSigPrunable {
            commitments,
            encrypted_amounts,
            bulletproofs,
            clsag_sigs,
        }
    }

    /// Serialize the prunable part (BIP-compatible with the XMR wire format)
    /// Format: varint commitments_count + commitments + varint encrypted_amounts_count + encrypted + varint clsag_sigs_count + clsag
    /// bulletproofs go last (per-output BP for type=2, or a single aggregated BP for type=3)
    /// Serialize the prunable part into a caller buffer (Z2.4d C-class).
    /// The vendor BP block is written in two passes (length counter, then in place)
    /// so no intermediate buffer exists. Byte-identical to `serialize`.
    pub fn serialize_into(&self, out: &mut [u8], n: &mut usize) -> Result<()> {
        use crate::chain::xmr::transaction::monero_encode_varint_at;
        use crate::types::push::push_slice;
        // commitments
        monero_encode_varint_at(out, n, self.commitments.len() as u64)?;
        for c in self.commitments.iter() {
            push_slice(out, n, c)?;
        }
        // encrypted_amounts
        monero_encode_varint_at(out, n, self.encrypted_amounts.len() as u64)?;
        for a in self.encrypted_amounts.iter() {
            push_slice(out, n, a)?;
        }
        // bulletproofs: length pass, then write at the right offset
        let mut lc = LenCounter(0);
        for bp in self.bulletproofs.iter().flatten() {
            bp.write(&mut lc)
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
        }
        monero_encode_varint_at(out, n, lc.0 as u64)?;
        for bp in self.bulletproofs.iter().flatten() {
            bp.write(&mut SliceWriter { out, n: &mut *n })
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
        }
        // clsag_sigs
        monero_encode_varint_at(out, n, self.clsag_sigs.len() as u64)?;
        for clsag in self.clsag_sigs.iter() {
            let bytes = clsag.to_bytes();
            monero_encode_varint_at(out, n, bytes.len() as u64)?;
            push_slice(out, n, bytes)?;
        }
        Ok(())
    }

    /// Test/legacy convenience (allocates). Production writes through `serialize_into`.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        // commitments
        crate::chain::xmr::transaction::monero_encode_varint(
            &mut out,
            self.commitments.len() as u64,
        );
        for c in self.commitments.iter() {
            out.extend_from_slice(c);
        }
        // encrypted_amounts
        crate::chain::xmr::transaction::monero_encode_varint(
            &mut out,
            self.encrypted_amounts.len() as u64,
        );
        for a in self.encrypted_amounts.iter() {
            out.extend_from_slice(a);
        }
        // bulletproofs (variable size, written via Write trait)
        let mut bp_buf = Vec::new();
        for bp in self.bulletproofs.iter().flatten() {
            let mut single = Vec::new();
            bp.write(&mut single)
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
            bp_buf.extend_from_slice(&single);
        }
        crate::chain::xmr::transaction::monero_encode_varint(&mut out, bp_buf.len() as u64);
        out.extend_from_slice(&bp_buf);
        // clsag_sigs
        crate::chain::xmr::transaction::monero_encode_varint(
            &mut out,
            self.clsag_sigs.len() as u64,
        );
        for clsag in self.clsag_sigs.iter() {
            // Z2.3 C3b-2: borrow the proof bytes directly (was a to_vec() copy)
            let bytes = clsag.to_bytes();
            crate::chain::xmr::transaction::monero_encode_varint(&mut out, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
        Ok(out)
    }
}

/// Complete RctSig (Base + Prunable)
/// Z2.3 C3b-2 (2026-09-24, option 2): carries the caller-storage lifetimes.
pub struct RctSig<'a> {
    pub base: RctSigBase<'a>,
    pub prunable: RctSigPrunable<'a>,
}

impl<'a> RctSig<'a> {
    pub fn new(base: RctSigBase<'a>, prunable: RctSigPrunable<'a>) -> Self {
        RctSig { base, prunable }
    }

    /// Serialize the complete RctSig into a caller buffer (Z2.4d C-class).
    pub fn serialize_into(&self, out: &mut [u8], n: &mut usize) -> Result<()> {
        self.base.serialize_into(out, n)?;
        self.prunable.serialize_into(out, n)
    }

    /// Test/legacy convenience (allocates). Production writes through `serialize_into`.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut out = self.base.serialize();
        let prunable_bytes = self.prunable.serialize()?;
        out.extend_from_slice(&prunable_bytes);
        Ok(out)
    }
}

/// Construct a Pedersen commitment (mask, amount)
pub fn make_commitment(mask: &Scalar, amount: u64) -> MoneroCommitment {
    MoneroCommitment::new(*mask, amount)
}

/// Construct commitment points (VarInt count + 32 bytes each) — XMR wire format
pub fn serialize_commitments(commitments: &[MoneroCommitment]) -> Vec<u8> {
    let mut out = Vec::new();
    crate::chain::xmr::transaction::monero_encode_varint(&mut out, commitments.len() as u64);
    for c in commitments {
        // Commitment::commit() returns Point (monero-ed25519::Point)
        let point = c.commit();
        let compressed = point.compress();
        out.extend_from_slice(&compressed.to_bytes());
    }
    out
}

/// Generate Bulletproofs+ for a list of commitments (RingCTType 2/3 aggregated)
///
/// **Inputs**:
/// - `rng`: cryptographically secure RNG
/// - `commitments`: list of Pedersen commitments (one per output)
///
/// **Output**: Bulletproof (Plus type, aggregating multiple commitments)
///
/// **Constraint**: commitments.len() <= MAX_COMMITMENTS (16)
pub fn prove_bulletproofs_plus<R: RngCore + CryptoRng>(
    rng: &mut R,
    commitments: Vec<MoneroCommitment>,
) -> Result<Bulletproof> {
    if commitments.is_empty() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    if commitments.len() > MAX_COMMITMENTS {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    Bulletproof::prove_plus(rng, commitments)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))
}

/// Verify Bulletproofs+ for given commitment points (32 bytes each)
///
/// **Inputs**:
/// - `rng`: cryptographically secure RNG
/// - `bp`: Bulletproof (Plus type)
/// - `commitments`: compressed points (32 bytes each) for verification
///
/// **Output**: true if valid
pub fn verify_bulletproofs_plus<R: RngCore + CryptoRng>(
    rng: &mut R,
    bp: &Bulletproof,
    commitments: &[CompressedPoint],
) -> bool {
    bp.verify(rng, commitments)
}

/// Generate pseudo output commitment: C' = Commitment(pseudo_mask, 0)
///
/// pseudo_outs[i] exists to make sum_input_commitments = sum_output_commitments + fee*G.
/// C' amount = 0 (within the BP+ range), but the mask is the pseudo_mask.
pub fn pseudo_out_commitment(pseudo_mask: &Scalar) -> [u8; 32] {
    let c = MoneroCommitment::new(*pseudo_mask, 0);
    let point = c.commit();
    point.compress().to_bytes()
}

/// Unit tests
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::chain::xmr::clsag as clsag_mod;
    use crate::chain::xmr::reduce_scalar::reduce_scalar;
    use alloc::string::String;
    use alloc::vec;
    use rand_core::OsRng;
    use std::eprintln;

    fn hex_encode(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&alloc::format!("{:02x}", byte));
        }
        s
    }

    /// RctSigBase serialization
    #[test]
    fn rct_sig_base_serialize() {
        let mut po = [[0u8; 32]; 2];
        let mut base = RctSigBase::new(
            rct_type::BULLETPROOFS_PLUS,
            100_000_000, // 0.0001 XMR
            SliceVec::new(&mut po),
        );
        base.pseudo_outs.push([0xab; 32]).unwrap();
        base.pseudo_outs.push([0xcd; 32]).unwrap();
        let bytes = base.serialize();
        // type=3, varint(fee), varint(2 pseudo_outs), 2x32 bytes
        assert_eq!(bytes[0], rct_type::BULLETPROOFS_PLUS);
        eprintln!("RctSigBase ({} bytes): {}", bytes.len(), hex_encode(&bytes));
    }

    /// Pedersen commitment construction
    #[test]
    fn commitment_construction() {
        let scalar_bytes = reduce_scalar(&[0x55u8; 32]).unwrap();
        let mask = {
            let bytes = crate::curve_primitive::ed25519::scalar_to_bytes(&scalar_bytes);
            let mut cursor = crate::chain::xmr::transaction::Read32Cursor(bytes);
            Scalar::read(&mut cursor).expect("reduced scalar")
        };
        let amount: u64 = 1000;
        let c = make_commitment(&mask, amount);
        let point = c.commit();
        let compressed = point.compress();
        assert_eq!(compressed.to_bytes().len(), 32);
        eprintln!(
            "Commitment({} piconero): {}",
            amount,
            hex_encode(&compressed.to_bytes())
        );
    }

    /// Pseudo output commitment
    #[test]
    fn pseudo_out() {
        let scalar_bytes = reduce_scalar(&[0x77u8; 32]).unwrap();
        let pseudo_mask = {
            let bytes = crate::curve_primitive::ed25519::scalar_to_bytes(&scalar_bytes);
            let mut cursor = crate::chain::xmr::transaction::Read32Cursor(bytes);
            Scalar::read(&mut cursor).expect("reduced scalar")
        };
        let bytes = pseudo_out_commitment(&pseudo_mask);
        assert_eq!(bytes.len(), 32);
        eprintln!("Pseudo out: {}", hex_encode(&bytes));
    }

    /// Bulletproofs+ range proof (1 commitment)
    #[test]
    fn bulletproof_plus_single() {
        let mut rng = OsRng;
        let scalar_bytes = reduce_scalar(&[0x33u8; 32]).unwrap();
        let mask = {
            let bytes = crate::curve_primitive::ed25519::scalar_to_bytes(&scalar_bytes);
            let mut cursor = crate::chain::xmr::transaction::Read32Cursor(bytes);
            Scalar::read(&mut cursor).expect("reduced scalar")
        };
        let commitments = vec![MoneroCommitment::new(mask, 100_000_000)];
        let bp = prove_bulletproofs_plus(&mut rng, commitments).unwrap();

        // Verify with commitments
        let verify_mask_bytes = reduce_scalar(&[0x33u8; 32]).unwrap();
        let verify_mask = crate::chain::xmr::transaction::bytes_to_monerod_scalar(
            &crate::curve_primitive::ed25519::scalar_to_bytes(&verify_mask_bytes),
        );
        let verify_commitment = MoneroCommitment::new(verify_mask, 100_000_000);
        let compressed = verify_commitment.commit().compress();
        let commitments_for_verify = vec![CompressedPoint::from(compressed.to_bytes())];
        assert!(verify_bulletproofs_plus(
            &mut rng,
            &bp,
            &commitments_for_verify
        ));

        // BP serialize
        let mut bp_bytes = Vec::new();
        bp.write(&mut bp_bytes).unwrap();
        eprintln!("BP+ single ({} bytes)", bp_bytes.len());
    }

    /// Bulletproofs+ multiple commitments (aggregated)
    #[test]
    fn bulletproof_plus_aggregated() {
        let mut rng = OsRng;
        let mut commitments = Vec::new();
        for i in 0u64..4 {
            let scalar_bytes = reduce_scalar(&[i as u8 + 1; 32]).unwrap();
            let mask = {
                let bytes = crate::curve_primitive::ed25519::scalar_to_bytes(&scalar_bytes);
                let mut cursor = crate::chain::xmr::transaction::Read32Cursor(bytes);
                Scalar::read(&mut cursor).expect("reduced scalar")
            };
            commitments.push(MoneroCommitment::new(mask, (i + 1) * 1000));
        }

        let bp = prove_bulletproofs_plus(&mut rng, commitments.clone()).unwrap();

        // Verify
        let mut compressed_pts = Vec::new();
        for c in &commitments {
            let cp = c.commit().compress();
            compressed_pts.push(CompressedPoint::from(cp.to_bytes()));
        }
        assert!(verify_bulletproofs_plus(&mut rng, &bp, &compressed_pts));

        eprintln!("BP+ aggregated (4 commitments): ok");
    }

    /// Bulletproofs+ empty commitments → Err
    #[test]
    fn bulletproof_plus_empty() {
        let mut rng = OsRng;
        let result = prove_bulletproofs_plus(&mut rng, vec![]);
        assert!(result.is_err());
    }

    /// Bulletproofs+ too many commitments → Err
    #[test]
    fn bulletproof_plus_too_many() {
        let mut rng = OsRng;
        let mut commitments = Vec::new();
        for i in 0u64..=MAX_COMMITMENTS as u64 {
            // MAX_COMMITMENTS+1 = 17, should fail
            let scalar_bytes = reduce_scalar(&[i as u8; 32]).unwrap();
            let mask = {
                let bytes = crate::curve_primitive::ed25519::scalar_to_bytes(&scalar_bytes);
                let mut cursor = crate::chain::xmr::transaction::Read32Cursor(bytes);
                Scalar::read(&mut cursor).expect("reduced scalar")
            };
            commitments.push(MoneroCommitment::new(mask, i));
        }
        let result = prove_bulletproofs_plus(&mut rng, commitments);
        assert!(result.is_err());
    }

    /// RctSigBase full round-trip
    #[test]
    fn rct_sig_base_round_trip() {
        let mut po = [[0u8; 32]; 1];
        let mut base = RctSigBase::new(rct_type::BULLETPROOFS_PLUS, 100, SliceVec::new(&mut po));
        base.pseudo_outs.push([0x42; 32]).unwrap();
        let bytes = base.serialize();
        assert_eq!(bytes[0], rct_type::BULLETPROOFS_PLUS);
        // then decode — simplified: verify the byte structure
        let mut pos = 1;
        let fee = crate::chain::xmr::transaction::monero_decode_varint(&bytes, &mut pos).unwrap();
        assert_eq!(fee, 100);
        let n = crate::chain::xmr::transaction::monero_decode_varint(&bytes, &mut pos).unwrap();
        assert_eq!(n, 1);
        let p: [u8; 32] = bytes[pos..pos + 32].try_into().unwrap();
        assert_eq!(p, [0x42; 32]);
        assert_eq!(pos + 32, bytes.len());
    }

    /// CLSAG round-trip (single input, BP+ 0 outputs, no RCT)
    /// — minimal demo: only verify clsag.sign and that the resulting ClsagProof can serialize
    #[test]
    fn clsag_minimal_demo() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use curve25519_dalek::Scalar as DScalar;
        let mut rng = OsRng;

        // 1. Build the ring (real + 1 decoy)
        let real_sk_arr = crate::curve_primitive::ed25519::scalar_to_bytes(
            &reduce_scalar(&[0x11u8; 32]).unwrap(),
        );

        let real_sk_dalek = DScalar::from_bytes_mod_order(real_sk_arr);
        let real_pub_point: curve25519_dalek::EdwardsPoint =
            ED25519_BASEPOINT_TABLE * &real_sk_dalek;
        let real_pub_bytes = real_pub_point.compress().to_bytes();
        let real_pub = CompressedPoint::from(real_pub_bytes);

        let decoy_sk_arr = crate::curve_primitive::ed25519::scalar_to_bytes(
            &reduce_scalar(&[0x22u8; 32]).unwrap(),
        );
        let decoy_sk_dalek = DScalar::from_bytes_mod_order(decoy_sk_arr);
        let decoy_pub_point: curve25519_dalek::EdwardsPoint =
            ED25519_BASEPOINT_TABLE * &decoy_sk_dalek;
        let decoy_pub_bytes = decoy_pub_point.compress().to_bytes();
        let decoy_pub = CompressedPoint::from(decoy_pub_bytes);

        let real_mask_bytes = reduce_scalar(&[0x33u8; 32]).unwrap();
        let real_mask = crate::chain::xmr::transaction::bytes_to_monerod_scalar(
            &crate::curve_primitive::ed25519::scalar_to_bytes(&real_mask_bytes),
        );
        let real_commit = MoneroCommitment::new(real_mask, 1000);

        let decoy_mask_bytes = reduce_scalar(&[0x44u8; 32]).unwrap();
        let decoy_mask = crate::chain::xmr::transaction::bytes_to_monerod_scalar(
            &crate::curve_primitive::ed25519::scalar_to_bytes(&decoy_mask_bytes),
        );
        let decoy_commit = MoneroCommitment::new(decoy_mask, 1000);

        let ring = vec![
            (real_pub, real_commit.commit().compress().to_bytes().into()),
            (
                decoy_pub,
                decoy_commit.commit().compress().to_bytes().into(),
            ),
        ];

        // 2. Build the pseudo_mask (different from real_mask)
        let pseudo_mask_bytes = reduce_scalar(&[0x55u8; 32]).unwrap();
        let pseudo_mask = crate::curve_primitive::ed25519::scalar_to_bytes(&pseudo_mask_bytes);
        let msg_hash: [u8; 32] = [0x99u8; 32];

        // 3. Call v8 clsag.sign
        let real_mask_arr = crate::curve_primitive::ed25519::scalar_to_bytes(&real_mask_bytes);
        let sign_result = clsag_mod::sign(
            &real_sk_arr,
            &ring,
            0, // real index
            &real_mask_arr,
            1000, // amount
            &pseudo_mask,
            &msg_hash,
            &mut rng,
        );

        let (clsag_proof, key_image, _pseudo_out) = sign_result.unwrap();

        // 4. Serialize ClsagProof bytes
        let clsag_bytes = clsag_proof.to_bytes().to_vec();
        assert!(clsag_bytes.len() >= 32 + 64);

        // 5. RctSigPrunable wrapper (no BP+, single-input CLSAG)
        let mut cm = [[0u8; 32]; 2];
        let mut ea = [[0u8; 8]; 2];
        let mut bp_slots: [Option<Bulletproof>; 2] = core::array::from_fn(|_| None);
        let mut cs = core::array::from_fn::<ClsagProof, 2, _>(|_| ClsagProof::default());
        let mut prunable = RctSigPrunable::new(
            SliceVec::new(&mut cm),
            SliceVec::new(&mut ea),
            SliceVec::new(&mut bp_slots),
            SliceVec::new(&mut cs),
        );
        prunable
            .commitments
            .push(real_commit.commit().compress().to_bytes())
            .unwrap();
        prunable.encrypted_amounts.push([0u8; 8]).unwrap();
        // no BP+ — CLSAG demo only
        prunable.clsag_sigs.push(clsag_proof).unwrap();
        let prunable_bytes = prunable.serialize().unwrap();
        assert!(prunable_bytes.len() > 32);

        eprintln!(
            "CLSAG demo: clsag_bytes={}, prunable={}, ki={}",
            clsag_bytes.len(),
            prunable_bytes.len(),
            hex_encode(&key_image.to_bytes())
        );
    }

    /// RctSig full serialization (Base + Prunable) — minimal
    #[test]
    fn rct_sig_serialize_minimal() {
        let mut po = [[0u8; 32]; 1];
        let mut base = RctSigBase::new(rct_type::BULLETPROOFS_PLUS, 100, SliceVec::new(&mut po));
        base.pseudo_outs.push([0x11; 32]).unwrap();
        let mut cm = [[0u8; 32]; 1];
        let mut ea = [[0u8; 8]; 1];
        let mut bp_slots: [Option<Bulletproof>; 1] = core::array::from_fn(|_| None);
        let mut cs = core::array::from_fn::<ClsagProof, 1, _>(|_| ClsagProof::default());
        let mut prunable = RctSigPrunable::new(
            SliceVec::new(&mut cm),
            SliceVec::new(&mut ea),
            SliceVec::new(&mut bp_slots),
            SliceVec::new(&mut cs),
        );
        prunable.commitments.push([0x22; 32]).unwrap();
        prunable.encrypted_amounts.push([0x33; 8]).unwrap();
        let sig = RctSig::new(base, prunable);
        let bytes = sig.serialize().unwrap();
        eprintln!("RctSig ({} bytes): {}", bytes.len(), hex_encode(&bytes));
    }

    /// Z2.4d: serialize_into must be byte-identical to the alloc convenience — with a
    /// REAL Bulletproof+ (exercises the LenCounter length-pass + SliceWriter adapters).
    #[test]
    fn serialize_into_matches_convenience_with_bp() {
        let mut po = [[0u8; 32]; 1];
        let mut base = RctSigBase::new(rct_type::BULLETPROOFS_PLUS, 100, SliceVec::new(&mut po));
        base.pseudo_outs.push([0x11; 32]).unwrap();

        let mut rng = OsRng;
        let scalar_bytes = reduce_scalar(&[0x33u8; 32]).unwrap();
        let mask = {
            let bytes = crate::curve_primitive::ed25519::scalar_to_bytes(&scalar_bytes);
            let mut cursor = crate::chain::xmr::transaction::Read32Cursor(bytes);
            Scalar::read(&mut cursor).expect("reduced scalar")
        };
        let bp = prove_bulletproofs_plus(
            &mut rng,
            alloc::vec![MoneroCommitment::new(mask, 100_000_000)],
        )
        .unwrap();

        let mut cm = [[0u8; 32]; 1];
        let mut ea = [[0u8; 8]; 1];
        let mut bp_slots: [Option<Bulletproof>; 1] = core::array::from_fn(|_| None);
        let mut cs = core::array::from_fn::<ClsagProof, 1, _>(|_| ClsagProof::default());
        let mut prunable = RctSigPrunable::new(
            SliceVec::new(&mut cm),
            SliceVec::new(&mut ea),
            SliceVec::new(&mut bp_slots),
            SliceVec::new(&mut cs),
        );
        prunable.commitments.push([0x22; 32]).unwrap();
        prunable.encrypted_amounts.push([0x33; 8]).unwrap();
        prunable.bulletproofs.push(Some(bp)).unwrap();

        let sig = RctSig::new(base, prunable);
        let mut buf = alloc::vec![0u8; 4096];
        let mut n = 0;
        sig.serialize_into(&mut buf, &mut n).unwrap();
        assert_eq!(
            &buf[..n],
            sig.serialize().unwrap().as_slice(),
            "RctSig with BP+"
        );
    }
}
