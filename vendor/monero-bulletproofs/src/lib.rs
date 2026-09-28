#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

#[cfg(feature = "alloc-fallback")]
use std_shims::{
    io::{self, Read, Write},
    prelude::*,
    sync::LazyLock,
};

use rand_core::{CryptoRng, RngCore};

use curve25519_dalek::traits::Identity as _;

// Z6 link-surface: `io::Error::other` boxes its payload. With alloc-fallback
// disabled (zero-heap builds) a ZST payload keeps the error KIND (Other) and
// the explicit-Err contract without a heap round-trip; messages stay in alloc
// builds.
#[cfg(feature = "alloc-fallback")]
pub(crate) fn ser_err(msg: &'static str) -> io::Error {
    io::Error::other(msg)
}

#[cfg(not(feature = "alloc-fallback"))]
#[cfg(feature = "alloc-fallback")]
pub(crate) fn ser_err(_msg: &'static str) -> io::Error {
    #[derive(Debug)]
    struct SerErr;
    io::Error::other(SerErr)
}

use curve25519_dalek::EdwardsPoint;

// shlosilo vendor patch: per-platform BP+ multiexp chunk tuning (core.rs).
// `crate::core` (not `core::`) — the crate has a module of that name, so the
// bare path would be ambiguous at the root scope.
#[cfg(feature = "prove-timing")]
pub use crate::core::bench_multiexp_chain;
pub use crate::core::{multiexp_chunk_terms, set_multiexp_chunk_terms};

use monero_bulletproofs_generators::COMMITMENT_BITS;
pub use monero_bulletproofs_generators::MAX_BULLETPROOF_COMMITMENTS as MAX_COMMITMENTS;
use monero_ed25519::*;
use monero_io::*;

pub(crate) mod point_vector;
pub(crate) mod scalar_vector;

pub(crate) mod generator_cache_hook;
pub use generator_cache_hook::{
    generator_table_sizes, provide_generator_table_storage, register_generator_cache_hooks,
    GeneratorSet, GeneratorTableStorage,
};

#[cfg(feature = "prove-timing")]
#[path = "prove_timing_hook.rs"]
pub(crate) mod prove_timing_hook;
#[cfg(feature = "prove-timing")]
pub use prove_timing_hook::{phase_ms, register_prove_timing_clock, reset as reset_prove_timing};

pub(crate) mod core;

#[cfg(feature = "alloc-fallback")]
pub(crate) mod batch_verifier;
#[cfg(feature = "alloc-fallback")]
pub use batch_verifier::BatchVerifier;
#[cfg(feature = "alloc-fallback")]
use batch_verifier::{BulletproofsBatchVerifier, BulletproofsPlusBatchVerifier};

#[cfg(feature = "alloc-fallback")]
pub(crate) mod original;
// Z6 link-surface: the legacy Original line is alloc-fallback material —
// its IpProof Vec fields put dealloc sites in the enum's shared drop glue.
#[cfg(feature = "alloc-fallback")]
use crate::original::{
    AggregateRangeProof as OriginalProof, AggregateRangeStatement as OriginalStatement,
    AggregateRangeWitness as OriginalWitness, IpProof,
};

pub mod plus;
pub use crate::plus::WipScratch;
use crate::plus::{
    AggregateRangeProof as PlusProof, AggregateRangeStatement as PlusStatement,
    AggregateRangeWitness as PlusWitness, WipProof,
};

#[cfg(test)]
mod tests;

// The logarithm (over 2) of the amount of bits a value within a commitment may use.
#[allow(clippy::as_conversions)]
const LOG_COMMITMENT_BITS: usize = COMMITMENT_BITS.ilog2() as usize;
// The maximum length of L/R `Vec`s.
#[allow(clippy::as_conversions)]
const MAX_LR: usize = (MAX_COMMITMENTS.ilog2() as usize) + LOG_COMMITMENT_BITS;

// A static for `H` as it's frequently used yet this decompression is expensive.
static MONERO_H: LazyLock<EdwardsPoint> = LazyLock::new(|| {
    CompressedPoint::H
        .decompress()
        .expect("couldn't decompress `CompressedPoint::H`")
        .into()
});

/// An error from proving/verifying Bulletproofs(+).
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum BulletproofError {
    /// Proving/verifying a Bulletproof(+) range proof with no commitments.
    #[error("no commitments to prove the range for")]
    NoCommitments,
    /// Proving/verifying a Bulletproof(+) range proof with more commitments than supported.
    #[error("too many commitments to prove the range for")]
    TooManyCommitments,
}

/// A Bulletproof(+).
///
/// This encapsulates either a Bulletproof or a Bulletproof+.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Bulletproof {
    #[cfg(feature = "alloc-fallback")]
    /// A Bulletproof.
    Original(OriginalProof),
    /// A Bulletproof+.
    Plus(PlusProof),
}

impl Bulletproof {
    fn bp_fields(plus: bool) -> usize {
        if plus {
            6
        } else {
            9
        }
    }

    /// Calculate the weight penalty for the Bulletproof(+).
    ///
    /// Bulletproofs(+) are logarithmically sized yet linearly timed. Evaluating by their size alone
    /// accordingly doesn't properly represent the burden of the proof. Monero 'claws back' some of
    /// the weight lost by using a proof smaller than it is fast to compensate for this.
    ///
    /// If the amount of outputs specified exceeds the maximum amount of outputs, the result for the
    /// maximum amount of outputs will be returned.
    // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
    //   src/cryptonote_basic/cryptonote_format_utils.cpp#L106-L124
    pub fn calculate_clawback(plus: bool, n_outputs: usize) -> (usize, usize) {
        #[allow(non_snake_case)]
        let mut LR_len = 0;
        let mut n_padded_outputs = 1;
        while n_padded_outputs < n_outputs.min(MAX_COMMITMENTS) {
            LR_len += 1;
            n_padded_outputs = 1 << LR_len;
        }
        LR_len += LOG_COMMITMENT_BITS;

        let mut clawback = 0;
        if n_padded_outputs > 2 {
            let fields = Bulletproof::bp_fields(plus);
            let base = ((fields + (2 * (LOG_COMMITMENT_BITS + 1))) * 32) / 2;
            let size = (fields + (2 * LR_len)) * 32;
            clawback = ((base * n_padded_outputs) - size) * 4 / 5;
        }

        (clawback, LR_len)
    }

    #[cfg(feature = "alloc-fallback")]
    /// Prove the list of commitments are within [0 .. 2^64) with an aggregate Bulletproof.
    ///
    /// This function runs in time variable to the validity of the arguments and the public data.
    // shlosilo vendor patch (Z5.1): slice API — callers keep ownership of the
    // commitment storage (wipe duty included). Memory-management only.
    pub fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        outputs: &[Commitment],
    ) -> Result<Bulletproof, BulletproofError> {
        if outputs.is_empty() {
            Err(BulletproofError::NoCommitments)?;
        }
        if outputs.len() > MAX_COMMITMENTS {
            Err(BulletproofError::TooManyCommitments)?;
        }
        let commitments = outputs
            .iter()
            .map(|commitment| commitment.commit().into())
            .collect::<Vec<_>>();
        Ok(Bulletproof::Original(
      OriginalStatement::new(&commitments)
        .expect("failed to create statement despite checking amount of commitments")
        .prove(
          rng,
          OriginalWitness::new(outputs)
            .expect("failed to create witness despite checking amount of commitments"),
        )
        .expect(
          "failed to prove Bulletproof::Original despite ensuring statement/witness consistency",
        ),
    ))
    }

    /// Prove the list of commitments are within [0 .. 2^64) with an aggregate Bulletproof+.
    ///
    /// This function runs in time variable to the validity of the arguments and the public data.
    // shlosilo vendor patch (Z5.1): slice API — callers keep ownership of the
    // commitment storage (wipe duty included). Memory-management only.
    /// shlosilo vendor patch (Z5.3 pool cut): `terms` is the caller-owned
    /// multiexp scratch (`>= 2 * padded_pow_of_2(outputs.len() * 64) + 2`
    /// entries; over-cap is an explicit `BulletproofError`). The prove chain
    /// writes its per-site term lists here instead of heap Vecs.
    pub fn prove_plus<R: RngCore + CryptoRng>(
        rng: &mut R,
        outputs: &[Commitment],
        terms: &mut [(curve25519_dalek::Scalar, curve25519_dalek::EdwardsPoint)],
        straus: &mut curve25519_dalek::scratch::StrausScratch,
        wip: &mut plus::weighted_inner_product::WipScratch,
    ) -> Result<Bulletproof, BulletproofError> {
        if outputs.is_empty() {
            Err(BulletproofError::NoCommitments)?;
        }
        if outputs.len() > MAX_COMMITMENTS {
            Err(BulletproofError::TooManyCommitments)?;
        }
        // shlosilo vendor patch: wrapper sub-phase probes (device perf).
        #[cfg(feature = "prove-timing")]
        let wrap_commits =
            prove_timing_hook::PhaseProbe::start(prove_timing_hook::PHASE_WRAP_COMMITS);
        // shlosilo vendor patch (Z5.3 final sweep): fixed-capacity commitment
        // staging (MAX_COMMITMENTS) — the Vec collect allocated per proof.
        let mut commitments = [curve25519_dalek::EdwardsPoint::identity(); MAX_COMMITMENTS];
        let mut commitments_len = 0usize;
        for (dst, commitment) in commitments.iter_mut().zip(outputs.iter()) {
            *dst = commitment.commit().into();
            commitments_len += 1;
        }
        let commitments = &commitments[..commitments_len];
        #[cfg(feature = "prove-timing")]
        wrap_commits.end();
        #[cfg(feature = "prove-timing")]
        let wrap_statement =
            prove_timing_hook::PhaseProbe::start(prove_timing_hook::PHASE_WRAP_STATEMENT);
        let statement_res = PlusStatement::new(&commitments);
        let witness_res = PlusWitness::new(outputs);
        #[cfg(feature = "prove-timing")]
        wrap_statement.end();
        Ok(Bulletproof::Plus(
      statement_res
        .expect("failed to create statement despite checking amount of commitments")
        .prove(
          rng,
          // shlosilo vendor patch (Z5.1): the witness borrows the caller's
          // commitments — the Zeroizing wrapper (wipe-on-drop of the old owned
          // Vec) is retired; wipe duty lives at the call site (forms owner).
          &witness_res
            .expect("failed to create witness despite checking amount of commitments"),
          terms,
          straus,
          wip,
        )
        .expect("failed to prove Bulletproof::Plus despite ensuring statement/witness consistency"),
    ))
    }

    /// Verify the given Bulletproof(+).
    #[must_use]
#[cfg(feature = "alloc-fallback")]
    pub fn verify<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        commitments: &[CompressedPoint],
    ) -> bool {
        let Some(commitments) = commitments
            .iter()
            .map(|point| point.decompress().map(Point::into))
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };

        match self {
            #[cfg(feature = "alloc-fallback")]
            Bulletproof::Original(bp) => {
                let mut verifier = BulletproofsBatchVerifier::default();
                let Some(statement) = OriginalStatement::new(&commitments) else {
                    return false;
                };
                if !statement.verify(rng, &mut verifier, bp.clone()) {
                    return false;
                }
                verifier.verify()
            }
            Bulletproof::Plus(bp) => {
                let mut verifier = BulletproofsPlusBatchVerifier::default();
                let Some(statement) = PlusStatement::new(&commitments) else {
                    return false;
                };
                if !statement.verify(rng, &mut verifier, bp.clone()) {
                    return false;
                }
                verifier.verify()
            }
        }
    }

    /// Accumulate the verification for the given Bulletproof(+) into the specified BatchVerifier.
    ///
    /// Returns false if the Bulletproof(+) isn't sane, leaving the BatchVerifier in an undefined
    /// state.
    ///
    /// Returns true if the Bulletproof(+) is sane, regardless of its validity.
    ///
    /// The BatchVerifier must have its verification function executed to actually verify this proof.
    #[must_use]
#[cfg(feature = "alloc-fallback")]
    pub fn batch_verify<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        verifier: &mut BatchVerifier,
        commitments: &[CompressedPoint],
    ) -> bool {
        let Some(commitments) = commitments
            .iter()
            .map(|point| point.decompress().map(Point::into))
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };

        match self {
            #[cfg(feature = "alloc-fallback")]
            Bulletproof::Original(bp) => {
                let Some(statement) = OriginalStatement::new(&commitments) else {
                    return false;
                };
                statement.verify(rng, &mut verifier.original, bp.clone())
            }
            Bulletproof::Plus(bp) => {
                let Some(statement) = PlusStatement::new(&commitments) else {
                    return false;
                };
                statement.verify(rng, &mut verifier.plus, bp.clone())
            }
        }
    }

    // This uses `write_all(scalar.to_bytes())` as these are `curve25519_dalek::Scalar`, not
    // `monero_ed25519::Scalar`
#[cfg(feature = "alloc-fallback")]
    fn write_core<W: Write, F: Fn(&[CompressedPoint], &mut W) -> io::Result<()>>(
        &self,
        w: &mut W,
        specific_write_vec: F,
    ) -> io::Result<()> {
        match self {
            #[cfg(feature = "alloc-fallback")]
            Bulletproof::Original(bp) => {
                bp.A.write(w)?;
                bp.S.write(w)?;
                bp.T1.write(w)?;
                bp.T2.write(w)?;
                w.write_all(&bp.tau_x.to_bytes())?;
                w.write_all(&bp.mu.to_bytes())?;
                specific_write_vec(&bp.ip.L, w)?;
                specific_write_vec(&bp.ip.R, w)?;
                w.write_all(&bp.ip.a.to_bytes())?;
                w.write_all(&bp.ip.b.to_bytes())?;
                w.write_all(&bp.t_hat.to_bytes())
            }

            Bulletproof::Plus(bp) => {
                bp.A.write(w)?;
                bp.wip.A.write(w)?;
                bp.wip.B.write(w)?;
                w.write_all(&bp.wip.r_answer.to_bytes())?;
                w.write_all(&bp.wip.s_answer.to_bytes())?;
                w.write_all(&bp.wip.delta_answer.to_bytes())?;
                specific_write_vec(&bp.wip.L[..bp.wip.L_len], w)?;
                specific_write_vec(&bp.wip.R[..bp.wip.R_len], w)
            }
        }
    }

    /// Write a Bulletproof(+) for the message signed by a transaction's signature.
    ///
    /// This has a distinct encoding from the standard encoding.
#[cfg(feature = "alloc-fallback")]
    pub fn signature_write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.write_core(w, |points, w| {
            write_raw_vec(CompressedPoint::write, points, w)
        })
    }

    /// Write a Bulletproof(+).
#[cfg(feature = "alloc-fallback")]
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.write_core(w, |points, w| write_vec(CompressedPoint::write, points, w))
    }

    // ── shlosilo vendor patch (T-06, 2026-09-26): caller-buffer serialization.
    // Same bytes as `write`; `serialized_len` is the single length source of
    // truth (previously measured by a forms-side counting adapter). Wipe of
    // secrets is not at issue here (proofs are public wire data).

    /// Serialized length in bytes (identical output to `write`).
    pub fn serialized_len(&self) -> usize {
        struct Counter(usize);
#[cfg(feature = "alloc-fallback")]
        impl Write for Counter {
#[cfg(feature = "alloc-fallback")]
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0 += buf.len();
                Ok(buf.len())
            }
        }
        let mut c = Counter(0);
        self.write(&mut c)
            .expect("write into a counter cannot fail");
        c.0
    }

    /// Serialize into a caller-provided buffer, returning the length written.
    /// Over-capacity is an EXPLICIT `io::Error` (never truncates).
#[cfg(feature = "alloc-fallback")]
    pub fn serialize_into(&self, out: &mut [u8]) -> io::Result<usize> {
        struct SliceWriter<'a> {
            buf: &'a mut [u8],
            pos: usize,
        }
        impl<'a> Write for SliceWriter<'a> {
#[cfg(feature = "alloc-fallback")]
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                let end = self
                    .pos
                    .checked_add(data.len())
                    .ok_or_else(|| crate::ser_err("overflow"))?;
                if end > self.buf.len() {
                    return Err(crate::ser_err("proof serialize buffer too small"));
                }
                self.buf[self.pos..end].copy_from_slice(data);
                self.pos = end;
                Ok(data.len())
            }
            // Z6 link-surface: override the default `write_all` (its
            // short-write error path boxes the error payload). `write` is
            // all-or-error by construction, so this is byte-equivalent.
#[cfg(feature = "alloc-fallback")]
            fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
                self.write(data).map(|_| ())
            }
        }
        let mut w = SliceWriter { buf: out, pos: 0 };
        self.write(&mut w)?;
        Ok(w.pos)
    }

    /// shlosilo vendor patch (Z5.3 tail): the `signature_write` form into a
    /// caller buffer (same bytes; explicit overflow error).
#[cfg(feature = "alloc-fallback")]
    pub fn signature_serialize_into(&self, out: &mut [u8]) -> io::Result<usize> {
        struct SliceWriter<'a> {
            buf: &'a mut [u8],
            pos: usize,
        }
        impl<'a> Write for SliceWriter<'a> {
#[cfg(feature = "alloc-fallback")]
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                let end = self
                    .pos
                    .checked_add(data.len())
                    .ok_or_else(|| crate::ser_err("overflow"))?;
                if end > self.buf.len() {
                    return Err(crate::ser_err("signature serialize buffer too small"));
                }
                self.buf[self.pos..end].copy_from_slice(data);
                self.pos = end;
                Ok(data.len())
            }
            // Z6 link-surface: override the default `write_all` (its
            // short-write error path boxes the error payload). `write` is
            // all-or-error by construction, so this is byte-equivalent.
            fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
                self.write(data).map(|_| ())
            }
        }
        let mut w = SliceWriter { buf: out, pos: 0 };
        self.signature_write(&mut w)?;
        Ok(w.pos)
    }

    /// Serialize a Bulletproof(+) to a `Vec<u8>`.
#[cfg(feature = "alloc-fallback")]
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::with_capacity(512);
        self.write(&mut serialized)
            .expect("write failed but <Vec as io::Write> doesn't fail");
        serialized
    }

    #[cfg(feature = "alloc-fallback")]
    /// Read a Bulletproof.
    #[cfg(feature = "alloc")]
    #[cfg(feature = "alloc")]
pub fn read<R: Read>(r: &mut R) -> io::Result<Bulletproof> {
        Ok(Bulletproof::Original(OriginalProof {
            A: CompressedPoint::read(r)?,
            S: CompressedPoint::read(r)?,
            T1: CompressedPoint::read(r)?,
            T2: CompressedPoint::read(r)?,
            tau_x: Scalar::read(r)?.into(),
            mu: Scalar::read(r)?.into(),
            ip: IpProof {
                L: read_vec(CompressedPoint::read, Some(MAX_LR), r)?,
                R: read_vec(CompressedPoint::read, Some(MAX_LR), r)?,
                a: Scalar::read(r)?.into(),
                b: Scalar::read(r)?.into(),
            },
            t_hat: Scalar::read(r)?.into(),
        }))
    }

    /// Read a Bulletproof+.
    #[cfg(feature = "alloc")]
    #[cfg(feature = "alloc")]
pub fn read_plus<R: Read>(r: &mut R) -> io::Result<Bulletproof> {
        // shlosilo vendor patch (Z5.3 C-cut C): the wire reader stages into a
        // Vec (verify-side only) then copies into the proof's fixed arrays —
        // the wire ORDER and bytes are unchanged.
        let l_v = read_vec(CompressedPoint::read, Some(MAX_LR), r)?;
        let r_v = read_vec(CompressedPoint::read, Some(MAX_LR), r)?;
        let mut L =
            [CompressedPoint::from([0u8; 32]); plus::weighted_inner_product::WIP_MAX_ROUNDS];
        let mut R =
            [CompressedPoint::from([0u8; 32]); plus::weighted_inner_product::WIP_MAX_ROUNDS];
        // read_vec caps at MAX_LR == WIP_MAX_ROUNDS, so this never trips.
        debug_assert!(l_v.len() <= L.len() && r_v.len() <= R.len());
        for (dst, src) in L.iter_mut().zip(l_v.iter()) {
            *dst = *src;
        }
        for (dst, src) in R.iter_mut().zip(r_v.iter()) {
            *dst = *src;
        }
        Ok(Bulletproof::Plus(PlusProof {
            A: CompressedPoint::read(r)?,
            wip: WipProof {
                A: CompressedPoint::read(r)?,
                B: CompressedPoint::read(r)?,
                r_answer: Scalar::read(r)?.into(),
                s_answer: Scalar::read(r)?.into(),
                delta_answer: Scalar::read(r)?.into(),
                L,
                L_len: l_v.len(),
                R,
                R_len: r_v.len(),
            },
        }))
    }
}
