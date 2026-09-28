use std_shims::{vec, vec::Vec};

// shlosilo vendor patch: prove-phase timing (device perf decomposition).
// No-op stubs keep call sites unconditional; real impl is feature-gated.
#[cfg(feature = "prove-timing")]
use crate::prove_timing_hook::{
    PhaseProbe, PHASE_A_HAT, PHASE_INITIAL_MULTISEXP, PHASE_TOTAL, PHASE_WIP_ROUNDS,
};
#[cfg(not(feature = "prove-timing"))]
mod timing_noop {
    pub(crate) struct PhaseProbe(pub(crate) u8, pub(crate) u32);
    impl PhaseProbe {
        pub(crate) fn start(_phase: u8) -> Self {
            PhaseProbe(0, 0)
        }
#[cfg(feature = "alloc-fallback")]
        pub(crate) fn end(self) {}
    }
    pub(crate) const PHASE_A_HAT: u8 = 0;
    pub(crate) const PHASE_INITIAL_MULTISEXP: u8 = 0;
    pub(crate) const PHASE_TOTAL: u8 = 0;
    pub(crate) const PHASE_WIP_ROUNDS: u8 = 0;
}
#[cfg(not(feature = "prove-timing"))]
use timing_noop::{
    PhaseProbe, PHASE_A_HAT, PHASE_INITIAL_MULTISEXP, PHASE_TOTAL, PHASE_WIP_ROUNDS,
};

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar, traits::Identity as _};

use monero_ed25519::{Commitment, CompressedPoint, Point};

use crate::{
    batch_verifier::BulletproofsPlusBatchVerifier,
    core::{multiexp, multiexp_vartime, COMMITMENT_BITS, MAX_COMMITMENTS},
    plus::{
        padded_pow_of_2,
        transcript::*,
        weighted_inner_product::{WipProof, WipStatement, WipWitness},
        BpPlusGenerators, GeneratorsList,
    },
};
#[cfg(feature = "alloc-fallback")]
#[cfg(feature = "alloc-fallback")]
use crate::plus::{u64_decompose, PointVector, ScalarVector};

const INV_EIGHT: monero_ed25519::Scalar = monero_ed25519::Scalar::INV_EIGHT;

// Figure 3 of the Bulletproofs+ Paper
#[derive(Clone, Debug)]
pub(crate) struct AggregateRangeStatement<'a> {
    generators: BpPlusGenerators,
    V: &'a [EdwardsPoint],
}

// shlosilo vendor patch (Z5.1, 2026-09-25): the witness BORROWS the caller's
// commitments (was: owned Vec). Memory-management only — the proof math is
// untouched. Wipe duty for the mask-bearing Commitment values moves to the
// caller: the API contract is "commitments live in a Zeroizing owner at the
// call site" (forms keeps one; the old Vec-witness ZeroizeOnDrop is retired).
#[derive(Clone)]
pub(crate) struct AggregateRangeWitness<'a>(&'a [Commitment]);

impl<'a> AggregateRangeWitness<'a> {
    pub(crate) fn new(commitments: &'a [Commitment]) -> Option<Self> {
        if commitments.is_empty() || (commitments.len() > MAX_COMMITMENTS) {
            return None;
        }

        Some(AggregateRangeWitness(commitments))
    }
}

/// Internal structure representing a Bulletproof+, as defined by Monero.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct AggregateRangeProof {
    pub(crate) A: CompressedPoint,
    pub(crate) wip: WipProof,
}

struct AHatComputation<'a> {
    y: Scalar,
    d_descending_y_plus_z: &'a [Scalar],
    y_mn_plus_one: Scalar,
    z: Scalar,
    z_pow: [Scalar; crate::MAX_COMMITMENTS + 1],
    A_hat: EdwardsPoint,
}

impl<'a> AggregateRangeStatement<'a> {
    pub(crate) fn new(V: &'a [EdwardsPoint]) -> Option<Self> {
        if V.is_empty() || (V.len() > MAX_COMMITMENTS) {
            return None;
        }

        Some(Self {
            generators: BpPlusGenerators::new().ok()?,
            V,
        })
    }

    fn transcript_A(transcript: &mut Scalar, A: CompressedPoint) -> (Scalar, Scalar) {
        // Z5.3 F-cut: fixed-size stack concat (byte-identical).
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&transcript.to_bytes());
        buf[32..].copy_from_slice(&A.to_bytes());
        let y = monero_ed25519::Scalar::hash(buf).into();
        let z = monero_ed25519::Scalar::hash(y.to_bytes()).into();
        *transcript = z;
        (y, z)
    }

#[cfg(feature = "alloc-fallback")]
    fn d_j(j: usize, m: usize) -> ScalarVector {
        let mut d_j = Vec::with_capacity(m * COMMITMENT_BITS);
        for _ in 0..(j - 1) * COMMITMENT_BITS {
            d_j.push(Scalar::ZERO);
        }
        d_j.append(&mut ScalarVector::powers(Scalar::from(2u8), COMMITMENT_BITS).0);
        for _ in 0..(m - j) * COMMITMENT_BITS {
            d_j.push(Scalar::ZERO);
        }
        ScalarVector(d_j)
    }

#[cfg(feature = "alloc-fallback")]
    fn compute_A_hat<'z>(
        V: &[EdwardsPoint],
        generators: &BpPlusGenerators,
        transcript: &mut Scalar,
        A: CompressedPoint,
        terms: &mut [(Scalar, EdwardsPoint)],
        straus: &mut curve25519_dalek::scratch::StrausScratch,
        p_d: &mut [Scalar],
        p_ay: &mut [Scalar],
        p_zp: &'z mut [Scalar],
    ) -> Option<AHatComputation<'z>> {
        let (y, z) = Self::transcript_A(transcript, A);

        let A = A
            .decompress()
            .map(Point::into)
            .as_ref()
            .map(EdwardsPoint::mul_by_cofactor)?;

        // (the caller pads V to a pow2 with identity tail — see the Z5.3
        // tail cut; this fn consumes the padded slice)
        let mn = V.len() * COMMITMENT_BITS;

        // shlosilo vendor patch (Z5.3 cut 6): the z/d/y construction runs
        // in place — the old per-j `d_j` + `powers` temporaries, the
        // `vec![y]` push-realloc traffic, and three `clone()`s are gone.
        // Same values, same order of operations per element (byte-pinned).
        if V.len() > MAX_COMMITMENTS {
            return None;
        }
        // 2, 4, 6, 8... powers of z (one past V.len(), as the old Vec kept)
        let mut z_pow = [Scalar::ZERO; MAX_COMMITMENTS + 1];
        // z**2
        z_pow[0] = z * z;
        for i in 1..=V.len() {
            z_pow[i] = z_pow[i - 1] * z_pow[0];
        }

        let d = &mut p_d[..mn];
        // Z6 link-surface audit fix: the C-cut E scratch move dropped the
        // zero-init the old `ScalarVector::new(mn)` provided — `+=` over a
        // REUSED WipScratch accumulated stale values from the previous prove
        // (every second-and-later sign produced an invalid proof). Zero the
        // region first; same values as the old zero-backed Vec, byte-identical
        // first-prove outputs, correct subsequent proves.
        for e in d.iter_mut() {
            *e = Scalar::ZERO;
        }
        for j in 1..=V.len() {
            // d += d_j(j) * z_pow[j-1]; d_j is zero outside its 2^k block
            let zj = z_pow[j - 1];
            let base = (j - 1) * COMMITMENT_BITS;
            let mut p = Scalar::ONE;
            for k in 0..COMMITMENT_BITS {
                d[base + k] += p * zj;
                p += p;
            }
        }

        let ascending_y = &mut p_ay[..mn];
        ascending_y[0] = y;
        for i in 1..d.len() {
            ascending_y[i] = ascending_y[i - 1] * y;
        }
        let y_pows: Scalar = ascending_y.iter().sum();
        // `d.sum()` is needed at the end — hoist it, then consume d below
        let d_sum: Scalar = d.iter().sum();

        // descending = ascending reversed in place (only descending survives);
        // the fused product lands in p_zp (z_pow is a stack array, done by
        // now) and outlives this fn via the returned borrow.
        ascending_y.reverse();
        let descending_y: &[Scalar] = ascending_y;
        let d_descending_y_plus_z: &mut [Scalar] = &mut p_zp[..mn];
        for i in 0..mn {
            d_descending_y_plus_z[i] = d[i] * descending_y[i] + z;
        }

        let y_mn_plus_one = descending_y[0] * y;

        let mut commitment_accum = EdwardsPoint::identity();
        for (j, commitment) in V.iter().enumerate() {
            commitment_accum += *commitment * z_pow[j];
        }

        let neg_z = -z;
        // Z5.3 pool cut: A_terms fills the caller scratch (explicit over-cap
        // error instead of a Vec; same order of terms).
        let a_terms_len = (d_descending_y_plus_z.len() * 2) + 2;
        if terms.len() < a_terms_len {
            return None;
        }
        let A_terms = &mut terms[..a_terms_len];
        let mut t = 0;
        for (i, d_y_z) in d_descending_y_plus_z.iter().enumerate() {
            A_terms[t] = (neg_z, generators.generator(GeneratorsList::GBold, i));
            t += 1;
            A_terms[t] = (*d_y_z, generators.generator(GeneratorsList::HBold, i));
            t += 1;
        }
        A_terms[t] = (y_mn_plus_one, commitment_accum);
        t += 1;
        A_terms[t] = (
            ((y_pows * z) - (d_sum * y_mn_plus_one * z) - (y_pows * (z * z))),
            BpPlusGenerators::g(),
        );

        Some(AHatComputation {
            y,
            d_descending_y_plus_z,
            y_mn_plus_one,
            z,
            z_pow,
            A_hat: {
                let hat = A + multiexp_vartime(A_terms, straus).ok()?;
                for e in A_terms.iter_mut() {
                    e.zeroize();
                }
                hat
            },
        })
    }

#[cfg(feature = "alloc-fallback")]
    pub(crate) fn prove<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        witness: &AggregateRangeWitness,
        terms: &mut [(Scalar, EdwardsPoint)],
        straus: &mut curve25519_dalek::scratch::StrausScratch,
        wip: &mut crate::plus::weighted_inner_product::WipScratch,
    ) -> Option<AggregateRangeProof> {
        // Z5.3 C-cut D: split the scratch into disjoint field borrows.
        let crate::plus::weighted_inner_product::WipScratch {
            a: rb_a,
            b: rb_b,
            g: rb_g,
            h: rb_h,
            p_d,
            p_ay,
            p_al,
            p_ar,
            p_zp,
            p_y,
        } = wip;
        // Check for consistency with the witness
        #[cfg(feature = "prove-timing")]
        let consistency = PhaseProbe::start(crate::prove_timing_hook::PHASE_WRAP_CONSISTENCY);
        if self.V.len() != witness.0.len() {
            return None;
        }
        for (commitment, witness) in self.V.iter().zip(witness.0.iter()) {
            if witness.commit().into() != *commitment {
                return None;
            }
        }
        #[cfg(feature = "prove-timing")]
        consistency.end();
        let _total = PhaseProbe::start(PHASE_TOTAL);

        let Self { generators, V } = self;
        // Monero expects all of these points to be torsion-free
        // Generally, for Bulletproofs, it sends points * INV_EIGHT and then performs a torsion clear
        // by multiplying by 8
        // This also restores the original value due to the preprocessing
        // Commitments aren't transmitted INV_EIGHT though, so this multiplies by INV_EIGHT to enable
        // clearing its cofactor without mutating the value
        // For some reason, these values are transcripted * INV_EIGHT, not as transmitted
        // Z5.3 tail cut: V staging is one fixed array — scaled by INV_EIGHT,
        // transcribed in that exact form (the wire convention), then folded by
        // the cofactor in place; the pow2 pad is the identity tail. Same
        // values, same transcript bytes (the pins hold).
        let mut v_stg = [EdwardsPoint::identity(); crate::MAX_COMMITMENTS];
        let mut v_len = V.len();
        for (dst, src) in v_stg.iter_mut().zip(V.iter()) {
            *dst = *src * INV_EIGHT.into();
        }
        let mut transcript = initial_transcript(v_stg[..v_len].iter());
        for i in 0..v_len {
            v_stg[i] = v_stg[i].mul_by_cofactor();
        }
        let padded_v = padded_pow_of_2(v_len);
        for i in v_len..padded_v {
            v_stg[i] = EdwardsPoint::identity();
        }
        v_len = padded_v;

        let generators = generators.reduce(v_len * COMMITMENT_BITS);

        // Z5.3 tail: `d_js` was built and never read (dead collection — the
        // per-j `d_j` temporaries died with it); the amount decomposition now
        // writes straight into `a_l` (missing commitments decompose to zero,
        // matching the old `unwrap_or(&0)` path bit for bit).
        let mn = V.len() * COMMITMENT_BITS;
        // Z5.3 C-cut D: a_l/a_r live in the caller staging regions; the
        // witness pow2 padding is the zero tail (same values as the old
        // WipWitness::new reserve+push padding).
        let padded = padded_pow_of_2(mn);
        if p_al.len() < padded || p_ar.len() < padded {
            return None;
        }
        let a_l = &mut p_al[..padded];
        for e in a_l.iter_mut() {
            *e = Scalar::ZERO;
        }
        for j in 1..=V.len() {
            let amount = *witness
                .0
                .get(j - 1)
                .map(|commitment| &commitment.amount)
                .unwrap_or(&0);
            let base = (j - 1) * COMMITMENT_BITS;
            for bit in 0..64 {
                if base + bit < mn {
                    a_l[base + bit] = Scalar::from((amount >> bit) & 1);
                }
            }
        }

        let a_r = &mut p_ar[..padded];
        for e in a_r.iter_mut() {
            *e = Scalar::ZERO;
        }
        for i in 0..mn {
            a_r[i] = a_l[i] - Scalar::ONE;
        }

        let alpha = monero_ed25519::Scalar::random(&mut *rng).into();

        // Z5.3 pool cut: A-terms fill the caller scratch (sequential with the
        // compute_A_hat use below).
        let a_terms_len = (mn * 2) + 1;
        if terms.len() < a_terms_len {
            return None;
        }
        let A_terms = &mut terms[..a_terms_len];
        let mut t = 0;
        for (i, a_l) in a_l.iter().enumerate() {
            A_terms[t] = (*a_l, generators.generator(GeneratorsList::GBold, i));
            t += 1;
        }
        for (i, a_r) in a_r.iter().enumerate() {
            A_terms[t] = (*a_r, generators.generator(GeneratorsList::HBold, i));
            t += 1;
        }
        A_terms[t] = (alpha, BpPlusGenerators::h());
        let _p1 = PhaseProbe::start(PHASE_INITIAL_MULTISEXP);
        let mut A = multiexp(A_terms, straus).ok()?;
        _p1.end();
        for e in A_terms.iter_mut() {
            e.zeroize();
        }

        // Multiply by INV_EIGHT per earlier commentary
        A *= INV_EIGHT.into();

        let A = CompressedPoint::from(A.compress().to_bytes());

        let _p2 = PhaseProbe::start(PHASE_A_HAT);
        let AHatComputation {
            y,
            d_descending_y_plus_z,
            y_mn_plus_one,
            z,
            z_pow,
            A_hat,
        } = Self::compute_A_hat(
            &v_stg[..v_len],
            &generators,
            &mut transcript,
            A,
            terms,
            straus,
            p_d,
            p_ay,
            &mut *p_zp,
        )
        .expect("A is a valid point as we just compressed it");
        _p2.end();

        for i in 0..mn {
            a_l[i] -= z;
            a_r[i] += d_descending_y_plus_z[i];
        }
        let mut alpha = alpha;
        for j in 1..=witness.0.len() {
            alpha += z_pow[j - 1] * witness.0[j - 1].mask.into() * y_mn_plus_one;
        }

        let proof = AggregateRangeProof {
            A,
            wip: {
                let _p3 = PhaseProbe::start(PHASE_WIP_ROUNDS);
                let wip = WipStatement::new(generators, A_hat, y)
                    .prove(
                        rng,
                        transcript,
                        &WipWitness::new(a_l, a_r, alpha)
                            .expect("Bulletproofs::Plus created an invalid WipWitness"),
                        terms,
                        straus,
                        &mut crate::plus::weighted_inner_product::RoundBufs {
                            a: rb_a,
                            b: rb_b,
                            g: rb_g,
                            h: rb_h,
                            p_y,
                            p_zp,
                        },
                    )
                    .expect("Bulletproof::Plus failed to prove the weighted inner-product");
                _p3.end();
                // Z5.3 C-cut D: the witness wipe duty moved here with the
                // borrowed staging (was ZeroizeOnDrop on the owned vectors).
                for e in p_al[..padded].iter_mut() {
                    *e = Scalar::ZERO;
                }
                for e in p_ar[..padded].iter_mut() {
                    *e = Scalar::ZERO;
                }
                wip
            },
        };
        _total.end();
        Some(proof)
    }

#[cfg(feature = "alloc-fallback")]
    pub(crate) fn verify<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        verifier: &mut BulletproofsPlusBatchVerifier,
        proof: AggregateRangeProof,
    ) -> bool {
        let Self { generators, V } = self;

        let V = V.iter().map(|V| V * INV_EIGHT.into()).collect::<Vec<_>>();
        let mut transcript = initial_transcript(V.iter());
        let V = V
            .iter()
            .map(EdwardsPoint::mul_by_cofactor)
            .collect::<Vec<_>>();

        let generators = generators.reduce(V.len() * COMMITMENT_BITS);

        // Z5.3 pool cut: verify self-provisions one staging Vec (the Z6
        // zero-alloc claim covers the sign path; verify staging is tracked).
        let mut verify_d = vec![Scalar::ZERO; 1024];
        let mut verify_ay = vec![Scalar::ZERO; 1024];
        let mut verify_zp = vec![Scalar::ZERO; 1024];
        let a_hat_res = {
            // Z5.3 D-cut: verify self-provisions both scratch buffers (the
            // Z6 zero-alloc claim covers the sign path; verify staging is
            // tracked). `terms.len()` is checked, so the buffer is sized.
            let mut verify_terms = vec![(Scalar::ZERO, EdwardsPoint::identity()); (2 * 1024) + 2];
            let mut verify_straus_storage =
                vec![0u8; curve25519_dalek::scratch::StrausScratch::storage_bytes((2 * 1024) + 2)];
            let Ok(mut verify_straus) = curve25519_dalek::scratch::StrausScratch::new(
                &mut verify_straus_storage,
                (2 * 1024) + 2,
            ) else {
                return false;
            };
            let mut verify_v_padded = V.clone();
            while verify_v_padded.len() < padded_pow_of_2(verify_v_padded.len()) {
                verify_v_padded.push(EdwardsPoint::identity());
            }
            Self::compute_A_hat(
                &verify_v_padded,
                &generators,
                &mut transcript,
                proof.A,
                &mut verify_terms,
                &mut verify_straus,
                &mut verify_d,
                &mut verify_ay,
                &mut verify_zp,
            )
        };
        let Some(AHatComputation { y, A_hat, .. }) = a_hat_res else {
            return false;
        };
        WipStatement::new(generators, A_hat, y).verify(rng, verifier, transcript, proof.wip)
    }
}
