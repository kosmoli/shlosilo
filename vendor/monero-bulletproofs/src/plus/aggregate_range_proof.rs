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
        u64_decompose,
        weighted_inner_product::{WipProof, WipStatement, WipWitness},
        BpPlusGenerators, GeneratorsList, PointVector, ScalarVector,
    },
};

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

struct AHatComputation {
    y: Scalar,
    d_descending_y_plus_z: ScalarVector,
    y_mn_plus_one: Scalar,
    z: Scalar,
    z_pow: ScalarVector,
    A_hat: EdwardsPoint,
}

impl<'a> AggregateRangeStatement<'a> {
    pub(crate) fn new(V: &'a [EdwardsPoint]) -> Option<Self> {
        if V.is_empty() || (V.len() > MAX_COMMITMENTS) {
            return None;
        }

        Some(Self {
            generators: BpPlusGenerators::new(),
            V,
        })
    }

    fn transcript_A(transcript: &mut Scalar, A: CompressedPoint) -> (Scalar, Scalar) {
        let y = monero_ed25519::Scalar::hash([transcript.to_bytes(), A.to_bytes()].concat()).into();
        let z = monero_ed25519::Scalar::hash(y.to_bytes()).into();
        *transcript = z;
        (y, z)
    }

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

    fn compute_A_hat(
        mut V: PointVector,
        generators: &BpPlusGenerators,
        transcript: &mut Scalar,
        A: CompressedPoint,
    ) -> Option<AHatComputation> {
        let (y, z) = Self::transcript_A(transcript, A);

        let A = A
            .decompress()
            .map(Point::into)
            .as_ref()
            .map(EdwardsPoint::mul_by_cofactor)?;

        while V.len() < padded_pow_of_2(V.len()) {
            V.0.push(EdwardsPoint::identity());
        }
        let mn = V.len() * COMMITMENT_BITS;

        // 2, 4, 6, 8... powers of z, of length equivalent to the amount of commitments
        let mut z_pow = Vec::with_capacity(V.len());
        // z**2
        z_pow.push(z * z);

        let mut d = ScalarVector::new(mn);
        for j in 1..=V.len() {
            z_pow.push(
                *z_pow
                    .last()
                    .expect("couldn't get last z_pow despite always being non-empty")
                    * z_pow[0],
            );
            d = d + &(Self::d_j(j, V.len()) * (z_pow[j - 1]));
        }

        let mut ascending_y = ScalarVector(vec![y]);
        for i in 1..d.len() {
            ascending_y.0.push(ascending_y[i - 1] * y);
        }
        let y_pows = ascending_y.clone().sum();

        let mut descending_y = ascending_y.clone();
        descending_y.0.reverse();

        let d_descending_y = d.clone() * &descending_y;
        let d_descending_y_plus_z = d_descending_y + z;

        let y_mn_plus_one = descending_y[0] * y;

        let mut commitment_accum = EdwardsPoint::identity();
        for (j, commitment) in V.0.iter().enumerate() {
            commitment_accum += *commitment * z_pow[j];
        }

        let neg_z = -z;
        let mut A_terms = Vec::with_capacity((generators.len() * 2) + 2);
        for (i, d_y_z) in d_descending_y_plus_z.0.iter().enumerate() {
            A_terms.push((neg_z, generators.generator(GeneratorsList::GBold, i)));
            A_terms.push((*d_y_z, generators.generator(GeneratorsList::HBold, i)));
        }
        A_terms.push((y_mn_plus_one, commitment_accum));
        A_terms.push((
            ((y_pows * z) - (d.sum() * y_mn_plus_one * z) - (y_pows * (z * z))),
            BpPlusGenerators::g(),
        ));

        Some(AHatComputation {
            y,
            d_descending_y_plus_z,
            y_mn_plus_one,
            z,
            z_pow: ScalarVector(z_pow),
            A_hat: A + multiexp_vartime(&A_terms),
        })
    }

    pub(crate) fn prove<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        witness: &AggregateRangeWitness,
    ) -> Option<AggregateRangeProof> {
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
        let V = V.iter().map(|V| V * INV_EIGHT.into()).collect::<Vec<_>>();
        let mut transcript = initial_transcript(V.iter());
        let mut V = V
            .iter()
            .map(EdwardsPoint::mul_by_cofactor)
            .collect::<Vec<_>>();

        // Pad V
        while V.len() < padded_pow_of_2(V.len()) {
            V.push(EdwardsPoint::identity());
        }

        let generators = generators.reduce(V.len() * COMMITMENT_BITS);

        let mut d_js = Vec::with_capacity(V.len());
        let mut a_l = ScalarVector(Vec::with_capacity(V.len() * COMMITMENT_BITS));
        for j in 1..=V.len() {
            d_js.push(Self::d_j(j, V.len()));
            #[allow(clippy::map_unwrap_or)]
            a_l.0.append(
                &mut u64_decompose(
                    *witness
                        .0
                        .get(j - 1)
                        .map(|commitment| &commitment.amount)
                        .unwrap_or(&0),
                )
                .0,
            );
        }

        let a_r = a_l.clone() - Scalar::ONE;

        let alpha = monero_ed25519::Scalar::random(&mut *rng).into();

        let mut A_terms = Vec::with_capacity((generators.len() * 2) + 1);
        for (i, a_l) in a_l.0.iter().enumerate() {
            A_terms.push((*a_l, generators.generator(GeneratorsList::GBold, i)));
        }
        for (i, a_r) in a_r.0.iter().enumerate() {
            A_terms.push((*a_r, generators.generator(GeneratorsList::HBold, i)));
        }
        A_terms.push((alpha, BpPlusGenerators::h()));
        let _p1 = PhaseProbe::start(PHASE_INITIAL_MULTISEXP);
        let mut A = multiexp(&A_terms);
        _p1.end();
        A_terms.zeroize();

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
        } = Self::compute_A_hat(PointVector(V), &generators, &mut transcript, A)
            .expect("A is a valid point as we just compressed it");
        _p2.end();

        let a_l = a_l - z;
        let a_r = a_r + &d_descending_y_plus_z;
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
                        &Zeroizing::new(
                            WipWitness::new(a_l, a_r, alpha)
                                .expect("Bulletproofs::Plus created an invalid WipWitness"),
                        ),
                    )
                    .expect("Bulletproof::Plus failed to prove the weighted inner-product");
                _p3.end();
                wip
            },
        };
        _total.end();
        Some(proof)
    }

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

        let Some(AHatComputation { y, A_hat, .. }) =
            Self::compute_A_hat(PointVector(V), &generators, &mut transcript, proof.A)
        else {
            return false;
        };
        WipStatement::new(generators, A_hat, y).verify(rng, verifier, transcript, proof.wip)
    }
}
