use std_shims::{vec, vec::Vec};

// shlosilo vendor patch: prove-phase timing (WIP round decomposition: L/R multiexp
// vs generator folding). No-op stubs keep call sites unconditional; real impl is
// feature-gated (mirrors aggregate_range_proof.rs pattern).
#[cfg(feature = "prove-timing")]
use crate::prove_timing_hook::{
    PhaseProbe, PHASE_WIP_FOLD, PHASE_WIP_L_BASE, PHASE_WIP_L_R, PHASE_WIP_R_BASE,
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
    pub(crate) const PHASE_WIP_FOLD: u8 = 0;
    pub(crate) const PHASE_WIP_L_R: u8 = 0;
}
#[cfg(not(feature = "prove-timing"))]
use timing_noop::{PhaseProbe, PHASE_WIP_FOLD, PHASE_WIP_L_R};

use rand_core::{CryptoRng, RngCore};

/// shlosilo vendor patch (Z5.3 C-cut): borrow-form weighted inner product —
/// the consuming form clones its operands; this computes the identical
/// `sum(a*b*y)` over borrows (field arithmetic is exact, outputs bit-equal).

/// shlosilo vendor patch (Z5.3 final sweep): Montgomery batch inversion with
/// a caller-sized STACK scratch (the sign path's inverse-power stack is <= 10
/// entries) — dalek's `Scalar::batch_invert` stages its scratch in a Vec,
/// which the constrained path cannot afford. Same field inversions, same
/// outputs (inversion is unique); the scratch is zeroized (secret-class
/// products). Zero inputs panic in `invert`, matching dalek's contract.
fn batch_invert_stack(inputs: &mut [Scalar]) {
    let n = inputs.len();
    debug_assert!(n <= 32);
    let mut scratch = [Scalar::ONE; 32];
    let mut acc = Scalar::ONE;
    for (s, x) in scratch[..n].iter_mut().zip(inputs.iter()) {
        *s = acc;
        acc *= *x;
    }
    let mut inv = acc.invert();
    for (s, x) in scratch[..n].iter_mut().zip(inputs.iter_mut()).rev() {
        let tmp = *x;
        *x = inv * *s;
        inv *= tmp;
    }
    for s in scratch[..n].iter_mut() {
        s.zeroize();
    }
}

fn wip_ref(a: &[Scalar], b: &[Scalar], y: &[Scalar]) -> Scalar {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), y.len());
    let mut acc = Scalar::ZERO;
    for ((x, z), w) in a.iter().zip(b.iter()).zip(y.iter()) {
        acc += (*x * *z) * *w;
    }
    acc
}

/// shlosilo vendor patch (Z5.3 C-cut B): caller-owned WIP round scratch —
/// four ping-pong buffer pairs (a, b scalars; g, h points) over one byte
/// region. The rounds shrink the vectors in place (split_at + write into the
/// paired buffer), so the whole inner-product proof runs without allocating.
/// Secret-class data (a/b/alpha-derived) lives here; the caller wipes the
/// region per its policy (the prove chain zeroes `a`/`b` tails below).
pub struct WipScratch<'a> {
    pub(crate) a: &'a mut [Scalar],
    pub(crate) b: &'a mut [Scalar],
    pub(crate) g: &'a mut [EdwardsPoint],
    pub(crate) h: &'a mut [EdwardsPoint],
    // Z5.3 C-cut D: proof-staging scalar regions (disjoint fields, so the
    // caller can borrow them independently): d, ascending_y, a_l, a_r, z_pow.
    pub(crate) p_d: &'a mut [Scalar],
    pub(crate) p_ay: &'a mut [Scalar],
    pub(crate) p_al: &'a mut [Scalar],
    pub(crate) p_ar: &'a mut [Scalar],
    pub(crate) p_zp: &'a mut [Scalar],
    pub(crate) p_y: &'a mut [Scalar],
}

/// Z5.3 C-cut D: the prove-side parts of a WipScratch, split out so the
/// caller can borrow the staging regions (p_al/p_ar/...) independently.
pub struct RoundBufs<'a> {
    pub a: &'a mut [Scalar],
    pub b: &'a mut [Scalar],
    pub g: &'a mut [EdwardsPoint],
    pub h: &'a mut [EdwardsPoint],
    pub p_y: &'a mut [Scalar],
    pub p_zp: &'a mut [Scalar],
}

impl<'a> WipScratch<'a> {
    /// Sizing source of truth: two buffers of `terms_cap` for each of the
    /// four vectors (scalars 32 B, points 160 B worst case).
    pub const fn storage_bytes(terms_cap: usize) -> usize {
        // four round buffers (two each of scalars/points) + five staging
        // scalar regions
        terms_cap * 2 * (32 + 32 + 160 + 160) + terms_cap * 6 * 32
    }

    /// Build over caller storage (8-aligned; exact regions — `None` on
    /// too-small or misaligned, loud and explicit per G1). Regions are laid
    /// out a, b, g, h — each `2 * terms_cap`.
    pub fn new(storage: &'a mut [u8], terms_cap: usize) -> Option<Self> {
        if storage.len() < Self::storage_bytes(terms_cap) {
            return None;
        }
        if (storage.as_ptr() as usize) % 8 != 0 {
            return None;
        }
        fn cast_slice<T>(bytes: &mut [u8]) -> &mut [T] {
            // SAFETY: the caller guarantees 8-alignment of the base and every
            // region size is a whole number of elements (32/160 are multiples
            // of 8); the round code writes before reading each element.
            unsafe {
                core::slice::from_raw_parts_mut(
                    bytes.as_mut_ptr() as *mut T,
                    bytes.len() / core::mem::size_of::<T>(),
                )
            }
        }
        let (a_bytes, rest) = storage.split_at_mut(terms_cap * 2 * 32);
        let (b_bytes, rest) = rest.split_at_mut(terms_cap * 2 * 32);
        let (g_bytes, rest) = rest.split_at_mut(terms_cap * 2 * 160);
        let (h_bytes, rest) = rest.split_at_mut(terms_cap * 2 * 160);
        let (d_bytes, rest) = rest.split_at_mut(terms_cap * 32);
        let (ay_bytes, rest) = rest.split_at_mut(terms_cap * 32);
        let (al_bytes, rest) = rest.split_at_mut(terms_cap * 32);
        let (ar_bytes, rest) = rest.split_at_mut(terms_cap * 32);
        let (zp_bytes, rest) = rest.split_at_mut(terms_cap * 32);
        let (y_bytes, _slack) = rest.split_at_mut(terms_cap * 32);
        Some(WipScratch {
            a: cast_slice(a_bytes),
            b: cast_slice(b_bytes),
            g: cast_slice(g_bytes),
            h: cast_slice(h_bytes),
            p_d: cast_slice(d_bytes),
            p_ay: cast_slice(ay_bytes),
            p_al: cast_slice(al_bytes),
            p_ar: cast_slice(ar_bytes),
            p_zp: cast_slice(zp_bytes),
            p_y: cast_slice(y_bytes),
        })
    }
}
use zeroize::{Zeroize, ZeroizeOnDrop};

use curve25519_dalek::{EdwardsPoint, Scalar};

use crate::{
    batch_verifier::BulletproofsPlusBatchVerifier,
    core::{challenge_products, multiexp, multiexp_vartime, multiexp_vartime_small},
    plus::{padded_pow_of_2, BpPlusGenerators, GeneratorsList, PointVector, ScalarVector},
};
use monero_ed25519::CompressedPoint;

const INV_EIGHT: monero_ed25519::Scalar = monero_ed25519::Scalar::INV_EIGHT;

// Figure 1 of the Bulletproofs+ paper
#[derive(Clone, Debug)]
pub(crate) struct WipStatement {
    generators: BpPlusGenerators,
    P: EdwardsPoint,
    y: Scalar,
}

impl Zeroize for WipStatement {
    fn zeroize(&mut self) {
        self.P.zeroize();
        self.y.zeroize();
    }
}

// Z5.3 C-cut D: the witness borrows the caller's staging regions — the
// wipe duty moves to the region owner (the caller zeroes the regions after
// the prove call; see aggregate_range_proof::prove).
#[derive(Clone)]
pub(crate) struct WipWitness<'a> {
    a: &'a [Scalar],
    b: &'a [Scalar],
    alpha: Scalar,
}

impl<'a> WipWitness<'a> {
    pub(crate) fn new(a: &'a [Scalar], b: &'a [Scalar], alpha: Scalar) -> Option<Self> {
        if a.is_empty() || (a.len() != b.len()) {
            return None;
        }
        // Z5.3 C-cut D: the caller stages a/b in its scratch ALREADY padded
        // to a power of two (zero tail), so no reserve+push growth here.
        if a.len() != padded_pow_of_2(a.len()) {
            return None;
        }
        Some(Self { a, b, alpha })
    }
}

/// shlosilo vendor patch (Z5.3 C-cut C): the proof L/R rounds live in fixed
/// arrays (the round count is log2 of the padded generator count <= 1024, so
/// 10 is the format-correct bound — same L/R ORDER, byte-identical wire).
pub(crate) const WIP_MAX_ROUNDS: usize = 10;

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub(crate) struct WipProof {
    pub(crate) L: [CompressedPoint; WIP_MAX_ROUNDS],
    pub(crate) L_len: usize,
    pub(crate) R: [CompressedPoint; WIP_MAX_ROUNDS],
    pub(crate) R_len: usize,
    pub(crate) A: CompressedPoint,
    pub(crate) B: CompressedPoint,
    pub(crate) r_answer: Scalar,
    pub(crate) s_answer: Scalar,
    pub(crate) delta_answer: Scalar,
}

impl WipStatement {
    pub(crate) fn new(generators: BpPlusGenerators, P: EdwardsPoint, y: Scalar) -> Self {
        debug_assert_eq!(generators.len(), padded_pow_of_2(generators.len()));

        // Z5.3 C-cut D: the challenge-power vector is NOT built here — the
        // prover materialises it into its scratch (`p_y`), the verifier into
        // a local Vec (verify-side staging is tracked, not pool-bound).
        Self { generators, P, y }
    }

    fn transcript_L_R(transcript: &mut Scalar, L: CompressedPoint, R: CompressedPoint) -> Scalar {
        // Z5.3 F-cut: fixed-size stack concat (byte-identical input to the
        // same hash fn; the Vec concat allocated on every round).
        let mut buf = [0u8; 96];
        buf[..32].copy_from_slice(&transcript.to_bytes());
        buf[32..64].copy_from_slice(&L.to_bytes());
        buf[64..].copy_from_slice(&R.to_bytes());
        let e = monero_ed25519::Scalar::hash(buf).into();
        *transcript = e;
        e
    }

    fn transcript_A_B(transcript: &mut Scalar, A: CompressedPoint, B: CompressedPoint) -> Scalar {
        let mut buf = [0u8; 96];
        buf[..32].copy_from_slice(&transcript.to_bytes());
        buf[32..64].copy_from_slice(&A.to_bytes());
        buf[64..].copy_from_slice(&B.to_bytes());
        let e = monero_ed25519::Scalar::hash(buf).into();
        *transcript = e;
        e
    }

    // Prover's variant of the shared code block to calculate G/H/P when n > 1
    // Returns each permutation of G/H since the prover needs to do operation on each permutation
    // P is dropped as it's unused in the prover's path
    #[allow(clippy::too_many_arguments)]
    // Prover's variant of the shared code block to calculate G/H/P when n > 1
    // Returns each permutation of G/H since the prover needs to do operation on each permutation
    // P is dropped as it's unused in the prover's path
    #[allow(clippy::too_many_arguments)]
    fn next_G_H(
        transcript: &mut Scalar,
        mut g_bold1: PointVector,
        mut g_bold2: PointVector,
        mut h_bold1: PointVector,
        mut h_bold2: PointVector,
        L: CompressedPoint,
        R: CompressedPoint,
        y_inv_n_hat: Scalar,
        straus: &mut curve25519_dalek::scratch::StrausScratch,
    ) -> (Scalar, Scalar, Scalar, Scalar, PointVector, PointVector) {
        debug_assert_eq!(g_bold1.len(), g_bold2.len());
        debug_assert_eq!(h_bold1.len(), h_bold2.len());
        debug_assert_eq!(g_bold1.len(), h_bold1.len());

        let e = Self::transcript_L_R(transcript, L, R);
        let inv_e = e.invert();
        let _fold_probe = PhaseProbe::start(PHASE_WIP_FOLD);

        // This vartime is safe as all of these arguments are public
        let mut new_g_bold = Vec::with_capacity(g_bold1.len());
        let e_y_inv = e * y_inv_n_hat;
        for g_bold in g_bold1.0.drain(..).zip(g_bold2.0.drain(..)) {
            new_g_bold.push(multiexp_vartime_small(&[
                (inv_e, g_bold.0),
                (e_y_inv, g_bold.1),
            ]));
        }

        let mut new_h_bold = Vec::with_capacity(h_bold1.len());
        for h_bold in h_bold1.0.drain(..).zip(h_bold2.0.drain(..)) {
            new_h_bold.push(multiexp_vartime_small(&[(e, h_bold.0), (inv_e, h_bold.1)]));
        }

        let e_square = e * e;
        let inv_e_square = inv_e * inv_e;

        _fold_probe.end();
        (
            e,
            inv_e,
            e_square,
            inv_e_square,
            PointVector(new_g_bold),
            PointVector(new_h_bold),
        )
    }

    pub(crate) fn prove<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        mut transcript: Scalar,
        witness: &WipWitness,
        terms: &mut [(Scalar, EdwardsPoint)],
        straus: &mut curve25519_dalek::scratch::StrausScratch,
        round: &mut RoundBufs,
    ) -> Option<WipProof> {
        let WipStatement {
            generators,
            P,
            mut y,
        } = self;
        #[cfg(not(debug_assertions))]
        let _ = P;

        if generators.len() != witness.a.len() {
            return None;
        }
        let (g, h) = (BpPlusGenerators::g(), BpPlusGenerators::h());
        // Z5.3 C-cut D: generators, challenge powers and the inverse stack
        // all land in the caller's WipScratch — no Vec staging on the sign
        // path. (The challenge-power semantics match the old constructor:
        // p_y[0] = y, p_y[i] = p_y[i-1] * y.)
        let n_gen = generators.len();
        let p_y: &mut [Scalar] = &mut round.p_y[..n_gen];
        p_y[0] = y;
        for i in 1..n_gen {
            p_y[i] = p_y[i - 1] * y;
        }
        let mut y_len = n_gen;

        // Check P has the expected relationship
        #[cfg(debug_assertions)]
        // Z5.3 pool cut: this block exists only for the debug assertion —
        // gating it removes its staging Vec from release builds (identical
        // release behavior).
        #[cfg(debug_assertions)]
        {
            let mut P_terms = witness
                .a
                .iter()
                .copied()
                .zip((0..generators.len()).map(|i| generators.generator(GeneratorsList::GBold, i)))
                .chain(witness.b.iter().copied().zip(
                    (0..generators.len()).map(|i| generators.generator(GeneratorsList::HBold, i)),
                ))
                .collect::<Vec<_>>();
            P_terms.push((wip_ref(witness.a, witness.b, p_y), g));
            P_terms.push((witness.alpha, h));
            debug_assert_eq!(crate::core::multiexp_alloc(&P_terms), P);
            P_terms.zeroize();
        }

        // Z5.3 C-cut B: the round state lives in the caller's WipScratch as
        // four ping-pong buffer pairs. The math is unchanged — same element
        // expressions, same order of operations per element (field ops are
        // exact; the wire pins hold).
        let mut alpha = witness.alpha;
        let n = witness.a.len();
        if n == 0 || !n.is_power_of_two() || (n / 2) * 2 != n {
            return None;
        }
        if round.a.len() < n {
            return None; // explicit over-cap (G1)
        }
        let (a0, a1) = round.a.split_at_mut(n);
        let (b0, b1) = round.b.split_at_mut(n);
        let (g0, g1) = round.g.split_at_mut(n);
        let (h0, h1) = round.h.split_at_mut(n);
        let mut cur_len = n; // logical round length (the ping-pong tails are
                             // capacity leftovers, not round data)
        a0[..n].copy_from_slice(witness.a);
        b0[..n].copy_from_slice(witness.b);
        for i in 0..n {
            g0[i] = generators.generator(GeneratorsList::GBold, i);
            h0[i] = generators.generator(GeneratorsList::HBold, i);
        }

        let mut a_cur: &mut [Scalar] = a0;
        let mut a_next: &mut [Scalar] = a1;
        let mut b_cur: &mut [Scalar] = b0;
        let mut b_next: &mut [Scalar] = b1;
        let mut g_cur: &mut [EdwardsPoint] = g0;
        let mut g_next: &mut [EdwardsPoint] = g1;
        let mut h_cur: &mut [EdwardsPoint] = h0;
        let mut h_next: &mut [EdwardsPoint] = h1;

        // inverse-power stack (same order: y[0], y[1], y[3], ... popped from
        // the end each round) lives in the p_zp staging region (free by now).
        let mut y_inv_len = 0usize;
        {
            let mut i = 1;
            while i < n {
                round.p_zp[y_inv_len] = p_y[i - 1];
                y_inv_len += 1;
                i *= 2;
            }
            batch_invert_stack(&mut round.p_zp[..y_inv_len]);
        }

        let mut L_vec = [CompressedPoint::from([0u8; 32]); WIP_MAX_ROUNDS];
        let mut L_len = 0usize;
        let mut R_vec = [CompressedPoint::from([0u8; 32]); WIP_MAX_ROUNDS];
        let mut R_len = 0usize;

        // bp5 drill-down (shlosilo, prove-timing): round counter for the
        // per-round L/R multiexp probes.
        #[cfg(feature = "prove-timing")]
        let mut wip_round: u8 = 0;

        while cur_len > 1 {
            #[cfg(feature = "prove-timing")]
            {
                wip_round += 1;
            }
            let n_hat = cur_len / 2;
            let (g1s, g2s) = g_cur[..cur_len].split_at(n_hat);
            let (h1s, h2s) = h_cur[..cur_len].split_at(n_hat);
            let (a1s, a2s) = a_cur[..cur_len].split_at(n_hat);
            let (b1s, b2s) = b_cur[..cur_len].split_at(n_hat);

            let y_n_hat = p_y[n_hat - 1];
            y_len = n_hat;

            let d_l = monero_ed25519::Scalar::random(&mut *rng).into();
            let d_r = monero_ed25519::Scalar::random(&mut *rng).into();

            let c_l = wip_ref(a1s, b2s, &p_y[..y_len]);
            let c_r = y_n_hat * wip_ref(a2s, b1s, &p_y[..y_len]);

            y_inv_len -= 1;
            let y_inv_n_hat = round.p_zp[y_inv_len];

            // L terms fill the caller scratch (see the Z5.3 pool cut notes)
            let l_len = (n_hat * 2) + 2;
            if terms.len() < l_len {
                return None;
            }
            let L_terms = &mut terms[..l_len];
            let mut t = 0;
            for (i, g2) in g2s.iter().enumerate() {
                L_terms[t] = (a1s[i] * y_inv_n_hat, *g2);
                t += 1;
            }
            for (i, h1) in h1s.iter().enumerate() {
                L_terms[t] = (b2s[i], *h1);
                t += 1;
            }
            L_terms[t] = (c_l, g);
            L_terms[t + 1] = (d_l, h);
            let lr_probe = PhaseProbe::start(PHASE_WIP_L_R);
            #[cfg(feature = "prove-timing")]
            let round_l = PhaseProbe::start(PHASE_WIP_L_BASE + wip_round);
            let L = CompressedPoint::from(
                (multiexp(L_terms, straus).ok()? * INV_EIGHT.into())
                    .compress()
                    .to_bytes(),
            );
            #[cfg(feature = "prove-timing")]
            round_l.end();
            L_vec[L_len] = L;
            L_len += 1;
            for e in L_terms.iter_mut() {
                e.zeroize();
            }

            let r_len = (n_hat * 2) + 2;
            if terms.len() < r_len {
                return None;
            }
            let R_terms = &mut terms[..r_len];
            let mut t = 0;
            for (i, g1) in g1s.iter().enumerate() {
                R_terms[t] = (a2s[i] * y_n_hat, *g1);
                t += 1;
            }
            for (i, h2) in h2s.iter().enumerate() {
                R_terms[t] = (b1s[i], *h2);
                t += 1;
            }
            R_terms[t] = (c_r, g);
            R_terms[t + 1] = (d_r, h);
            #[cfg(feature = "prove-timing")]
            let round_r = PhaseProbe::start(PHASE_WIP_R_BASE + wip_round);
            let R = CompressedPoint::from(
                (multiexp(R_terms, straus).ok()? * INV_EIGHT.into())
                    .compress()
                    .to_bytes(),
            );
            #[cfg(feature = "prove-timing")]
            round_r.end();
            R_vec[R_len] = R;
            R_len += 1;
            for e in R_terms.iter_mut() {
                e.zeroize();
            }
            lr_probe.end();

            let e = Self::transcript_L_R(&mut transcript, L, R);
            let inv_e = e.invert();
            let e_square = e * e;
            let inv_e_square = inv_e * inv_e;

            let _fold_probe = PhaseProbe::start(PHASE_WIP_FOLD);
            // fold (public arguments — vartime, per the original commentary)
            let e_y_inv = e * y_inv_n_hat;
            for i in 0..n_hat {
                g_next[i] = multiexp_vartime_small(&[(inv_e, g1s[i]), (e_y_inv, g2s[i])]);
                h_next[i] = multiexp_vartime_small(&[(e, h1s[i]), (inv_e, h2s[i])]);
                a_next[i] = (a1s[i] * e) + (a2s[i] * (y_n_hat * inv_e));
                b_next[i] = (b1s[i] * inv_e) + (b2s[i] * e);
            }
            _fold_probe.end();

            alpha += (d_l * e_square) + (d_r * inv_e_square);

            core::mem::swap(&mut a_cur, &mut a_next);
            core::mem::swap(&mut b_cur, &mut b_next);
            core::mem::swap(&mut g_cur, &mut g_next);
            core::mem::swap(&mut h_cur, &mut h_next);
            cur_len = n_hat;
        }

        // n == 1 case from figure 1
        debug_assert_eq!(cur_len, 1);
        // (cur_len covers all four buffers)

        let r = monero_ed25519::Scalar::random(&mut *rng).into();
        let s = monero_ed25519::Scalar::random(&mut *rng).into();
        let delta = monero_ed25519::Scalar::random(&mut *rng).into();
        let eta = monero_ed25519::Scalar::random(&mut *rng).into();

        let ry = r * y;

        // Z5.3 tail cut: A/B terms fill the caller scratch (same order,
        // same zeroize duty — the Vec staging allocated twice per proof).
        if terms.len() < 6 {
            return None;
        }
        let A_terms = &mut terms[..4];
        A_terms[0] = (r, g_cur[0]);
        A_terms[1] = (s, h_cur[0]);
        A_terms[2] = ((ry * b_cur[0]) + (s * y * a_cur[0]), g);
        A_terms[3] = (delta, h);
        let A = CompressedPoint::from(
            (multiexp(A_terms, straus).ok()? * INV_EIGHT.into())
                .compress()
                .to_bytes(),
        );
        for e in A_terms.iter_mut() {
            e.zeroize();
        }

        let B_terms = &mut terms[..2];
        B_terms[0] = (ry * s, g);
        B_terms[1] = (eta, h);
        let B = CompressedPoint::from(
            (multiexp(B_terms, straus).ok()? * INV_EIGHT.into())
                .compress()
                .to_bytes(),
        );
        for e in B_terms.iter_mut() {
            e.zeroize();
        }

        let e = Self::transcript_A_B(&mut transcript, A, B);

        let r_answer = r + (a_cur[0] * e);
        let s_answer = s + (b_cur[0] * e);
        let delta_answer = eta + (delta * e) + (alpha * (e * e));

        Some(WipProof {
            L: L_vec,
            L_len,
            R: R_vec,
            R_len,
            A,
            B,
            r_answer,
            s_answer,
            delta_answer,
        })
    }

#[cfg(feature = "alloc-fallback")]
    pub(crate) fn verify<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        verifier: &mut BulletproofsPlusBatchVerifier,
        mut transcript: Scalar,
        WipProof {
            L,
            L_len,
            R,
            R_len,
            A,
            B,
            r_answer,
            s_answer,
            delta_answer,
        }: WipProof,
    ) -> bool {
        let L = &L[..L_len];
        let R = &R[..R_len];
        let verifier_weight = monero_ed25519::Scalar::random(rng).into();

        let WipStatement { generators, P, y } = self;
        // verify-side staging (tracked, not pool-bound): materialise the
        // challenge-power vector from the statement's scalar.
        let y = {
            let mut v = Vec::with_capacity(generators.len());
            v.push(y);
            for i in 1..generators.len() {
                let p = v[i - 1] * y;
                v.push(p);
            }
            ScalarVector(v)
        };

        // Verify the L/R lengths
        {
            let mut lr_len = 0;
            while (1 << lr_len) < generators.len() {
                lr_len += 1;
            }
            if (L.len() != lr_len) || (R.len() != lr_len) || (generators.len() != (1 << lr_len)) {
                return false;
            }
        }

        let inv_y = {
            let inv_y = y[0].invert();
            let mut res = Vec::with_capacity(y.len());
            res.push(inv_y);
            while res.len() < y.len() {
                res.push(
                    inv_y
                        * res
                            .last()
                            .expect("couldn't get last inv_y despite inv_y always being non-empty"),
                );
            }
            res
        };

        let mut e_is = Vec::with_capacity(L.len());
        let mut L_decomp = Vec::with_capacity(L.len());
        let mut R_decomp = Vec::with_capacity(R.len());

        let decomp_mul_cofactor =
            |p| CompressedPoint::decompress(&p).map(|p| EdwardsPoint::mul_by_cofactor(&p.into()));

        for (L_i, R_i) in L.iter().copied().zip(R.iter().copied()) {
            e_is.push(Self::transcript_L_R(&mut transcript, L_i, R_i));

            let (Some(L_i), Some(R_i)) = (decomp_mul_cofactor(L_i), decomp_mul_cofactor(R_i))
            else {
                return false;
            };

            L_decomp.push(L_i);
            R_decomp.push(R_i);
        }

        let L = L_decomp;
        let R = R_decomp;

        let e = Self::transcript_A_B(&mut transcript, A, B);

        let (Some(A), Some(B)) = (decomp_mul_cofactor(A), decomp_mul_cofactor(B)) else {
            return false;
        };

        let neg_e_square = verifier_weight * -(e * e);

        verifier.0.other.push((neg_e_square, P));

        let mut challenges = Vec::with_capacity(L.len());
        let product_cache = {
            let mut inv_e_is = e_is.clone();
            Scalar::batch_invert(&mut inv_e_is);

            debug_assert_eq!(e_is.len(), inv_e_is.len());
            debug_assert_eq!(e_is.len(), L.len());
            debug_assert_eq!(e_is.len(), R.len());
            for ((e_i, inv_e_i), (L, R)) in e_is
                .drain(..)
                .zip(inv_e_is.drain(..))
                .zip(L.iter().zip(R.iter()))
            {
                debug_assert_eq!(e_i.invert(), inv_e_i);

                challenges.push((e_i, inv_e_i));

                let e_i_square = e_i * e_i;
                let inv_e_i_square = inv_e_i * inv_e_i;
                verifier.0.other.push((neg_e_square * e_i_square, *L));
                verifier.0.other.push((neg_e_square * inv_e_i_square, *R));
            }

            challenge_products(&challenges)
        };

        while verifier.0.g_bold.len() < generators.len() {
            verifier.0.g_bold.push(Scalar::ZERO);
        }
        while verifier.0.h_bold.len() < generators.len() {
            verifier.0.h_bold.push(Scalar::ZERO);
        }

        let re = r_answer * e;
        for i in 0..generators.len() {
            let mut scalar = product_cache[i] * re;
            if i > 0 {
                scalar *= inv_y[i - 1];
            }
            verifier.0.g_bold[i] += verifier_weight * scalar;
        }

        let se = s_answer * e;
        for i in 0..generators.len() {
            verifier.0.h_bold[i] +=
                verifier_weight * (se * product_cache[product_cache.len() - 1 - i]);
        }

        verifier.0.other.push((verifier_weight * -e, A));
        verifier.0.g += verifier_weight * (r_answer * y[0] * s_answer);
        verifier.0.h += verifier_weight * delta_answer;
        verifier.0.other.push((-verifier_weight, B));

        true
    }
}
