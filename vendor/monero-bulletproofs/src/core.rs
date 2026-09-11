use std_shims::{vec, vec::Vec};

use curve25519_dalek::{
    edwards::EdwardsPoint,
    scalar::Scalar,
    traits::{Identity as _, MultiscalarMul as _, VartimeMultiscalarMul as _},
};

pub(crate) use monero_bulletproofs_generators::{
    COMMITMENT_BITS, MAX_BULLETPROOF_COMMITMENTS as MAX_COMMITMENTS,
};

/// Constant-time multiexp, chunked so every Straus lookup table fits the
/// device's SRAM pool (shlosilo L3 allocator, 48K bypass threshold).
///
/// Each term's constant-time Straus table stores 8 `ProjectiveNielsPoint`
/// entries (8 x 160B = 1280B), and every constant-time select scans all 8
/// entries: 1280B of memory traffic per select+add step. On the ForgeBox
/// device (MH1903, QSPI PSRAM heap + SRAM pool) a PSRAM-resident table
/// costs ~30k cycles per step — measured: bp1 (257 terms, 16,448 steps)
/// 2.2s; and the K2-D A/B where the 34-term 43,520B table moved between
/// PSRAM and SRAM swung bp4 by ~409ms over 4,352 steps.
///
/// A table is sized by the (public) term count: `n` terms -> `n * 1280B`.
/// The prove path's tables are 166,400B (WIP round 1, 130 terms) and
/// 328,960B (initial commit, 257 terms) — far above the threshold, and no
/// size threshold can admit them while excluding the gencache generator
/// vectors (2 x 163,840B, permanent `LazyLock` allocations that must stay
/// in PSRAM: at a 192K threshold they entered the pool, starved the whole
/// BP+ working set and regressed xmr by +1.5s). Chunking caps every table
/// at 36 x 1280B = 46,080B instead, leaving the threshold untouched.
///
/// Correctness: the sum of chunk sums equals the unchunked multiexp
/// (point addition is associative/commutative); chunk boundaries depend
/// only on the public term count; each chunk keeps dalek's constant-time
/// select discipline. The only cost is re-running the per-chunk doubling
/// chain (64 iterations per chunk instead of once overall) — negligible
/// next to moving 16k+ select steps from PSRAM to SRAM.
const MULTIEXP_CHUNK_TERMS: usize = 36;

pub(crate) fn multiexp(pairs: &[(Scalar, EdwardsPoint)]) -> EdwardsPoint {
    if pairs.len() <= MULTIEXP_CHUNK_TERMS {
        return multiexp_terms(pairs);
    }
    let mut acc = EdwardsPoint::identity();
    let mut remaining = pairs;
    while !remaining.is_empty() {
        let take = remaining.len().min(MULTIEXP_CHUNK_TERMS);
        acc += multiexp_terms(&remaining[..take]);
        remaining = &remaining[take..];
    }
    acc
}

fn multiexp_terms(pairs: &[(Scalar, EdwardsPoint)]) -> EdwardsPoint {
    let mut buf_scalars = Vec::with_capacity(pairs.len());
    let mut buf_points = Vec::with_capacity(pairs.len());
    for (scalar, point) in pairs {
        buf_scalars.push(scalar);
        buf_points.push(point);
    }
    EdwardsPoint::multiscalar_mul(buf_scalars, buf_points)
}

pub(crate) fn multiexp_vartime(pairs: &[(Scalar, EdwardsPoint)]) -> EdwardsPoint {
    let mut buf_scalars = Vec::with_capacity(pairs.len());
    let mut buf_points = Vec::with_capacity(pairs.len());
    for (scalar, point) in pairs {
        buf_scalars.push(scalar);
        buf_points.push(point);
    }
    EdwardsPoint::vartime_multiscalar_mul(buf_scalars, buf_points)
}

/*
This has room for optimization worth investigating further. It currently takes
an iterative approach. It can be optimized further via divide and conquer.

Assume there are 4 challenges.

Iterative approach (current):
  1. Do the optimal multiplications across challenge column 0 and 1.
  2. Do the optimal multiplications across that result and column 2.
  3. Do the optimal multiplications across that result and column 3.

Divide and conquer (worth investigating further):
  1. Do the optimal multiplications across challenge column 0 and 1.
  2. Do the optimal multiplications across challenge column 2 and 3.
  3. Multiply both results together.

When there are 4 challenges (n=16), the iterative approach does 28 multiplications
versus divide and conquer's 24.
*/
pub(crate) fn challenge_products(challenges: &[(Scalar, Scalar)]) -> Vec<Scalar> {
    let mut products = vec![Scalar::ONE; 1 << challenges.len()];

    if !challenges.is_empty() {
        products[0] = challenges[0].1;
        products[1] = challenges[0].0;

        for (j, challenge) in challenges.iter().enumerate().skip(1) {
            let mut slots = (1 << (j + 1)) - 1;
            while slots > 0 {
                products[slots] = products[slots / 2] * challenge.0;
                products[slots - 1] = products[slots / 2] * challenge.1;

                slots = slots.saturating_sub(2);
            }
        }

        // Sanity check since if the above failed to populate, it'd be critical
        for product in &products {
            debug_assert!(*product != Scalar::ZERO);
        }
    }

    products
}
