use core::sync::atomic::{AtomicUsize, Ordering};

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
/// host's fast memory. The chunk size is a PER-PLATFORM tuning knob
/// (runtime, default 36):
///
/// Each term's constant-time Straus table stores 8 `ProjectiveNielsPoint`
/// entries (8 x 160B = 1280B), and every constant-time select scans all 8
/// entries: 1280B of memory traffic per select+add step. A table is sized
/// by the (public) term count: `n` terms -> `n * 1280B`. A host picks the
/// largest chunk whose table still lands in its fastest memory:
///
/// - ForgeBox (MH1903): SRAM pool with a 48K bypass threshold -> 36 terms
///   = 46,080B fits. Measured: a PSRAM-resident table costs ~30k cycles
///   per step; the K2-D A/B where the 34-term 43,520B table moved between
///   PSRAM and SRAM swung bp4 by ~409ms over 4,352 steps; chunking (A2)
///   cut 3.26s off the full sign.
/// - pico2 (RP2350): SRAM heap with a 16 KiB PSRAM routing threshold ->
///   12 terms = 15,360B fits. Measured 2026-09-14 (per chunk, one CT
///   Straus multiexp): SRAM tables = ~11.7ms + n x 4.0ms; PSRAM tables =
///   ~7.6ms + n x 9.34ms — ~2x per-term at every size (the 16/32-term
///   points sit right above the threshold and jump to the PSRAM curve).
///
/// No size threshold can admit the unchunked tables (166,400B / 328,960B)
/// while excluding the gencache generator vectors (2 x 163,840B, permanent
/// `LazyLock` allocations that must stay in PSRAM: at a 192K threshold
/// they entered the pool, starved the whole BP+ working set and regressed
/// xmr by +1.5s on forgebox).
///
/// Correctness: the sum of chunk sums equals the unchunked multiexp
/// (point addition is associative/commutative); chunk boundaries depend
/// only on the public term count; each chunk keeps dalek's constant-time
/// select discipline. The only cost is re-running the per-chunk doubling
/// chain (64 iterations per chunk instead of once overall) — measured at
/// ~12ms/chunk on pico2, small against the per-term table traffic.
static MULTIEXP_CHUNK_TERMS: AtomicUsize = AtomicUsize::new(36);

/// Set the per-platform chunk size (terms per CT Straus table). The host
/// calls this once at boot with the largest chunk whose table
/// (`n * 1280B`) fits its fastest memory. Values of 0 are clamped to 1.
pub fn set_multiexp_chunk_terms(n: usize) {
    MULTIEXP_CHUNK_TERMS.store(n.max(1), Ordering::Relaxed);
}

/// Current chunk size in terms (default 36).
#[must_use]
pub fn multiexp_chunk_terms() -> usize {
    MULTIEXP_CHUNK_TERMS.load(Ordering::Relaxed)
}

pub(crate) fn multiexp(pairs: &[(Scalar, EdwardsPoint)]) -> EdwardsPoint {
    let chunk = multiexp_chunk_terms();
    if pairs.len() <= chunk {
        return multiexp_terms(pairs);
    }
    let mut acc = EdwardsPoint::identity();
    let mut remaining = pairs;
    while !remaining.is_empty() {
        let take = remaining.len().min(chunk);
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

/// shlosilo bench (feature `prove-timing`): replicate the WIP L/R call
/// chain in a clean bench, so the in-situ per-round probe times can be
/// attributed. Mirrors exactly what `weighted_inner_product` does: build a
/// `Vec<(Scalar, EdwardsPoint)>` (the L_terms shape), run the chunked
/// `multiexp` wrapper (this crate's monomorphization), then optionally the
/// `* INV_EIGHT` + `compress` tail that the WIP probes include.
///
/// `gen_points` selects the data source: generator-table points (PSRAM
/// heap, the in-situ source) vs the basepoint constant (the ctm bench).
#[cfg(feature = "prove-timing")]
pub fn bench_multiexp_chain(n: usize, iters: u32, tail: bool, gen_points: bool) -> u64 {
    use crate::plus::{BpPlusGenerators, GeneratorsList};

    let gens = BpPlusGenerators::new();
    let mut out = [0u8; 32];
    for it in 0..iters.max(1) {
        let pairs: Vec<(Scalar, EdwardsPoint)> = (0..n)
            .map(|i| {
                let s = bench_scalar(i + (it as usize) * 9973);
                let p = if gen_points {
                    // The sign's reduced view: the first 128 generators.
                    gens.generator(GeneratorsList::GBold, i % 128)
                } else {
                    curve25519_dalek::constants::ED25519_BASEPOINT_POINT
                };
                (s, p)
            })
            .collect();
        let point = multiexp(&pairs);
        let point = if tail {
            point * monero_ed25519::Scalar::INV_EIGHT.into()
        } else {
            point
        };
        out = point.compress().to_bytes();
    }
    u64::from(out[0])
}

/// Deterministic full-width scalar (the in-situ magnitude class).
#[cfg(feature = "prove-timing")]
fn bench_scalar(seed: usize) -> Scalar {
    let mut b = [0u8; 32];
    let mut k = (seed as u8).wrapping_mul(31).wrapping_add(7);
    for x in b.iter_mut() {
        k = k.wrapping_mul(97).wrapping_add(53);
        *x = k;
    }
    Scalar::from_bytes_mod_order(b)
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
