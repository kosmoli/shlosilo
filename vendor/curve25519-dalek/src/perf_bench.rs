// -*- mode: rust; -*-
//
// This file is part of curve25519-dalek (shlosilo vendor patch).
//
// Device perf-bench entry points (feature `perf-bench`).
//
// shlosilo perf session: measures raw primitive costs on the target device so
// the remaining optimization space is quantified from hardware numbers instead
// of fitted models. The C caller (helloworld smoke task) times each call with
// its own millisecond tick; every function returns a digest and `black_box`
// forces the benchmarked values to be materialized, so nothing is eliminated.
//
// Feature-gated: zero code when off (production .a does not enable it).

#![allow(clippy::needless_range_loop)]

use core::hint::black_box;
use core::iter::repeat;

use crate::constants::ED25519_BASEPOINT_POINT;
use crate::edwards::EdwardsPoint;
use crate::field::FieldElement;
use crate::scalar::Scalar;
use crate::traits::{Identity, MultiscalarMul as _, VartimeMultiscalarMul as _};
use crate::window::LookupTable;

use crate::backend::serial::curve_models::ProjectiveNielsPoint;

/// Affine-niels table variant of `select`: 3 field elements per entry
/// (96 bytes) instead of 5 (160 bytes), so the constant-time scan and the
/// conditional selects shrink by 40%. Candidate for the CT Straus hot loop;
/// costs one batch inversion to build the table (not timed here).
pub fn select_affine(iters: u32) -> u64 {
    let table = LookupTable::<crate::backend::serial::curve_models::AffineNielsPoint>::from(
        &ED25519_BASEPOINT_POINT,
    );
    let mut acc: u64 = 0;
    for i in 0..iters {
        let d = ((i % 15) as i8) - 7;
        let t = table.select(black_box(d));
        black_box(t);
        acc = acc.wrapping_add(1);
    }
    black_box(acc)
}

/// Affine variant of `madd`: select + mixed add + convert.
pub fn madd_affine(iters: u32) -> u64 {
    let table = LookupTable::<crate::backend::serial::curve_models::AffineNielsPoint>::from(
        &ED25519_BASEPOINT_POINT,
    );
    let mut q = ED25519_BASEPOINT_POINT;
    for i in 0..iters {
        let d = ((i % 15) as i8) - 7;
        let r = table.select(d);
        q = (&q + &r).as_extended();
    }
    q.compress().to_bytes()[0] as u64
}

/// Field multiplication `x = x * y` iterated `iters` times.
/// Digest: first byte of the final element.
pub fn fmul(iters: u32) -> u64 {
    let mut x = FieldElement::from_bytes(&[0x42u8; 32]);
    let y = FieldElement::from_bytes(&[0x17u8; 32]);
    for _ in 0..iters {
        x = &x * &y;
    }
    black_box(x.as_bytes()[0]) as u64
}

/// Field squaring `x = x.square()` iterated `iters` times.
pub fn fsq(iters: u32) -> u64 {
    let mut x = FieldElement::from_bytes(&[0x42u8; 32]);
    for _ in 0..iters {
        x = x.square();
    }
    black_box(x.as_bytes()[0]) as u64
}

/// One constant-time table select per iteration (8 ProjectiveNiels entries,
/// all scanned — the CT Straus inner select).
pub fn select(iters: u32) -> u64 {
    let table = LookupTable::<ProjectiveNielsPoint>::from(&ED25519_BASEPOINT_POINT);
    let mut acc: u64 = 0;
    for i in 0..iters {
        let d = ((i % 15) as i8) - 7;
        let t = table.select(black_box(d));
        black_box(t);
        acc = acc.wrapping_add(1);
    }
    black_box(acc)
}

/// One mixed addition per iteration: `EdwardsPoint + ProjectiveNiels -> as_extended`
/// (the CT Straus per-step arithmetic, sans select).
pub fn madd(iters: u32) -> u64 {
    let table = LookupTable::<ProjectiveNielsPoint>::from(&ED25519_BASEPOINT_POINT);
    let mut q = ED25519_BASEPOINT_POINT;
    for i in 0..iters {
        let d = ((i % 15) as i8) - 7;
        let r = table.select(d);
        q = (&q + &r).as_extended();
    }
    q.compress().to_bytes()[0] as u64
}

/// Quadruple doubling `q = q.mul_by_pow_2(4)` per iteration (the CT Straus
/// per-j-iteration doubling chain).
pub fn quadruple(iters: u32) -> u64 {
    let mut q = ED25519_BASEPOINT_POINT;
    for _ in 0..iters {
        q = q.mul_by_pow_2(4);
    }
    q.compress().to_bytes()[0] as u64
}

/// One constant-time Straus multiexp over `n` terms (the A2 chunk shape;
/// n = 36 on device). Inputs vary per iteration so nothing hoists.
pub fn ct_chunk(n: u32, iters: u32) -> u64 {
    let n = n as u64;
    let mut acc = EdwardsPoint::identity();
    for it in 0..iters {
        let scalars = (0..n).map(|i| Scalar::from(i + 3 + (it as u64) * 7));
        let points = repeat(ED25519_BASEPOINT_POINT).take(n as usize);
        acc = &acc + &EdwardsPoint::multiscalar_mul(scalars, points);
    }
    acc.compress().to_bytes()[0] as u64
}

/// One variable-time 2-term multiexp per iteration (the bp6 fold shape:
/// 256 iterations of NAF-5 within dalek). Inputs vary per iteration.
pub fn vartime_2term(iters: u32) -> u64 {
    let mut acc = EdwardsPoint::identity();
    for it in 0..iters {
        let s1 = Scalar::from(0x1111u64 + it as u64);
        let s2 = Scalar::from(0x9999u64 + (it as u64) * 3);
        acc = &acc
            + &EdwardsPoint::vartime_multiscalar_mul(
                [black_box(s1), black_box(s2)],
                [ED25519_BASEPOINT_POINT, ED25519_BASEPOINT_POINT],
            );
    }
    acc.compress().to_bytes()[0] as u64
}

/// Deterministic full-width scalar (the in-situ magnitude class: products of
/// witness scalars, unlike the small `Scalar::from` values used above).
fn full_width_scalar(seed: u64) -> Scalar {
    let mut b = [0u8; 32];
    let mut k = (seed as u8).wrapping_mul(31).wrapping_add(7);
    for x in b.iter_mut() {
        k = k.wrapping_mul(97).wrapping_add(53);
        *x = k;
    }
    Scalar::from_bytes_mod_order(b)
}

/// Chunked constant-time multiexp with full-width scalars, mirroring the
/// BP+ helper (monero-bulletproofs `core.rs::multiexp`): the n-term sum is
/// split into chunks of `chunk` terms, each running its own Straus
/// `multiscalar_mul`. Use this (not `ct_chunk`) to model the in-situ cost:
/// the signing workload's scalars are full-width.
pub fn ct_chunked(n: u32, chunk: u32, iters: u32) -> u64 {
    let n = u64::from(n);
    let chunk = u64::from(chunk).max(1);
    let mut acc = EdwardsPoint::identity();
    for it in 0..iters {
        let mut off = 0;
        while off < n {
            let take = (n - off).min(chunk);
            let scalars = (0..take).map(|i| full_width_scalar(i + off + u64::from(it) * 1000));
            let points = repeat(ED25519_BASEPOINT_POINT).take(take as usize);
            acc = &acc + &EdwardsPoint::multiscalar_mul(scalars, points);
            off += take;
        }
    }
    acc.compress().to_bytes()[0] as u64
}

/// One variable-time 2-term multiexp per iteration with full-width scalars
/// (the bp6 fold shape; `vartime_2term` feeds ~17-bit scalars, which skip
/// nearly every NAF addition and under-count the real fold cost).
pub fn vartime_2term_fullwidth(iters: u32) -> u64 {
    let s1 = full_width_scalar(0x1111);
    let s2 = full_width_scalar(0x9999);
    let mut acc = EdwardsPoint::identity();
    for _ in 0..iters {
        acc = &acc
            + &EdwardsPoint::vartime_multiscalar_mul(
                [black_box(s1), black_box(s2)],
                [ED25519_BASEPOINT_POINT, ED25519_BASEPOINT_POINT],
            );
    }
    acc.compress().to_bytes()[0] as u64
}
