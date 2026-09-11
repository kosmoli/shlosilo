//! Host micro-benchmark for the BP+ Straus hot loops (shlosilo perf session).
//!
//! Mirrors the on-device workloads so loop-level optimizations can be
//! validated on host before spending device A/B cycles:
//!   - bp1 mode: 257-term CT multiexp (initial commitment, 1 call)
//!   - bp5 mode: 7 WIP rounds, L+R CT multiexp each (130/66/34/18/10/6/4 terms)
//!   - bp6 mode: 254 two-term vartime multiexps (generator fold)
//!   - bp2 mode: 258-term vartime multiexp (A_hat, Pippenger path)
//!
//! Run: cargo run --release --example bp_loop_bench
use std::hint::black_box;
use std::time::Instant;

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul, VartimeMultiscalarMul};
use rand_core::OsRng;

fn random_scalar() -> Scalar {
    Scalar::random(&mut OsRng)
}

fn random_point() -> EdwardsPoint {
    EdwardsPoint::mul_base(&random_scalar())
}

fn bench<F: FnMut() -> EdwardsPoint>(name: &str, iters: u32, mut f: F) {
    black_box(f()); // warmup
    let t0 = Instant::now();
    for _ in 0..iters {
        black_box(f());
    }
    let dt = t0.elapsed();
    println!(
        "{name}: {:.3} ms/iter ({iters} iters, total {dt:?})",
        dt.as_secs_f64() * 1e3 / iters as f64
    );
}

fn main() {
    // ---- bp1 mode: initial commitment (257 CT terms, m=2 outputs) ----
    let bp1_s: Vec<Scalar> = (0..257).map(|_| random_scalar()).collect();
    let bp1_p: Vec<EdwardsPoint> = (0..257).map(|_| random_point()).collect();
    bench("bp1 mode (257-term CT)", 30, || {
        EdwardsPoint::multiscalar_mul(bp1_s.iter(), bp1_p.iter())
    });

    // ---- bp5 mode: WIP rounds, L and R CT multiexp each ----
    let round_terms = [130usize, 66, 34, 18, 10, 6, 4];
    let rounds: Vec<(Vec<Scalar>, Vec<EdwardsPoint>)> = round_terms
        .iter()
        .map(|&t| {
            (
                (0..t).map(|_| random_scalar()).collect(),
                (0..t).map(|_| random_point()).collect(),
            )
        })
        .collect();
    bench("bp5 mode (7 rounds x L+R CT)", 20, || {
        let mut acc = EdwardsPoint::identity();
        for (s, p) in &rounds {
            acc += EdwardsPoint::multiscalar_mul(s.iter(), p.iter());
            acc += EdwardsPoint::multiscalar_mul(s.iter(), p.iter());
        }
        acc
    });

    // ---- bp6 mode: generator fold, 254 two-term vartime multiexps ----
    let mut fold: Vec<(Scalar, Scalar, EdwardsPoint, EdwardsPoint)> = Vec::new();
    for &n_hat in &[64usize, 32, 16, 8, 4, 2, 1] {
        let (a_g, b_g) = (random_scalar(), random_scalar());
        let (a_h, b_h) = (random_scalar(), random_scalar());
        for _ in 0..n_hat {
            fold.push((a_g, b_g, random_point(), random_point()));
        }
        for _ in 0..n_hat {
            fold.push((a_h, b_h, random_point(), random_point()));
        }
    }
    println!("bp6 fold workload: {} two-term calls", fold.len());
    bench("bp6 mode (254 two-term vartime)", 50, || {
        let mut acc = EdwardsPoint::identity();
        for (a, b, p1, p2) in &fold {
            acc += EdwardsPoint::vartime_multiscalar_mul([*a, *b], [*p1, *p2]);
        }
        acc
    });

    // ---- bp2 mode: A_hat (258-term vartime, Pippenger path) ----
    let bp2_s: Vec<Scalar> = (0..258).map(|_| random_scalar()).collect();
    let bp2_p: Vec<EdwardsPoint> = (0..258).map(|_| random_point()).collect();
    bench("bp2 mode (258-term vartime)", 30, || {
        EdwardsPoint::vartime_multiscalar_mul(bp2_s.iter(), bp2_p.iter())
    });
}
