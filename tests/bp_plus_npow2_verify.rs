//! BP+ non-pow2 acceptance (pin 3 companion, 2026-10-21).
//!
//! The Z5.3 scratch refactor of the vendored bulletproofs+ aggregate prover
//! sized the A-terms/witness from the UNPADDED bit count and zero-filled the
//! witness tail, so non-pow2 commitment counts panicked (the pinned-red
//! 3-output sign) — and any non-panicking wrong-tail proof would have failed
//! chain verification. This test proves AND verifies across non-pow2 counts
//! through the production entry (`prove_plus`, caller-scratch recipe copied
//! from the sign path) and the vendored `Bulletproof::verify` (the port of
//! monero's check).
//!
//! Run: cargo test --offline --test bp_plus_npow2_verify
#![cfg(feature = "alloc-fallback")]

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use monero_bulletproofs::{Bulletproof, WipScratch};
use monero_ed25519::{Commitment, CompressedPoint, Scalar};
use rand_chacha::rand_core::{RngCore as _, SeedableRng as _};
use shlosilo::types::caps::SIGN_WS_BP_TERMS;

/// Non-pow2 counts (3/5/6/7 are the crash/validity shapes) + pow2 controls.
const COUNTS: [usize; 8] = [1, 2, 3, 5, 6, 7, 8, 16];

#[test]
fn bp_plus_non_pow2_prove_verify() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x00B9_0025);
    for m in COUNTS {
        let outputs: Vec<Commitment> = (0..m)
            .map(|_| Commitment::new(Scalar::random(&mut rng), rng.next_u64()))
            .collect();

        // caller-scratch recipe = the sign path's (tx_signer.rs).
        let mut terms =
            vec![(curve25519_dalek::Scalar::ZERO, ED25519_BASEPOINT_POINT); SIGN_WS_BP_TERMS];
        let mut straus_storage =
            vec![0u8; curve25519_dalek::scratch::StrausScratch::storage_bytes(SIGN_WS_BP_TERMS)];
        let mut straus =
            curve25519_dalek::scratch::StrausScratch::new(&mut straus_storage, SIGN_WS_BP_TERMS)
                .expect("straus scratch");
        let mut wip_storage = vec![0u8; WipScratch::storage_bytes(SIGN_WS_BP_TERMS)];
        let mut wip = WipScratch::new(&mut wip_storage, SIGN_WS_BP_TERMS).expect("wip scratch");

        let proof = Bulletproof::prove_plus(&mut rng, &outputs, &mut terms, &mut straus, &mut wip)
            .unwrap_or_else(|e| panic!("prove_plus must succeed for m={m}: {e:?}"));

        let compressed: Vec<CompressedPoint> = outputs
            .iter()
            .map(|c| {
                let p: curve25519_dalek::EdwardsPoint = c.commit().into();
                CompressedPoint::from(p.compress().to_bytes())
            })
            .collect();
        assert!(
            proof.verify(&mut rng, &compressed),
            "m={m}: the proved aggregate range proof must verify"
        );
    }
}
