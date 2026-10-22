use rand_core::{OsRng, RngCore as _};

use crate::{
    batch_verifier::BulletproofsPlusBatchVerifier,
    plus::aggregate_range_proof::{AggregateRangeStatement, AggregateRangeWitness},
};
use curve25519_dalek::{traits::Identity as _, EdwardsPoint};
use monero_ed25519::{Commitment, Scalar};

#[test]
fn test_aggregate_range_proof() {
    let mut verifier = BulletproofsPlusBatchVerifier::default();
    // Z5.3 scratch API (vendor test-infra patch): the prove chain takes
    // caller scratch; provision it once and reuse across iterations (the
    // reused-scratch zeroing fix is exercised by that reuse).
    let mut terms = vec![(curve25519_dalek::Scalar::ZERO, EdwardsPoint::identity()); 2050];
    let mut straus_storage =
        vec![0u8; curve25519_dalek::scratch::StrausScratch::storage_bytes(2050)];
    let mut straus =
        curve25519_dalek::scratch::StrausScratch::new(&mut straus_storage, 2050).unwrap();
    let mut wip_storage =
        vec![0u8; crate::plus::weighted_inner_product::WipScratch::storage_bytes(2050)];
    let mut wip =
        crate::plus::weighted_inner_product::WipScratch::new(&mut wip_storage, 2050).unwrap();
    for m in 1..=16 {
        let mut commitments = vec![];
        for _ in 0..m {
            commitments.push(Commitment::new(
                Scalar::random(&mut OsRng),
                OsRng.next_u64(),
            ));
        }
        let commitment_points = commitments
            .iter()
            .map(|commitment| commitment.commit().into())
            .collect::<Vec<_>>();
        let statement = AggregateRangeStatement::new(&commitment_points).unwrap();
        let witness = AggregateRangeWitness::new(&commitments).unwrap();

        let proof = statement
            .clone()
            .prove(&mut OsRng, &witness, &mut terms, &mut straus, &mut wip)
            .unwrap();
        statement.verify(&mut OsRng, &mut verifier, proof);
    }
    assert!(verifier.verify());
}
