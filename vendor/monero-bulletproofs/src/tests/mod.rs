use rand_core::{OsRng, RngCore as _};

use crate::{batch_verifier::BatchVerifier, Bulletproof, BulletproofError};
use curve25519_dalek::{traits::Identity as _, EdwardsPoint};
use monero_ed25519::{Commitment, Scalar};

mod original;
mod plus;

macro_rules! bulletproofs_tests {
    ($name: ident, $max: ident, $plus: literal) => {
        #[test]
        fn $name() {
            // Create Bulletproofs for all possible output quantities
            let mut verifier = BatchVerifier::new();
            for i in 1..=16 {
                let commitments = (1..=i)
                    .map(|_| Commitment::new(Scalar::random(&mut OsRng), OsRng.next_u64()))
                    .collect::<Vec<_>>();

                let bp = if $plus {
                    // Z5.3 scratch API (vendor test-infra patch).
                    let mut terms =
                        vec![(curve25519_dalek::Scalar::ZERO, EdwardsPoint::identity()); 2050];
                    let mut straus_storage = vec![
                        0u8;
                        curve25519_dalek::scratch::StrausScratch::storage_bytes(2050)
                    ];
                    let mut straus =
                        curve25519_dalek::scratch::StrausScratch::new(&mut straus_storage, 2050)
                            .unwrap();
                    let mut wip_storage = vec![
                        0u8;
                        crate::plus::weighted_inner_product::WipScratch::storage_bytes(2050)
                    ];
                    let mut wip =
                        crate::plus::weighted_inner_product::WipScratch::new(&mut wip_storage, 2050)
                            .unwrap();
                    Bulletproof::prove_plus(
                        &mut OsRng,
                        &commitments,
                        &mut terms,
                        &mut straus,
                        &mut wip,
                    )
                    .unwrap()
                } else {
                    Bulletproof::prove(&mut OsRng, &commitments).unwrap()
                };

                let commitments = commitments
                    .iter()
                    .map(Commitment::commit)
                    .map(|p| p.compress().into())
                    .collect::<Vec<_>>();
                assert!(bp.verify(&mut OsRng, &commitments));
                assert!(bp.batch_verify(&mut OsRng, &mut verifier, &commitments));
            }
            assert!(verifier.verify());
        }

        #[test]
        fn $max() {
            // Check Bulletproofs errors if we try to prove for too many outputs
            let mut commitments = vec![];
            for _ in 0..17 {
                commitments.push(Commitment::new(Scalar::ZERO, 0));
            }
            assert_eq!(
                (if $plus {
                    // Z5.3 scratch API (vendor test-infra patch) — the
                    // TooManyCommitments rejection fires before any scratch
                    // use, but the args must exist.
                    let mut terms =
                        vec![(curve25519_dalek::Scalar::ZERO, EdwardsPoint::identity()); 2050];
                    let mut straus_storage = vec![
                        0u8;
                        curve25519_dalek::scratch::StrausScratch::storage_bytes(2050)
                    ];
                    let mut straus =
                        curve25519_dalek::scratch::StrausScratch::new(&mut straus_storage, 2050)
                            .unwrap();
                    let mut wip_storage = vec![
                        0u8;
                        crate::plus::weighted_inner_product::WipScratch::storage_bytes(2050)
                    ];
                    let mut wip =
                        crate::plus::weighted_inner_product::WipScratch::new(&mut wip_storage, 2050)
                            .unwrap();
                    Bulletproof::prove_plus(
                        &mut OsRng,
                        &commitments,
                        &mut terms,
                        &mut straus,
                        &mut wip,
                    )
                } else {
                    Bulletproof::prove(&mut OsRng, &commitments)
                })
                .unwrap_err(),
                BulletproofError::TooManyCommitments,
            );
        }
    };
}

bulletproofs_tests!(bulletproofs, bulletproofs_max, false);
bulletproofs_tests!(bulletproofs_plus, bulletproofs_plus_max, true);
