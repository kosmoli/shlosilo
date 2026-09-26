//! Test-only hooks for the BP+ generator cache (see tests/xmr_generator_cache.rs).
//!
//! `#[doc(hidden)]`: not part of the public API surface; used exclusively by integration
//! tests and the device smoke task to exercise the vendor generator-cache hooks.

extern crate alloc;
// std is linked explicitly: the crate is `#![no_std]`, and this module only
// exists under the `std` feature (host builds) - see the cfg on the `mod`
// declaration.
extern crate std;
use alloc::vec::Vec;
// Host-only: the embedded build has no OsRng (no getrandom) and no test harness; the
// device-side hook registration arrives with the L3 flash backend (shlosilo_init FFI path).
use monero_bulletproofs::register_generator_cache_hooks;

// Z5.2: caller-provided decompressed table storage (test surface for
// tests/xmr_generator_storage.rs; the device wires this through the L3
// backend at Z5.2b).
pub use monero_bulletproofs::{GeneratorSet, GeneratorTableStorage};

pub fn provide_table_storage(set: GeneratorSet, storage: GeneratorTableStorage) -> bool {
    monero_bulletproofs::provide_generator_table_storage(set, storage)
}

/// Register load/store hooks into the vendored bulletproofs crate. Idempotent: a second
/// call with the same functions (e.g. two tests in one binary) returns true.
///
/// `OnceLock` (not a plain atomic flag): the two integration tests run on separate
/// threads, and a check-then-call on a flag let both callers through - the second
/// got the vendored crate's "first registration wins" `false` and failed its
/// assertion (observed as a flaky `make test-all`). `get_or_init` makes the
/// initialization atomic, so concurrent callers observe one registration result.
pub fn register(
    load: fn(&'static [u8]) -> Option<&'static [u8]>,
    store: fn(&'static [u8], &[u8]),
) -> bool {
    use std::sync::OnceLock;
    static REGISTERED_HERE: OnceLock<bool> = OnceLock::new();
    *REGISTERED_HERE.get_or_init(|| register_generator_cache_hooks(load, store))
}

/// Force the vendored crate's `GENERATORS` LazyLock to initialize through a real BP+
/// prove (same code path an XMR sign takes). 2 commitments x 64 bits = minimal proof.
pub fn prove_tiny_bp_plus() {
    use crate::chain::xmr::rct_sig::prove_bulletproofs_plus;
    use monero_ed25519::Commitment as MoneroCommitment;

    let mut rng = rand_core::OsRng;
    let mask_bytes = crate::curve_primitive::ed25519::scalar_to_bytes(
        &crate::chain::xmr::reduce_scalar::reduce_scalar(&[0x42u8; 32]).expect("scalar"),
    );
    let mask = crate::chain::xmr::transaction::bytes_to_monerod_scalar(&mask_bytes);
    let commitments: Vec<MoneroCommitment> = [
        MoneroCommitment::new(mask, 100_000_000),
        MoneroCommitment::new(mask, 200_000_000),
    ]
    .into();
    let mut terms = alloc::vec![
        (
            curve25519_dalek::Scalar::ZERO,
            curve25519_dalek::constants::ED25519_BASEPOINT_POINT,
        );
        crate::types::caps::SIGN_WS_BP_TERMS
    ];
    let _proof =
        prove_bulletproofs_plus(&mut rng, &commitments, &mut terms).expect("tiny bp+ prove");
}
