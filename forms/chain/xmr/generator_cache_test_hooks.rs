//! Test-only hooks for the BP+ generator cache (see tests/xmr_generator_cache.rs).
//!
//! `#[doc(hidden)]`: not part of the public API surface; used exclusively by integration
//! tests and the device smoke task to exercise the vendor generator-cache hooks.

extern crate alloc;
use alloc::vec::Vec;
// Host-only: the embedded build has no OsRng (no getrandom) and no test harness; the
// device-side hook registration arrives with the L3 flash backend (shlosilo_init FFI path).
use monero_bulletproofs::register_generator_cache_hooks;

/// Register load/store hooks into the vendored bulletproofs crate. Idempotent: a second
/// call with the same functions (e.g. two tests in one binary) returns true.
pub fn register(
    load: fn(&'static [u8]) -> Option<&'static [u8]>,
    store: fn(&'static [u8], &[u8]),
) -> bool {
    use core::sync::atomic::{AtomicBool, Ordering};
    static REGISTERED_HERE: AtomicBool = AtomicBool::new(false);
    if REGISTERED_HERE.load(Ordering::Acquire) {
        return true;
    }
    let ok = register_generator_cache_hooks(load, store);
    REGISTERED_HERE.store(true, Ordering::Release);
    ok
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
    let mask = {
        use crate::chain::xmr::transaction::Read32Cursor;
        let mut cursor = Read32Cursor(mask_bytes);
        monero_ed25519::Scalar::read(&mut cursor).expect("reduced scalar")
    };
    let commitments: Vec<MoneroCommitment> = [
        MoneroCommitment::new(mask, 100_000_000),
        MoneroCommitment::new(mask, 200_000_000),
    ]
    .into();
    let _proof = prove_bulletproofs_plus(&mut rng, commitments).expect("tiny bp+ prove");
}
