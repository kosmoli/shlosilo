//! Z5.2: caller-provided decompressed generator table storage must fill with
//! points IDENTICAL to the reference tables (the registry crate's own
//! generators — the oracle). Also proves the storage path is taken at init
//! (the buffers are written in place).
//!
//! Own integration binary: the vendored `GENERATORS` LazyLock is fresh per
//! process (same pattern as tests/xmr_generator_cache.rs).
#![cfg(feature = "std")]

use curve25519_dalek::EdwardsPoint;
use monero_bulletproofs_generators::bulletproofs_generators;
use shlosilo::chain::xmr::generator_cache_test_hooks::{
    provide_table_storage, prove_tiny_bp_plus, GeneratorSet, GeneratorTableStorage,
};

#[test]
fn caller_storage_fills_reference_generators() {
    let reference = bulletproofs_generators(b"bulletproof_plus");
    let n_g = reference.G.len();
    let n_h = reference.H.len();
    assert_eq!(n_g + n_h, 2048, "generator set shape");

    // caller-owned 'static storage (device: static/PSRAM; here: leaked test memory)
    let base = curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    let g: &'static mut [EdwardsPoint] =
        Box::leak(vec![base; n_g].into_boxed_slice());
    let h: &'static mut [EdwardsPoint] =
        Box::leak(vec![base; n_h].into_boxed_slice());
    let blob: &'static mut [u8] = Box::leak(vec![0u8; (n_g + n_h) * 128].into_boxed_slice());
    let g_ptr = g.as_ptr();
    let h_ptr = h.as_ptr();

    assert!(provide_table_storage(
        GeneratorSet::BulletproofPlus,
        GeneratorTableStorage { g, h, blob },
    ));

    // fill happens at first generator use: force init through the real BP+
    // signing path (same code path an XMR sign takes)
    prove_tiny_bp_plus();

    // the in-place-filled tables must equal the reference point for point
    let filled_g: &[EdwardsPoint] = unsafe { core::slice::from_raw_parts(g_ptr, n_g) };
    let filled_h: &[EdwardsPoint] = unsafe { core::slice::from_raw_parts(h_ptr, n_h) };
    assert_eq!(filled_g, &reference.G[..], "G table == reference");
    assert_eq!(filled_h, &reference.H[..], "H table == reference");

    // double-provide is rejected (first registration wins)
    let g2: &'static mut [EdwardsPoint] = Box::leak(vec![base; n_g].into_boxed_slice());
    let h2: &'static mut [EdwardsPoint] = Box::leak(vec![base; n_h].into_boxed_slice());
    let b2: &'static mut [u8] = Box::leak(vec![0u8; (n_g + n_h) * 128].into_boxed_slice());
    assert!(!provide_table_storage(
        GeneratorSet::BulletproofPlus,
        GeneratorTableStorage { g: g2, h: h2, blob: b2 },
    ));
}
