//! Bug B pin (2026-10-09): the SECOND sign must not panic.
//!
//! Device failure: `generator_cache_hook.rs:309 guard.as_mut().expect("ready
//! flag implies storage")` fired on every sign AFTER the first. Mechanism:
//! the init flow CONSUMES the provide slot (`take_table_storage`), while the
//! read side (`table_generators` -> `table_slices`) sourced the table pointers
//! from that same (now empty) slot. Sign 1 runs take -> init and never touches
//! the read side; sign 2 takes the read-side fallback and panicked.
//!
//! This pin provides caller-owned table storage (the device Z5.2b shape), runs
//! THREE real BP+ proves (sign 1 = init, signs 2-3 = read side), and checks
//! the tables stay equal to the reference generators throughout. With the
//! pre-fix read side restored the second `prove_tiny_bp_plus()` panics
//! (mutation-verified: see the fix report).
//!
//! Own integration binary: the vendored generator statics are per-process
//! (same pattern as tests/xmr_generator_cache*.rs / xmr_generator_storage.rs).
#![cfg(feature = "std")]

use curve25519_dalek::EdwardsPoint;
use monero_bulletproofs_generators::bulletproofs_generators;
use shlosilo::chain::xmr::generator_cache_test_hooks::{
    prove_tiny_bp_plus, provide_table_storage, GeneratorSet, GeneratorTableStorage,
};

#[test]
fn second_and_third_sign_read_cached_tables_without_panicking() {
    let reference = bulletproofs_generators(b"bulletproof_plus");
    let n_g = reference.G.len();
    let n_h = reference.H.len();
    assert_eq!(n_g + n_h, 2048, "generator set shape");

    // caller-owned 'static storage (device: static/PSRAM; here: leaked test
    // memory) — the exact shape the device provides at gencache_prepare().
    let base = curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    let g: &'static mut [EdwardsPoint] = Box::leak(vec![base; n_g].into_boxed_slice());
    let h: &'static mut [EdwardsPoint] = Box::leak(vec![base; n_h].into_boxed_slice());
    let blob: &'static mut [u8] = Box::leak(vec![0u8; (n_g + n_h) * 128].into_boxed_slice());
    let g_ptr = g.as_ptr();
    let h_ptr = h.as_ptr();

    assert!(provide_table_storage(
        GeneratorSet::BulletproofPlus,
        GeneratorTableStorage { g, h, blob },
    ));

    // sign 1: take_table_storage -> init_tables (emplacement fill, ready up)
    prove_tiny_bp_plus();
    // sign 2: read side (table_generators) — THE panic site before the fix
    prove_tiny_bp_plus();
    // sign 3: still the read side
    prove_tiny_bp_plus();

    // The borrowed tables the read side serves are the SAME buffers the
    // caller provided, still holding the reference generators.
    let filled_g: &[EdwardsPoint] = unsafe { core::slice::from_raw_parts(g_ptr, n_g) };
    let filled_h: &[EdwardsPoint] = unsafe { core::slice::from_raw_parts(h_ptr, n_h) };
    assert_eq!(
        filled_g,
        &reference.G[..],
        "G table == reference after 3 signs"
    );
    assert_eq!(
        filled_h,
        &reference.H[..],
        "H table == reference after 3 signs"
    );
}
