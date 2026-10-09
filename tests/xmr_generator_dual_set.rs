//! Prefix key-collapse pin (2026-10-09): both compiled-in generator sets in
//! ONE process must live on SEPARATE cache slots.
//!
//! Pre-fix mechanism (vendor/monero-bulletproofs/src/generator_cache_hook.rs):
//! `ready_flag_for`/`desc_slot_for` dispatched on `b"bp+"/b"bp"` literals the
//! generated code never passes (it passes "bulletproof_plus"/"bulletproof"),
//! so BOTH sets matched the else branch and collapsed onto the BP slot. In a
//! dual-set process the later init overwrote the descriptor and readers of
//! the first set silently got the OTHER set's generators -> invalid
//! proofs/signatures with no error anywhere.
//!
//! The pin inits BP+ and BP in one process (caller-owned storage, the device
//! Z5.2b shape) and then asserts each WIRE-LITERAL key serves its OWN
//! reference table. Querying by literal is deliberate: it cross-checks the
//! runtime key constants against the exact bytes the persistence backend and
//! the C probe see ("bulletproof" / "bulletproof_plus").
//!
//! Mutation-verified (see the fix report): restoring the pre-fix key
//! constants/dispatch turns this pin red on the BP+ arm; the reference-table
//! pin (tests/xmr_generator_storage.rs) stays green throughout.
//!
//! Own integration binary: the vendored generator statics are per-process
//! (same pattern as tests/xmr_generator_cache*.rs).
#![cfg(all(feature = "std", feature = "alloc-fallback"))]

use curve25519_dalek::EdwardsPoint;
use monero_bulletproofs_generators::bulletproofs_generators;
use shlosilo::monero_bulletproofs::{
    init_generator_set, provide_generator_table_storage, table_generators, GeneratorSet,
    GeneratorTableStorage,
};

#[test]
fn bp_and_bp_plus_keep_separate_cache_slots() {
    let ref_plus = bulletproofs_generators(b"bulletproof_plus");
    let ref_orig = bulletproofs_generators(b"bulletproof");
    assert_eq!(ref_plus.G.len() + ref_plus.H.len(), 2048, "bp+ shape");
    assert_eq!(ref_orig.G.len() + ref_orig.H.len(), 2048, "bp shape");

    // caller-owned 'static storage per set (device: static/PSRAM; here:
    // leaked test memory) — the exact shape gencache_prepare() provides.
    let base = curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    let provide = |set: GeneratorSet, n_g: usize, n_h: usize| {
        let g: &'static mut [EdwardsPoint] = Box::leak(vec![base; n_g].into_boxed_slice());
        let h: &'static mut [EdwardsPoint] = Box::leak(vec![base; n_h].into_boxed_slice());
        let blob: &'static mut [u8] = Box::leak(vec![0u8; (n_g + n_h) * 128].into_boxed_slice());
        assert!(
            provide_generator_table_storage(set, GeneratorTableStorage { g, h, blob }),
            "first provide wins for {set:?}"
        );
    };
    provide(
        GeneratorSet::BulletproofPlus,
        ref_plus.G.len(),
        ref_plus.H.len(),
    );
    provide(
        GeneratorSet::Bulletproof,
        ref_orig.G.len(),
        ref_orig.H.len(),
    );

    // Init BOTH sets in one process — BP+ first, then BP. The pre-fix
    // collapse made the second init overwrite the first one's descriptor.
    init_generator_set(GeneratorSet::BulletproofPlus).expect("bp+ init");
    init_generator_set(GeneratorSet::Bulletproof).expect("bp init");

    // Each wire-literal key must serve its OWN reference table (point for
    // point). Under the collapse the BP+ query serves the BP table -> red.
    let plus = table_generators(b"bulletproof_plus").expect("bp+ tables ready");
    assert_eq!(plus.G, &ref_plus.G[..], "bp+ G slot");
    assert_eq!(plus.H, &ref_plus.H[..], "bp+ H slot");
    let orig = table_generators(b"bulletproof").expect("bp tables ready");
    assert_eq!(orig.G, &ref_orig.G[..], "bp G slot");
    assert_eq!(orig.H, &ref_orig.H[..], "bp H slot");
}
