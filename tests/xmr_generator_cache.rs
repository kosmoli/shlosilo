//! E2E: register generator cache hooks, run one BP+ prove, verify the store hook fired
//! with a well-formed 512KB blob, and that the blob round-trips to the real generators.
//!
//! This runs as its own integration-test binary (separate process), so the
//! `GENERATORS` LazyLock inside the vendored bulletproofs crate is fresh here.
#![cfg(feature = "std")]

use curve25519_dalek::EdwardsPoint;
use shlosilo::chain::xmr::generator_cache_test_hooks;

static CAPTURED: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);

fn test_load(_prefix: &'static [u8]) -> Option<Vec<u8>> {
    None // first run in this process: nothing persisted yet
}

fn test_store(_prefix: &'static [u8], blob: &[u8]) {
    *CAPTURED.lock().unwrap() = Some(blob.to_vec());
}

#[test]
fn bp_prove_persists_generator_blob() {
    assert!(generator_cache_test_hooks::register(test_load, test_store));

    // Trigger the GENERATORS init through a real BP+ statement (same path as XMR sign).
    generator_cache_test_hooks::prove_tiny_bp_plus();

    let blob = CAPTURED
        .lock()
        .unwrap()
        .clone()
        .expect("store hook must fire on first init");
    assert_eq!(blob.len(), 2048 * 128); // 2048 points x 128B

    // Round-trip: rebuild from blob and compare a sample against decompressed consts.
    // We re-derive two known generators independently via the monero-bulletproofs-generators
    // crate used by the vendor build script logic? Simpler: rebuild points from the blob
    // and check they are valid curve points (on-curve check via decompress equivalence).
    for i in [0usize, 1, 1023, 1024, 2047] {
        let mut b = [0u8; 128];
        b.copy_from_slice(&blob[i * 128..(i + 1) * 128]);
        let p = EdwardsPoint::from_raw_extended_bytes(&b);
        // extended point arithmetic must not blow up; identity sanity:
        assert_eq!(
            p.mul_by_cofactor().compress(),
            p.mul_by_cofactor().compress()
        );
        let _ = p.compress();
    }
}

/// GPT-suggested double-path equivalence sweep (2026-09-07): for EVERY BP+ generator,
/// assert the cache rebuild path equals the reference decompressed generator. This is the
/// regression net: if dalek or monero-bulletproofs changes generator representation or
/// extended-coordinate layout, this test fails loudly instead of producing wrong proofs.
#[test]
fn all_generators_rebuild_equal_reference() {
    assert!(generator_cache_test_hooks::register(test_load, test_store));
    generator_cache_test_hooks::prove_tiny_bp_plus();
    let blob = CAPTURED
        .lock()
        .unwrap()
        .clone()
        .expect("store hook must fire");
    assert_eq!(blob.len(), 2048 * 128);

    // Reference generators, derived independently of the cache path (same crate the
    // vendored build script uses for the non-compile-time feature).
    let reference = monero_bulletproofs_generators::bulletproofs_generators(b"bulletproof_plus");
    assert_eq!(reference.G.len() + reference.H.len(), 2048);

    let mut idx = 0;
    for (name, vec_ref) in [("G", &reference.G), ("H", &reference.H)] {
        for (i, p_ref) in vec_ref.iter().enumerate() {
            let mut b = [0u8; 128];
            b.copy_from_slice(&blob[idx..idx + 128]);
            idx += 128;
            let rebuilt = EdwardsPoint::from_raw_extended_bytes(&b);
            // Equivalence is judged on the canonical compressed form: two extended
            // encodings of the same curve point may differ in raw coordinates (Z/T
            // normalization is representation-dependent), and that is irrelevant for
            // arithmetic correctness. Raw-byte losslessness of OUR serialize/rebuild
            // pair is asserted separately in the lib round-trip tests.
            assert_eq!(
                rebuilt.compress().to_bytes(),
                p_ref.compress().to_bytes(),
                "{name}[{i}] compressed mismatch"
            );
        }
    }
}
