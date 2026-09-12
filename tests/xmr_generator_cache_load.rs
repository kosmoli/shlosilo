//! E2E for the zero-copy LOAD path: the load hook hands out a BORROWED slice
//! (mirroring the device, where the C backend returns a pointer into memory-mapped
//! flash), the generators must initialize from it, and the store hook must NOT fire
//! (store only runs on a load miss).
//!
//! Separate integration-test binary: `GENERATORS` inside the vendored bulletproofs
//! crate is a per-process LazyLock, so this process must see a fresh one.
#![cfg(feature = "std")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use shlosilo::chain::xmr::generator_cache_test_hooks;

static LOAD_CALLED: AtomicBool = AtomicBool::new(false);
static STORE_FIRED: AtomicBool = AtomicBool::new(false);

/// The blob the backend would serve. Leaked so the borrow is `'static`, exactly like
/// the device's flash-mapped region (which lives for the whole program lifetime).
static BLOB: OnceLock<&'static [u8]> = OnceLock::new();

fn build_blob() -> &'static [u8] {
    let reference = monero_bulletproofs_generators::bulletproofs_generators(b"bulletproof_plus");
    let mut blob = Vec::with_capacity(2048 * 128);
    for p in reference.G.iter().chain(reference.H.iter()) {
        blob.extend_from_slice(&p.to_raw_extended_bytes());
    }
    Box::leak(blob.into_boxed_slice())
}

fn load_hit(_prefix: &'static [u8]) -> Option<&'static [u8]> {
    LOAD_CALLED.store(true, Ordering::SeqCst);
    Some(BLOB.get_or_init(build_blob))
}

fn store_should_not_fire(_prefix: &'static [u8], _blob: &[u8]) {
    STORE_FIRED.store(true, Ordering::SeqCst);
}

#[test]
fn load_hit_initializes_from_borrowed_blob_without_store() {
    assert!(generator_cache_test_hooks::register(
        load_hit,
        store_should_not_fire
    ));

    // Same init path as XMR sign (real BP+ statement).
    generator_cache_test_hooks::prove_tiny_bp_plus();

    assert!(
        LOAD_CALLED.load(Ordering::SeqCst),
        "load hook must be consulted on generator init"
    );
    assert!(
        !STORE_FIRED.load(Ordering::SeqCst),
        "store hook must NOT fire when the load path hits"
    );
}
