//! shlosilo vendor patch (2026-09-07): external generator cache hooks.
//!
//! BP+/BP generators are public constants. On embedded targets the default
//! `compile-time-generators` init decompresses 2048 points per generator set on first
//! use (~14-17s on MH1903 for BP+). When persistence hooks are registered, the first
//! init stores the decompressed generators' raw extended coordinates (X,Y,Z,T, 128
//! B/point) via `STORE`, and subsequent boots load them via `LOAD`, rebuilding points
//! with the dalek vendor-patch constructor `EdwardsPoint::from_raw_extended_bytes`
//! (no sqrt, no hash-to-curve, no inversions).
//!
//! The LOAD hook returns a BORROWED slice: the backend owns the storage (memory-mapped
//! flash on the device) and the bytes stay valid for the program lifetime, so the load
//! path reads them in place — no intermediate copy, no allocation (the blob is 256 KB;
//! copying it cost an alloc + memset + a PSRAM round trip on the device).
//!
//! Hooks are tagged by the generator-set prefix ("bulletproof" / "bulletproof_plus")
//! so multiple generator sets can persist independently.
//!
//! Security note: the blob MUST be integrity-protected by the backend (magic + version +
//! CRC32). Generators are public constants, so corruption can only break proof
//! soundness for the affected transaction (detectable on verification), never leak
//! secrets. The load path deliberately does NOT re-check curve membership.

use std_shims::sync::{LazyLock, Mutex};

pub(crate) type LoadFn = fn(prefix: &'static [u8]) -> Option<&'static [u8]>;
pub(crate) type StoreFn = fn(prefix: &'static [u8], blob: &[u8]);

static LOAD: LazyLock<Mutex<Option<LoadFn>>> = LazyLock::new(|| Mutex::new(None));
static STORE: LazyLock<Mutex<Option<StoreFn>>> = LazyLock::new(|| Mutex::new(None));
static REGISTERED: LazyLock<Mutex<bool>> = LazyLock::new(|| Mutex::new(false));

/// Register persistence hooks. Call before any BP+/BP prove/verify (e.g. from shlosilo
/// init). Returns false if hooks were already registered (first registration wins).
pub fn register_generator_cache_hooks(load: LoadFn, store: StoreFn) -> bool {
    let mut reg = REGISTERED.lock();
    if *reg {
        return false;
    }
    *LOAD.lock() = Some(load);
    *STORE.lock() = Some(store);
    *reg = true;
    true
}

/// Expected blob length for a generator set with `n_points` points (128 B each).
pub(crate) fn blob_len(n_points: usize) -> usize {
    n_points * 128
}

pub(crate) fn try_load_blob(prefix: &'static [u8], n_points: usize) -> Option<&'static [u8]> {
    let blob = match *LOAD.lock() {
        Some(f) => f(prefix),
        None => return None,
    };
    match blob {
        Some(b) if b.len() == blob_len(n_points) => Some(b),
        _ => None,
    }
}

pub(crate) fn try_store_blob(prefix: &'static [u8], blob: &[u8]) {
    if let Some(f) = *STORE.lock() {
        f(prefix, blob);
    }
}
