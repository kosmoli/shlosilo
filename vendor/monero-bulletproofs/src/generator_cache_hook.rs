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

use std_shims::sync::Mutex;

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

// ─────────────────────────────────────────────────────────────────────────────
// Z5.2 (2026-09-26): caller-owned storage for the DECOMPRESSED generator tables
// ("生成器 Vec -> 调用方缓冲"; the gencache mechanism extended from the raw
// blob to the hot-path point tables). Memory-management only — the table
// CONTENT is identical either way (pinned by tests/xmr_generator_storage.rs
// against the reference tables).
//
// Contract for `provide_generator_table_storage`:
// - `g`/`h` must have EXACTLY the compiled table lengths (checked at init;
//   a mismatch falls back to the transitional path);
// - `blob` scratch must be (g.len() + h.len()) * 128 bytes (checked at provide);
// - the buffers must live for `'static` (device: static/PSRAM regions) and are
//   written ONCE at first generator use (decompress or blob rebuild).
//
// The generated `Generators` facade is built over these slices and held in a
// `LazyLock` static that never drops; the transitional fallback (no storage
// provided) decompresses into a Vec and leaks it via `leak_vec` — one-shot
// alloc on hosts that do not provision (removed when every host provisions).
// ─────────────────────────────────────────────────────────────────────────────

use curve25519_dalek::EdwardsPoint;

/// Borrowed generator tables (G, H) — the shape the statics hold.
/// Field names match the upstream `Generators` type so consumers are unchanged.
pub struct Generators<'a> {
    pub G: &'a [EdwardsPoint],
    pub H: &'a [EdwardsPoint],
}

/// Caller-owned decompressed table storage (see the module contract above).
pub struct GeneratorTableStorage {
    /// G table storage (exact generated length).
    pub g: &'static mut [EdwardsPoint],
    /// H table storage (exact generated length).
    pub h: &'static mut [EdwardsPoint],
    /// Raw-blob scratch, (g.len() + h.len()) * 128 bytes.
    pub blob: &'static mut [u8],
}

/// Which compiled-in generator set (keyed by the persistence prefix).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GeneratorSet {
    /// The original Bulletproofs set.
    Bulletproof,
    /// The Bulletproof+ set.
    BulletproofPlus,
}

impl GeneratorSet {
#[cfg(feature = "alloc-fallback")]
    pub(crate) fn from_prefix(prefix: &'static [u8]) -> Option<Self> {
        match prefix {
            b"bulletproof" => Some(Self::Bulletproof),
            b"bulletproof_plus" => Some(Self::BulletproofPlus),
            _ => None,
        }
    }
}

// shlosilo vendor patch: plain statics (const-constructible mutexes) — the
// LazyLock once-cells pulled `alloc::sync` into the graph.
static TABLE_BP: Mutex<Option<GeneratorTableStorage>> = Mutex::new(None);
static TABLE_BP_PLUS: Mutex<Option<GeneratorTableStorage>> = Mutex::new(None);
static TABLE_TAKEN_BP: Mutex<bool> = Mutex::new(false);
static TABLE_TAKEN_BP_PLUS: Mutex<bool> = Mutex::new(false);

/// Provide the decompressed-table storage for one generator set (once; first
/// registration wins). Returns false when the slot is taken or ALREADY
/// CONSUMED at init (a late provide would mislead the caller into thinking
/// the buffers were used), or when the blob scratch is inconsistently sized.
pub fn provide_generator_table_storage(set: GeneratorSet, storage: GeneratorTableStorage) -> bool {
    if storage.blob.len() != (storage.g.len() + storage.h.len()) * 128 {
        return false;
    }
    let (slot, taken) = match set {
        GeneratorSet::Bulletproof => (&TABLE_BP, &TABLE_TAKEN_BP),
        GeneratorSet::BulletproofPlus => (&TABLE_BP_PLUS, &TABLE_TAKEN_BP_PLUS),
    };
    let mut slot = slot.lock();
    if slot.is_some() || *taken.lock() {
        return false;
    }
    *slot = Some(storage);
    true
}

pub(crate) fn take_table_storage(prefix: &'static [u8]) -> Option<GeneratorTableStorage> {
    let set = GeneratorSet::from_prefix(prefix)?;
    let (slot, taken) = match set {
        GeneratorSet::Bulletproof => (&TABLE_BP, &TABLE_TAKEN_BP),
        GeneratorSet::BulletproofPlus => (&TABLE_BP_PLUS, &TABLE_TAKEN_BP_PLUS),
    };
    let out = slot.lock().take();
    if out.is_some() {
        *taken.lock() = true;
    }
    out
}

/// Z5.2b: the single sizing source of truth — the C probe, the provide-time
/// capacity validation, and the init-time fill check all derive from here.
/// Returns (g_bytes, h_bytes, blob_bytes).
#[cfg(feature = "alloc-fallback")]
pub fn generator_table_sizes(set: GeneratorSet) -> (usize, usize, usize) {
    let (g, h) = match set {
        GeneratorSet::Bulletproof => (crate::original::TABLE_G_LEN, crate::original::TABLE_H_LEN),
        GeneratorSet::BulletproofPlus => (crate::plus::TABLE_G_LEN, crate::plus::TABLE_H_LEN),
    };
    let g_bytes = g * core::mem::size_of::<EdwardsPoint>();
    let h_bytes = h * core::mem::size_of::<EdwardsPoint>();
    (g_bytes, h_bytes, (g + h) * 128)
}

/// Leak a Vec as a 'static slice WITHOUT requiring Box (MSRV-safe one-shot
/// leak for the transitional fallback path; the memory is never freed).
#[cfg(feature = "alloc-fallback")]
pub(crate) fn leak_vec<T>(mut v: std_shims::vec::Vec<T>) -> &'static mut [T] {
    let ptr = v.as_mut_ptr();
    let len = v.len();
    core::mem::forget(v);
    unsafe { core::slice::from_raw_parts_mut(ptr, len) }
}

/// Fill caller tables from the compiled compressed constants (cache-miss path
/// without persistence) or from the persisted raw blob (cache-hit path); on a
/// miss with persistence available, builds the blob in the caller's scratch
/// and STOREs it. Returns the borrowed tables.
pub(crate) fn init_tables(
    prefix: &'static [u8],
    n_points: usize,
    g_bytes: &[[u8; 32]],
    h_bytes: &[[u8; 32]],
    storage: GeneratorTableStorage,
) -> Generators<'static> {
    let GeneratorTableStorage { g, h, blob } = storage;
    if let Some(b) = try_load_blob(prefix, n_points) {
        let mut idx = 0;
        for p in g.iter_mut() {
            let mut raw = [0u8; 128];
            raw.copy_from_slice(&b[idx..idx + 128]);
            idx += 128;
            *p = curve25519_dalek::EdwardsPoint::from_raw_extended_bytes(&raw);
        }
        for p in h.iter_mut() {
            let mut raw = [0u8; 128];
            raw.copy_from_slice(&b[idx..idx + 128]);
            idx += 128;
            *p = curve25519_dalek::EdwardsPoint::from_raw_extended_bytes(&raw);
        }
    } else {
        for (p, b) in g.iter_mut().zip(g_bytes.iter()) {
            *p = curve25519_dalek::edwards::CompressedEdwardsY(*b)
                .decompress()
                .expect("generator from build script wasn't on-curve");
        }
        for (p, b) in h.iter_mut().zip(h_bytes.iter()) {
            *p = curve25519_dalek::edwards::CompressedEdwardsY(*b)
                .decompress()
                .expect("generator from build script wasn't on-curve");
        }
        // build + persist the raw blob in the caller's scratch (no alloc)
        let mut idx = 0;
        for p in g.iter() {
            blob[idx..idx + 128].copy_from_slice(&p.to_raw_extended_bytes());
            idx += 128;
        }
        for p in h.iter() {
            blob[idx..idx + 128].copy_from_slice(&p.to_raw_extended_bytes());
            idx += 128;
        }
        try_store_blob(prefix, &blob[..idx]);
    }
    Generators { G: g, H: h }
}
