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

static LOAD: Mutex<Option<LoadFn>> = Mutex::new(None);
static STORE: Mutex<Option<StoreFn>> = Mutex::new(None);
static REGISTERED: Mutex<bool> = Mutex::new(false);

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

/// Cache-key prefixes identifying the two generated tables. The ONLY key
/// literals in the runtime: the build.rs templates pass these constants BY
/// NAME as their cache key (generated code holds no raw `b"..."` key), and
/// `GeneratorSet::from_prefix` matches on them — one source, no human sync.
/// The byte values are the wire form the persistence backend / C probe see
/// ("bulletproof" / "bulletproof_plus"), pinned by
/// tests/xmr_generator_dual_set.rs.
pub(crate) const BP_PLUS_PREFIX: &[u8] = b"bulletproof_plus";
pub(crate) const BP_PREFIX: &[u8] = b"bulletproof";

impl GeneratorSet {
    /// THE key dispatch: every slot decision (provide/take/ready/desc) routes
    /// through here. 2026-10-09 (key-collapse fix): `ready_flag_for`/
    /// `desc_slot_for` used to compare the prefix against `b"bp+"/b"bp"`
    /// literals the generated code never passes — both sets matched the else
    /// branch, collapsed onto the BP slot, and the second init silently won
    /// the descriptor (readers of the first set got the WRONG generators ->
    /// invalid proofs/signatures). Unknown keys return None (no slot is ever
    /// borrowed for them).
    pub(crate) fn from_prefix(prefix: &[u8]) -> Option<Self> {
        if prefix == BP_PREFIX {
            Some(Self::Bulletproof)
        } else if prefix == BP_PLUS_PREFIX {
            Some(Self::BulletproofPlus)
        } else {
            None
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
pub fn generator_table_sizes(set: GeneratorSet) -> (usize, usize, usize) {
    let (g, h) = match set {
        // Z6: the Original table only exists on the alloc face. Zero capacity
        // is the honest no-alloc answer — provide/init fail cleanly on it.
        GeneratorSet::Bulletproof => {
            #[cfg(feature = "alloc-fallback")]
            {
                (crate::original::TABLE_G_LEN, crate::original::TABLE_H_LEN)
            }
            #[cfg(not(feature = "alloc-fallback"))]
            {
                (0, 0)
            }
        }
        GeneratorSet::BulletproofPlus => (crate::plus::TABLE_G_LEN, crate::plus::TABLE_H_LEN),
    };
    let g_bytes = g * core::mem::size_of::<EdwardsPoint>();
    let h_bytes = h * core::mem::size_of::<EdwardsPoint>();
    (g_bytes, h_bytes, (g + h) * 128)
}

/// Leak a Vec as a 'static slice WITHOUT requiring Box (MSRV-safe one-shot
/// leak for the transitional fallback path; the memory is never freed).
#[cfg(feature = "alloc-fallback")]
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
/// Table-initialization failure (explicit — never a panic, never a
/// partially-initialized table exposed; invariant 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    OffCurve,
    BlobMismatch,
}

/// Emplacement decompression (invariant 1): points are decompressed
/// straight into the caller's storage — no intermediate Vec, no copy of a
/// complete table. Success is what flips the ready flag (invariant 2).
pub(crate) fn init_tables(
    prefix: &'static [u8],
    n_points: usize,
    g_bytes: &[[u8; 32]],
    h_bytes: &[[u8; 32]],
    storage: GeneratorTableStorage,
) -> Result<Generators<'static>, InitError> {
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
                .ok_or(InitError::OffCurve)?;
        }
        for (p, b) in h.iter_mut().zip(h_bytes.iter()) {
            *p = curve25519_dalek::edwards::CompressedEdwardsY(*b)
                .decompress()
                .ok_or(InitError::OffCurve)?;
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
    // invariant 2: the table is only marked ready AFTER every point is in
    // place; a failure above returns Err with the flag still down and no
    // partial table ever readable (invariant 3).
    //
    // shlosilo vendor patch (2026-10-09, second-sign fix): the ready flag is
    // set over the DESCRIPTOR CACHE below, not over the provide slot — the
    // slot is CONSUMED by `take_table_storage` at init, so it is empty from
    // the first init onward and cannot be the read source. Record the table
    // descriptors BEFORE the Release store: a reader that observes ready must
    // also observe the cache (invariant: ready == cache populated).
    //
    // Key-collapse fix (2026-10-09): slot choice goes through
    // `GeneratorSet::from_prefix` (both sets used to land on the BP slot).
    // The prefix comes from the generated code (= the named constants), so a
    // non-compiled-in key here is a programming error, not data.
    let set = GeneratorSet::from_prefix(prefix)
        .expect("init_tables: prefix is a compiled-in generator set");
    *desc_slot_for(set).lock() = Some(TableDesc {
        g_ptr: g.as_ptr() as usize,
        g_len: g.len(),
        h_ptr: h.as_ptr() as usize,
        h_len: h.len(),
    });
    ready_flag_for(set).store(true, core::sync::atomic::Ordering::Release);
    Ok(Generators { G: g, H: h })
}

/// Per-set ready flags (Release on success / Acquire on read) — the atomic
/// uninitialized -> ready transition of A3. Keyed by `GeneratorSet` (via
/// `from_prefix` upstream), never by raw-literal comparison.
fn ready_flag_for(set: GeneratorSet) -> &'static core::sync::atomic::AtomicBool {
    match set {
        GeneratorSet::Bulletproof => &READY_BP,
        GeneratorSet::BulletproofPlus => &READY_BP_PLUS,
    }
}

static READY_BP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static READY_BP_PLUS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

// shlosilo vendor patch (2026-10-09, second-sign fix — device panic at the
// old `expect("ready flag implies storage")` on every sign AFTER the first):
// the read side used to source the table pointers from the provide slot, but
// `take_table_storage` empties that slot at init (its whole point: the caller
// owns the buffers and the slot must not hand them out twice), so on the
// second sign `table_slices` found `None` and panicked. The fix caches the
// initialized tables' raw descriptors (ptr + len) at `init_tables` success;
// `table_slices` reads the cache. Memory-management only: the descriptors
// point at the very same caller-provided buffers the slot carried, so the
// generator table CONTENT and every signature byte are unchanged
// (pinned by tests/xmr_generator_storage.rs + tests/xmr_generator_second_sign.rs).
// usize fields (not raw pointers) keep the statics Send for the Mutex.
#[derive(Clone, Copy)]
struct TableDesc {
    g_ptr: usize,
    g_len: usize,
    h_ptr: usize,
    h_len: usize,
}

static DESC_BP: Mutex<Option<TableDesc>> = Mutex::new(None);
static DESC_BP_PLUS: Mutex<Option<TableDesc>> = Mutex::new(None);

fn desc_slot_for(set: GeneratorSet) -> &'static Mutex<Option<TableDesc>> {
    match set {
        GeneratorSet::Bulletproof => &DESC_BP,
        GeneratorSet::BulletproofPlus => &DESC_BP_PLUS,
    }
}

/// Read-side accessor (A3): borrows the decompressed table only when the
/// ready flag is up (Acquire pairs with `init_tables`' Release). An unknown
/// key serves NOTHING (pre-fix: any key fell onto the BP slot).
pub fn table_generators<'a>(prefix: &'static [u8]) -> Option<Generators<'a>> {
    let set = GeneratorSet::from_prefix(prefix)?;
    if !ready_flag_for(set).load(core::sync::atomic::Ordering::Acquire) {
        return None;
    }
    // SAFETY: ready implies `init_tables` completed over this set's storage;
    // the storage is 'static (caller-provided, stable per the ws contract)
    // and is only WRITTEN during that one init — every read-side borrow is
    // shared (no `&'static mut` is ever minted here).
    unsafe {
        let (g, h) = table_slices(set);
        Some(Generators { G: g, H: h })
    }
}

/// Read-side slice construction (A3): SHARED slices only. The pre-fix shape
/// minted fresh `&'static mut` slices per call, so two concurrent readers
/// could hold aliasing `&mut` to the same table (undefined behavior). The
/// tables are written exactly once at init (`take_table_storage` guarantees
/// single consumption) and read-only afterwards, so shared borrows are the
/// honest shape.
///
/// # Safety
/// Caller must have observed the set's ready flag with Acquire (the
/// descriptors are populated before `init_tables`' Release store).
unsafe fn table_slices(set: GeneratorSet) -> (&'static [EdwardsPoint], &'static [EdwardsPoint]) {
    // shlosilo vendor patch (2026-10-09, second-sign fix): source = the
    // init-time descriptor cache, NOT the provide slot. The slot is consumed
    // by `take_table_storage` at first init, so reading it here panicked on
    // every sign after the first ("ready flag implies storage"). The cache is
    // populated BEFORE the ready flag's Release store (init_tables), so the
    // ready read (Acquire) above guarantees it is present here.
    let desc = desc_slot_for(set).lock();
    let d = desc
        .as_ref()
        .expect("ready flag implies cached table descriptors");
    (
        core::slice::from_raw_parts(d.g_ptr as *const EdwardsPoint, d.g_len),
        core::slice::from_raw_parts(d.h_ptr as *const EdwardsPoint, d.h_len),
    )
}

/// #[doc(hidden)] init-entry surface for tests/diagnostics: run one set's
/// generated `generators()` entry exactly as the prove/verify faces do on
/// first use — emplacement into provided storage when provisioned (ready flag
/// up, descriptors cached), transitional fallback otherwise. Returns the
/// served tables.
#[doc(hidden)]
pub fn init_generator_set(set: GeneratorSet) -> Result<Generators<'static>, InitError> {
    match set {
        GeneratorSet::Bulletproof => {
            // Z6: the Original line is alloc-face only.
            #[cfg(feature = "alloc-fallback")]
            {
                crate::original::generators()
            }
            #[cfg(not(feature = "alloc-fallback"))]
            {
                Err(InitError::BlobMismatch)
            }
        }
        GeneratorSet::BulletproofPlus => crate::plus::generators(),
    }
}

// A3: `?` conversions from the table-init error into the proof error types.
#[cfg(feature = "alloc-fallback")]
impl From<InitError> for crate::original::inner_product::IpError {
    fn from(e: InitError) -> Self {
        match e {
            InitError::OffCurve => crate::original::inner_product::IpError::InvalidPoint,
            InitError::BlobMismatch => {
                crate::original::inner_product::IpError::IncorrectAmountOfGenerators
            }
        }
    }
}
