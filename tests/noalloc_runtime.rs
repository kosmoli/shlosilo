//! B6 (pool #19, closed 2026-10-28): host-side no-alloc RUNTIME coverage.
//!
//! Before this file, every integration test exercising the zero-heap faces
//! was gated `#![cfg(feature = "alloc-fallback")]` — under the TESTNOALLOC
//! gate (cargo test --no-default-features) the caller-pool parsers, Sink
//! writers and derivation paths never RAN (compile-only via the embed
//! checks). This file has NO feature gate: it runs on BOTH faces and holds
//! a ZERO-ALLOCATION receipt over the measured sections (the file's own
//! counting global allocator), so the zero-heap runtime picture is proven
//! by execution, not by link analysis (probes/noalloc is the static face).
//!
//! Measured sections exclude fixture materialization on purpose (decrypt
//! returns a Vec by contract); everything under measurement is the real
//! zero-heap path.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

struct Counting;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
// The counter is process-global: serialize the measured tests (the same
// lesson as xmr_sign_zero_alloc's bt 0 -> 203 pollution).
static SERIAL: Mutex<()> = Mutex::new(());

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc_zeroed(l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.realloc(p, l, n)
    }
}

#[global_allocator]
static A: Counting = Counting;

fn measured<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let guard: MutexGuard<'static, ()> = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let before = ALLOCS.load(Ordering::Relaxed);
    let out = f();
    let delta = ALLOCS.load(Ordering::Relaxed) - before;
    drop(guard);
    (out, delta as u64)
}

#[cfg(feature = "alloc-fallback")]
const GOLD_SIGNED: &[u8] = include_bytes!("fixtures/gold_signed_fa.bin");
const CONSTRUCTION: &[u8] = include_bytes!("fixtures/xmr_construction_unsorted_1023.bin");

// Public fixture material (same policy as tests/golden_wallet2_bytes.rs).
#[cfg(feature = "alloc-fallback")]
const LAB_VIEW_SK: [u8; 32] = [
    0xdb, 0x93, 0xce, 0x63, 0x2d, 0x8d, 0x31, 0xe3, 0x1b, 0xd0, 0xb4, 0xec, 0xbd, 0xbd, 0xb8, 0x33,
    0xca, 0xe8, 0x13, 0x92, 0x8a, 0xf4, 0x02, 0xc5, 0xb7, 0xff, 0xeb, 0x85, 0x76, 0x9c, 0xf0, 0x00,
];
const TEST2_VIEW_SK: [u8; 32] = [
    0x8d, 0xea, 0xed, 0xf1, 0x13, 0x7e, 0x24, 0xb9, 0xed, 0x25, 0x38, 0xae, 0x99, 0x53, 0x2f, 0x0f,
    0xf7, 0x71, 0x7c, 0x3c, 0x52, 0xd1, 0x16, 0x9c, 0xb0, 0x06, 0x88, 0x1c, 0x48, 0xa7, 0xbb, 0x04,
];
const TEST2_SPEND_SK: [u8; 32] = [
    0x12, 0x83, 0xcb, 0xd5, 0x3a, 0x57, 0x9f, 0x0e, 0x34, 0x90, 0xf3, 0xd9, 0x97, 0x8d, 0x7d, 0x42,
    0x3f, 0x98, 0x69, 0x23, 0xb3, 0x25, 0xa2, 0x33, 0x45, 0x4f, 0xb9, 0x91, 0xd0, 0xbb, 0x28, 0x0d,
];
const KI_HEX: [&str; 13] = [
    "49e43bb86116b14855827c2c3f17852e7455fc18ceb3f1822e970c007e585ab5",
    "2c85f150ef6de077ad85b15a7345dc3143ca72b4d69fc84241545f4a393a915c",
    "7306860214b4150ea4a3d28e615ed8931f2b0c4fea5331d7e2d80848662a9f80",
    "c0e6f88e409815a9cfb72b6ce479a2d1a45a24a3670f3436b225a9b808be422f",
    "dbb3d6b755d76e458c53844e93a694a5f791b81cb6f1c81822bfe897b1b42599",
    "865ad3ac91cde0c32a7d1e8ddc00a9fce4ce7cffdd8118e54e9ffbbe019bcea1",
    "431e1a493aa06bab0200fa43cf792f8329d4ed22f28563eea24c4986949cca5e",
    "75bbf00fd5437d3053dfc528eeb97b781350fca8f5cea20229017c6fd4d50d09",
    "1d4e1c5514bf53f12df4b277cb2b6ffd363d03fdaab439db9bcdb54b7c20166e",
    "b91046b0bc1decbdd70ca3914013e49839335c329016f613a3646f39ee03ac4c",
    "01616a00aa30eb73be7929ae5f18e41fca68302e9e81ef9783df2baf39595284",
    "ac27a182204551051e0de64910e95df8ad944ec093d3ae0aacd5bacf51a59362",
    "dec877e35f6c7f14361167e4d27472b404403775113d79b37c29d0332c446587",
];

fn hex32(h: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect();
    v.try_into().unwrap()
}

/// Zero-alloc receipt + byte identity over the wallet2 signed plaintext
/// (alloc face only: the signed-plain parser API is feature-gated; the
/// no-alloc face covers the derive path below on both faces):
/// the caller-pool parser and the Sink writer must run allocation-free.
#[cfg(feature = "alloc-fallback")]
#[test]
fn signed_plain_parse_reserialize_zero_alloc() {
    use shlosilo::chain::xmr::signed_txset::{
        decrypt_signed_txset, deserialize_signed_plain, PendingTx, SignedTxSetPools,
        TxKeyImageEntry,
    };
    use shlosilo::chain::xmr::unsigned_txset::{TxDestinationEntry, TxSourceEntry};

    // fixture materialization is allowed to allocate (Vec by contract)
    let plain = decrypt_signed_txset(GOLD_SIGNED, &LAB_VIEW_SK).expect("decrypt gold signed");

    let (result, allocs) = measured(|| {
        let mut p_txes = core::array::from_fn::<Option<PendingTx<'_>>, 2, _>(|_| None);
        let mut sel = [0u8; 64];
        let mut ki_str = [0u8; 4096];
        let mut dests =
            core::array::from_fn::<TxDestinationEntry, 16, _>(|_| TxDestinationEntry::default());
        let mut sources = core::array::from_fn::<Option<TxSourceEntry>, 32, _>(|_| None);
        let mut splitted =
            core::array::from_fn::<TxDestinationEntry, 64, _>(|_| TxDestinationEntry::default());
        let mut cons_sel = [0usize; 256];
        let mut extra = [0u8; 8192];
        let mut cons_dests =
            core::array::from_fn::<TxDestinationEntry, 64, _>(|_| TxDestinationEntry::default());
        let mut subidx = [0u32; 256];
        let mut key_images = [[0u8; 32]; 16];
        let mut tx_key_images =
            core::array::from_fn::<TxKeyImageEntry, 16, _>(|_| TxKeyImageEntry::default());
        let mut out = [0u8; 4096];

        let set = deserialize_signed_plain(
            &plain,
            &mut SignedTxSetPools {
                ptx: &mut p_txes,
                sel: &mut sel,
                ki_str: &mut ki_str,
                dests: &mut dests,
                sources: &mut sources,
                splitted: &mut splitted,
                cons_sel: &mut cons_sel,
                extra: &mut extra,
                cons_dests: &mut cons_dests,
                subidx: &mut subidx,
                key_images: &mut key_images,
                tx_key_images: &mut tx_key_images,
            },
        )
        .expect("parse wallet2 signed plain");
        let n = set.serialize_into(&mut out).expect("re-serialize");
        (n, out)
    });

    let (n, out) = result;
    assert_eq!(
        allocs, 0,
        "signed parse+reserialize must be allocation-free"
    );
    assert_eq!(n, plain.len(), "length identity");
    assert_eq!(&out[..n], &plain[..], "byte identity over wallet2 bytes");
}

/// Zero-alloc receipt + KAT over the derive path: deriving the one-time
/// input keys and key images of the real construction must be
/// allocation-free and match the pinned KI table.
#[test]
fn derive_key_images_zero_alloc() {
    use shlosilo::chain::xmr::subaddress::derive_input_from_source;
    use shlosilo::chain::xmr::unsigned_txset::{
        deserialize_unsigned_tx, TxConstructionData, TxDestinationEntry, TxSourceEntry,
        UnsignedTxPools,
    };

    let mut wire = [0u8; 2 + CONSTRUCTION.len()];
    wire[0] = 0x02;
    wire[1] = 0x01;
    wire[2..].copy_from_slice(CONSTRUCTION);

    // caller pools live outside the measured sections (stack only)
    let mut p_txes = core::array::from_fn::<Option<TxConstructionData<'_>>, 8, _>(|_| None);
    let mut p_src = core::array::from_fn::<Option<TxSourceEntry>, 32, _>(|_| None);
    let mut p_sd =
        core::array::from_fn::<TxDestinationEntry, 64, _>(|_| TxDestinationEntry::default());
    let mut p_sel = [0usize; 256];
    let mut p_ex = [0u8; 8192];
    let mut p_de =
        core::array::from_fn::<TxDestinationEntry, 64, _>(|_| TxDestinationEntry::default());
    let mut p_su = [0u32; 256];

    // One locked section: warm run + measured steady-state run. First-use
    // lazy inits (thread caches, LazyLock tables) land in the warm run by
    // design on some platforms; the RECEIPT is the steady-state run.
    // (CI 2026-10-29: the derive receipt caught 1 alloc under the jemalloc
    // wrapper with cross-test parallelism — warm-up outside the lock was
    // racy. Warm-up and measurement are now atomic under the serial lock.)
    let ((result, allocs_parse, allocs_steady), _total) = measured(|| {
        let before_parse = ALLOCS.load(Ordering::Relaxed);
        let utx = deserialize_unsigned_tx(
            &wire,
            UnsignedTxPools {
                txes: &mut p_txes,
                sources: &mut p_src,
                splitted_dsts: &mut p_sd,
                selected_transfers: &mut p_sel,
                extra: &mut p_ex,
                dests: &mut p_de,
                subaddr_indices: &mut p_su,
            },
        )
        .expect("parse 1023 construction");
        let parse_allocs = ALLOCS.load(Ordering::Relaxed) - before_parse;
        let derive_once = |utx: &shlosilo::chain::xmr::unsigned_txset::UnsignedTx<'_>| {
            let tx = utx.txes.iter().flatten().next().expect("one construction");
            let mut kis = [[0u8; 32]; 8];
            let mut n = 0usize;
            for src in tx.sources.iter().flatten() {
                let (image, _mask) = derive_input_from_source(
                    &TEST2_VIEW_SK,
                    &TEST2_SPEND_SK,
                    src,
                    tx.subaddr_account,
                    &tx.subaddr_indices,
                )
                .expect("derive input");
                kis[n] = image;
                n += 1;
            }
            let mut sel_arr = [0usize; 8];
            for (slot, t) in sel_arr.iter_mut().zip(tx.selected_transfers.iter()) {
                *slot = *t;
            }
            (kis, n, sel_arr)
        };
        let _ = derive_once(&utx); // warm run (first-use lazy inits land here)
        let before = ALLOCS.load(Ordering::Relaxed);
        let out = derive_once(&utx); // steady-state run = the receipt
        let derive_allocs = ALLOCS.load(Ordering::Relaxed) - before;
        (out, parse_allocs, derive_allocs)
    });

    let (kis, n, sel_arr) = result;
    assert_eq!(allocs_parse, 0, "parsing must be allocation-free");
    assert_eq!(
        allocs_steady, 0,
        "steady-state derivation must be allocation-free"
    );
    assert_eq!(n, 4, "the D-shape has four inputs");
    for (i, ki) in kis[..n].iter().enumerate() {
        assert_eq!(
            *ki,
            hex32(KI_HEX[sel_arr[i]]),
            "key image {} must match the pinned table",
            i
        );
    }
}
