//! Z6 runtime receipt: the production sign paths perform ZERO heap
//! allocations in steady state (one warm-up call absorbs lazy static init —
//! the deploy shape provides all storage up front: SignWs caller memory +
//! generator tables via `provide_generator_table_storage`).
//!
//! Measured sections wrap ONLY the sign entry calls; fixture prep and storage
//! provisioning happen before the counter is armed. A single allocation in a
//! measured section fails the test.

use rand_core::SeedableRng as _;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static MEASURING: AtomicBool = AtomicBool::new(false);
static EVENTS: AtomicU64 = AtomicU64::new(0);
static CAPTURING: AtomicBool = AtomicBool::new(false);
static CAPTURED: AtomicU64 = AtomicU64::new(0);
static SITES: std::sync::Mutex<std::collections::BTreeMap<String, usize>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if MEASURING.load(Ordering::Relaxed) {
            EVENTS.fetch_add(1, Ordering::Relaxed);
        }
        if CAPTURING.load(Ordering::Relaxed) {
            // diagnosis only (first 200 sites — symbolization is slow). The
            // capture path allocates (backtrace + map growth), so guard the
            // re-entry or the map lock deadlocks against itself.
            thread_local! {
                static IN_CAPTURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
            }
            IN_CAPTURE.with(|flag| {
                if flag.get() {
                    return;
                }
                flag.set(true);
                // spread the sample over the WHOLE sign (every 20th alloc):
                // a leading window hides the bulk wherever it sits later.
                let k = CAPTURED.fetch_add(1, Ordering::Relaxed);
                if !k.is_multiple_of(1) {
                    flag.set(false);
                    return;
                }
                let bt = std::backtrace::Backtrace::force_capture();
                // innermost-first: the true site is the first frame in OUR
                // code (shlosilo OR the vendored crates) — earlier revisions
                // filtered to `shlosilo::` only and flattened every vendor
                // site into the outer wrapper.
                let text = format!("{bt}");
                let lines: Vec<&str> = text.lines().skip(1).collect();
                // first OUR-code frame + its `at file:line` line (debug builds)
                let mut frame = String::new();
                for (i, l) in lines.iter().enumerate() {
                    if l.contains("shlosilo::")
                        || l.contains("monero_bulletproofs::")
                        || l.contains("monero_clsag::")
                    {
                        frame.push_str(l.trim());
                        if let Some(at) = lines.get(i + 1) {
                            let at = at.trim();
                            if at.starts_with("at ") {
                                frame.push(' ');
                                frame.push_str(at);
                            }
                        }
                        break;
                    }
                }
                *SITES.lock().unwrap().entry(frame).or_insert(0) += 1;
                flag.set(false);
            });
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if MEASURING.load(Ordering::Relaxed) {
            EVENTS.fetch_add(1, Ordering::Relaxed);
        }
        System.dealloc(ptr, layout)
    }
}

/// Mirror the device path: provide the BP+ generator-table storage before the
/// first sign (the C-ABI callers do this at init; without it the vendored
/// LazyLock decompresses its own table — the one-time init allocs).
fn provide_generators_like_device() {
    use shlosilo::chain::xmr::generator_cache_test_hooks::{
        provide_table_storage, GeneratorSet, GeneratorTableStorage,
    };
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let n = 1024usize;
        let base = curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        let g: &'static mut [curve25519_dalek::EdwardsPoint] =
            Box::leak(vec![base; n].into_boxed_slice());
        let h: &'static mut [curve25519_dalek::EdwardsPoint] =
            Box::leak(vec![base; n].into_boxed_slice());
        let blob: &'static mut [u8] = Box::leak(vec![0u8; (n + n) * 128].into_boxed_slice());
        let _ = provide_table_storage(
            GeneratorSet::BulletproofPlus,
            GeneratorTableStorage { g, h, blob },
        );
    });
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn measured<T>(f: impl FnOnce() -> T) -> (T, u64) {
    EVENTS.store(0, Ordering::Relaxed);
    MEASURING.store(true, Ordering::Relaxed);
    let out = f();
    MEASURING.store(false, Ordering::Relaxed);
    (out, EVENTS.load(Ordering::Relaxed))
}

/// Z6-R2 (measured, tracked): the typed FFI sign entry (crypto-psbt fixture)
/// currently allocates 172 times per sign — the Z4-pending surface (PSBT
/// conveniences). Kept as the measuring instrument; green when the Z4
/// de-alloc lands. See the Z6 note in the audit ledger.
#[test]
fn bt_typed_sign_zero_alloc() {
    use shlosilo::ffi::c_abi::r3::shlosilo_sign_typed_ffi;
    use shlosilo::ffi::c_abi::shlosilo_sign_ws_len;

    const PSBT: &[u8] = include_bytes!("fixtures/sparrow_signet_12k.psbt");
    let payload = shlosilo::encoding::cbor::encode_bytes(PSBT);
    let ent: [u8; 16] = [
        0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29,
        0x16,
    ];
    let mnem = shlosilo::entropy::mnemonic::Mnemonic::from_entropy(&ent).unwrap();
    let idx: Vec<u16> = mnem.indices().to_vec();
    let mut out = vec![0u8; 16384 + 512];
    let mut actual: u32 = 0;
    let need = shlosilo_sign_ws_len();
    let mut ws_buf = vec![0u8; need as usize];
    let tname = c"crypto-psbt";

    // warm-up (lazy static init outside the measured section)
    let rc = shlosilo_sign_typed_ffi(
        tname.as_ptr(),
        payload.as_ptr(),
        payload.len() as u32,
        idx.as_ptr(),
        idx.len() as i32,
        core::ptr::null(),
        0,
        0,
        core::ptr::null(),
        0,
        out.as_mut_ptr(),
        out.len() as u32,
        &mut actual,
        ws_buf.as_mut_ptr(),
        need,
    );
    assert_eq!(rc, 0, "warm-up sign must succeed");

    let (rc, events) = measured(|| {
        shlosilo_sign_typed_ffi(
            tname.as_ptr(),
            payload.as_ptr(),
            payload.len() as u32,
            idx.as_ptr(),
            idx.len() as i32,
            core::ptr::null(),
            0,
            0,
            core::ptr::null(),
            0,
            out.as_mut_ptr(),
            out.len() as u32,
            &mut actual,
            ws_buf.as_mut_ptr(),
            need,
        )
    });
    assert_eq!(rc, 0, "measured sign must succeed");
    assert_eq!(events, 0, "Z6: the BT sign path allocated {events} time(s)");
}

/// Z6-R2: the XMR sign path (BP+/CLSAG/gencache) is alloc-free when the
/// deploy shape is used: caller storage provided (SignWs + generator tables).
/// Env-gated like p63 (real fixture keys).
#[test]
#[ignore = "Z6: requires SHLOSILO_TEST_XMR_* env (P2IN keys). Release form = zero-count receipt (0 allocs); debug form = relation shadow + re-sign byte-equality pin"]
fn xmr_sign_zero_alloc() {
    use shlosilo::chain::xmr::tx_signer::sign_tx_from_construction_with_rngs_into;
    use shlosilo::chain::xmr::unsigned_txset::{
        deserialize_unsigned_tx, TxConstructionData, TxDestinationEntry, TxSourceEntry,
        UnsignedTxPools,
    };

    fn env_hex(name: &str) -> Option<[u8; 32]> {
        let s = std::env::var(name).ok()?;
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect::<Option<_>>()?;
        v.try_into().ok()
    }
    let spend_sk = env_hex("SHLOSILO_TEST_XMR_SPEND_SK").expect("env");
    let view_sk = env_hex("SHLOSILO_TEST_XMR_VIEW_SK").expect("env");

    // generator tables: caller storage (deploy shape) — provisioning BEFORE
    // the measured section; the first use fills in place (no allocation)
    let reference = monero_bulletproofs_generators::bulletproofs_generators(b"bulletproof_plus");
    let (n_g, n_h) = (reference.G.len(), reference.H.len());
    let g: &'static mut [curve25519_dalek::EdwardsPoint] = Box::leak(
        vec![curve25519_dalek::constants::ED25519_BASEPOINT_POINT; n_g].into_boxed_slice(),
    );
    let h: &'static mut [curve25519_dalek::EdwardsPoint] = Box::leak(
        vec![curve25519_dalek::constants::ED25519_BASEPOINT_POINT; n_h].into_boxed_slice(),
    );
    let blob: &'static mut [u8] = Box::leak(vec![0u8; (n_g + n_h) * 128].into_boxed_slice());
    assert!(
        shlosilo::chain::xmr::generator_cache_test_hooks::provide_table_storage(
            shlosilo::chain::xmr::generator_cache_test_hooks::GeneratorSet::BulletproofPlus,
            shlosilo::chain::xmr::generator_cache_test_hooks::GeneratorTableStorage { g, h, blob },
        )
    );

    // fixture: the A'-wallet 2-input encrypted txset (p64 era) — decrypted
    // with the view key, then parsed into caller pools (deploy shape)
    const ENC: &[u8] = include_bytes!("fixtures/unsigned_txset_2in.bin");
    let plain = shlosilo::chain::xmr::unsigned_txset::decrypt_unsigned_txset(ENC, &view_sk)
        .expect("decrypt 2-input fixture");
    let mut p_txes = core::array::from_fn::<Option<TxConstructionData<'_>>, 8, _>(|_| None);
    let mut p_src = core::array::from_fn::<Option<TxSourceEntry>, 32, _>(|_| None);
    let mut p_sd =
        core::array::from_fn::<TxDestinationEntry, 64, _>(|_| TxDestinationEntry::default());
    let mut p_sel = [0usize; 256];
    let mut p_ex = [0u8; 8192];
    let mut p_de =
        core::array::from_fn::<TxDestinationEntry, 64, _>(|_| TxDestinationEntry::default());
    let mut p_su = [0u32; 256];
    let utx = deserialize_unsigned_tx(
        &plain,
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
    .expect("deserialize");
    let tx_data = utx.txes.iter().flatten().next().unwrap();

    let r_bytes = zeroize::Zeroizing::new([0x11u8; 32]);

    // warm-up (generators fill in place; lazy statics settle)
    let mut bp_rng = rand_chacha::ChaCha20Rng::from_seed([0xB1u8; 32]);
    let mut clsag_rng = rand_chacha::ChaCha20Rng::from_seed([0xC1u8; 32]);
    let mut out = vec![0u8; 65536];
    let mut bp_terms = vec![
        (
            curve25519_dalek::Scalar::ZERO,
            curve25519_dalek::constants::ED25519_BASEPOINT_POINT,
        );
        shlosilo::types::caps::SIGN_WS_BP_TERMS
    ];
    let mut bp_straus_storage = vec![
        0u8;
        curve25519_dalek::scratch::StrausScratch::storage_bytes(
            shlosilo::types::caps::SIGN_WS_BP_TERMS
        )
    ];
    let mut bp_straus = curve25519_dalek::scratch::StrausScratch::new(
        &mut bp_straus_storage,
        shlosilo::types::caps::SIGN_WS_BP_TERMS,
    )
    .expect("sized storage");
    let mut wip_storage =
        vec![
            0u8;
            monero_bulletproofs::WipScratch::storage_bytes(shlosilo::types::caps::SIGN_WS_BP_TERMS)
        ];
    let mut wip_scratch = monero_bulletproofs::WipScratch::new(
        &mut wip_storage,
        shlosilo::types::caps::SIGN_WS_BP_TERMS,
    )
    .expect("wip storage");

    let n = sign_tx_from_construction_with_rngs_into(
        tx_data,
        &spend_sk,
        &view_sk,
        &r_bytes,
        &mut bp_rng,
        &mut clsag_rng,
        &mut out,
        &mut bp_terms,
        &mut bp_straus,
        &mut wip_scratch,
    )
    .expect("warm-up sign");
    assert!(n > 0);
    // Z6 regression pin: the measured sign REUSES the same WipScratch, so the
    // two runs must be byte-identical (fixed RNG seeds + same fixture). A
    // stale-scratch read-modify-write in the prove path (the C-cut E d-accident)
    // only strikes on the second-and-later prove and shows up right here.
    let warmup_bytes = out[..n].to_vec();

    let mut bp_rng = rand_chacha::ChaCha20Rng::from_seed([0xB1u8; 32]);
    let mut clsag_rng = rand_chacha::ChaCha20Rng::from_seed([0xC1u8; 32]);
    let (n2, events) = measured(|| {
        sign_tx_from_construction_with_rngs_into(
            tx_data,
            &spend_sk,
            &view_sk,
            &r_bytes,
            &mut bp_rng,
            &mut clsag_rng,
            &mut out,
            &mut bp_terms,
            &mut bp_straus,
            &mut wip_scratch,
        )
        .expect("measured sign")
    });
    assert_eq!(
        &out[..n2],
        &warmup_bytes[..],
        "Z6: reusing the WipScratch must be deterministic (byte-identical re-sign)"
    );
    // The zero-count receipt is RELEASE-form: under debug_assertions the
    // relation shadow in wip::prove stages its own Vecs and would count
    // against the budget. The debug form of this test is still meaningful —
    // the shadow's relation assert runs on both signs and the byte-equality
    // pin above holds.
    if !cfg!(debug_assertions) {
        assert_eq!(
            events, 0,
            "Z6: the XMR sign path allocated {events} time(s)"
        );
    }
}

/// Z4 diagnosis: allocation-site histogram over one XMR sign (ignored; the
/// backtrace capture allocates, so this measures SITES, not counts).
#[test]
#[ignore = "Z4 diagnosis: run manually with P2IN keys to profile alloc sites"]
fn alloc_site_histogram() {
    provide_generators_like_device();
    // Reuse the XMR fixture flow (duplicated minimally to keep this file's
    // helpers independent of test order).
    fn env_hex(name: &str) -> Option<[u8; 32]> {
        let s = std::env::var(name).ok()?;
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect::<Option<_>>()?;
        v.try_into().ok()
    }
    use shlosilo::chain::xmr::tx_signer::sign_tx_from_construction_with_rngs_into;
    use shlosilo::chain::xmr::unsigned_txset::{
        decrypt_unsigned_txset, deserialize_unsigned_tx, TxConstructionData, TxDestinationEntry,
        TxSourceEntry, UnsignedTxPools,
    };
    let spend_sk = env_hex("SHLOSILO_TEST_XMR_SPEND_SK").expect("env");
    let view_sk = env_hex("SHLOSILO_TEST_XMR_VIEW_SK").expect("env");
    const ENC: &[u8] = include_bytes!("fixtures/unsigned_txset_2in.bin");
    let plain = decrypt_unsigned_txset(ENC, &view_sk).expect("decrypt");
    let mut p_txes = core::array::from_fn::<Option<TxConstructionData<'_>>, 8, _>(|_| None);
    let mut p_src = core::array::from_fn::<Option<TxSourceEntry>, 32, _>(|_| None);
    let mut p_sd =
        core::array::from_fn::<TxDestinationEntry, 64, _>(|_| TxDestinationEntry::default());
    let mut p_sel = [0usize; 256];
    let mut p_ex = [0u8; 8192];
    let mut p_de =
        core::array::from_fn::<TxDestinationEntry, 64, _>(|_| TxDestinationEntry::default());
    let mut p_su = [0u32; 256];
    let utx = deserialize_unsigned_tx(
        &plain,
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
    .expect("deserialize");
    let tx_data = utx.txes.iter().flatten().next().unwrap();
    let r_bytes = zeroize::Zeroizing::new([0x11u8; 32]);
    let mut bp_rng = rand_chacha::ChaCha20Rng::from_seed([0xB1u8; 32]);
    let mut clsag_rng = rand_chacha::ChaCha20Rng::from_seed([0xC1u8; 32]);
    let mut out = vec![0u8; 65536];
    let mut bp_terms = vec![
        (
            curve25519_dalek::Scalar::ZERO,
            curve25519_dalek::constants::ED25519_BASEPOINT_POINT,
        );
        shlosilo::types::caps::SIGN_WS_BP_TERMS
    ];
    let mut bp_straus_storage = vec![
        0u8;
        curve25519_dalek::scratch::StrausScratch::storage_bytes(
            shlosilo::types::caps::SIGN_WS_BP_TERMS
        )
    ];
    let mut bp_straus = curve25519_dalek::scratch::StrausScratch::new(
        &mut bp_straus_storage,
        shlosilo::types::caps::SIGN_WS_BP_TERMS,
    )
    .expect("sized storage");
    let mut wip_storage =
        vec![
            0u8;
            monero_bulletproofs::WipScratch::storage_bytes(shlosilo::types::caps::SIGN_WS_BP_TERMS)
        ];
    let mut wip_scratch = monero_bulletproofs::WipScratch::new(
        &mut wip_storage,
        shlosilo::types::caps::SIGN_WS_BP_TERMS,
    )
    .expect("wip storage");

    CAPTURED.store(0, Ordering::Relaxed);
    CAPTURING.store(true, Ordering::Relaxed);
    let _ = sign_tx_from_construction_with_rngs_into(
        tx_data,
        &spend_sk,
        &view_sk,
        &r_bytes,
        &mut bp_rng,
        &mut clsag_rng,
        &mut out,
        &mut bp_terms,
        &mut bp_straus,
        &mut wip_scratch,
    )
    .expect("sign");
    CAPTURING.store(false, Ordering::Relaxed);

    let mut sites: Vec<(usize, String)> = SITES
        .lock()
        .unwrap()
        .iter()
        .map(|(k, v)| (*v, k.clone()))
        .collect();
    sites.sort_by_key(|(n, _)| std::cmp::Reverse(*n));
    println!(
        "=== Z4 alloc site histogram (top 25 of {}) ===",
        sites.len()
    );
    for (n, site) in sites.iter().take(25) {
        println!("{n:>6}  {site}");
    }
}
