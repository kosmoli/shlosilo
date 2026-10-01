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
    prove_tiny_bp_plus, provide_table_storage, GeneratorSet, GeneratorTableStorage,
};

#[test]
fn caller_storage_fills_reference_generators() {
    let reference = bulletproofs_generators(b"bulletproof_plus");
    let n_g = reference.G.len();
    let n_h = reference.H.len();
    assert_eq!(n_g + n_h, 2048, "generator set shape");

    // caller-owned 'static storage (device: static/PSRAM; here: leaked test memory)
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
        GeneratorTableStorage {
            g: g2,
            h: h2,
            blob: b2
        },
    ));
}

/// Z5.3: the caps byte-expressions must come from the SAME source of truth
/// as the scratch sizing (a stale expression silently turns every sign into
/// an explicit over-cap error — caught once as a full-suite red).
#[test]
fn bp_wip_bytes_match_storage_source_of_truth() {
    assert_eq!(
        shlosilo::types::caps::SIGN_WS_BP_WIP_BYTES,
        shlosilo::monero_bulletproofs::WipScratch::storage_bytes(
            shlosilo::types::caps::SIGN_WS_BP_TERMS
        ),
    );
}

/// T-04 follow-up: the straus pool is sized for the CHUNK capacity (the
/// chunked multiexp never holds more than the chunk in the scratch).
#[test]
fn bp_straus_bytes_match_storage_source_of_truth() {
    assert_eq!(
        shlosilo::types::caps::SIGN_WS_BP_STRAUS_BYTES,
        shlosilo::curve25519_dalek::scratch::StrausScratch::storage_bytes(
            shlosilo::types::caps::SIGN_WS_BP_CHUNK_MAX
        ),
    );
}

/// T-04 follow-up inv: the CN scratchpad OVERLAYS the straus+wip region —
/// same slot start, whole 2MB inside the region, region inside the ws.
#[test]
fn cn_overlay_shares_straus_slot_and_fits() {
    let l = shlosilo::business::sign::SignWsLayout::compute();
    assert_eq!(
        l.cn_scratch, l.bp_straus,
        "cn_scratch must start at the straus slot (overlay)"
    );
    let region = shlosilo::types::caps::SIGN_WS_BP_OVERLAY_BYTES;
    assert!(shlosilo::types::caps::SIGN_WS_CN_SCRATCH <= region);
    assert!(
        l.cn_scratch + shlosilo::types::caps::SIGN_WS_CN_SCRATCH <= l.total,
        "CN overlay must stay inside the workspace"
    );
    assert!(
        l.bp_wip + shlosilo::types::caps::SIGN_WS_BP_WIP_BYTES <= l.total,
        "WIP scratch must stay inside the workspace"
    );
}

/// T-04 follow-up inv: the workspace fits the forgebox PSRAM heap with
/// headroom (the v12 shape asked for 10.1MB and the host provision failed).
#[test]
fn sign_ws_len_fits_device_heap() {
    let total = shlosilo::business::sign::SignWsLayout::compute().total;
    assert!(
        total <= 3 * 1024 * 1024,
        "sign ws ({total} bytes) must fit the 8MB PSRAM heap alongside the \
         gencache provision (576KB), the QR decode pool (~410KB) and LVGL"
    );
}

/// T-04 follow-up inv: the chunk setter clamps to the cap the straus pool is
/// sized from (a larger chunk would make StrausScratch::new fail at prove).
#[test]
fn chunk_terms_clamp_to_ws_scratch_cap() {
    shlosilo::chain::xmr::set_bp_multiexp_chunk_terms(1000);
    assert_eq!(
        shlosilo::chain::xmr::bp_multiexp_chunk_terms(),
        shlosilo::types::caps::SIGN_WS_BP_CHUNK_MAX
    );
    shlosilo::chain::xmr::set_bp_multiexp_chunk_terms(12);
    assert_eq!(shlosilo::chain::xmr::bp_multiexp_chunk_terms(), 12);
}
