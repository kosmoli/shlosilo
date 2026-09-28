//! XMR chain business module
//!
//! Phase 5 v4 real implementation: reduce_scalar + Pedersen commitment + CLSAG signatures
//! Phase 5 v9.5 (2026-08-22):
//! transaction module (Phase A infrastructure), rct_sig module (Phase B RingCT integration),
//! tx_builder module (Phase C end-to-end construct+sign+serialize).
//! Phase 5 v9.19: view_tag + encrypted payment ID + payment proof

pub mod clsag;

/// BP+ multiexp chunk size (per-platform memory-placement tuning; see
/// `vendor/monero-bulletproofs/src/core.rs`). Table bytes = n x 1280B; each
/// host picks the largest chunk whose table fits its fastest memory
/// (forgebox SRAM pool 48K -> 36; pico2 SRAM heap 16K routing -> 12).
/// Default 36; call once at boot.
pub fn set_bp_multiexp_chunk_terms(n: usize) {
    monero_bulletproofs::set_multiexp_chunk_terms(n);
}

/// Current BP+ multiexp chunk size in terms (default 36).
#[must_use]
pub fn bp_multiexp_chunk_terms() -> usize {
    monero_bulletproofs::multiexp_chunk_terms()
}
pub mod commitment;
/// Test-only hooks for the BP+ generator cache (`#[doc(hidden)]`, not public API).
#[cfg(feature = "std")]
#[doc(hidden)]
#[cfg(feature = "alloc-fallback")]
pub mod generator_cache_test_hooks;
#[cfg(feature = "alloc-fallback")]
pub mod key_image_export;
pub mod output_export;
pub mod rct_sig;
pub mod reduce_scalar;
pub mod signed_txset;
pub mod signing_rng;
pub mod subaddress;
pub mod transaction;
pub mod tx_builder;
pub mod tx_signer;
pub mod unsigned_txset;
pub mod view_tag;
