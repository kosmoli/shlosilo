//! XMR chain business module
//!
//! Phase 5 v4 real implementation: reduce_scalar + Pedersen commitment + CLSAG signatures
//! Phase 5 v9.5 (2026-08-22):
//! transaction module (Phase A infrastructure), rct_sig module (Phase B RingCT integration),
//! tx_builder module (Phase C end-to-end construct+sign+serialize).
//! Phase 5 v9.19: view_tag + encrypted payment ID + payment proof

pub mod clsag;

/// BP+ multiexp chunk size in terms — a *per-call* choice recorded on the
/// caller's `StrausScratch` (`with_chunk_terms`), never a process-wide value.
/// Table bytes = n x 1280B; each carrier picks the largest chunk whose table
/// fits its fastest memory (forgebox SRAM pool 48K -> 36; pico2 SRAM heap
/// 16K routing -> 12). Clamped to `caps::SIGN_WS_BP_CHUNK_MAX` at the point
/// the scratch is built, because the workspace straus region is sized from
/// that cap. See `vendor/monero-bulletproofs/src/core.rs`.
pub mod commitment;
/// Test-only hooks for the BP+ generator cache (`#[doc(hidden)]`, not public API).
#[cfg(feature = "std")]
#[doc(hidden)]
#[cfg(any(feature = "alloc-fallback", test))]
pub mod generator_cache_test_hooks;
// Zero-alloc on every face since the pairing campaign: the CN key derivation
// rides the caller's `cn_scratch` (`_into` cores); the Vec conveniences keep
// their alloc-fallback gate inside the module.
pub mod key_image_export;
pub mod output_export;
pub mod rct_sig;
/// Path alias for the shared ed25519 scalar reduction. The implementation lives in
/// `curve_primitive::scalar_reduce` (it is a curve operation, not XMR wire semantics,
/// and the un-gated derivation/session/export faces need it) — see that module's docs
/// for why the chain axis pushed it out of this tree.
pub use crate::curve_primitive::scalar_reduce as reduce_scalar;
pub mod signed_txset;
pub mod signing_rng;
pub mod subaddress;
pub mod transaction;
pub mod tx_builder;
pub mod tx_signer;
pub mod unsigned_txset;
pub mod view_tag;
