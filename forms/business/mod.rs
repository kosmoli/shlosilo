//! shlosilo business module entry (v2 §4.3)
//!
//! Phase 2.0: only type signatures + unimplemented!() stubs
//! Phase 4 wiring: fill in the real algorithm implementations (k256 / curve25519-dalek / monero-oxide)

pub mod create_account;
pub mod export_readonly;
pub mod restore_seed;
pub mod sign;
/// Cake direct pairing receive leg. The chain layer it wraps
/// (`chain::xmr::key_image_export`) requires the alloc-backed CryptoNight
/// scratchpad (`cuprate_cryptonight::cryptonight_hash_v0`), so this module rides
/// the same alloc-fallback gate — the FFI entry carries a stable-error stub on
/// the no-alloc face.
#[cfg(feature = "alloc-fallback")]
pub mod xmr_pairing;
