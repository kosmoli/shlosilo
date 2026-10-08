//! shlosilo business module entry (v2 §4.3)
//!
//! Phase 2.0: only type signatures + unimplemented!() stubs
//! Phase 4 wiring: fill in the real algorithm implementations (k256 / curve25519-dalek / monero-oxide)

pub mod create_account;
pub mod export_readonly;
pub mod restore_seed;
pub mod sign;
/// Cake direct pairing receive leg. The chain layer it wraps
/// (`chain::xmr::key_image_export`) derives the container ChaCha key with
/// CryptoNight-V0 over the caller-provided workspace scratchpad
/// (`PairingWs` carries the `cn_scratch` region), so the whole receive chain
/// is alloc-free — the FFI entry is the real body on every face.
pub mod xmr_pairing;
