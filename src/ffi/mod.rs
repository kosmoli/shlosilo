//! FFI module — C-ABI shim for L3 imperative shell
//!
//! **Phase 2.5 stub scope**:
//! - `c_abi.rs` 4 extern "C" functions (sign / export_readonly / create_account / restore_seed)
//! - `error_code.rs` ShlosiloError → i32 conversion
//! - `version.rs` version string
//! - L3 finds these symbols via dlsym/dlopen
//!
//! **v2.4 security constraints (v2 §4.1 invariants)**:
//! - ❌ **the seed never crosses the FFI boundary** — the business function signature `seed: &[u8; 64]` is not exposed
//! - ✅ FFI accepts `mnemonic_indices: *const u16` + `len` + `passphrase: *const u8`
//! - L2b internally calls `bip39_passphrase::mnemonic_to_seed(&mnemonic, passphrase)` to produce the seed
//! - **raw private key pointers are never exposed** — only public outputs (signed tx bytes / xpub)

pub mod c_abi;
#[cfg(feature = "cn-timing-ffi")]
pub mod cn_timing_ffi;
pub mod error_code;
/// BP+ generator cache FFI hooks (device flash backend). See module docs.
#[cfg(feature = "generator-cache-ffi")]
pub mod generator_cache_ffi;
/// BP+ prove-phase timing FFI (device perf decomposition). See module docs.
#[cfg(feature = "prove-timing-ffi")]
pub mod prove_timing_ffi;
pub mod version;
