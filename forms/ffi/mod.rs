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
/// Diagnostic FFI modules. They are compiled UNCONDITIONALLY: each one carries
/// `#[cfg(feature = ...)]` on its real implementations and `#[cfg(not(feature))]`
/// no-op stubs, so the C host always links (the stubs' whole point). Gating the
/// module itself would drop the stubs too, which is what the previous layout did
/// by mistake (audit #15 P1-01).
pub mod cn_timing_ffi;
pub mod error_code;
/// BP+ generator cache FFI hooks (device flash backend). See module docs.
pub mod generator_cache_ffi;
/// Device primitive perf-bench FFI (raw per-op costs). See module docs.
pub mod perf_bench_ffi;
/// BP+ prove-phase timing FFI (device perf decomposition). See module docs.
pub mod prove_timing_ffi;
pub mod tx_phase_ffi;
pub mod version;
