//! FFI module — C-ABI shim for L3 imperative shell
//!
//! **Phase 2.5 stub 范围**：
//! - `c_abi.rs` 4 个 extern "C" 函数（sign / export_readonly / create_account / restore_seed）
//! - `error_code.rs` ShlosiloError → i32 转换
//! - `version.rs` 版本字符串
//! - L3 通过 dlsym/dlopen 找这些符号
//!
//! **v2.4 安全约束（v2 §4.1 不变量）**：
//! - ❌ **seed 不跨 FFI boundary**——业务函数签名 `seed: &[u8; 64]` 不暴露
//! - ✅ FFI 接受 `mnemonic_indices: *const u16` + `len` + `passphrase: *const u8`
//! - L2b 在内部调 `bip39_passphrase::mnemonic_to_seed(&mnemonic, passphrase)` 转 seed
//! - **不暴露 raw private key 指针**——只有公开输出（signed tx bytes / xpub）

pub mod c_abi;
pub mod error_code;
pub mod version;
