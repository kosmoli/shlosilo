//! shlosilo L1 派生模块（Layer C）
//!
//! **设计原则（v2 §2.3）**：
//! - 派生方案通过私钥的**具体类型**绑定曲线：`bip32_secp256k1::derive` 返回 `Secp256k1Scalar`
//! - 业务层拿到 `Secp256k1Scalar` 后只能传给 `ecdsa_secp256k1::sign` 或 `base_mul`……（编译期拒绝错误路径）
//! - 多私钥链用聚合结构：`MoneroKeyPair { spend_priv, view_priv }` / `CardanoExtSk { spend, stake?, drep?, ccl? }`
//! - 业务模块是唯一持有完整聚合结构的位置——签名方案只接收 `&Ed25519Scalar`，由业务代码解构
//!
//! **Phase 2.2 stub 范围**：
//! - 5 个派生模块 + path.rs（Phase 2.0 已落地）
//! - 每个模块：返回类型 + derive 函数 + 函数体 `unimplemented!()`
//! - Phase 4 真实现：替换 unimplemented!() 为真实算法调用
//!   - `bip32_secp256k1` → bip32 crate
//!   - `slip10_ed25519` → slip10 crate
//!   - `icarus_ed25519` → cardano crate
//!   - `monero_reduce_scalar` → monero-oxide
//!   - `bip32_secp256k1_multisig` → v1 不支持，直接返回 `MultisigNotSupported`
//!
//! **Phase 8+ 待补**：
//!   - `sr25519.rs`（Substrate 签名栈）
//!   - `bip32_secp256k1_multisig.rs` 真实实现

pub mod bip32_secp256k1;
pub mod bip32_secp256k1_multisig;
pub mod icarus_ed25519;
pub mod monero_reduce_scalar;
pub mod path;
pub mod slip10_ed25519;
