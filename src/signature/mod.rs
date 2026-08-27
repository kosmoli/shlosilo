//! shlosilo L1 Layer B：签名 / 证明方案（独立密码学协议）
//!
//! **设计原则（v2 §2.2）**：
//! - ❌ 不定义 `SignatureScheme` trait（v2.2 删除 trait 决策）
//! - ✅ 用具体函数签名直接表达约束：`fn sign(sk: &Secp256k1Scalar, ...) -> EcdsaSignature`
//! - 类型签名直接绑定"签名方案配哪条曲线"——`&Secp256k1Scalar` 不能传给 `eddsa_ed25519::sign`
//! - 签名输出结构都实现 `Zeroize + ZeroizeOnDrop`（v2 §2.3 关键约束）
//!
//! **Phase 2.2 stub 范围**：
//! - 6 个签名模块 + mod.rs
//! - 每个模块：签名结构 + sign / verify 函数 + 函数体 `unimplemented!()`
//! - Phase 4 真实现：替换 unimplemented!() 为真实算法调用
//!   - `ecdsa_secp256k1` → k256
//!   - `schnorr_secp256k1` → secp256k1 crate
//!   - `eddsa_ed25519` → ed25519-dalek
//!   - `clsag_ed25519` → monero-oxide
//!   - `rsa_pss` → rsa
//!   - `fcmp_ed25519` → Phase 7 才真实实现

pub mod clsag_ed25519;
pub mod ecdsa_secp256k1;
pub mod eddsa_ed25519;
pub mod fcmp_ed25519;
pub mod rsa_pss;
pub mod schnorr_secp256k1;