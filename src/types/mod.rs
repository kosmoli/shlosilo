//! shlosilo L1 共享类型
//!
//! Phase 2.0 仅含 chain_kind.rs；后续 Phase 2.1+ 加：
//!   - curve.rs（Curve enum：标识曲线族）
//!   - 其他共享类型

pub mod chain_kind;
pub mod secret_bytes;

pub use secret_bytes::SecretBytes;
