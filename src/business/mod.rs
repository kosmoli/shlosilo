//! shlosilo 业务模块入口（v2 §4.3）
//!
//! Phase 2.0：仅定义类型签名 + unimplemented!() stub
//! Phase 4 接入：填实际算法实现（k256 / curve25519-dalek / monero-oxide）

pub mod create_account;
pub mod export_readonly;
pub mod restore_seed;
pub mod sign;
