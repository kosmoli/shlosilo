//! ETH 链业务模块
//!
//! Phase 5 v9.0 (2026-08-22): 清理 EIP-2930 + EIP-4844 (移 `src/_experimental/`)
//! Phase 5 v9.1 (2026-08-22): + EIP-712 typed data signing
//! Phase 5 v9.1.1 (2026-08-22): + EIP-712 JSON v4 parser + human-readable v1
//! Phase 5 v9.2 (2026-08-22): + personal_sign (EIP-191 v0x45)
//! Phase 5 v9.17 (2026-08-23): + calldata ABI 解码（ERC-20 + 721/1155 selector）
//! Phase 5 v9.18 (2026-08-23): + tx summary（确认屏风险摘要）
//! Phase 5 v8.1: + EIP-1559 fee market
//!
//! **v9 正式项目范围**: EIP-155 + EIP-1559 + EIP-712 + personal_sign (其余 EIP 待 v9.3+)

pub mod calldata;
pub mod eip155;
pub mod eip1559;
pub mod eip712;
pub mod from_rlp;
pub mod personal_sign;
pub mod rlp;
pub mod sign;
pub mod summary;
