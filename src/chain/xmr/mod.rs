//! XMR 链业务模块
//!
//! Phase 5 v4 真实实现：reduce_scalar + Pedersen commitment + CLSAG 签名
//! Phase 5 v9.5 (2026-08-22):
//! transaction 模块 (Phase A 基础设施)、rct_sig 模块 (Phase B RingCT 集成)、
//! tx_builder 模块 (Phase C 端到端构造+签名+序列化)。
//! Phase 5 v9.19: view_tag + encrypted payment ID + payment proof

pub mod clsag;
pub mod commitment;
pub mod rct_sig;
pub mod reduce_scalar;
pub mod signed_txset;
pub mod signing_rng;
pub mod subaddress;
pub mod transaction;
pub mod tx_builder;
pub mod tx_signer;
pub mod key_image_export;
pub mod output_export;
pub mod unsigned_txset;
pub mod view_tag;