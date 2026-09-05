//! XMR chain business module
//!
//! Phase 5 v4 real implementation: reduce_scalar + Pedersen commitment + CLSAG signatures
//! Phase 5 v9.5 (2026-08-22):
//! transaction module (Phase A infrastructure), rct_sig module (Phase B RingCT integration),
//! tx_builder module (Phase C end-to-end construct+sign+serialize).
//! Phase 5 v9.19: view_tag + encrypted payment ID + payment proof

pub mod clsag;
pub mod commitment;
pub mod key_image_export;
pub mod output_export;
pub mod rct_sig;
pub mod reduce_scalar;
pub mod signed_txset;
pub mod signing_rng;
pub mod subaddress;
pub mod transaction;
pub mod tx_builder;
pub mod tx_signer;
pub mod unsigned_txset;
pub mod view_tag;
