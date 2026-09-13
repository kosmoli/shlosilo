//! shlosilo L1 Layer A: curve primitives (chain-agnostic)
//!
//! **Design principles (v2 §2.1)**:
//! - only curve math: add / scalar_mul / base_mul / bilinear pairings
//! - one codebase serves BTC, ETH, SOL, XMR, ZEC (as needed)
//! - **`Scalar` forbids `Copy`** — Copy types passed by value leave "byte copies" on the call stack,
//!   and zeroize can only clear the copy in the current stack frame (v2 §2.1 v2.x Gemini review security fix)
//! - **`Point` allows `Copy + Eq`** — public keys are public verification material, not keys
//! - **Type naming convention**: `{Curve}Scalar` / `{Curve}Point` — cross-curve code reads the type name and knows the curve
//!
//! Phase 2.1 stub scope:
//! - 5 files: secp256k1 / ed25519 / rsa / p256 + this mod.rs
//! - per file: `{Curve}Scalar` + `{Curve}Point` + free functions (`unimplemented!()`) + `#[should_panic]` tests
//! - Phase 4 replaces `unimplemented!()` with real algorithm calls (`k256` / `curve25519-dalek` / etc.)

pub mod ed25519;
pub mod p256;
pub mod rsa;
pub mod secp256k1;
