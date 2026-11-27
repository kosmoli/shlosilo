//! shlosilo L1 Layer B: signature / proof schemes (independent cryptographic protocols)
//!
//! **Design principles (v2 §2.2)**:
//! - ❌ No `SignatureScheme` trait (v2.2 decision to drop traits)
//! - ✅ Express constraints directly with concrete function signatures: `fn sign(sk: &Secp256k1Scalar, ...) -> EcdsaSignature`
//! - type signatures directly bind "which curve a signing scheme uses" — `&Secp256k1Scalar` cannot be passed to `eddsa_ed25519::sign`
//! - all signature output structs implement `Zeroize + ZeroizeOnDrop` (key constraint from v2 §2.3)
//!
//! **Phase 2.2 stub scope**:
//! - 6 signature modules + mod.rs
//! - each module: signature struct + sign / verify functions + `unimplemented!()` bodies
//! - Phase 4 real implementation: replaces unimplemented!() with real algorithm calls
//!   - `ecdsa_secp256k1` → k256
//!   - `schnorr_secp256k1` → secp256k1 crate
//!   - `eddsa_ed25519` → ed25519-dalek
//!   - `clsag_ed25519` → monero-oxide
//!   - `rsa_pss` → rsa
//!   - `fcmp_ed25519` → real implementation deferred to Phase 7

// Primitive axis (S9 batch B): the three Ed25519 schemes take `&Ed25519Scalar` /
// `&Ed25519Point`, so they follow the curve primitive that owns those types (and the two
// dalek crates behind them). The secp256k1 / RSA files are untouched.
#[cfg(feature = "prim-ed25519")]
pub mod clsag_ed25519;
pub mod ecdsa_secp256k1;
#[cfg(feature = "prim-ed25519")]
pub mod eddsa_ed25519;
#[cfg(feature = "prim-ed25519")]
pub mod fcmp_ed25519;
pub mod rsa_pss;
pub mod schnorr_secp256k1;
