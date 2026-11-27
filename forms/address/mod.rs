//! shlosilo L1 Layer D: address encoding (chain-specific, shared encoding primitives)
//!
//! **Design principles (v2 §2.4)**:
//! - accepts public material (`&Secp256k1Point` / `&Ed25519Point` / `&RsaPubKey`), never touches private keys
//! - returns an owned `AddressString` (`heapless::String<N>`); business modules take it as needed
//! - Phase 4 wires in encoding primitives like `bech32` / `base58` / `keccak256` / `ripemd160` / `sha256`
//!
//! **Phase 2.3 stub scope**:
//! - 10 address encoding modules
//! - each module: address string struct + `encode` function + `unimplemented!()` body
//! - Phase 4 real implementation: replaces unimplemented!() with real algorithm calls
//!
//! **v2.4 security fix**: every `encode` function takes the pubkey parameter by borrow, never cloning a copy.
//! Business modules lend via `&Point` — Layer D only gets a borrow and never holds an owned pubkey copy.
//!
//! **Debug privacy**: the address struct's Debug output never leaks the full address (shows only the first 6 and last 4 characters),
//! Prevents debug logs from accidentally exposing user addresses.

/// Primitive axis (S9 batch B): the `*_ed25519` encoders take `&Ed25519Point`.
#[cfg(feature = "prim-ed25519")]
pub mod aptos_sui;
pub mod arweave;
pub mod btc_legacy;
pub mod btc_script;
pub mod btc_segwit;
#[cfg(feature = "prim-ed25519")]
pub mod cardano;
pub mod eth;
#[cfg(feature = "prim-ed25519")]
pub mod sol;
pub mod tron;
/// Owned by `prim-base58-monero` (the audited block-wise base58 crate) and, through the
/// `Ed25519Point` payload it encodes, by `prim-ed25519`. Debt D1's positive side.
/// Both features are required: `prim-base58-monero`-alone was measured to fail here
/// (`use crate::curve_primitive::ed25519::…` with the curve absent), and a declaration
/// that names only the encoding primitive has no business compiling an address encoder.
#[cfg(all(feature = "prim-base58-monero", feature = "prim-ed25519"))]
pub mod xmr;
pub mod xrp;
