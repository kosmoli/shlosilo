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

pub mod aptos_sui;
pub mod arweave;
pub mod btc_legacy;
pub mod btc_segwit;
pub mod cardano;
pub mod eth;
pub mod sol;
pub mod tron;
pub mod xmr;
pub mod xrp;
