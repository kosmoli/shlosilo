//! shlosilo L1 derivation module (Layer C)
//!
//! **Design principles (v2 §2.3)**:
//! - Derivation schemes bind the curve via the private key's **concrete type**: `bip32_secp256k1::derive` returns `Secp256k1Scalar`
//! - Once the business layer holds a `Secp256k1Scalar`, it can only pass it to `ecdsa_secp256k1::sign` or `base_mul`… (wrong paths rejected at compile time)
//! - Multi-key chains use aggregate structures: `MoneroKeyPair { spend_priv, view_priv }` / `CardanoExtSk { spend, stake?, drep?, ccl? }`
//! - Business modules are the only place holding the complete aggregate structures — signing schemes only receive `&Ed25519Scalar`, destructured by business code
//!
//! **Phase 2.2 stub scope**:
//! - 5 derivation modules + path.rs (landed in Phase 2.0)
//! - Each module: return type + derive function + a `unimplemented!()` body
//! - Phase 4 real implementation: replace unimplemented!() with real algorithm calls
//!   - `bip32_secp256k1` → bip32 crate
//!   - `slip10_ed25519` → slip10 crate
//!   - `icarus_ed25519` → cardano crate
//!   - `monero_reduce_scalar` → monero-oxide
//!   - `bip32_secp256k1_multisig` → unsupported in v1; returns `MultisigNotSupported` directly
//!
//! **Deferred to Phase 8+**:
//!   - `sr25519.rs` (the Substrate signing stack)
//!   - a real `bip32_secp256k1_multisig.rs` implementation

pub mod bip32_secp256k1;
pub mod bip32_secp256k1_multisig;
pub mod icarus_ed25519;
pub mod monero_reduce_scalar;
pub mod path;
pub mod slip10_ed25519;
