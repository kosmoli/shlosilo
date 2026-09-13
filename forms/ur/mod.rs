//! shlosilo L1 Layer E: UR encoding (UR-type-specific, accepts chain-agnostic data)
//!
//! **Design principles (v2 §2.5)**:
//! - BC-UR standard (CBOR + Fountain Codes multi-part)
//! - Each codec accepts chain-agnostic inputs (Bip32XPub / TxTemplate / AddressString etc.)
//! - Never touches private keys — xpub output carries only public keys
//!
//! **Phase 2.3 stub scope**:
//- 2 generic UR functions (ur_encode / ur_decode)
//- 7 codecs (6 BC-UR + 1 JSON-monero-viewkey)
//- Function bodies `unimplemented!()`; zcash_accounts returns `UnsupportedExportProtocol`
//!
//! **v2.4 security fix**: all codecs take borrow inputs (`&Bip32XPub` / `&DerivationPath` / `&Ed25519Scalar`),
//! with no cloned copies.

pub mod codec;
pub mod ur_decode;
pub mod ur_encode;
pub mod ur_multipart;
