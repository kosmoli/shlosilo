//! UR codec submodule collection
//!
//! Each codec accepts chain-agnostic inputs (Bip32XPub / TxTemplate etc.),
//! Outputs chain-specific UR payload bytes (CBOR encoded).

pub mod account_text;
pub mod arweave_crypto_account;
pub mod bytes;
pub mod crypto_account;
pub mod crypto_hd_key;
#[cfg(any(feature = "alloc-fallback", test))]
pub mod crypto_psbt;
pub mod eth_sign_request;
pub mod json_monero_viewkey;
pub mod zcash_accounts;
