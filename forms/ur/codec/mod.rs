//! UR codec submodule collection
//!
//! Each codec accepts chain-agnostic inputs (Bip32XPub / TxTemplate etc.),
//! Outputs chain-specific UR payload bytes (CBOR encoded).

pub mod arweave_crypto_account;
pub mod bytes;
pub mod crypto_account;
pub mod crypto_hd_key;
pub mod crypto_multi_accounts;
pub mod crypto_psbt;
pub mod eth_sign_request;
pub mod json_monero_viewkey;
pub mod zcash_accounts;
