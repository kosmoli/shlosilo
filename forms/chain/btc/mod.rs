//! BTC chain business module
//!
//! Phase 5 v6 real implementation: full P2WPKH transaction signing (BIP-143 segwit sighash + BIP-144 serialization)
//! Phase 5 v9.3 (2026-08-22): + P2PKH + P2SH-P2WPKH script type signing
//! `p2pkh`: old-style P2PKH (pre-BIP-16, legacy sighash);
//! `p2sh`: P2SH-P2WPKH (BIP-141 wrapped segwit, BIP-143 sighash + redeemScript).
//! Phase 5 v9.4 (2026-08-22): + PSBT (BIP-174 Partially Signed Bitcoin Transaction) parse/sign/serialize
//! Phase 5 v9.18 (2026-08-23): + summary (fee / RBF / locktime / CSV / unknown scripts)

pub mod change_detect;
#[cfg(feature = "alloc-fallback")]
pub mod message_sign;
#[cfg(feature = "alloc-fallback")]
pub mod multisig;
#[cfg(feature = "alloc-fallback")]
pub mod musig2;
#[cfg(feature = "alloc-fallback")]
pub mod p2pkh;
#[cfg(feature = "alloc-fallback")]
pub mod p2sh;
pub mod p2wpkh;
pub mod psbt;
pub mod summary;
#[cfg(feature = "alloc-fallback")]
pub mod taproot;
