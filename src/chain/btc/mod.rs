//! BTC 链业务模块
//!
//! Phase 5 v6 真实实现：P2WPKH 完整交易签名（BIP-143 segwit sighash + BIP-144 serialization）
//! Phase 5 v9.3 (2026-08-22): + P2PKH + P2SH-P2WPKH script type 签名
//! `p2pkh`: 旧式 P2PKH (BIP-16 之前, legacy sighash)；
//! `p2sh`: P2SH-P2WPKH (BIP-141 wrapped segwit, BIP-143 sighash + redeemScript)。
//! Phase 5 v9.4 (2026-08-22): + PSBT (BIP-174 Partially Signed Bitcoin Transaction) 解析/签名/序列化
//! Phase 5 v9.18 (2026-08-23): + summary（fee / RBF / locktime / CSV / 未知脚本）

pub mod p2pkh;
pub mod p2sh;
pub mod p2wpkh;
pub mod psbt;
pub mod taproot;
pub mod multisig;
pub mod musig2;
pub mod message_sign;
pub mod summary;
pub mod change_detect;