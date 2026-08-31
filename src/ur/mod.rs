//! shlosilo L1 Layer E：UR 编码（UR-type-specific, 接受 chain-agnostic 数据）
//!
//! **设计原则（v2 §2.5）**：
//! - BC-UR 标准（CBOR + Fountain Codes multi-part）
//! - 各 codec 接受 chain-agnostic 输入（Bip32XPub / TxTemplate / AddressString 等）
//! - 不接触私钥——xpub 输出只带公钥
//!
//! **Phase 2.3 stub 范围**：
//- 2 个 UR 通用函数（ur_encode / ur_decode）
//- 7 个 codec（6 BC-UR + 1 JSON-monero-viewkey）
//- 函数体 `unimplemented!()`，zcash_accounts 返回 `UnsupportedExportProtocol`
//!
//! **v2.4 安全修正**：所有 codec 接受 borrow 输入（`&Bip32XPub` / `&DerivationPath` / `&Ed25519Scalar`），
//! 不 clone 副本。

pub mod codec;
pub mod ur_decode;
pub mod ur_encode;
pub mod ur_multipart;
