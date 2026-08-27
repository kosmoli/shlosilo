//! shlosilo L1 Layer D：地址编码（chain-specific, encoding primitives 共享）
//!
//! **设计原则（v2 §2.4）**：
//! - 接受公开材料（`&Secp256k1Point` / `&Ed25519Point` / `&RsaPubKey`），不接触私钥
//! - 返回 owned `AddressString`（`heapless::String<N>`），业务模块按需拿
//! - Phase 4 接入 `bech32` / `base58` / `keccak256` / `ripemd160` / `sha256` 等编码原语
//!
//! **Phase 2.3 stub 范围**：
//! - 10 个地址编码模块
//! - 每个模块：地址字符串结构 + `encode` 函数 + 函数体 `unimplemented!()`
//! - Phase 4 真实实现：替换 unimplemented!() 为真实算法调用
//!
//! **v2.4 安全修正**：所有 `encode` 函数的 pubkey 参数都是 borrow，不 clone 副本。
//! 业务模块通过 `&Point` 借出——Layer D 拿到的只是 borrow，不持有 owned 公钥副本。
//!
//! **Debug 隐私保护**：地址结构 Debug 不泄露完整地址（只显示前 6 后 4 字符），
//! 防止 debug 日志意外暴露用户地址。

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
