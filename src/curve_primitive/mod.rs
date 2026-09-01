//! shlosilo L1 Layer A：曲线原语（chain-agnostic）
//!
//! **设计原则（v2 §2.1）**：
//! - 只管曲线数学：add / scalar_mul / base_mul / 双线性对
//! - 同一份代码服务 BTC、ETH、SOL、XMR、ZEC（按需）
//! - **`Scalar` 禁用 `Copy`**——Copy 类型按值传递会在调用栈上留"按字节副本"，
//!   zeroize 只能清当前栈帧的那一份（v2 §2.1 v2.x Gemini review 安全修正）
//! - **`Point` 允许 `Copy + Eq`**——公钥是公开验证材料，不是密钥
//! - **类型命名约定**：`{Curve}Scalar` / `{Curve}Point`——跨曲线代码读到类型名即可知道曲线归属
//!
//! Phase 2.1 stub 范围：
//! - 5 个文件：secp256k1 / ed25519 / rsa / p256 + 本 mod.rs
//! - 每个文件：`{Curve}Scalar` + `{Curve}Point` + free function（`unimplemented!()`）+ `#[should_panic]` 测试
//! - Phase 4 直接替换 `unimplemented!()` 为真实算法调用（`k256` / `curve25519-dalek` / 等）

pub mod ed25519;
pub mod p256;
pub mod rsa;
pub mod secp256k1;
