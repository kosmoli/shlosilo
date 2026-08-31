//! 编码原语（hash + 字符串编码）
//!
//! Phase 4 真实实现（v2 §2.4）：
//! - `sha2::Sha256` / `sha2::Sha512`
//! - `tiny-keccak`（Keccak256，**不是** SHA3-256）
//! - `bech32` / `bech32m`
//! - `bs58`（base58check）

pub mod base58;
pub mod base64;
pub mod bech32;
pub mod bytewords;
pub mod fountain;
pub mod cbor;
pub mod keccak256;
pub mod ripemd160;
pub mod sha256;
pub mod sha512;

/// 共享 hex 模块（仅 dev/test 用）
///
/// **Phase 4 简化**：自己实现 hex 编码，避免 hex crate 依赖
#[cfg(test)]
pub mod hex {
    /// 简化版 hex 编码
    pub fn encode(bytes: &[u8]) -> alloc::string::String {
        let mut s = alloc::string::String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }

    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
}