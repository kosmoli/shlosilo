//! Encoding primitives (hash + string encoding)
//!
//! Phase 4 real implementation (v2 §2.4):
//! - `sha2::Sha256` / `sha2::Sha512`
//! - `tiny-keccak` (Keccak256, **not** SHA3-256)
//! - `bech32` / `bech32m`
//! - `bs58`（base58check）

pub mod base58;
pub mod base64;
pub mod bech32;
pub mod bytewords;
pub mod cbor;
pub mod fountain;
pub mod keccak256;
pub mod ripemd160;
pub mod sha256;
pub mod sha512;

/// Shared hex module (dev/test only)
///
/// **Phase 4 simplification**: hex encoding implemented in-house, avoiding the hex crate dependency
#[cfg(test)]
pub mod hex {
    /// Simplified hex encoding
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
