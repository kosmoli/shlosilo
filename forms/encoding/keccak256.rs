//! Keccak-256 hash (ETH address construction + XMR checksum)
//!
//! **Important distinction**: Keccak-256 ≠ SHA3-256 (different nonce). ETH uses Keccak-256.

use crate::error::Result;
use tiny_keccak::{Hasher, Keccak};

/// Keccak-256 output length
pub const KECCAK256_OUTPUT_LEN: usize = 32;

/// Keccak-256 hash
///
/// Z2.4d-3: streaming Keccak-256 sink — absorbs a byte stream (e.g. the txset
/// writer family) without materializing it; feeds `crate::types::push::Sink`
/// consumers via `write_all`. The sponge transient follows the established
/// `keccak256::hash` precedent (permutation state is not zeroized).
pub struct KeccakSink {
    inner: tiny_keccak::Keccak,
}

impl KeccakSink {
    pub fn new() -> Self {
        Self {
            inner: tiny_keccak::Keccak::v256(),
        }
    }

    pub fn absorb(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    pub fn finalize(self) -> [u8; KECCAK256_OUTPUT_LEN] {
        let mut output = [0u8; KECCAK256_OUTPUT_LEN];
        self.inner.finalize(&mut output);
        output
    }
}

impl Default for KeccakSink {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::types::push::Sink for KeccakSink {
    fn put(&mut self, bytes: &[u8]) -> crate::error::Result<()> {
        self.inner.update(bytes);
        Ok(())
    }
}

/// Phase 4 real implementation: `tiny_keccak::Keccak::v256()`
///
/// **v2.4 security**: input borrowed, output owned (the hash carries no secret information)
pub fn hash(data: &[u8]) -> Result<[u8; KECCAK256_OUTPUT_LEN]> {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut output = [0u8; KECCAK256_OUTPUT_LEN];
    hasher.finalize(&mut output);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&[u8]) -> Result<[u8; KECCAK256_OUTPUT_LEN]> = hash;

    #[test]
    fn output_len() {
        assert_eq!(KECCAK256_OUTPUT_LEN, 32);
    }

    /// Keccak-256("") standard test vector
    /// https://github.com/ethereum/go-ethereum/blob/master/crypto/crypto.go
    #[test]
    fn hash_empty() {
        let h = hash(&[]).unwrap();
        let expected = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
        assert_eq!(hex::encode_to_string(&h), expected);
    }

    /// Keccak-256("abc") standard test vector
    #[test]
    fn hash_abc() {
        let h = hash(b"abc").unwrap();
        let expected = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45";
        assert_eq!(hex::encode_to_string(&h), expected);
    }
}

// hex helper for the keccak256 tests (independent module)
#[cfg(test)]
mod hex {
    pub fn encode_to_string(bytes: &[u8]) -> alloc::string::String {
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        let mut s = alloc::string::String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }
}
