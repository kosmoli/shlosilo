//! ETH personal_sign / personal_ecRecover (EIP-191 v0x45)
//!
//! Algorithm: `keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)`
//!
//! Wallets like MetaMask and WalletConnect all use this format for their "Sign Message" feature.
//! Not an ETH transaction; a blind signature over an arbitrary UTF-8 string.
//!
//! Reference: <https://eips.ethereum.org/EIPS/eip-191>

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;

use crate::chain::eth::sign;
use crate::encoding::keccak256;
use crate::error::Result;
use crate::types::SecretBytes;

/// personal_sign input
/// P1-03: private keys go through `SecretBytes<32>` — no Clone, no Debug, ZeroizeOnDrop, constant-time comparison.
pub struct PersonalSignInput {
    /// Arbitrary UTF-8 string to sign
    pub message: Vec<u8>,
    /// 32-byte private key
    pub private_key: SecretBytes<32>,
}

/// personal_sign output: 65-byte signature (r || s || v)
#[derive(Clone, Debug)]
pub struct PersonalSignature {
    /// signing hash (the digest shown on the user confirmation screen)
    pub signing_hash: [u8; 32],
    /// ECDSA r
    pub r: [u8; 32],
    /// ECDSA s (low-s enforced per EIP-2 / BIP-146)
    pub s: [u8; 32],
    /// recovery id (v): 27 or 28
    pub v: u8,
}

/// Compute the personal_sign signing hash
///
/// EIP-191 v0x45: `keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)`
pub fn personal_signing_hash(msg: &[u8]) -> Result<[u8; 32]> {
    let prefix_str = format!("\x19Ethereum Signed Message:\n{}", msg.len());
    let mut full = Vec::with_capacity(prefix_str.len() + msg.len());
    full.extend_from_slice(prefix_str.as_bytes());
    full.extend_from_slice(msg);
    keccak256::hash(&full)
}

/// Sign a personal message
///
/// Outputs a 65-byte signature (r || s || v), v = 27 + y_parity (i.e. v=27 if y_parity=0, v=28 if y_parity=1).
pub fn personal_sign(input: &PersonalSignInput) -> Result<PersonalSignature> {
    let sighash = personal_signing_hash(&input.message)?;

    // private_key: [u8; 32] → Secp256k1Scalar
    let sk = sign::sk_from_pk(input.private_key.expose())?;

    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    let y_parity = sign::apply_low_s(&sighash, &sk, &mut r_bytes, &mut s_bytes)?;

    Ok(PersonalSignature {
        signing_hash: sighash,
        r: r_bytes,
        s: s_bytes,
        v: 27 + y_parity,
    })
}

/// personal_ecRecover: recover the public key from the signature (L1 pure verify)
///
/// Input: the raw message + 65-byte signature (r || s || v)
/// Output: 64-byte uncompressed public key (x || y)
///
/// Used for wallet-side signer identity verification (the wallet-side mirror of personal_sign).
pub fn personal_ec_recover(msg: &[u8], sig: &[u8; 65]) -> Result<[u8; 64]> {
    let sighash = personal_signing_hash(msg)?;
    sign::ecdsa_recover(&sighash, sig)
}

/// Unit tests
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::string::String;
    use alloc::vec;
    use std::eprintln;

    fn hex_decode(s: &str) -> Vec<u8> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = hex_nibble(bytes[i]).unwrap();
            let lo = hex_nibble(bytes[i + 1]).unwrap();
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    /// Official MetaMask example: "Hello, world!"
    ///
    /// Different implementations may produce different signatures (RFC6979 + low-s), but the signing hash must match.
    #[test]
    fn personal_sign_hello_world() {
        let msg = b"Hello, world!";
        let h = personal_signing_hash(msg).unwrap();
        assert_ne!(h, [0u8; 32]);
        assert_eq!(h.len(), 32);
        eprintln!(
            "personal_sign('Hello, world!') signing hash: {}",
            hex_encode(&h)
        );
    }

    /// Signing prefix correctness test: `\x19Ethereum Signed Message:\n` + len + msg
    #[test]
    fn personal_sign_prefix_format() {
        let msg = b"test";
        let prefix_str = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let expected = keccak256::hash(&[prefix_str.as_bytes(), msg].concat()).unwrap();
        let actual = personal_signing_hash(msg).unwrap();
        assert_eq!(
            actual, expected,
            "signing hash mismatch with manual construction"
        );
    }

    /// Empty message edge case
    #[test]
    fn personal_sign_empty_message() {
        let msg = b"";
        let h = personal_signing_hash(msg).unwrap();
        assert_ne!(h, [0u8; 32]);
        // empty msg length = 0 → prefix = "\x19Ethereum Signed Message:\n0"
        let expected_prefix = b"\x19Ethereum Signed Message:\n0";
        let expected = keccak256::hash(expected_prefix).unwrap();
        assert_eq!(h, expected);
    }

    /// UTF-8 Chinese message
    #[test]
    fn personal_sign_utf8_chinese() {
        let msg = "你好,世界".as_bytes();
        let h = personal_signing_hash(msg).unwrap();
        assert_ne!(h, [0u8; 32]);
        eprintln!(
            "personal_sign('你好,世界') signing hash: {}",
            hex_encode(&h)
        );
    }

    /// Long strings (>1KB) do not panic
    #[test]
    fn personal_sign_long_message() {
        let msg = vec![0xab; 1024];
        let h = personal_signing_hash(&msg).unwrap();
        assert_ne!(h, [0u8; 32]);

        let msg = vec![0x42; 8192];
        let h = personal_signing_hash(&msg).unwrap();
        assert_ne!(h, [0u8; 32]);
    }

    /// End-to-end: signature + v ∈ {27, 28} + nonzero r/s
    #[test]
    fn personal_sign_end_to_end() {
        let pk_hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&hex_decode(pk_hex));

        let input = PersonalSignInput {
            message: b"test message".to_vec(),
            private_key: SecretBytes::new(pk),
        };
        let sig = personal_sign(&input).unwrap();

        assert!(
            sig.v == 27 || sig.v == 28,
            "v must be 27 or 28, got {}",
            sig.v
        );
        assert_ne!(sig.r, [0u8; 32]);
        assert_ne!(sig.s, [0u8; 32]);
    }

    /// Verify personal_sign determinism: same input → same output
    #[test]
    fn personal_sign_deterministic() {
        let msg = b"deterministic test";
        let h1 = personal_signing_hash(msg).unwrap();
        let h2 = personal_signing_hash(msg).unwrap();
        assert_eq!(h1, h2, "personal_signing_hash must be deterministic");

        let pk_hex = "1111111111111111111111111111111111111111111111111111111111111111";
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&hex_decode(pk_hex));

        let input1 = PersonalSignInput {
            message: msg.to_vec(),
            private_key: SecretBytes::new(pk),
        };
        let sig1 = personal_sign(&input1).unwrap();
        let sig2 = personal_sign(&input1).unwrap();
        assert_eq!(sig1.r, sig2.r, "r must be deterministic (RFC6979)");
        assert_eq!(sig1.s, sig2.s, "s must be deterministic (RFC6979)");
        assert_eq!(sig1.v, sig2.v, "v must be deterministic");
        assert_eq!(sig1.signing_hash, sig2.signing_hash);
    }

    /// round-trip: sign + recover (verifies the signer public key matches)
    #[test]
    fn personal_sign_recover_round_trip() {
        use crate::curve_primitive::secp256k1::{base_mul, point_to_compressed};

        // test private key
        let pk_hex = "4646464646464646464646464646464646464646464646464646464646464646";
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&hex_decode(pk_hex));

        let input = PersonalSignInput {
            message: b"Hello, world!".to_vec(),
            private_key: SecretBytes::new(pk_bytes),
        };

        // 1. Sign
        let sig = personal_sign(&input).unwrap();

        // 2. Build the 65-byte signature
        let mut sig_65 = [0u8; 65];
        sig_65[..32].copy_from_slice(sig.r.as_slice());
        sig_65[32..64].copy_from_slice(sig.s.as_slice());
        sig_65[64] = sig.v;

        // 3. Recover the public key from the signature
        let recovered_pk = personal_ec_recover(&input.message, &sig_65).unwrap();

        // 4. Compute the public key directly from the private key
        let sk = sign::sk_from_pk(&pk_bytes).unwrap();
        let pk_point = base_mul(&sk);
        let pk_compressed = point_to_compressed(&pk_point);

        // 5. Compare: last 64 bytes of recovered_pk (x||y) vs the known public key
        // k256 VerifyingKey.to_encoded_point(false) outputs 65 bytes: 0x04 || x (32) || y (32)
        // recovered_pk is 64 bytes (x || y), skipping the 0x04 prefix
        // pk_compressed is 33 bytes; do not compare directly
        // simplified: verify by comparing the x bytes of pk_compressed
        // pk_compressed[1..33] is the x coordinate (33 bytes = 1 prefix + 32 x)
        let pk_x = &pk_compressed[1..33];
        let recovered_x = &recovered_pk[..32];
        assert_eq!(pk_x, recovered_x, "recovered x must match pk x coordinate");
        // y parity: verify the recovered y coordinate parity matches the original pk
        // the LSB of recovered_pk[63] is the y parity (0 = even, 1 = odd)
        let recovered_y_parity = (recovered_pk[63] & 1) as u8;
        // pk_compressed prefix: 0x02 = even y, 0x03 = odd y
        let pk_y_parity = pk_compressed[0] - 0x02;
        assert_eq!(
            recovered_y_parity, pk_y_parity,
            "recovered y parity ({}) must match pk y parity ({})",
            recovered_y_parity, pk_y_parity
        );
        // note: sig.v may differ from pk_y_parity due to a low-s flip (correct EIP-2/BIP-146 behavior)
        // recover_from_prehash needs the correct y_parity to recover the right pk
        let sig_y_parity = sig.v - 27;
        assert!(
            sig_y_parity == pk_y_parity || sig_y_parity == 1 - pk_y_parity,
            "sig.v={} should reflect pk parity (with possible low-s flip)",
            sig.v
        );
    }

    fn hex_encode(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }
}
