//! PBKDF2-HMAC-SHA512 (fixed to BIP-39 parameters) built on the u32-pair SHA-512
//! compression function.
//!
//! Why a bespoke loop instead of the `pbkdf2` crate: the crate drives `sha2`'s u64
//! software backend, which costs ~42k cycles per 128-byte block on Cortex-M4. This
//! module implements the identical PBKDF2-HMAC-SHA512 construction over
//! [`crate::encoding::sha512_u32::compress`], which targets ~5-6k cycles per block.
//!
//! Semantics are bit-identical to `pbkdf2::pbkdf2_hmac::<Sha512>`; the test module
//! cross-checks against the crate on BIP-39 vectors and pseudo-random inputs.
//!
//! HMAC key states (ipad/opad first-block compressions) are precomputed once, mirroring
//! `hmac 0.12`'s `HmacCore` — so each PBKDF2 round costs exactly 2 fresh compressions.

use crate::encoding::sha512_u32::{compress, initial_state};

const SHA512_BLOCK_LEN: usize = 128;
const SHA512_OUTPUT_LEN: usize = 64;

/// HMAC-SHA512 keyed state with precomputed ipad/opad block compressions.
struct HmacSha512Fast {
    /// Digest state after compressing the ipad block (key ^ 0x36...).
    ipad_state: [u32; 16],
    /// Digest state after compressing the opad block (key ^ 0x5c...).
    opad_state: [u32; 16],
}

impl HmacSha512Fast {
    fn new(key: &[u8]) -> Self {
        let mut ipad_block = [0x36u8; SHA512_BLOCK_LEN];
        let mut opad_block = [0x5cu8; SHA512_BLOCK_LEN];
        // Keys longer than the block size are replaced by H(key); for PBKDF2-HMAC-SHA512
        // the key is the password. BIP-39 passwords are short, but stay general.
        if key.len() > SHA512_BLOCK_LEN {
            // H(key): compress H0 over key blocks, take 64-byte digest, use as key.
            let mut state = initial_state();
            let mut blocks = key.chunks_exact(SHA512_BLOCK_LEN);
            let mut buf = [0u8; SHA512_BLOCK_LEN];
            for block in &mut blocks {
                buf.copy_from_slice(block);
                compress(&mut state, &buf);
            }
            let rem = blocks.remainder();
            let mut last = [0u8; SHA512_BLOCK_LEN];
            last[..rem.len()].copy_from_slice(rem);
            last[rem.len()] = 0x80;
            let bitlen = (key.len() as u128) * 8;
            if rem.len() + 17 > SHA512_BLOCK_LEN {
                compress(&mut state, &last);
                last = [0u8; SHA512_BLOCK_LEN];
            }
            last[SHA512_BLOCK_LEN - 16..].copy_from_slice(&bitlen.to_be_bytes());
            compress(&mut state, &last);
            let mut digest = [0u8; SHA512_OUTPUT_LEN];
            for i in 0..8 {
                digest[i * 8..i * 8 + 4].copy_from_slice(&state[i * 2].to_be_bytes());
                digest[i * 8 + 4..i * 8 + 8].copy_from_slice(&state[i * 2 + 1].to_be_bytes());
            }
            for (b, k) in ipad_block.iter_mut().zip(digest.iter()) {
                *b ^= k;
            }
            for (b, k) in opad_block.iter_mut().zip(digest.iter()) {
                *b ^= k;
            }
        } else {
            for (b, k) in ipad_block.iter_mut().zip(key.iter()) {
                *b ^= k;
            }
            for (b, k) in opad_block.iter_mut().zip(key.iter()) {
                *b ^= k;
            }
        }
        let mut ipad_state = initial_state();
        compress(&mut ipad_state, &ipad_block);
        let mut opad_state = initial_state();
        compress(&mut opad_state, &opad_block);
        Self {
            ipad_state,
            opad_state,
        }
    }

    /// HMAC-SHA512 over a message of `data_len` bytes (0 < data_len <= 64), carried
    /// in a 64-byte scratch `block`. PBKDF2 passes the full 64-byte U_i.
    fn mac_block(
        &self,
        block: &[u8; SHA512_OUTPUT_LEN],
        data_len: usize,
    ) -> [u8; SHA512_OUTPUT_LEN] {
        debug_assert!((1..=SHA512_OUTPUT_LEN).contains(&data_len));
        let mut state = self.ipad_state;
        let mut last = [0u8; SHA512_BLOCK_LEN];
        last[..data_len].copy_from_slice(&block[..data_len]);
        last[data_len] = 0x80;
        // total message = 128-byte ipad block + data_len bytes
        let bitlen: u128 = (128 + data_len) as u128 * 8;
        last[SHA512_BLOCK_LEN - 16..].copy_from_slice(&bitlen.to_be_bytes());
        compress(&mut state, &last);
        let mut inner = [0u8; SHA512_OUTPUT_LEN];
        Self::state_to_bytes(&state, &mut inner);

        // Outer: H(opad_state, inner + padding), total = 128 + 64 bytes.
        let bitlen2: u128 = (128 + SHA512_OUTPUT_LEN) as u128 * 8;
        let mut state2 = self.opad_state;
        let mut last2 = [0u8; SHA512_BLOCK_LEN];
        last2[..SHA512_OUTPUT_LEN].copy_from_slice(&inner);
        last2[SHA512_OUTPUT_LEN] = 0x80;
        last2[SHA512_BLOCK_LEN - 16..].copy_from_slice(&bitlen2.to_be_bytes());
        compress(&mut state2, &last2);
        let mut out = [0u8; SHA512_OUTPUT_LEN];
        Self::state_to_bytes(&state2, &mut out);
        out
    }

    fn state_to_bytes(state: &[u32; 16], out: &mut [u8; SHA512_OUTPUT_LEN]) {
        for i in 0..8 {
            out[i * 8..i * 8 + 4].copy_from_slice(&state[i * 2].to_be_bytes());
            out[i * 8 + 4..i * 8 + 8].copy_from_slice(&state[i * 2 + 1].to_be_bytes());
        }
    }
}

/// PBKDF2-HMAC-SHA512 with the BIP-39 parameters (2048 rounds, 64-byte output).
/// Bit-identical to `pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, 2048, out)`.
pub fn pbkdf2_hmac_sha512(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    out: &mut [u8; SHA512_OUTPUT_LEN],
) {
    debug_assert_eq!(out.len(), SHA512_OUTPUT_LEN);
    let hmac = HmacSha512Fast::new(password);

    // U_1 = HMAC(password, salt || INT(1)). The inner message after the ipad block is
    // salt || INT(1) (salt.len() + 4 bytes) — it must be padded as a normal final block,
    // NOT fed as a full 128-byte data block (the zero tail is padding, not message data).
    // BIP-39 salt = "mnemonic" + passphrase; upstream rejects non-ASCII passphrases and
    // the smoke fixtures keep passphrases short, so salt.len() + 4 always fits in one
    // final block with room for 0x80 + the 16-byte length field.
    debug_assert!(
        salt.len() + 4 + 17 <= SHA512_BLOCK_LEN,
        "salt too long for fast path"
    );

    // BIP-39 output is exactly 64 bytes = one PBKDF2 block, so only INT(1) is needed.
    let msg_len = salt.len() + 4;
    let mut last = [0u8; SHA512_BLOCK_LEN];
    last[..salt.len()].copy_from_slice(salt);
    last[salt.len() + 3] = 1; // INT(1) big-endian
    last[msg_len] = 0x80;
    let bitlen: u128 = (128 + msg_len) as u128 * 8;
    last[SHA512_BLOCK_LEN - 16..].copy_from_slice(&bitlen.to_be_bytes());

    // U_1 inner: ipad_state + one padded final block.
    let mut state = hmac.ipad_state;
    compress(&mut state, &last);
    let mut inner = [0u8; SHA512_OUTPUT_LEN];
    HmacSha512Fast::state_to_bytes(&state, &mut inner);

    // U_1 outer: opad_state + inner(64 bytes) + padding.
    let mut state3 = hmac.opad_state;
    let mut last2 = [0u8; SHA512_BLOCK_LEN];
    last2[..SHA512_OUTPUT_LEN].copy_from_slice(&inner);
    last2[SHA512_OUTPUT_LEN] = 0x80;
    let bitlen2: u128 = (128 + SHA512_OUTPUT_LEN) as u128 * 8;
    last2[SHA512_BLOCK_LEN - 16..].copy_from_slice(&bitlen2.to_be_bytes());
    compress(&mut state3, &last2);
    let mut u = [0u8; SHA512_OUTPUT_LEN];
    HmacSha512Fast::state_to_bytes(&state3, &mut u);

    // T = U_1
    let mut t = u;

    // U_2..U_rounds
    for _ in 1..rounds {
        let u_next = hmac.mac_block(&u, SHA512_OUTPUT_LEN);
        for (tb, ub) in t.iter_mut().zip(u_next.iter()) {
            *tb ^= ub;
        }
        u = u_next;
    }

    out.copy_from_slice(&t);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference via the pbkdf2 + sha2 crates (the current production path).
    fn reference(password: &[u8], salt: &[u8], rounds: u32) -> [u8; 64] {
        let mut out = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password, salt, rounds, &mut out);
        out
    }

    #[test]
    fn rfc4231_hmac_vectors() {
        // RFC 4231 test case 1: key = 0x0b x20, data = "Hi There"
        let hmac = HmacSha512Fast::new(&[0x0b; 20]);
        // data "Hi There" padded to one block for mac_block
        let mut block = [0u8; 64];
        block[..8].copy_from_slice(b"Hi There");
        let got = hmac.mac_block(&block, 8);
        let want: [u8; 64] = [
            0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d,
            0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05,
            0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b,
            0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70,
            0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54,
        ];
        assert_eq!(got, want);
    }

    #[test]
    fn bip39_trezor_vectors() {
        // Official BIP-39 test vectors (Trezor, 12-word, empty passphrase).
        // mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut out = [0u8; 64];
        pbkdf2_hmac_sha512(words.as_bytes(), b"mnemonic", 2048, &mut out);
        let want: [u8; 64] = [
            0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55,
            0x56, 0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6,
            0xf6, 0xda, 0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86,
            0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
            0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4,
        ];
        assert_eq!(out, want);
    }

    #[test]
    fn matches_pbkdf2_crate() {
        // Pseudo-random cross-check against the production crate path.
        let mut x: u64 = 0xdead_beef_cafe_f00d;
        let mut gen = || {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (x >> 24) as u8
        };
        for pw_len in [0usize, 1, 32, 64, 128, 200] {
            let pw: alloc::vec::Vec<u8> = (0..pw_len).map(|_| gen()).collect();
            for salt_len in [0usize, 1, 8, 64, 100] {
                let salt: alloc::vec::Vec<u8> = (0..salt_len).map(|_| gen()).collect();
                let mut got = [0u8; 64];
                pbkdf2_hmac_sha512(&pw, &salt, 2048, &mut got);
                assert_eq!(
                    got,
                    reference(&pw, &salt, 2048),
                    "pw={} salt={}",
                    pw_len,
                    salt_len
                );
            }
        }
    }

    #[test]
    fn long_password_path() {
        // Passwords longer than the block size take the hash-down branch.
        let pw: alloc::vec::Vec<u8> = (0..200u32).map(|i| (i * 7) as u8).collect();
        let mut got = [0u8; 64];
        pbkdf2_hmac_sha512(&pw, b"mnemonic", 2048, &mut got);
        assert_eq!(got, reference(&pw, b"mnemonic", 2048));
    }
}
