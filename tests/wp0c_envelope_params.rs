//! S1 WP0-C envelope parameter pins (design §6 WP0-C) — the parameter VALUES
//! that the golden bytes only pin implicitly.
//!
//! Already pinned elsewhere (not re-pinned here):
//! - signature hash identity = Keccak-256 (official vectors, forms/encoding/
//!   keccak256.rs module tests);
//! - signature COVERAGE of (nonce || ciphertext) = byte-by-byte mutation
//!   sweeps, tests/wp0c_malformed_inputs.rs;
//! - container geometry (magic(23) || nonce(8) || cipher || sig(64)) = the
//!   golden byte-identity pins.
//!
//! Pinned here:
//! - key derivation is cn_slow_hash variant0 applied EXACTLY ONCE
//!   (kdf_rounds = 1);
//! - the nonce is 8 bytes, big-endian, the rng's FIRST draw.

#![cfg(feature = "alloc-fallback")]

use rand_chacha::rand_core::{RngCore as _, SeedableRng as _};
use shlosilo::chain::xmr::signed_txset::encrypt_unsigned_txset;

/// "Monero unsigned tx set\005" — the unsigned container magic.
const MAGIC_LEN: usize = 23;
const NONCE_LEN: usize = 8;
const SIG_LEN: usize = 64;
const VIEW_SK: [u8; 32] = [0x51; 32];

fn build() -> (Vec<u8>, Vec<u8>) {
    let plain = b"wp0c envelope params probe".to_vec();
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xE77E_1001);
    let container =
        encrypt_unsigned_txset(zeroize::Zeroizing::new(plain.clone()), &VIEW_SK, &mut rng)
            .expect("synthetic container")
            .to_vec();
    (container, plain)
}

/// The envelope key is cn_slow_hash variant0 over the view secret key applied
/// EXACTLY ONCE (kdf_rounds = 1): a manual keystream built from a single
/// cryptonight_hash_v0 round must reproduce the plaintext, and a second KDF
/// application must not (the round count is a contract, not >= 1).
#[test]
fn envelope_key_is_exactly_one_cn_v0_round() {
    use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};

    let (container, plain) = build();
    let nonce = &container[MAGIC_LEN..MAGIC_LEN + NONCE_LEN];
    let ct = &container[MAGIC_LEN + NONCE_LEN..container.len() - SIG_LEN];

    let mut scratch = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
    let key1 =
        cuprate_cryptonight::cryptonight_hash_v0_into(&VIEW_SK, &mut scratch).expect("cn round 1");
    let mut p1 = ct.to_vec();
    chacha20::ChaCha20Legacy::new_from_slices(key1.as_slice(), nonce)
        .expect("cipher")
        .apply_keystream(&mut p1);
    assert_eq!(p1, plain, "one CN-v0 round reproduces the plaintext");

    // Negative control: one MORE KDF application yields a different key and
    // therefore garbage — the pin discriminates the round count.
    let mut scratch2 = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
    let key2 = cuprate_cryptonight::cryptonight_hash_v0_into(key1.as_slice(), &mut scratch2)
        .expect("cn round 2");
    let mut p2 = ct.to_vec();
    chacha20::ChaCha20Legacy::new_from_slices(key2.as_slice(), nonce)
        .expect("cipher")
        .apply_keystream(&mut p2);
    assert_ne!(p2, plain, "kdf_rounds=2 must NOT reproduce the plaintext");
}

/// The envelope nonce is exactly 8 bytes, big-endian, taken as the rng's
/// first draw (`rng.next_u64().to_be_bytes()` — the shared parameterization
/// of both encrypt legs).
#[test]
fn envelope_nonce_is_first_rng_draw_big_endian_8() {
    let (container, _plain) = build();
    let mut twin = rand_chacha::ChaCha20Rng::seed_from_u64(0xE77E_1001);
    let expected = twin.next_u64().to_be_bytes();
    assert_eq!(
        &container[MAGIC_LEN..MAGIC_LEN + NONCE_LEN],
        &expected,
        "the nonce is the rng's first draw, 8 bytes big-endian"
    );
}
