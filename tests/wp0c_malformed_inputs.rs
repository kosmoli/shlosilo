//! S1 WP0-C malicious-input set (design doc §6 WP0-C).
//!
//! Envelope mutation and truncation coverage for the container parsers, plus
//! strict-geometry pins for the pairing-request plaintext. Every malformed
//! input must be REJECTED with an Err — never panic, never silently accepted.
//! Strictness floor (design ruling): keystone's 96B record loop does not
//! validate remainders; we do not copy its loose boundaries.
//!
//! Envelope layout (wallet2 family): `magic(23) || nonce(8) || ciphertext ||
//! sig(64)`, sig = Ed25519(view_pub) over keccak256(nonce || ciphertext).
//! Every single-byte mutation therefore MUST fail verification: the sweep
//! pins below prove that coverage byte-by-byte, not just the happy path.
//! Each pin runs a positive control first (probe calibration: a pin that
//! rejects everything because the artifact was never valid proves nothing).

// Alloc-face test: the container decrypt APIs are `alloc-fallback` gated
// (invisible to integration tests on the no-default-features face — pool
// #46 lesson), so this whole face rides that feature.
#![cfg(feature = "alloc-fallback")]

use rand_chacha::rand_core::SeedableRng as _;
use shlosilo::business::xmr_pairing::{
    carve_pairing_ws, pairing_ws_len, process_output_export_with_records,
};
use shlosilo::chain::xmr::key_image_export::{encrypt_export_payload_into, OUTPUT_EXPORT_MAGIC};
use shlosilo::chain::xmr::signed_txset::{decrypt_signed_txset, encrypt_unsigned_txset};
use shlosilo::chain::xmr::unsigned_txset::decrypt_unsigned_txset;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;

/// Synthetic-envelope test key (not a wallet key).
const VIEW_SK: [u8; 32] = [0x42; 32];
/// A different key: same shape, wrong owner.
const FOREIGN_VIEW_SK: [u8; 32] = [0x43; 32];

/// DEV test wallet A' view secret key — decrypt key of
/// signed_txset_1in_fresh.bin (same bytes as tests/golden_p2in_decrypt.rs).
const DEV_VIEW_SK: [u8; 32] = [
    0xdd, 0x87, 0x2c, 0xe8, 0x67, 0x39, 0xd7, 0x8d, 0xf0, 0x71, 0xd7, 0xf9, 0xef, 0x72, 0x91, 0x3b,
    0xd5, 0xf3, 0xc2, 0xdb, 0x02, 0xcb, 0x55, 0x5c, 0x24, 0x4b, 0x07, 0x6e, 0xfa, 0x5a, 0x9a, 0x0f,
];

/// Deterministic seed shared by the synthetic artifacts.
fn wp0c_seed() -> u64 {
    0x00c0_ffee_0042_0007
}

/// Deterministic synthetic unsigned container (opaque plaintext is fine:
/// the envelope does not parse the body).
fn unsigned_container_seeded() -> Vec<u8> {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(wp0c_seed());
    let plain = zeroize::Zeroizing::new(b"wp0c probe plaintext".to_vec());
    encrypt_unsigned_txset(plain, &VIEW_SK, &mut rng)
        .expect("synthetic container build")
        .to_vec()
}

/// Positive control + rejection: the container must decrypt under its own
/// key (control) and reject under a foreign one.
#[test]
fn unsigned_envelope_control_then_foreign_key_rejects() {
    let c = unsigned_container_seeded();
    assert!(
        decrypt_unsigned_txset(&c, &VIEW_SK).is_ok(),
        "positive control: the synthetic container must decrypt under VIEW_SK"
    );
    assert!(
        decrypt_unsigned_txset(&c, &FOREIGN_VIEW_SK).is_err(),
        "a foreign view key must be rejected at the envelope signature"
    );
}

/// Single-byte mutation sweep over the whole container: every byte flip
/// (magic / nonce / ciphertext / signature) must be rejected. One pass, one
/// assertion per byte — the envelope signature covers nonce || ciphertext
/// and the magic is checked verbatim, so no mutation may survive.
#[test]
fn unsigned_envelope_rejects_every_single_byte_mutation() {
    let c = unsigned_container_seeded();
    assert!(decrypt_unsigned_txset(&c, &VIEW_SK).is_ok(), "control");
    for i in 0..c.len() {
        let mut m = c.clone();
        m[i] ^= 0x5A;
        assert!(
            decrypt_unsigned_txset(&m, &VIEW_SK).is_err(),
            "byte {i} mutation must be rejected"
        );
    }
}

/// Truncation sweep: EVERY strict prefix must be rejected (length floor,
/// magic, and the signature window all catch cuts).
#[test]
fn unsigned_envelope_rejects_every_strict_prefix() {
    let c = unsigned_container_seeded();
    assert!(decrypt_unsigned_txset(&c, &VIEW_SK).is_ok(), "control");
    for cut in 0..c.len() {
        assert!(
            decrypt_unsigned_txset(&c[..cut], &VIEW_SK).is_err(),
            "prefix of length {cut} must be rejected"
        );
    }
}

/// Appended garbage shifts the signature window: every extension must be
/// rejected (no trailing-bytes acceptance).
#[test]
fn unsigned_envelope_rejects_appended_garbage() {
    let c = unsigned_container_seeded();
    for n in 1..=16usize {
        let mut m = c.clone();
        m.extend(std::iter::repeat_n(0x42u8, n));
        assert!(
            decrypt_unsigned_txset(&m, &VIEW_SK).is_err(),
            "container + {n} trailing bytes must be rejected"
        );
    }
}

/// Same family on the signed leg over the REAL chain artifact
/// (signed_txset_1in_fresh.bin): mutation sweep + prefix sweep.
#[test]
fn signed_envelope_rejects_every_mutation_and_prefix() {
    let c: &[u8] = include_bytes!("fixtures/signed_txset_1in_fresh.bin");
    assert!(
        decrypt_signed_txset(c, &DEV_VIEW_SK).is_ok(),
        "positive control: the chain artifact decrypts under DEV_VIEW_SK"
    );
    for i in 0..c.len() {
        let mut m = c.to_vec();
        m[i] ^= 0x5A;
        assert!(
            decrypt_signed_txset(&m, &DEV_VIEW_SK).is_err(),
            "signed byte {i} mutation must be rejected"
        );
    }
    for cut in 0..c.len() {
        assert!(
            decrypt_signed_txset(&c[..cut], &DEV_VIEW_SK).is_err(),
            "signed prefix of length {cut} must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// Pairing-request plaintext strict geometry (WP0-C: 严格长度校验)
// ---------------------------------------------------------------------------

fn point(sk: &[u8; 32]) -> [u8; 32] {
    (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*sk))
        .compress()
        .to_bytes()
}

fn encode_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

/// Two-output main-address export plaintext (same shape family as
/// tests/pin_failure_text.rs).
fn build_plain(count: usize, view_sk: &[u8; 32], spend_sk: &[u8; 32]) -> Vec<u8> {
    let mut plain = Vec::new();
    encode_varint(1, &mut plain); // has_transfers
    encode_varint(0, &mut plain); // offset
    encode_varint(count as u64, &mut plain); // transfers total
    encode_varint(count as u64, &mut plain); // record count
    for i in 0..count {
        let tx_sk = [0x24u8.wrapping_add(i as u8 * 5); 32];
        let tx_pub = point(&tx_sk);
        let off = crate_hs_offset(view_sk, &tx_pub, i as u64);
        let input_sk = Scalar::from_bytes_mod_order(*spend_sk) + Scalar::from_bytes_mod_order(off);
        let out_pub = (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes();

        encode_varint(1, &mut plain); // record version
        plain.extend_from_slice(&out_pub);
        encode_varint(i as u64, &mut plain); // internal_output_index
        encode_varint(10 + i as u64, &mut plain); // global_output_index
        plain.extend_from_slice(&tx_pub);
        plain.push(0b0000_0100); // flags (main address)
        encode_varint(1_000_000 + i as u64, &mut plain); // amount
        encode_varint(0, &mut plain); // additional_tx_keys count
        encode_varint(0, &mut plain); // major
        encode_varint(0, &mut plain); // minor
    }
    plain
}

fn crate_hs_offset(view_sk: &[u8; 32], tx_pub: &[u8; 32], idx: u64) -> [u8; 32] {
    shlosilo::chain::xmr::subaddress::calc_output_key_offset(view_sk, tx_pub, idx, 0, 0)
        .expect("hs offset")
}

/// Run the pairing receive leg over a request container built from `plain`.
/// Returns Ok(()) when the leg accepted the request.
fn pairing_accepts(plain: &[u8], view_sk: &[u8; 32], spend_sk: &[u8; 32]) -> bool {
    let spend_pub = point(spend_sk);
    let view_pub = point(view_sk);
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(wp0c_seed() ^ 0x55);
    let mut req_buf = vec![0u8; 16384];
    let mut cn = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
    let req_n = match encrypt_export_payload_into(
        OUTPUT_EXPORT_MAGIC,
        view_sk,
        &spend_pub,
        &view_pub,
        0u32,
        plain,
        &mut rng,
        &mut req_buf,
        &mut cn,
    ) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let mut out = vec![0u8; 16384];
    let mut ws_raw = vec![0u8; pairing_ws_len()];
    let mut ws = match carve_pairing_ws(&mut ws_raw) {
        Some(w) => w,
        None => return false,
    };
    let mut ki_out = [shlosilo::business::sign::WalletKiRecord {
        transfer_idx: u32::MAX,
        wallet_fp: [0u8; 8],
        key_image: [0u8; 32],
    }; 2];
    let mut ki_written = 0usize;
    process_output_export_with_records(
        view_sk,
        spend_sk,
        &req_buf[..req_n],
        &mut ws,
        &mut out,
        &mut rng,
        &mut ki_out,
        &mut ki_written,
    )
    .is_ok()
}

/// Strict geometry, truncated side: cutting the export plaintext mid-record
/// must be rejected (control first: the whole plaintext is accepted).
#[test]
fn pairing_request_rejects_truncated_plaintext() {
    let view_sk = [6u8; 32];
    let spend_sk = [5u8; 32];
    let plain = build_plain(2, &view_sk, &spend_sk);
    assert!(
        pairing_accepts(&plain, &view_sk, &spend_sk),
        "positive control: the whole plaintext must be accepted"
    );
    // Cut inside every record byte of the tail record and inside the
    // varint header: no cut may parse as a valid request.
    for cut in 1..plain.len() {
        assert!(
            !pairing_accepts(&plain[..cut], &view_sk, &spend_sk),
            "plaintext truncated at {cut} must be rejected"
        );
    }
}

/// Strict geometry, trailing side: appended bytes after the last record must
/// NOT be silently accepted (design ruling: strict length validation).
/// If this pin goes red the epee reader needs a trailing-bytes check.
#[test]
fn pairing_request_rejects_trailing_garbage() {
    let view_sk = [6u8; 32];
    let spend_sk = [5u8; 32];
    let plain = build_plain(2, &view_sk, &spend_sk);
    assert!(
        pairing_accepts(&plain, &view_sk, &spend_sk),
        "positive control: the whole plaintext must be accepted"
    );
    for n in 1..=8usize {
        let mut m = plain.clone();
        m.extend(std::iter::repeat_n(0x42u8, n));
        assert!(
            !pairing_accepts(&m, &view_sk, &spend_sk),
            "plaintext + {n} trailing bytes must be rejected"
        );
    }
}

/// Random-mutation robustness: any garbage must produce Ok or Err, never a
/// panic (no unwrap/expect may sit on the parse path). Deterministic LCG.
#[test]
fn random_mutations_never_panic() {
    let c = unsigned_container_seeded();
    let mut state: u64 = wp0c_seed() ^ 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as usize
    };
    for _ in 0..300 {
        let mut m = c.clone();
        match next() % 3 {
            0 => {
                let i = next() % m.len();
                m[i] ^= (next() as u8) | 1;
            }
            1 => {
                let cut = next() % (m.len() + 1);
                m.truncate(cut);
            }
            _ => {
                let n = 1 + next() % 24;
                m.extend(std::iter::repeat_n((next() as u8) | 1, n));
            }
        }
        // Ok or Err both fine; a panic fails the test.
        let _ = decrypt_unsigned_txset(&m, &VIEW_SK);
    }
}
