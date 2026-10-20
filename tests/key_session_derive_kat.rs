//! KeySession derivation chain — absolute-value KAT pins (pool §21a).
//!
//! tests/key_session_ffi.rs only has a *differential* pin (session path vs
//! typed-entry path, byte-for-byte): if both sides drift together the suite
//! stays green. This file pins the derivation chain's **absolute** outputs so
//! a drift cannot hide behind agreement:
//!
//! Chain under test (KeySession::from_entropy):
//!   BIP-39 entropy -> mnemonic -> PBKDF2-HMAC-SHA512 seed (64B, empty/"TREZOR"
//!   passphrase) -> BIP-32/secp256k1 CKDpriv m/44'/128'/0'/0/0 ->
//!   spend = reduce_scalar(keccak256(raw)) -> view = Hs(spend) ->
//!   Monero mainnet address (base58-monero).
//!
//! NOTE on the middle layer: the SLIP-0010 ed25519 module in this tree
//! (forms/derivation/slip10_ed25519.rs) is a FeatureNotImplemented stub and is
//! NOT on the KeySession chain — the middle layer actually exercised is
//! BIP-32/secp256k1 CKDpriv (forms/derivation/monero_reduce_scalar.rs::derive,
//! aligned with keystone apps/monero/src/key.rs). The middle-layer anchor
//! therefore uses the BIP-32 official test vectors (the authoritative vectors
//! for the algorithm that is really in the chain); a SLIP-0010 ed25519 vector
//! cannot pin anything here because no live code implements it.
//!
//! Anchor tiers (per the pin-provenance rule — a current implementation's own
//! output is never cited as an external anchor):
//!
//! * Tier 1 (external authority):
//!   - BIP-39 official test vectors (trezor/python-mnemonic vectors.json,
//!     referenced by the BIP-39 spec): entropy -> mnemonic -> seed.
//!   - BIP-32 official Test Vector 1 (bitcoin/bips bip-0032.mediawiki):
//!     seed 000102030405060708090a0b0c0d0e0f -> master / m/0' / m/0'/1.
//! * Tier 2 (repo-history anchored, externally cross-validated):
//!   - DEV_WALLET: deterministic device wallet entropy
//!     (flux/pico2/bench/xmr_2in_bringup.py `DEV_ENTROPY`) -> Monero mainnet
//!     address 4844Nk4X...q5nM. The address string is printed by monero core
//!     itself (wallet2) in flux/forgebox/monero-wallet-rpc.log when loading the
//!     `sh_dev_correct` watch-only wallet restored from these keys, and the
//!     same wallet produced the device-signed mainnet transaction
//!     ebc663d6314c0814dec471b334d5cb4e494aabaad3ab3f6d8cc08806f8c9b6d1
//!     (h=3763087, accepted by monerod); see tests/fixtures/README.md.

use shlosilo::address::xmr::encode;
use shlosilo::curve_primitive::ed25519::{
    point_from_compressed, point_to_compressed, Ed25519Point,
};
use shlosilo::derivation::bip32_secp256k1::{derive_from_seed, master_from_seed};
use shlosilo::derivation::path::DerivationPath;
use shlosilo::entropy::bip39_passphrase::mnemonic_to_seed;
use shlosilo::entropy::mnemonic::Mnemonic;
use shlosilo::network::Network;
use shlosilo::types::key_session::KeySession;

// ---------------------------------------------------------------------------
// Tier 1 anchors — BIP-39 official test vector 1 (trezor/python-mnemonic
// vectors.json "english"[0]; also the vector quoted by the BIP-39 spec page).
// passphrase = "TREZOR" (the vectors' fixed passphrase).
// ---------------------------------------------------------------------------

/// Entropy of BIP-39 vector 1 (16 bytes, all zero).
const BIP39_V1_ENTROPY: [u8; 16] = [0u8; 16];

/// Official sentence: eleven "abandon" + "about"; word indices (English list:
/// abandon = 0, about = 3).
const BIP39_V1_INDICES: [u16; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];

/// Official 64-byte seed for entropy above with passphrase "TREZOR".
const BIP39_V1_SEED_HEX: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

// ---------------------------------------------------------------------------
// Tier 1 anchors — BIP-32 official Test Vector 1 (bip-0032.mediawiki,
// "Test Vectors" section). The xprv strings below are copied verbatim from
// the spec; the tests decode them (own base58check + sha256d) and compare the
// raw fields, so the spec strings themselves are the pinned literals.
// ---------------------------------------------------------------------------

/// BIP-32 TV1 seed (hex): 000102030405060708090a0b0c0d0e0f
const BIP32_TV1_SEED: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

/// BIP-32 TV1 chain m (master) — official ext prv.
const BIP32_TV1_MASTER_XPRV: &str =
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

/// BIP-32 TV1 chain m/0' — official ext prv (first hardened child).
const BIP32_TV1_M_0H_XPRV: &str =
    "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";

/// BIP-32 TV1 chain m/0'/1 — official ext prv (normal child of a hardened key;
/// exercises CKDpub-style ser_P input on the priv path).
const BIP32_TV1_M_0H_1_XPRV: &str =
    "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs";

// ---------------------------------------------------------------------------
// Tier 2 anchors — DEV_WALLET (see module docs).
// ---------------------------------------------------------------------------

/// Deterministic device wallet entropy (flux/pico2/bench/xmr_2in_bringup.py
/// `DEV_ENTROPY`, 32 bytes = 24-word family).
const DEV_WALLET_ENTROPY_HEX: &str =
    "4a9291a702c0ba28aa285882efde4f2c9237556ceb685570d595fd6586074530";

/// Monero mainnet address of the DEV_WALLET (95 chars, standard address):
/// monero core (wallet2) output in flux/forgebox/monero-wallet-rpc.log when
/// loading the `sh_dev_correct` watch-only wallet; prefix documented in
/// tests/fixtures/README.md (`unsigned_txset_2in_dev.bin`, 4844Nk4X...).
const DEV_WALLET_ADDRESS: &str =
    "4844Nk4Xb2K2HcxUkfQSaLiJFHikLALiKX7re6aHrw1q8RUDg921rQTcwvwS4C8dK5YnUv3PHGHJQjaMyaxSfCEz7D6q5nM";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Independent base58 decode (Bitcoin alphabet) — not the production
/// `encoding::base58`, so the extraction of expected values from the official
/// xprv strings cannot be masked by a bug in the production decoder.
fn base58_decode_own(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut out: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let v = ALPHABET
            .iter()
            .position(|&a| a == c)
            .expect("base58 character") as u32;
        let mut carry = v;
        for byte in out.iter_mut() {
            let t = *byte as u32 * 58 + carry;
            *byte = (t & 0xff) as u8;
            carry = t >> 8;
        }
        while carry > 0 {
            out.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // leading '1' characters are encoded zero bytes
    for c in s.bytes() {
        if c == b'1' {
            out.push(0);
        } else {
            break;
        }
    }
    out.reverse();
    out
}

/// Base58check decode: base58 + verify the 4-byte double-SHA-256 checksum
/// (sha2 crate — independent of the production sha256 wrapper). Returns the
/// 78-byte xprv payload.
fn xprv_payload(xprv: &str) -> [u8; 78] {
    use sha2::{Digest, Sha256};
    let raw = base58_decode_own(xprv);
    assert_eq!(raw.len(), 82, "xprv base58check length");
    let (body, checksum) = raw.split_at(78);
    let h1 = Sha256::digest(body);
    let h2 = Sha256::digest(h1);
    assert_eq!(checksum, &h2[..4], "xprv base58check checksum");
    let mut out = [0u8; 78];
    out.copy_from_slice(body);
    out
}

/// Independent Monero base58 decode (block-wise: 8 data bytes -> 11 chars,
/// final partial block sized by the encoded length). Decodes a standard
/// 95-char XMR address into its 69 raw bytes.
fn monero_base58_decode_own(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const FULL_BLOCK: usize = 8;
    const ENCODED_FULL_BLOCK: usize = 11;
    const ENCODED_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

    let mut out: Vec<u8> = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let enc_len = std::cmp::min(ENCODED_FULL_BLOCK, b.len() - i);
        let dec_len = ENCODED_BLOCK_SIZES
            .iter()
            .position(|&e| e == enc_len)
            .expect("valid encoded block size");
        // big-number decode of one block (little-endian accumulate, then flip)
        let mut acc: Vec<u8> = Vec::new();
        for &c in &b[i..i + enc_len] {
            let v = ALPHABET
                .iter()
                .position(|&a| a == c)
                .expect("monero base58 character") as u32;
            let mut carry = v;
            for byte in acc.iter_mut() {
                let t = *byte as u32 * 58 + carry;
                *byte = (t & 0xff) as u8;
                carry = t >> 8;
            }
            while carry > 0 {
                acc.push((carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        acc.reverse();
        while acc.len() < dec_len {
            acc.insert(0, 0);
        }
        assert_eq!(acc.len(), dec_len, "monero base58 block decode size");
        out.extend_from_slice(&acc);
        i += enc_len;
    }
    assert!(
        out.len() == FULL_BLOCK * 8 + 5 || out.len() == FULL_BLOCK * 8,
        "unexpected decoded length"
    );
    out
}

/// Monero-correct pubkey: raw_scalar * G -> Ed25519Point wrapper.
///
/// NOT ed25519-dalek's RFC-8032 seed semantics (`base_mul`); pattern shared
/// with tests/p64_xmr_multi_input.rs `monero_pub`.
fn monero_pub(sec: &[u8; 32]) -> Ed25519Point {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    let s = Scalar::from_bytes_mod_order(*sec);
    let compressed = (ED25519_BASEPOINT_TABLE * &s).compress().to_bytes();
    point_from_compressed(&compressed).expect("valid point")
}

// ---------------------------------------------------------------------------
// Tier 1 pins — BIP-39 entropy -> mnemonic -> seed (front of the chain)
// ---------------------------------------------------------------------------

/// BIP-39 official vector 1: entropy 0x00*16 -> eleven "abandon" + "about"
/// and, with passphrase "TREZOR", the spec's 64-byte seed. Anchors the
/// entropy -> mnemonic -> PBKDF2 stage of the KeySession chain.
#[test]
fn bip39_entropy_to_seed_official_vector_tier1() {
    let m = Mnemonic::from_entropy(&BIP39_V1_ENTROPY).expect("mnemonic from entropy");
    assert_eq!(
        m.indices(),
        &BIP39_V1_INDICES[..],
        "entropy -> mnemonic indices must match the BIP-39 official vector"
    );
    let seed = mnemonic_to_seed(&m, b"TREZOR").expect("bip39 seed");
    assert_eq!(
        hex(&seed.into_bytes()),
        BIP39_V1_SEED_HEX.replace('\n', ""),
        "entropy -> 64B seed must match the BIP-39 official vector (passphrase TREZOR)"
    );
}

/// The same anchor seen through KeySession itself: a session built from the
/// BIP-39 vector-1 entropy + "TREZOR" passphrase must hold exactly the
/// official 64-byte seed (KeySession's entropy->seed stage pinned absolute).
#[test]
fn key_session_seed_stage_matches_bip39_official_vector_tier1() {
    let session =
        KeySession::from_entropy(&BIP39_V1_ENTROPY, b"TREZOR").expect("session from entropy");
    assert_eq!(
        hex(session.seed().expose()),
        BIP39_V1_SEED_HEX.replace('\n', ""),
        "KeySession seed stage must reproduce the BIP-39 official seed"
    );
}

// ---------------------------------------------------------------------------
// Tier 1 pins — BIP-32 middle layer (official Test Vector 1)
// ---------------------------------------------------------------------------

/// BIP-32 TV1 master: master_from_seed must serialize to exactly the spec's
/// xprv (version/depth/fingerprint/child/chain code/key all compared after an
/// independent base58check decode of the official string).
#[test]
fn bip32_master_matches_official_vector_tier1() {
    let master = master_from_seed(&BIP32_TV1_SEED).expect("master from seed");
    let official = xprv_payload(BIP32_TV1_MASTER_XPRV);
    assert_eq!(
        hex(master.as_ref()),
        hex(&official),
        "master serialization must equal the decoded BIP-32 TV1 master xprv"
    );
    // Raw-field spelling of the same anchor (spec's xprv decoded):
    // chain_code = 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
    // key        = e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
    assert_eq!(
        hex(&official[13..45]),
        "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
        "master chain code must match the official vector"
    );
    assert_eq!(
        hex(&official[46..78]),
        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        "master key must match the official vector"
    );
}

/// BIP-32 TV1 children: m/0' (hardened) and m/0'/1 (normal child of a
/// hardened key) — the two CKDpriv flavors the Monero path mixes
/// (m/44'/128'/0'/0/0 = hardened, hardened, hardened, normal, normal).
#[test]
fn bip32_children_match_official_vector_tier1() {
    // m/0'
    let official_0h = xprv_payload(BIP32_TV1_M_0H_XPRV);
    let s = derive_from_seed(
        &BIP32_TV1_SEED,
        &DerivationPath::parse("m/0'").expect("path"),
    )
    .expect("derive m/0'");
    let raw = shlosilo::curve_primitive::secp256k1::scalar_to_bytes(&s);
    assert_eq!(
        hex(&raw),
        hex(&official_0h[46..78]),
        "m/0' key must match the official vector (key = edb2e14f...afea)"
    );

    // m/0'/1
    let official_0h_1 = xprv_payload(BIP32_TV1_M_0H_1_XPRV);
    let s = derive_from_seed(
        &BIP32_TV1_SEED,
        &DerivationPath::parse("m/0'/1").expect("path"),
    )
    .expect("derive m/0'/1");
    let raw = shlosilo::curve_primitive::secp256k1::scalar_to_bytes(&s);
    assert_eq!(
        hex(&raw),
        hex(&official_0h_1[46..78]),
        "m/0'/1 key must match the official vector (key = 3c6cb8d0...3368)"
    );
}

// ---------------------------------------------------------------------------
// Tier 2 pin — full chain: DEV_WALLET entropy -> Monero address
// ---------------------------------------------------------------------------

/// Fixed BIP-39 entropy -> Monero spend/view -> mainnet address, absolute.
///
/// Input = DEV_WALLET entropy (tier 2, repo-history anchored). Output =
/// the 95-char mainnet address monero core itself reports for this wallet
/// (tier 2, monero core output + mainnet-proven). Together they freeze the
/// ENTIRE KeySession derivation chain end to end: BIP-39 entropy->seed,
/// BIP-32 m/44'/128'/0'/0/0, keccak reduce_scalar spend/view, and the
/// base58-monero address encoding.
#[test]
fn key_session_dev_wallet_entropy_to_address_anchor_tier2() {
    let entropy = unhex(DEV_WALLET_ENTROPY_HEX);
    assert_eq!(
        entropy.len(),
        32,
        "dev entropy is 32 bytes (24-word family)"
    );

    let session = KeySession::from_entropy(&entropy, b"").expect("session from entropy");
    let keys = session.monero();
    let spend_sec: [u8; 32] = *keys.spend_sk.expose();
    let view_sec: [u8; 32] = *keys.view_sk.expose();

    let spend_pub = monero_pub(&spend_sec);
    let view_pub = monero_pub(&view_sec);
    let addr = encode(&spend_pub, &view_pub, Network::MoneroMainnet).expect("xmr address encode");

    assert_eq!(
        addr.as_ref(),
        DEV_WALLET_ADDRESS,
        "DEV_WALLET entropy -> address must reproduce the monero-core-validated address"
    );
}

/// The same anchor verified independently of the production address encoder:
/// decode the 95-char anchor literal with an own Monero-base58 decoder and
/// check (a) it holds exactly the derived spend/view pubs and (b) its 4-byte
/// checksum is keccak256(payload)[..4] recomputed through the independent
/// `sha3` crate (not tiny-keccak). This ties the derived keys to the anchor
/// literal without trusting `address::xmr::encode`.
#[test]
fn key_session_dev_wallet_pubs_reproduce_anchor_address() {
    let entropy = unhex(DEV_WALLET_ENTROPY_HEX);
    let session = KeySession::from_entropy(&entropy, b"").expect("session from entropy");
    let keys = session.monero();

    let spend_pub = monero_pub(keys.spend_sk.expose());
    let view_pub = monero_pub(keys.view_sk.expose());

    let decoded = monero_base58_decode_own(DEV_WALLET_ADDRESS);
    assert_eq!(
        decoded.len(),
        69,
        "standard XMR address payload is 69 bytes"
    );
    assert_eq!(decoded[0], 0x12, "anchor address is Monero mainnet");
    assert_eq!(
        hex(&decoded[1..33]),
        hex(&point_to_compressed(&spend_pub)),
        "anchor address must encode the chain-derived spend_pub"
    );
    assert_eq!(
        hex(&decoded[33..65]),
        hex(&point_to_compressed(&view_pub)),
        "anchor address must encode the chain-derived view_pub"
    );
    // independent keccak checksum (sha3 crate)
    use sha3::Digest;
    let mut h = sha3::Keccak256::new();
    h.update(&decoded[..65]);
    let cksum = h.finalize();
    assert_eq!(
        hex(&decoded[65..69]),
        hex(&cksum[..4]),
        "anchor address checksum must be keccak256(payload)[..4]"
    );
}
