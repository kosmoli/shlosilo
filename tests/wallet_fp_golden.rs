//! `wallet_fp` absolute-value golden pins (fix37 binding + 10-19 length fix).
//!
//! `WalletKiRecord.wallet_fp = keccak256(spend_pub || view_pub)[..8]`
//! (forms/business/sign.rs, fix37). The existing tests only exercise it
//! *indirectly* (foreign-fp records treated as absent), so a drift in the
//! fingerprint computation itself would go unnoticed. This file freezes the
//! absolute values.
//!
//! Design:
//! * fixed, externally meaningful key bytes (RFC 8032 point encodings) so the
//!   keccak256 input is reproducible by ANY external Keccak-256 tool;
//! * the expected constants are asserted against BOTH the production path
//!   (`business::sign::wallet_fingerprint`, tiny-keccak wrapper) and an
//!   independent path (hand-built `spend_pub || view_pub` concatenation
//!   hashed with the `sha3` crate's Keccak-256 — a different keccak
//!   implementation), so the pin cannot go green against a single drifted
//!   implementation;
//! * `wallet_fingerprint_from_seed` (10-19 fixed a real bug where the API
//!   took `&[u8;32]` instead of the 64-byte BIP-39 seed) is pinned for its
//!   LENGTH SEMANTICS: the full 64 bytes must participate, a 32-byte prefix
//!   must give a different fingerprint, and non-BIP-32 lengths must be
//!   rejected rather than silently truncated. The 64-byte golden is
//!   additionally cross-checked against a fully independent re-derivation
//!   (own BIP-32 CKDpriv via hmac+sha2+k256, own keccak via sha3, ed25519
//!   pubs via curve25519-dalek).
//!
//! Provenance: the fixed INPUTS are externally anchored (RFC 8032 point
//! encodings; BIP-39 official vector-1 seed). The fingerprint OUTPUT
//! constants are golden-frozen values, cross-verified through the independent
//! paths above — they are not claimed as third-party vectors.

use shlosilo::business::sign::{wallet_fingerprint, wallet_fingerprint_from_seed};

// ---------------------------------------------------------------------------
// Fixed inputs (externally documented constants)
// ---------------------------------------------------------------------------

/// Compressed Ed25519 basepoint G — RFC 8032 point encoding
/// (0x58 || 0x66*31), the canonical "4/5" y-coordinate encoding.
const SPEND_PUB_G: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// Compressed Ed25519 identity element — RFC 8032 encoding (0x01 || 0x00*31).
const VIEW_PUB_ID: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// BIP-39 official test vector 1 seed (entropy 0x00*16, passphrase "TREZOR";
/// trezor/python-mnemonic vectors.json) — a fixed, externally anchored
/// 64-byte BIP-39 seed for the from_seed length-semantics pins.
const BIP39_V1_SEED: [u8; 64] = [
    0xc5, 0x52, 0x57, 0xc3, 0x60, 0xc0, 0x7c, 0x72, 0x02, 0x9a, 0xeb, 0xc1, 0xb5, 0x3c, 0x05, 0xed,
    0x03, 0x62, 0xad, 0xa3, 0x8e, 0xad, 0x3e, 0x3e, 0x9e, 0xfa, 0x37, 0x08, 0xe5, 0x34, 0x95, 0x53,
    0x1f, 0x09, 0xa6, 0x98, 0x75, 0x99, 0xd1, 0x82, 0x64, 0xc1, 0xe1, 0xc9, 0x2f, 0x2c, 0xf1, 0x41,
    0x63, 0x0c, 0x7a, 0x3c, 0x4a, 0xb7, 0xc8, 0x1b, 0x2f, 0x00, 0x16, 0x98, 0xe7, 0x46, 0x3b, 0x04,
];

/// Monero path m/44'/128'/0'/0/0 as BIP-32 CKDpriv indices (hardened bit set
/// on 44, 128, 0 — as forms/derivation/monero_reduce_scalar.rs builds it).
const MONERO_PATH_INDICES: [u32; 5] = [0x8000_002C, 0x8000_0080, 0x8000_0000, 0, 0];

// ---------------------------------------------------------------------------
// Golden constants (frozen; recomputable from the fixed inputs above with any
// Keccak-256 tool — keccak256(spend_pub || view_pub)[..8])
// ---------------------------------------------------------------------------

/// keccak256(SPEND_PUB_G || VIEW_PUB_ID) — full 32-byte digest.
const GOLDEN_KECCAK_G_ID: [u8; 32] = [
    0xa5, 0x44, 0x00, 0xf8, 0x71, 0x4e, 0x77, 0x22, 0x12, 0x8c, 0x0a, 0xd2, 0x3a, 0x0c, 0x26, 0xb3,
    0xe9, 0x60, 0x3d, 0xf5, 0xda, 0x3b, 0x1a, 0xfb, 0xea, 0xf7, 0x1d, 0x5d, 0x25, 0xce, 0x4d, 0x75,
];
/// keccak256(SPEND_PUB_G || VIEW_PUB_ID)[..8] — wallet_fp for the fixed pair.
const GOLDEN_FP_G_ID: [u8; 8] = [0xa5, 0x44, 0x00, 0xf8, 0x71, 0x4e, 0x77, 0x22];
/// keccak256(VIEW_PUB_ID || SPEND_PUB_G)[..8] — swapped order (different!).
const GOLDEN_FP_ID_G: [u8; 8] = [0x5e, 0x72, 0xac, 0x6f, 0x1a, 0x7f, 0x87, 0x61];
/// wallet_fingerprint_from_seed(BIP39_V1_SEED) — 64-byte BIP-39 seed.
const GOLDEN_SEED_FP: [u8; 8] = [0x4b, 0xa2, 0x2b, 0x6b, 0x05, 0xd6, 0x7d, 0x8e];
/// wallet_fingerprint_from_seed(&BIP39_V1_SEED[..32]) — 32-byte prefix.
const GOLDEN_SEED_FP_32: [u8; 8] = [0xbd, 0x3a, 0xfd, 0x3b, 0xe1, 0x13, 0x5c, 0xdd];

// ---------------------------------------------------------------------------
// Independent computation paths
// ---------------------------------------------------------------------------

/// Independent Keccak-256 (sha3 crate — NOT the production tiny-keccak).
fn keccak256_ind(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let mut h = sha3::Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// Independent wallet fingerprint: hand-built spend||view concatenation, then
/// the independent keccak. This is the "另一个 keccak crate / 手写拼接后哈希
/// 对照" cross-check.
fn wallet_fp_ind(spend_pub: &[u8; 32], view_pub: &[u8; 32]) -> ([u8; 8], [u8; 32]) {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(spend_pub);
    buf[32..].copy_from_slice(view_pub);
    let full = keccak256_ind(&buf);
    let mut fp = [0u8; 8];
    fp.copy_from_slice(&full[..8]);
    (fp, full)
}

/// Independent HMAC-SHA512 (hmac + sha2 crates).
fn hmac_sha512_ind(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("hmac key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// Independent BIP-32 CKDpriv (spec text: I = HMAC-SHA512(c_par, ...),
/// k_i = parse256(I_L) + k_par mod n). Fixed test vectors only: the
/// "invalid child, try next index" rule (I_L >= n) is not exercised by them.
fn bip32_raw_ind(seed: &[u8], indices: &[u32]) -> [u8; 32] {
    use k256::elliptic_curve::ff::PrimeField;
    use k256::elliptic_curve::sec1::ToSec1Point;

    let i = hmac_sha512_ind(b"Bitcoin seed", &[seed]);
    let mut k: [u8; 32] = i[..32].try_into().expect("32");
    let mut c: [u8; 32] = i[32..].try_into().expect("32");

    for &idx in indices {
        let i = if idx >= 0x8000_0000 {
            // hardened: 0x00 || ser256(k_par) || ser32(i)
            hmac_sha512_ind(&c, &[&[0u8], &k, &idx.to_be_bytes()])
        } else {
            // normal: ser_P(point(k_par)) || ser32(i)
            let s = <k256::Scalar as PrimeField>::from_repr(k256::FieldBytes::from(k))
                .expect("canonical secp scalar");
            let p = (k256::ProjectivePoint::from(k256::AffinePoint::GENERATOR) * s).to_affine();
            let pk: [u8; 33] = p
                .to_sec1_point(true)
                .as_bytes()
                .try_into()
                .expect("33-byte compressed");
            hmac_sha512_ind(&c, &[&pk, &idx.to_be_bytes()])
        };
        let il: [u8; 32] = i[..32].try_into().expect("32");
        c = i[32..].try_into().expect("32");
        // k_i = parse256(I_L) + k_par (mod n)
        let il_s = <k256::Scalar as PrimeField>::from_repr(k256::FieldBytes::from(il))
            .expect("canonical I_L for fixed vectors");
        let k_s = <k256::Scalar as PrimeField>::from_repr(k256::FieldBytes::from(k))
            .expect("canonical k_par");
        let sum: k256::Scalar = il_s + k_s;
        k = sum.to_bytes().into();
    }
    k
}

/// Independent full recomputation of `wallet_fingerprint_from_seed`: BIP-32
/// m/44'/128'/0'/0/0 (own CKDpriv) -> keccak-reduce spend/view (own keccak +
/// curve25519-dalek reduction) -> pubs -> fingerprint (own keccak).
fn from_seed_fp_ind(seed: &[u8]) -> [u8; 8] {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;

    let raw = bip32_raw_ind(seed, &MONERO_PATH_INDICES);
    let spend_s = Scalar::from_bytes_mod_order(keccak256_ind(&raw));
    let spend_bytes = spend_s.to_bytes();
    let view_s = Scalar::from_bytes_mod_order(keccak256_ind(&spend_bytes));
    let sp = (ED25519_BASEPOINT_TABLE * &spend_s).compress().to_bytes();
    let vp = (ED25519_BASEPOINT_TABLE * &view_s).compress().to_bytes();
    wallet_fp_ind(&sp, &vp).0
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Golden pins
// ---------------------------------------------------------------------------

/// wallet_fp absolute golden for the fixed pair: production == independent
/// (sha3 + hand concat) == frozen constant, and the full digest is pinned too.
#[test]
fn wallet_fp_golden_fixed_pair() {
    let (fp_ind, full_ind) = wallet_fp_ind(&SPEND_PUB_G, &VIEW_PUB_ID);

    assert_eq!(
        wallet_fingerprint(&SPEND_PUB_G, &VIEW_PUB_ID),
        GOLDEN_FP_G_ID,
        "production wallet_fingerprint drifted from the golden constant"
    );
    assert_eq!(
        fp_ind, GOLDEN_FP_G_ID,
        "independent keccak path drifted from the golden constant"
    );
    assert_eq!(
        full_ind, GOLDEN_KECCAK_G_ID,
        "full keccak256(spend||view) drifted from the golden constant"
    );
}

/// wallet_fp must be order-sensitive: swapping spend/view changes it.
#[test]
fn wallet_fp_golden_is_order_sensitive() {
    assert_eq!(
        wallet_fingerprint(&VIEW_PUB_ID, &SPEND_PUB_G),
        GOLDEN_FP_ID_G,
        "swapped-order fingerprint drifted from its golden constant"
    );
    assert_ne!(
        GOLDEN_FP_ID_G, GOLDEN_FP_G_ID,
        "spend||view and view||spend must fingerprint differently"
    );
    assert_eq!(
        wallet_fp_ind(&VIEW_PUB_ID, &SPEND_PUB_G).0,
        GOLDEN_FP_ID_G,
        "independent path agrees on the swapped-order golden"
    );
}

/// wallet_fingerprint_from_seed absolute golden on a fixed 64-byte BIP-39
/// seed (BIP-39 official vector-1 seed): production == fully independent
/// re-derivation == frozen constant.
#[test]
fn wallet_fp_from_seed_golden_64_byte_bip39_seed() {
    let got = wallet_fingerprint_from_seed(&BIP39_V1_SEED);
    assert_eq!(
        got, GOLDEN_SEED_FP,
        "wallet_fingerprint_from_seed(64B BIP-39 seed) drifted from its golden constant"
    );
    assert_eq!(
        from_seed_fp_ind(&BIP39_V1_SEED),
        GOLDEN_SEED_FP,
        "independent re-derivation disagrees with the golden constant"
    );
}

/// Length semantics (regression for the 2026-10-19 `&[u8;32]` mis-signature
/// bug): the seed length materially changes the result and must never be
/// silently truncated or ignored.
#[test]
fn wallet_fp_from_seed_is_length_sensitive() {
    // 64 bytes fully participate: the 32-byte prefix fingerprints differently.
    let fp32 = wallet_fingerprint_from_seed(&BIP39_V1_SEED[..32]);
    assert_eq!(
        fp32, GOLDEN_SEED_FP_32,
        "32-byte-prefix fingerprint drifted from its golden constant"
    );
    assert_ne!(
        fp32, GOLDEN_SEED_FP,
        "a 32-byte prefix must NOT reproduce the 64-byte-seed fingerprint \
         (this is exactly the old &[u8;32] truncation bug)"
    );
    // Independent cross-check of the 32-byte case too.
    assert_eq!(
        from_seed_fp_ind(&BIP39_V1_SEED[..32]),
        GOLDEN_SEED_FP_32,
        "independent re-derivation disagrees on the 32-byte input"
    );

    // Any other 64-byte seed fingerprints differently.
    let mut other = BIP39_V1_SEED;
    other[63] ^= 0x01;
    assert_ne!(
        wallet_fingerprint_from_seed(&other),
        GOLDEN_SEED_FP,
        "the last seed byte must participate in the derivation"
    );

    // 16-byte seed is a legal BIP-32 length (12-word family) — differs too.
    assert_ne!(
        wallet_fingerprint_from_seed(&BIP39_V1_SEED[..16]),
        wallet_fingerprint_from_seed(&BIP39_V1_SEED[..32]),
        "different seed lengths must derive different fingerprints"
    );

    // A 65-byte input is not a legal BIP-32 seed length: it must be REJECTED
    // (today via the derive().expect panic) — never silently truncated to 64.
    let mut seed65 = [0u8; 65];
    seed65[..64].copy_from_slice(&BIP39_V1_SEED);
    let rejected = std::panic::catch_unwind(|| wallet_fingerprint_from_seed(&seed65));
    assert!(
        rejected.is_err(),
        "a 65-byte seed must be rejected, not silently truncated to 64 bytes"
    );
}

/// Dev-only constant dump used once to freeze the golden constants above.
/// Kept ignored: run with `--ignored --nocapture` to re-derive them.
#[test]
#[ignore = "constant freezer: prints the golden values, asserts nothing"]
fn dump_golden_constants() {
    let (fp_a, full_a) = wallet_fp_ind(&SPEND_PUB_G, &VIEW_PUB_ID);
    let (fp_b, _) = wallet_fp_ind(&VIEW_PUB_ID, &SPEND_PUB_G);
    println!("GOLDEN_KECCAK_G_ID = {}", hex(&full_a));
    println!("GOLDEN_FP_G_ID     = {}", hex(&fp_a));
    println!("GOLDEN_FP_ID_G     = {}", hex(&fp_b));
    println!(
        "GOLDEN_SEED_FP     = {}",
        hex(&wallet_fingerprint_from_seed(&BIP39_V1_SEED))
    );
    println!(
        "GOLDEN_SEED_FP_32  = {}",
        hex(&wallet_fingerprint_from_seed(&BIP39_V1_SEED[..32]))
    );
    // cross-path sanity while dumping
    assert_eq!(wallet_fingerprint(&SPEND_PUB_G, &VIEW_PUB_ID), fp_a);
    assert_eq!(
        from_seed_fp_ind(&BIP39_V1_SEED),
        wallet_fingerprint_from_seed(&BIP39_V1_SEED)
    );
}
