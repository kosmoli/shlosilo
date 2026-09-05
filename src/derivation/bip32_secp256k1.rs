//! BIP-32 derivation over secp256k1 (BTC + ETH + Cosmos + Tron + XRP)
//!
//! Phase 5 v3 self-implementation (P2-04 option 1): no longer wraps the `bip32` crate,
//! implements CKDpriv directly per the BIP-32 spec — aligned with §2.3 "self-implemented key derivation".
//!
//! ## Algorithm (BIP-32 §Child key derivation (CKD) functions)
//!
//! master (seed → master extended private key):
//!   `I = HMAC-SHA512(key = "Bitcoin seed", data = seed)`
//!   `master.sk = I[..32]`，`master.chain_code = I[32..]`
//!   The seed length only accepts 16/32/64 bytes (same constraint as BIP-32 / the bip32 crate).
//!
//! CKDpriv((k_par, c_par), i)：
//!   hardened (i ≥ 2^31)：`I = HMAC-SHA512(c_par, 0x00 ‖ ser256(k_par) ‖ ser32(i))`
//!   normal  (i < 2^31)： `I = HMAC-SHA512(c_par, ser_P(point(k_par)) ‖ ser32(i))`
//!   `k_i = I_L + k_par (mod n)` (IL ≥ n or k_i = 0 → invalid; the spec requires iterating further;
//!   probability < 2^-127; here we error out directly, matching the bip32 crate's policy)
//!   `c_i = I_R`
//!
//! ## Public API (v2 compatible, zero changes for callers)
//!
//! - `master_from_seed(seed) -> ExtendedPrivKey` (78 bytes serialized)
//! - `derive_from_seed(seed, path) -> Secp256k1Scalar`
//! - `xpub_from_seed(seed, path) -> [u8; 78]`
//! - `derive(master, path) -> Secp256k1Scalar` (real implementation since v3: deserializes from 78 bytes and continues deriving)
//!
//! ## oracle
//!
//! - BIP-32 official Test Vectors 1/2/3 (tests/bip32_vectors_self_impl.rs)
//! - keystone cross-validation (tests/xmr_keystone_cross_validation.rs, pre-existing)
//!
//! ## Security constraints (v2 §2.1, carried over)
//!
//! - `ExtendedPrivKey` fields private, ZeroizeOnDrop
//! - `derive_from_seed` accepts a `&[u8]` seed (BIP-39 outputs 64 bytes)
//! - The returned `Secp256k1Scalar` is directly protected by Zeroize

use crate::curve_primitive::secp256k1::{self as secp, Secp256k1Scalar};
use crate::derivation::path::DerivationPath;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

type HmacSha512 = Hmac<Sha512>;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// BIP-32 extended private key (78 bytes: version + depth + fp + chain_code + key + ...)
pub const EXTENDED_PRIVKEY_LEN: usize = 78;

/// master derivation domain separator: ASCII "Bitcoin seed"
const BITCOIN_SEED: &[u8] = b"Bitcoin seed";

/// High-bit-aligned prefix of the secp256k1 curve order n (compressed pubkey / private key serialized length)
const SCALAR_LEN: usize = 32;
const COMPRESSED_POINT_LEN: usize = 33;

/// BIP-32 extended private key wrapper
// P1-03: Clone forbidden (v2-security §2)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ExtendedPrivKey {
    bytes: [u8; EXTENDED_PRIVKEY_LEN],
}

impl AsRef<[u8]> for ExtendedPrivKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for ExtendedPrivKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ExtendedPrivKey(<{} bytes redacted>)", self.bytes.len())
    }
}

/// Internal extended private key (working form during derivation; zeroized on drop)
struct ExtSk {
    key: [u8; SCALAR_LEN], // private key scalar (big-endian)
    chain_code: [u8; 32],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: u32,
}

impl ZeroizeOnDrop for ExtSk {}
impl Drop for ExtSk {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
// chain_code / fingerprint / child_number are public material; no zeroization needed

fn err_invalid() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// 78-byte serialization (xprv layout)
fn extsk_to_bytes(k: &ExtSk, key_or_pub: KeyOrPub) -> [u8; EXTENDED_PRIVKEY_LEN] {
    let mut bytes = [0u8; EXTENDED_PRIVKEY_LEN];
    match key_or_pub {
        KeyOrPub::Xprv => {
            bytes[..4].copy_from_slice(&0x0488_ADE4u32.to_be_bytes());
            bytes[45] = 0x00;
            bytes[46..78].copy_from_slice(&k.key);
        }
        KeyOrPub::Xpub => {
            bytes[..4].copy_from_slice(&0x0488_B21Eu32.to_be_bytes());
            // key = compressed public key (33 bytes)
            if let Ok(sk) = secp::scalar_from_bytes(&k.key) {
                let pk = secp::base_mul(&sk);
                let compressed = secp::point_to_compressed(&pk);
                bytes[45..78].copy_from_slice(&compressed);
            }
        }
    }
    bytes[4] = k.depth;
    bytes[5..9].copy_from_slice(&k.parent_fingerprint);
    bytes[9..13].copy_from_slice(&k.child_number.to_be_bytes());
    bytes[13..45].copy_from_slice(&k.chain_code);
    bytes
}

enum KeyOrPub {
    Xprv,
    Xpub,
}

/// 4-byte key fingerprint = RIPEMD160(SHA256(compressed_pub))[..4]
fn fingerprint(compressed_pub: &[u8; COMPRESSED_POINT_LEN]) -> [u8; 4] {
    let sha = Sha256::digest(compressed_pub);
    let ripemd = ripemd::Ripemd160::digest(sha);
    [ripemd[0], ripemd[1], ripemd[2], ripemd[3]]
}

/// master derivation: `I = HMAC-SHA512("Bitcoin seed", seed)`
fn master_extsk(seed: &[u8]) -> Result<ExtSk> {
    // Consistent with the bip32 crate / BIP-32 practice: only 16/32/64-byte seeds accepted
    if ![16, 32, 64].contains(&seed.len()) {
        return Err(err_invalid());
    }
    let mut mac = <HmacSha512 as Mac>::new_from_slice(BITCOIN_SEED).map_err(|_| err_invalid())?;
    Mac::update(&mut mac, seed);
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; SCALAR_LEN];
    key.copy_from_slice(&out[..SCALAR_LEN]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&out[SCALAR_LEN..]);

    // Private key is 0 or ≥ n → invalid seed (BIP-32: negligible probability, reject directly)
    let ok = secp::scalar_from_bytes(&key).is_ok() && key.iter().any(|&b| b != 0);
    if !ok {
        return Err(err_invalid());
    }

    Ok(ExtSk {
        key,
        chain_code,
        depth: 0,
        parent_fingerprint: [0; 4],
        child_number: 0,
    })
}

/// CKDpriv, one step
fn ckd_priv(parent: &ExtSk, index: DerivationIndex) -> Result<ExtSk> {
    // Parent compressed pubkey, computed once and shared by both consumers below:
    // normal-CKD HMAC data (BIP-32: ser_P(point(k_par))) and the parent fingerprint.
    // Hardened steps only need it for the fingerprint; normal steps previously
    // computed it twice (once in MacData, once here).
    let parent_scalar = secp::scalar_from_bytes(&parent.key).map_err(|_| err_invalid())?;
    let parent_pk = secp::base_mul(&parent_scalar);
    let parent_compressed = secp::point_to_compressed(&parent_pk);

    let mut mac =
        <HmacSha512 as Mac>::new_from_slice(&parent.chain_code).map_err(|_| err_invalid())?;

    let data = MacData::new(parent, index, &parent_compressed)?;
    Mac::update(&mut mac, &data.buf);

    let out = mac.finalize().into_bytes();
    let mut tweak = [0u8; SCALAR_LEN];
    tweak.copy_from_slice(&out[..SCALAR_LEN]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&out[SCALAR_LEN..]);

    // IL ≥ n → invalid (probability < 2^-127)
    let tweak_scalar = secp::scalar_from_bytes(&tweak).map_err(|_| err_invalid())?;
    let parent_scalar = secp::scalar_from_bytes(&parent.key).map_err(|_| err_invalid())?;
    let child_scalar = secp::scalar_add(&tweak_scalar, &parent_scalar);
    let child_key = secp::scalar_to_bytes(&child_scalar);

    // k_i = 0 → invalid (probability < 2^-127)
    if child_key.iter().all(|&b| b == 0) {
        return Err(err_invalid());
    }

    // parent fingerprint = RIPEMD160(SHA256(parent compressed pubkey))[..4]
    // (parent_compressed computed once at the top of this function)
    let parent_fingerprint = fingerprint(&parent_compressed);

    Ok(ExtSk {
        key: child_key,
        chain_code,
        depth: parent.depth.checked_add(1).ok_or_else(err_invalid)?,
        parent_fingerprint,
        child_number: index.0,
    })
}

/// HMAC data buffer (hardened: 1+32+4=37B; normal: 33+4=37B)
struct MacData {
    buf: [u8; 37],
}

impl MacData {
    fn new(parent: &ExtSk, index: DerivationIndex, parent_compressed: &[u8; 33]) -> Result<Self> {
        let mut buf = [0u8; 37];
        if index.is_hardened() {
            buf[0] = 0x00;
            buf[1..33].copy_from_slice(&parent.key);
        } else {
            // normal: needs the parent public key in compressed form
            // (passed in precomputed by ckd_priv — no extra scalar mult here)
            buf[..33].copy_from_slice(parent_compressed);
        }
        // ser32(i): when hardened, i carries the 2^31 bit (BIP-32 spec), i.e. the raw u32
        buf[33..37].copy_from_slice(&index.0.to_be_bytes());
        Ok(Self { buf })
    }
}

use crate::derivation::path::DerivationIndex;

/// Extract 78-byte serialization from a BIP-32 master XPrv (zero alloc, v2 API preserved)
fn xprv_to_bytes(k: &ExtSk) -> [u8; EXTENDED_PRIVKEY_LEN] {
    extsk_to_bytes(k, KeyOrPub::Xprv)
}

/// BIP-32 master derivation (derive the master key from a BIP-39 seed)
pub fn master_from_seed(seed: &[u8]) -> Result<ExtendedPrivKey> {
    let k = master_extsk(seed)?;
    Ok(ExtendedPrivKey {
        bytes: xprv_to_bytes(&k),
    })
}

/// Deserialize from a 78-byte xprv (v3 onward supports derive(master, path))
fn extsk_from_bytes(bytes: &[u8; EXTENDED_PRIVKEY_LEN]) -> Result<ExtSk> {
    // version must be xprv
    if bytes[..4] != 0x0488_ADE4u32.to_be_bytes() {
        return Err(err_invalid());
    }
    // key part: 0x00 prefix + 32 bytes
    if bytes[45] != 0x00 {
        return Err(err_invalid());
    }
    let mut key = [0u8; SCALAR_LEN];
    key.copy_from_slice(&bytes[46..78]);
    secp::scalar_from_bytes(&key).map_err(|_| err_invalid())?;
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&bytes[13..45]);
    Ok(ExtSk {
        key,
        chain_code,
        depth: bytes[4],
        parent_fingerprint: [bytes[5], bytes[6], bytes[7], bytes[8]],
        child_number: u32::from_be_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]),
    })
}

/// CKDpriv step by step along the path
fn derive_path(mut k: ExtSk, path: &DerivationPath) -> Result<ExtSk> {
    for idx in path.as_slice() {
        k = ckd_priv(&k, *idx)?;
    }
    Ok(k)
}

/// master key fingerprint = RIPEMD160(SHA256(master compressed pubkey))[..4]
/// (P1-02: used to compare the fingerprint in PSBT BIP32_DERIVATION against ours)
pub fn master_fingerprint_from_seed(seed: &[u8]) -> Result<[u8; 4]> {
    let k = master_extsk(seed)?;
    if let Ok(sk) = secp::scalar_from_bytes(&k.key) {
        let pk = secp::base_mul(&sk);
        let compressed = secp::point_to_compressed(&pk);
        Ok(fingerprint(&compressed))
    } else {
        Err(err_invalid())
    }
}

/// BIP-32 path derivation (derive a child key directly from the seed, returning a 32-byte scalar)
pub fn derive_from_seed(seed: &[u8], path: &DerivationPath) -> Result<Secp256k1Scalar> {
    let k = derive_path(master_extsk(seed)?, path)?;
    secp::scalar_from_bytes(&k.key).map_err(|_| err_invalid())
}

/// BIP-32 path derivation (derive a child scalar from a master extended key)
///
/// v3 real implementation: deserialize the master from 78 bytes, then CKDpriv step by step.
pub fn derive(master: &ExtendedPrivKey, path: &DerivationPath) -> Result<Secp256k1Scalar> {
    let k = derive_path(extsk_from_bytes(&master.bytes)?, path)?;
    secp::scalar_from_bytes(&k.key).map_err(|_| err_invalid())
}

/// Export a BIP-32 xpub from seed + path (78 bytes, version = 0x0488B21E)
pub fn xpub_from_seed(seed: &[u8], path: &DerivationPath) -> Result<[u8; EXTENDED_PRIVKEY_LEN]> {
    let k = derive_path(master_extsk(seed)?, path)?;
    Ok(extsk_to_bytes(&k, KeyOrPub::Xpub))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED16: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    #[test]
    fn extended_privkey_len() {
        assert_eq!(EXTENDED_PRIVKEY_LEN, 78);
    }

    #[test]
    fn extended_privkey_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<ExtendedPrivKey>());
    }

    /// BIP-32 Test Vector 1 (basic master_from_seed)
    #[test]
    fn master_from_seed_basic() {
        let master = master_from_seed(&SEED16).unwrap();
        assert_eq!(master.bytes.len(), EXTENDED_PRIVKEY_LEN);
        // Version bytes = 0x0488ade4 (BIP-32 mainnet xprv version)
        assert_eq!(&master.bytes[0..4], &[0x04, 0x88, 0xad, 0xe4]);
        // Depth = 0 (master)
        assert_eq!(master.bytes[4], 0);
    }

    /// BIP-32 derivation: seed → master scalar (m)
    #[test]
    fn derive_from_seed_master() {
        let path = DerivationPath::parse("m").unwrap();
        let scalar = derive_from_seed(&SEED16, &path).unwrap();
        let sk_bytes = secp::scalar_to_bytes(&scalar);
        assert_eq!(sk_bytes.len(), 32);
    }

    /// BIP-32 derivation: seed → m/0
    #[test]
    fn derive_from_seed_m_0() {
        let path = DerivationPath::parse("m/0").unwrap();
        let scalar = derive_from_seed(&SEED16, &path).unwrap();
        let sk_bytes = secp::scalar_to_bytes(&scalar);
        assert_eq!(sk_bytes.len(), 32);
        assert_ne!(sk_bytes, [0u8; 32]);
    }

    /// BIP-32 derivation: seed → m/44'/0'/0'/0/0 (BTC BIP-44 standard path)
    #[test]
    fn derive_from_seed_bip44() {
        let path = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
        let scalar = derive_from_seed(&SEED16, &path).unwrap();
        let sk_bytes = secp::scalar_to_bytes(&scalar);
        assert_eq!(sk_bytes.len(), 32);
    }

    /// BIP-32 derivation consistency: same seed + path produce the same scalar
    #[test]
    fn derive_from_seed_deterministic() {
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let s1 = derive_from_seed(&SEED16, &path).unwrap();
        let s2 = derive_from_seed(&SEED16, &path).unwrap();
        assert_eq!(secp::scalar_to_bytes(&s1), secp::scalar_to_bytes(&s2));
    }

    /// BIP-32 derivation: different paths produce different scalars
    #[test]
    fn derive_from_seed_different_paths() {
        let path_a = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
        let path_b = DerivationPath::parse("m/44'/0'/0'/0/1").unwrap();
        let s_a = derive_from_seed(&SEED16, &path_a).unwrap();
        let s_b = derive_from_seed(&SEED16, &path_b).unwrap();
        assert_ne!(secp::scalar_to_bytes(&s_a), secp::scalar_to_bytes(&s_b));
    }

    /// BIP-32 Test Vector 1: master xprv serialization (BIP-32 official vector)
    /// xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
    #[test]
    fn bip32_test_vector_1_master() {
        let master = master_from_seed(&SEED16).unwrap();
        // core fields (chain code + key) of the decoded official xprv base58check:
        // chain_code = 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
        // key        = e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
        let expected_chain: [u8; 32] = [
            0x87, 0x3d, 0xff, 0x81, 0xc0, 0x2f, 0x52, 0x56, 0x23, 0xfd, 0x1f, 0xe5, 0x16, 0x7e,
            0xac, 0x3a, 0x55, 0xa0, 0x49, 0xde, 0x3d, 0x31, 0x4b, 0xb4, 0x2e, 0xe2, 0x27, 0xff,
            0xed, 0x37, 0xd5, 0x08,
        ];
        let expected_key: [u8; 32] = [
            0xe8, 0xf3, 0x2e, 0x72, 0x3d, 0xec, 0xf4, 0x05, 0x1a, 0xef, 0xac, 0x8e, 0x2c, 0x93,
            0xc9, 0xc5, 0xb2, 0x14, 0x31, 0x38, 0x17, 0xcd, 0xb0, 0x1a, 0x14, 0x94, 0xb9, 0x17,
            0xc8, 0x43, 0x6b, 0x35,
        ];
        assert_eq!(&master.bytes[13..45], &expected_chain[..]);
        assert_eq!(&master.bytes[46..78], &expected_key[..]);
    }

    /// BIP-32 Test Vector 1: m/0' (first hardened child)
    /// Official vector (BIP-32 PDF): chain_code=47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141
    ///           key=edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
    #[test]
    fn bip32_test_vector_1_m_0h() {
        let path = DerivationPath::parse("m/0'").unwrap();
        let scalar = derive_from_seed(&SEED16, &path).unwrap();
        let sk_bytes = secp::scalar_to_bytes(&scalar);
        let expected_key: [u8; 32] = [
            0xed, 0xb2, 0xe1, 0x4f, 0x9e, 0xe7, 0x7d, 0x26, 0xdd, 0x93, 0xb4, 0xec, 0xed, 0xe8,
            0xd1, 0x6e, 0xd4, 0x08, 0xce, 0x14, 0x9b, 0x6c, 0xd8, 0x0b, 0x07, 0x15, 0xa2, 0xd9,
            0x11, 0xa0, 0xaf, 0xea,
        ];
        assert_eq!(sk_bytes, expected_key);
    }

    /// BIP-32 Test Vector 1: m/0'/1（normal child of hardened）
    /// Official vector: key=3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368
    #[test]
    fn bip32_test_vector_1_m_0h_1() {
        let path = DerivationPath::parse("m/0'/1").unwrap();
        let scalar = derive_from_seed(&SEED16, &path).unwrap();
        let sk_bytes = secp::scalar_to_bytes(&scalar);
        let expected_key: [u8; 32] = [
            0x3c, 0x6c, 0xb8, 0xd0, 0xf6, 0xa2, 0x64, 0xc9, 0x1e, 0xa8, 0xb5, 0x03, 0x0f, 0xad,
            0xaa, 0x8e, 0x53, 0x8b, 0x02, 0x0f, 0x0a, 0x38, 0x74, 0x21, 0xa1, 0x2d, 0xe9, 0x31,
            0x9d, 0xc9, 0x33, 0x68,
        ];
        assert_eq!(sk_bytes, expected_key);
    }

    /// BIP-32 Test Vector 1: m/0'/1/2'/2 (deep mixed path)
    /// Official vector (BIP-32 PDF): key=0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4
    #[test]
    fn bip32_test_vector_1_m_0h_1_2h_2() {
        let path = DerivationPath::parse("m/0'/1/2'/2").unwrap();
        let scalar = derive_from_seed(&SEED16, &path).unwrap();
        let sk_bytes = secp::scalar_to_bytes(&scalar);
        let expected_key: [u8; 32] = [
            0x0f, 0x47, 0x92, 0x45, 0xfb, 0x19, 0xa3, 0x8a, 0x19, 0x54, 0xc5, 0xc7, 0xc0, 0xeb,
            0xab, 0x2f, 0x9b, 0xdf, 0xd9, 0x6a, 0x17, 0x56, 0x3e, 0xf2, 0x8a, 0x6a, 0x4b, 0x1a,
            0x2a, 0x76, 0x4e, 0xf4,
        ];
        assert_eq!(sk_bytes, expected_key);
    }

    /// BIP-32 Test Vector 1: m/0'/1/2'/2/1000000000 (huge soft index)
    /// Official vector: key=471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8
    #[test]
    fn bip32_test_vector_1_m_0h_1_2h_2_1000000000() {
        let path = DerivationPath::parse("m/0'/1/2'/2/1000000000").unwrap();
        let scalar = derive_from_seed(&SEED16, &path).unwrap();
        let sk_bytes = secp::scalar_to_bytes(&scalar);
        let expected_key: [u8; 32] = [
            0x47, 0x1b, 0x76, 0xe3, 0x89, 0xe5, 0x28, 0xd6, 0xde, 0x6d, 0x81, 0x68, 0x57, 0xe0,
            0x12, 0xc5, 0x45, 0x50, 0x51, 0xca, 0xd6, 0x66, 0x08, 0x50, 0xe5, 0x83, 0x72, 0xa6,
            0xc3, 0xe6, 0xe7, 0xc8,
        ];
        assert_eq!(sk_bytes, expected_key);
    }

    /// master_from_seed error: seed too short
    #[test]
    fn master_from_seed_rejects_short_seed() {
        let seed = [0u8; 8];
        let result = master_from_seed(&seed);
        assert!(result.is_err());
    }

    /// Seed length whitelist: reject anything outside 16/32/64 (same constraint as the bip32 crate)
    #[test]
    fn master_from_seed_rejects_nonstandard_len() {
        assert!(master_from_seed(&[0u8; 24]).is_err());
        assert!(master_from_seed(&[0u8; 48]).is_err());
        assert!(master_from_seed(&[0u8; 16]).is_ok());
        assert!(master_from_seed(&[0u8; 32]).is_ok());
        assert!(master_from_seed(&[0u8; 64]).is_ok());
    }

    /// v3: derive(master, path) real implementation — equivalent to derive_from_seed
    #[test]
    fn derive_from_master_matches_seed() {
        let master = master_from_seed(&SEED16).unwrap();
        let path = DerivationPath::parse("m/44'/60'/0'/0/3").unwrap();
        let from_seed = derive_from_seed(&SEED16, &path).unwrap();
        let from_master = derive(&master, &path).unwrap();
        assert_eq!(
            secp::scalar_to_bytes(&from_seed),
            secp::scalar_to_bytes(&from_master)
        );
    }

    /// derive rejects a non-xprv version (a 78-byte xpub input must error)
    #[test]
    fn derive_rejects_xpub_version() {
        let master = master_from_seed(&SEED16).unwrap();
        let mut xpub_like = master.bytes;
        xpub_like[..4].copy_from_slice(&0x0488_B21Eu32.to_be_bytes());
        let fake = ExtendedPrivKey { bytes: xpub_like };
        let path = DerivationPath::parse("m/0").unwrap();
        assert!(derive(&fake, &path).is_err());
    }

    /// xpub_from_seed: 78 bytes, version = 0x0488B21E, key = compressed public key
    #[test]
    fn xpub_from_seed_shape() {
        let path = DerivationPath::parse("m/0").unwrap();
        let xpub = xpub_from_seed(&SEED16, &path).unwrap();
        assert_eq!(&xpub[..4], &[0x04, 0x88, 0xB2, 0x1E]);
        assert_eq!(xpub[4], 1); // depth = 1
                                // public key prefix: 02 or 03 (compressed SEC1)
        assert!(xpub[45] == 0x02 || xpub[45] == 0x03);
        // xpub[45..78] must equal base_mul(sk)
        let sk = derive_from_seed(&SEED16, &path).unwrap();
        let pk = secp::base_mul(&sk);
        assert_eq!(&xpub[45..78], &secp::point_to_compressed(&pk)[..]);
    }

    /// fingerprint chain: m/0's parent_fingerprint = the master compressed public key fingerprint
    #[test]
    fn parent_fingerprint_chain() {
        let master_path = DerivationPath::parse("m").unwrap();
        let master_sk = derive_from_seed(&SEED16, &master_path).unwrap();
        let master_pk = secp::base_mul(&master_sk);
        let expected_fp = fingerprint(&secp::point_to_compressed(&master_pk));

        let xpub = xpub_from_seed(&SEED16, &DerivationPath::parse("m/0").unwrap()).unwrap();
        assert_eq!(&xpub[5..9], &expected_fp[..]);
    }
}
