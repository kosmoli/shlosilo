//! Monero Subaddress derivation (Phase 5 v9.6)
//!
//! ## Algorithm (RFC / monero-project/research-lab)
//!
//! Subaddresses let the receiver generate unlimited unlinkable addresses under one seed (ledger isolation),
//! Does not expose the linkage to the XMR main address.
//!
//! **Derivation scalar**:
//! ```text
//! m = Hs("SubAddr" || 0x00 || view_sec || major_idx || minor_idx)
//! ```
//!
//! where `Hs` = Keccak-256 hash to scalar (modulo the curve order L).
//!
//! **Subaddress key pairs**:
//! ```text
//! m                  = Hs("SubAddr" || 0x00 || view_sec || major || minor)
//! subaddr_spend_pub  = main_spend_pub + m * G   (= subaddr_spend_sec * G)
//! subaddr_view_pub   = subaddr_spend_pub * view_sec
//! subaddr_spend_sec  = (m + main_spend_sec) mod L
//! subaddr_view_sec   = (view_sec * subaddr_spend_sec) mod L
//! ```
//!
//! **NOTE**: shlosilo does not generate XMR address strings (that needs base58 + network byte + checksum),
//! Only generates the (subaddr_spend_pub, subaddr_view_pub) byte pair. Full address generation lives in the keystone reference
//! is handled by (c).
//!
//! **References**:
//! - <https://github.com/monero-project/monero/blob/master/src/wallet/wallet2.cpp> (get_subaddress_*)
//! - <https://github.com/monero-project/research-lab/blob/master/monero-subaddresses.md>

extern crate alloc;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use monero_ed25519::CompressedPoint;

use tiny_keccak::{Hasher, Keccak};

use crate::chain::xmr::reduce_scalar::{reduce_scalar, reduce_scalar_to_dalek};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// Monero curve order L (Ed25519 group order)
/// L = 2^252 + 27742317777372353535851937790883648493
pub const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Hash to scalar (Monero Hs):
/// Hs(data) = Keccak-256(data) interpreted as reduced scalar modulo L
///
/// **Input**: `data: &[u8]` of any length
/// **Output**: 32-byte reduced scalar
pub fn hash_to_scalar(data: &[u8]) -> Result<[u8; 32]> {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    let scalar = reduce_scalar(&out)?;
    Ok(crate::curve_primitive::ed25519::scalar_to_bytes(&scalar))
}

/// Compute the subaddress derivation scalar m (aligned with keystone / official Monero wallet2.cpp)
///
/// ```text
/// m = Hs("SubAddr" || 0x00 || view_sec || major_idx (LE u32) || minor_idx (LE u32))
/// ```
///
/// This is the official Monero subaddress derivation (MRL-0006 / wallet2.cpp `get_subaddress_secret_key`),
/// byte-for-byte identical to keystone3-firmware `apps/monero/src/key.rs::calc_subaddress_m`.
///
/// **Input**:
/// - view_sec: 32-byte view private key (reduced scalar)
/// - account: major index (u32)
/// - minor: minor index (u32)
///
/// **Output**: 32-byte derivation scalar m (reduced)
pub fn calc_subaddress_m(view_sec: &[u8; 32], account: u32, minor: u32) -> Result<[u8; 32]> {
    // data = "SubAddr" || 0x00 || view_sec || major_LE || minor_LE
    // Z2.2 A-class (2026-09-24): 48B stack buffer (was a heap Vec) —
    // byte layout unchanged: "SubAddr" || 0x00 || view_sec || major_LE || minor_LE.
    let mut data = [0u8; 7 + 1 + 32 + 4 + 4];
    data[..7].copy_from_slice(b"SubAddr");
    // data[7] stays 0x00
    data[8..40].copy_from_slice(view_sec);
    data[40..44].copy_from_slice(&account.to_le_bytes());
    data[44..48].copy_from_slice(&minor.to_le_bytes());
    hash_to_scalar(&data)
}

/// Subaddress key pair
/// R1 (2026-08-31 review remediation): secret fields go through SecretBytes<32> (ZeroizeOnDrop,
/// no Clone, no Debug), while public fields output normally via a hand-written Debug.
pub struct SubaddressKeys {
    /// subaddress spend public key (32 bytes compressed)
    pub spend_pub: [u8; 32],
    /// subaddress view public key (32 bytes compressed)
    pub view_pub: [u8; 32],
    /// subaddress spend private key (32 bytes reduced scalar)
    pub spend_sec: crate::types::SecretBytes<32>,
    /// subaddress view private key (32 bytes reduced scalar)
    pub view_sec: crate::types::SecretBytes<32>,
}

impl core::fmt::Debug for SubaddressKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SubaddressKeys")
            .field("spend_pub", &self.spend_pub)
            .field("view_pub", &self.view_pub)
            .field("spend_sec", &"[REDACTED]")
            .field("view_sec", &"[REDACTED]")
            .finish()
    }
}

/// Derive a subaddress (full key pair)
///
/// **Input**:
/// - main_spend_sec: 32-byte main spend private key (reduced scalar)
/// - main_view_sec: 32-byte main view private key (reduced scalar)
/// - main_spend_pub: 32-byte main spend public key (compressed)
/// - main_view_pub: 32-byte main view public key (compressed)
/// - account: major index
/// - minor: minor index
///
/// **Output**: `SubaddressKeys { spend_pub, view_pub, spend_sec, view_sec }`
pub fn derive_subaddress(
    main_spend_sec: &[u8; 32],
    main_view_sec: &[u8; 32],
    main_spend_pub: &[u8; 32],
    _main_view_pub: &[u8; 32],
    account: u32,
    minor: u32,
) -> Result<SubaddressKeys> {
    // 1. m = Hs("SubAddr" || 0x00 || view_sec || major || minor)
    let m = calc_subaddress_m(main_view_sec, account, minor)?;
    let m_dalek = reduce_scalar_to_dalek(&m);

    // 2. subaddr_spend_sec = (m + main_spend_sec) mod L
    let spend_sec_dalek = reduce_scalar_to_dalek(main_spend_sec);
    let subaddr_spend_sec_dalek = m_dalek + spend_sec_dalek;
    let mut subaddr_spend_sec: [u8; 32] = subaddr_spend_sec_dalek.to_bytes();

    // 3. subaddr_spend_pub = main_spend_pub + m * G  (= subaddr_spend_sec * G)
    let m_g: curve25519_dalek::EdwardsPoint = ED25519_BASEPOINT_TABLE * &m_dalek;
    let main_spend_pub_comp = CompressedPoint::from(*main_spend_pub);
    let main_spend_pub_point = main_spend_pub_comp
        .decompress()
        .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let main_spend_pub_edwards: curve25519_dalek::EdwardsPoint = main_spend_pub_point.into();
    let subaddr_spend_pub_point = main_spend_pub_edwards + m_g;
    let subaddr_spend_pub = subaddr_spend_pub_point.compress().to_bytes();

    // 4. subaddr_view_sec = (view_sec * subaddr_spend_sec) mod L
    //    (official Monero sub view secret c = a * d, d = spend secret, a = view secret)
    let view_sec_dalek = reduce_scalar_to_dalek(main_view_sec);
    let subaddr_view_sec_dalek = view_sec_dalek * subaddr_spend_sec_dalek;
    let mut subaddr_view_sec: [u8; 32] = subaddr_view_sec_dalek.to_bytes();

    // 5. subaddr_view_pub = subaddr_spend_pub * view_sec  (= subaddr_view_sec * G)
    let subaddr_view_pub_point = subaddr_spend_pub_point * view_sec_dalek;
    let subaddr_view_pub = subaddr_view_pub_point.compress().to_bytes();

    Ok(SubaddressKeys {
        spend_pub: subaddr_spend_pub,
        view_pub: subaddr_view_pub,
        // P1-C: take over and zero the caller's intermediate array (new only zeroes the parameter copy; take is the proper primitive here)
        spend_sec: crate::types::SecretBytes::take(&mut subaddr_spend_sec),
        view_sec: crate::types::SecretBytes::take(&mut subaddr_view_sec),
    })
}

/// Derive the Nth subaddress from (account, minor) (simplified — receiver scenario)
///
/// **Returns**: 32-byte subaddress spend public key
///
/// **Use case**: the receiver publishes the subaddress spend pub; the sender uses it to build tx outputs
pub fn derive_subaddress_spend_pub(
    main_spend_pub: &[u8; 32],
    main_view_sec: &[u8; 32],
    account: u32,
    minor: u32,
) -> Result<[u8; 32]> {
    let m = calc_subaddress_m(main_view_sec, account, minor)?;
    let m_dalek = reduce_scalar_to_dalek(&m);
    let m_g: curve25519_dalek::EdwardsPoint = ED25519_BASEPOINT_TABLE * &m_dalek;
    let main_spend_pub_comp = CompressedPoint::from(*main_spend_pub);
    let main_spend_pub_point = main_spend_pub_comp
        .decompress()
        .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let main_spend_pub_edwards: curve25519_dalek::EdwardsPoint = main_spend_pub_point.into();
    let subaddr_spend_pub_point = main_spend_pub_edwards + m_g;
    Ok(subaddr_spend_pub_point.compress().to_bytes())
}

/// Unit tests
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use std::eprintln;

    fn hex_encode(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&alloc::format!("{:02x}", byte));
        }
        s
    }

    /// Hs (hash to scalar) round-trip
    #[test]
    fn hash_to_scalar_test() {
        let data = b"shlosilo test data";
        let s1 = hash_to_scalar(data).unwrap();
        let s2 = hash_to_scalar(data).unwrap();
        assert_eq!(s1, s2);
        eprintln!("Hs: {}", hex_encode(&s1));
    }

    /// Main key pair generation (for testing subaddress derivation)
    fn make_test_keypair(seed_byte: u8) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        let spend_sec_ed = reduce_scalar(&[seed_byte; 32]).unwrap();
        let spend_sec_bytes = crate::curve_primitive::ed25519::scalar_to_bytes(&spend_sec_ed);
        let spend_sec_dalek = reduce_scalar_to_dalek(&spend_sec_bytes);
        let spend_pub_point = ED25519_BASEPOINT_TABLE * &spend_sec_dalek;
        let spend_pub = spend_pub_point.compress().to_bytes();

        let view_sec_ed = reduce_scalar(&[seed_byte.wrapping_add(0x55); 32]).unwrap();
        let view_sec_bytes = crate::curve_primitive::ed25519::scalar_to_bytes(&view_sec_ed);
        let view_sec_dalek = reduce_scalar_to_dalek(&view_sec_bytes);
        let view_pub_point = ED25519_BASEPOINT_TABLE * &view_sec_dalek;
        let view_pub = view_pub_point.compress().to_bytes();

        (spend_sec_bytes, view_sec_bytes, spend_pub, view_pub)
    }

    /// Full subaddress derivation round-trip
    #[test]
    fn subaddress_derivation_round_trip() {
        let (spend_sec, view_sec, spend_pub, view_pub) = make_test_keypair(0x11);

        let sub0_0 = derive_subaddress(&spend_sec, &view_sec, &spend_pub, &view_pub, 0, 0).unwrap();
        let sub0_1 = derive_subaddress(&spend_sec, &view_sec, &spend_pub, &view_pub, 0, 1).unwrap();
        let sub1_0 = derive_subaddress(&spend_sec, &view_sec, &spend_pub, &view_pub, 1, 0).unwrap();

        // Different (account, minor) → different subaddress
        assert_ne!(sub0_0.spend_pub, sub0_1.spend_pub);
        assert_ne!(sub0_0.spend_pub, sub1_0.spend_pub);
        assert_ne!(sub0_1.spend_pub, sub1_0.spend_pub);

        // spend_pub must = spend_sec * G
        let sec_dalek = reduce_scalar_to_dalek(sub0_0.spend_sec.expose());
        let pub_point = ED25519_BASEPOINT_TABLE * &sec_dalek;
        assert_eq!(pub_point.compress().to_bytes(), sub0_0.spend_pub);

        eprintln!("Sub(0,0) spend_pub: {}", hex_encode(&sub0_0.spend_pub));
    }

    /// The simplified subaddress derivation (public spend_pub only) should match the full derivation
    #[test]
    fn subaddress_spend_pub_derivation() {
        let (spend_sec, view_sec, spend_pub, view_pub) = make_test_keypair(0x33);

        // full derivation
        let full = derive_subaddress(&spend_sec, &view_sec, &spend_pub, &view_pub, 2, 5).unwrap();

        // simplified derivation (spend_pub only)
        let simple_pub = derive_subaddress_spend_pub(&spend_pub, &view_sec, 2, 5).unwrap();

        assert_eq!(full.spend_pub, simple_pub);

        eprintln!("Sub(2,5) spend_pub: {}", hex_encode(&simple_pub));
    }

    /// Derivation determinism: same input → same output
    #[test]
    fn subaddress_deterministic() {
        let (spend_sec, view_sec, spend_pub, view_pub) = make_test_keypair(0x77);

        let s1 = derive_subaddress(&spend_sec, &view_sec, &spend_pub, &view_pub, 1, 2).unwrap();
        let s2 = derive_subaddress(&spend_sec, &view_sec, &spend_pub, &view_pub, 1, 2).unwrap();

        assert_eq!(s1.spend_pub, s2.spend_pub);
        assert_eq!(s1.view_pub, s2.view_pub);
        assert_eq!(s1.spend_sec, s2.spend_sec);
        assert_eq!(s1.view_sec, s2.view_sec);
    }

    /// Main address ≠ subaddress (subaddresses should be independent and unlinkable)
    #[test]
    fn main_not_equal_subaddress() {
        let (spend_sec, view_sec, spend_pub, view_pub) = make_test_keypair(0x42);

        let sub = derive_subaddress(&spend_sec, &view_sec, &spend_pub, &view_pub, 0, 0).unwrap();

        assert_ne!(sub.spend_pub, spend_pub);
        assert_ne!(sub.view_pub, view_pub);
        assert_ne!(*sub.spend_sec.expose(), spend_sec);
        assert_ne!(*sub.view_sec.expose(), view_sec);
    }

    /// Deriving many (100) across accounts / minors yields all-distinct results
    #[test]
    fn subaddress_many_derivations() {
        let (spend_sec, view_sec, spend_pub, view_pub) = make_test_keypair(0x99);

        let mut seen = Vec::new();
        for account in 0..10 {
            for minor in 0..10 {
                let sub =
                    derive_subaddress(&spend_sec, &view_sec, &spend_pub, &view_pub, account, minor)
                        .unwrap();
                assert!(
                    !seen.contains(&sub.spend_pub),
                    "collision at ({}, {})",
                    account,
                    minor
                );
                seen.push(sub.spend_pub);
            }
        }
        assert_eq!(seen.len(), 100);
        eprintln!("100 subaddresses all unique");
    }

    /// Hs and keccak consistency (verify hash_to_scalar via keccak-256 + reduce)
    #[test]
    fn hash_to_scalar_keccak_match() {
        // same input → same hash
        let data = b"another test";
        let h1 = hash_to_scalar(data).unwrap();
        let h2 = hash_to_scalar(data).unwrap();
        assert_eq!(h1, h2);

        // different input → different hash
        let h3 = hash_to_scalar(b"different input").unwrap();
        assert_ne!(h1, h3);
    }
}

/// Compute the output key offset (aligned with keystone key_images.rs::calc_output_key_offset)
///
/// ```text
/// recv_derivation = view_sec · tx_pubkey · cofactor(8)
/// key_offset = Hs(recv_derivation || varint(internal_output_index))
///              + (major≠0 || minor≠0) ? m(major,minor) : 0
/// ```
///
/// Used to recover the real spend private key from a subaddress input: `input_sk = spend_sec + key_offset`.
/// Verify: `input_sk · G == output_pubkey` (keystone's generate_key_image_from_offset).
///
/// **Input**:
/// - view_sec: 32-byte view private key
/// - tx_pubkey: the real input's tx pub key (real_out_tx_key)
/// - internal_output_index: real_output_in_tx_index
/// - major/minor: subaddress (account, minor); main address = (0,0)
///
/// **Output**: 32-byte key offset (reduced scalar)
pub fn calc_output_key_offset(
    view_sec: &[u8; 32],
    tx_pubkey: &[u8; 32],
    internal_output_index: u64,
    major: u32,
    minor: u32,
) -> Result<[u8; 32]> {
    // 1. recv_derivation = view · tx_pub, multiplied by cofactor 8
    let view_scalar = reduce_scalar_to_dalek(view_sec);
    let tx_pub_point: curve25519_dalek::EdwardsPoint = CompressedPoint::from(*tx_pubkey)
        .decompress()
        .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?
        .into();
    let recv = (tx_pub_point * view_scalar).mul_by_cofactor();
    let recv_bytes = recv.compress().to_bytes();

    // 2. Hs(recv || varint(index))
    // Z5.3 F-cut: fixed stack staging (the Vec allocated per input).
    let mut data = [0u8; 41];
    data[..32].copy_from_slice(&recv_bytes);
    let mut data_len = 32usize;
    // Z2.4d-2: varint is Monero LEB128 (identical to CompactSize below 0x80 only —
    // internal_output_index >= 128 previously derived a wrong key offset).
    crate::chain::xmr::transaction::monero_encode_varint_at(
        &mut data,
        &mut data_len,
        internal_output_index,
    )?;
    let mut key_offset = hash_to_scalar(&data[..data_len])?;

    // 3. Add subaddress m(major,minor)
    if major != 0 || minor != 0 {
        let m = calc_subaddress_m(view_sec, major, minor)?;
        let m_dalek = reduce_scalar_to_dalek(&m);
        let ko_dalek = reduce_scalar_to_dalek(&key_offset);
        key_offset = (ko_dalek + m_dalek).to_bytes();
    }
    Ok(key_offset)
}

/// Compute the input's real spend private key: spend_sec + key_offset
///
/// Aligned with keystone `generate_key_image_from_offset`.
pub fn derive_input_spend_key(spend_sec: &[u8; 32], key_offset: &[u8; 32]) -> Result<[u8; 32]> {
    let s = reduce_scalar_to_dalek(spend_sec);
    let o = reduce_scalar_to_dalek(key_offset);
    Ok((s + o).to_bytes())
}

/// Derive the key image from a subaddress input (full path, aligned with keystone)
///
/// Returns the key image only after verifying input_sk·G == output_pubkey;
/// Verification failure = this output does not belong to the current wallet → Err.
pub fn derive_key_image_with_offset(
    spend_sec: &[u8; 32],
    key_offset: &[u8; 32],
    output_pubkey: &[u8; 32],
) -> Result<[u8; 32]> {
    let input_sk = derive_input_spend_key(spend_sec, key_offset)?;
    let input_sk_dalek = reduce_scalar_to_dalek(&input_sk);

    // verify input_sk · G == output_pubkey
    let derived_pub = (ED25519_BASEPOINT_TABLE * &input_sk_dalek)
        .compress()
        .to_bytes();
    if derived_pub != *output_pubkey {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // image = input_sk · Hp(output_pubkey)
    let hp: curve25519_dalek::EdwardsPoint =
        monero_ed25519::Point::biased_hash(*output_pubkey).into();
    let image = (hp * input_sk_dalek).compress().to_bytes();
    Ok(image)
}

/// Derive a full input from a source entry (key_image + key_offset) — the real signing path
///
/// Aligned with keystone `calc_key_image_by_index` + `try_to_generate_image`:
/// 1. Select the tx pubkey (with additional keys, use additional[internal_output_index])
/// 2. For each subaddr minor: compute key_offset → verify output_pubkey → key image
pub fn derive_input_from_source(
    view_sec: &[u8; 32],
    spend_sec: &[u8; 32],
    source: &crate::chain::xmr::unsigned_txset::TxSourceEntry,
    subaddr_account: u32,
    subaddr_indices: &[u32],
) -> Result<([u8; 32], [u8; 32])> {
    let real = source
        .outputs
        .get(source.real_output as usize)
        .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let output_pubkey = real.dest;

    // tx pubkey: with additional keys, use additional[internal_output_index]
    let tx_pubkey = if !source.real_out_additional_tx_keys.is_empty() {
        let idx = source.real_output_in_tx_index as usize;
        source
            .real_out_additional_tx_keys
            .get(idx)
            .or_else(|| source.real_out_additional_tx_keys.first())
            .map(|z| **z)
            .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?
    } else {
        *source.real_out_tx_key
    };

    // iterate subaddr minors, verifying output_pubkey
    for &minor in subaddr_indices {
        let offset = calc_output_key_offset(
            view_sec,
            &tx_pubkey,
            source.real_output_in_tx_index,
            subaddr_account,
            minor,
        )?;
        if let Ok(image) = derive_key_image_with_offset(spend_sec, &offset, &output_pubkey) {
            return Ok((image, offset));
        }
    }
    // main-address fallback (major=0, minor=0)
    let offset = calc_output_key_offset(
        view_sec,
        &tx_pubkey,
        source.real_output_in_tx_index,
        subaddr_account,
        0,
    )?;
    let image = derive_key_image_with_offset(spend_sec, &offset, &output_pubkey)?;
    Ok((image, offset))
}

/// Main-address input derivation (no subaddress offset; image = spend · Hp(spend·G))
pub fn derive_key_image_main(spend_sec: &[u8; 32]) -> Result<[u8; 32]> {
    crate::chain::xmr::clsag::derive_key_image(spend_sec)
}

#[cfg(test)]
mod tests2 {
    use super::*;

    /// key_offset determinism: same input, same output
    #[test]
    fn offset_deterministic() {
        let view = [0x42u8; 32];
        let txpub = [0x11u8; 32];
        let o1 = calc_output_key_offset(&view, &txpub, 3, 0, 0).unwrap();
        let o2 = calc_output_key_offset(&view, &txpub, 3, 0, 0).unwrap();
        assert_eq!(o1, o2);
    }

    /// key_offset depends on the index (different internal_output_index → different offset)
    #[test]
    fn offset_differs_by_index() {
        let view = [0x42u8; 32];
        let txpub = [0x11u8; 32];
        let o0 = calc_output_key_offset(&view, &txpub, 0, 0, 0).unwrap();
        let o1 = calc_output_key_offset(&view, &txpub, 1, 0, 0).unwrap();
        assert_ne!(o0, o1);
    }

    /// Add the subaddress offset m (differs from the main address when major≠0)
    #[test]
    fn offset_differs_by_subaddr() {
        let view = [0x42u8; 32];
        let txpub = [0x11u8; 32];
        let main = calc_output_key_offset(&view, &txpub, 0, 0, 0).unwrap();
        let sub = calc_output_key_offset(&view, &txpub, 0, 0, 1).unwrap();
        assert_ne!(main, sub);
    }

    /// key image + offset end-to-end: the image can be derived when spend·G matches output_pubkey
    #[test]
    fn derive_image_roundtrip() {
        let spend_sec = [0x55u8; 32];
        let spend_dalek = reduce_scalar_to_dalek(&spend_sec);
        let output_pubkey = (ED25519_BASEPOINT_TABLE * &spend_dalek)
            .compress()
            .to_bytes();
        let offset = [0u8; 32];
        let image = derive_key_image_with_offset(&spend_sec, &offset, &output_pubkey).unwrap();
        assert_eq!(image.len(), 32);
        // consistent with clsag::derive_key_image (when offset=0)
        let direct = crate::chain::xmr::clsag::derive_key_image(&spend_sec).unwrap();
        assert_eq!(image, direct);
    }

    /// output_pubkey mismatch → Err (this output does not belong to this wallet)
    #[test]
    fn derive_image_wrong_pubkey_rejected() {
        let spend_sec = [0x55u8; 32];
        let wrong_pub = [0x99u8; 32];
        let offset = [0u8; 32];
        assert!(derive_key_image_with_offset(&spend_sec, &offset, &wrong_pub).is_err());
    }
}
