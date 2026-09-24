//! Signed txset serialization + encryption (P1-06 wrap-up, step 3 of the §B.5 finalized plan).
//!
//! Aligned with keystone:
//! - `signed_transaction.rs:87-138` `SignedTxSet::serialize` (wire layout matches byte for byte)
//! - `utils/mod.rs::encrypt_data_with_pvk` (magic + 8B big-endian nonce + ChaCha20-Legacy
//!   + trailing 64B Monero Schnorr signature)
//! - `utils/sign.rs::generate_signature` / `generate_ring_signature` (tx_key_images signatures)
//!
//! wire essentials (dual to the decryption side's read_*; both cross-verified against real P6.3 fixtures):
//! - varint = LEB128; u64 fields = 8B LE — except `tx_destination_entry.amount`,
//!   which monero serializes as VARINT_FIELD (see `write_destination_entry`)
//! - tx_key position written as Scalar::ONE (keystone zeroes it out — r is not returned to the host)
//! - key_images_str = `<hex> ` concatenated item by item (including the trailing space)
//! - tx_key_images item = 0x02 ‖ output one-time address ‖ key image (Hs(shared_key)·Hp)

extern crate alloc;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;

use crate::chain::xmr::subaddress::hash_to_scalar;
use crate::chain::xmr::unsigned_txset::{TxConstructionData, TxDestinationEntry};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

use alloc::{string::String, vec::Vec};

/// magic symmetric with the decryption side
pub const SIGNED_TX_PREFIX: &[u8] = b"Monero signed tx set\x05";

const NONCE_LEN: usize = 8;
const SIG_LEN: usize = 64;

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

fn put_varint(out: &mut Vec<u8>, n: u64) {
    crate::chain::xmr::transaction::monero_encode_varint(out, n);
}

// ============ Sub-struct serialization (aligned with keystone utils/io.rs) ============

pub(crate) fn write_destination_entry(out: &mut Vec<u8>, e: &TxDestinationEntry) {
    put_varint(out, e.original.len() as u64);
    out.extend_from_slice(&e.original);
    // monero `tx_destination_entry`: VARINT_FIELD(amount) — the amount here is a
    // varint, unlike `tx_source_entry.amount` which is a fixed u64 (both in
    // cryptonote_tx_utils.h). Writing a fixed u64 shifted every following field
    // by 7 bytes and made monero's `parse_tx_from_str` reject the whole file
    // (`submit_transfer`: "Failed to deserialize signed transaction"); fixed
    // 2026-09-15, broadcast re-verified.
    put_varint(out, e.amount);
    out.extend_from_slice(&e.spend_public_key);
    out.extend_from_slice(&e.view_public_key);
    out.push(e.is_subaddress as u8);
    out.push(e.is_integrated as u8);
}

fn write_output_entry(out: &mut Vec<u8>, index: u64, dest: &[u8; 32], mask: &[u8; 32]) {
    // std::pair is a class in binary_archive, prefixed with a field-count 0x02
    out.push(2);
    put_varint(out, index);
    out.extend_from_slice(dest);
    out.extend_from_slice(mask);
}

fn write_source_entry(out: &mut Vec<u8>, s: &crate::chain::xmr::unsigned_txset::TxSourceEntry) {
    put_varint(out, s.outputs.len() as u64);
    for o in &s.outputs {
        write_output_entry(out, o.index, &o.dest, &o.mask);
    }
    out.extend_from_slice(&s.real_output.to_le_bytes());
    out.extend_from_slice(s.real_out_tx_key.as_slice());
    put_varint(out, s.real_out_additional_tx_keys.len() as u64);
    for k in s.real_out_additional_tx_keys.iter() {
        out.extend_from_slice(k);
    }
    out.extend_from_slice(&s.real_output_in_tx_index.to_le_bytes());
    out.extend_from_slice(&s.amount.to_le_bytes());
    out.push(s.rct as u8);
    // P1-03: mask plaintext access is funneled through expose() — wire serialization is one of the few legitimate exits
    out.extend_from_slice(s.mask.expose());
    out.extend_from_slice(&s.multisig_kLRki.k);
    out.extend_from_slice(&s.multisig_kLRki.l);
    out.extend_from_slice(&s.multisig_kLRki.r);
    out.extend_from_slice(&s.multisig_kLRki.ki);
}

pub(crate) fn write_construction_data(out: &mut Vec<u8>, d: &TxConstructionData) {
    put_varint(out, d.sources.len() as u64);
    for s in &d.sources {
        write_source_entry(out, s);
    }
    write_destination_entry(out, &d.change_dts);
    put_varint(out, d.splitted_dsts.len() as u64);
    for dst in &d.splitted_dsts {
        write_destination_entry(out, dst);
    }
    put_varint(out, d.selected_transfers.len() as u64);
    // in construction_data, selected_transfers is varint (unlike the byte-per-u8 at the ptx top level!)
    for t in &d.selected_transfers {
        put_varint(out, *t as u64);
    }
    put_varint(out, d.extra.len() as u64);
    out.extend_from_slice(&d.extra);
    out.extend_from_slice(&d.unlock_time.to_le_bytes());
    out.push(d.use_rct);
    put_varint(out, d.rct_config.version);
    put_varint(out, d.rct_config.range_proof_type);
    put_varint(out, d.rct_config.bp_version);
    put_varint(out, d.dests.len() as u64);
    for dest in &d.dests {
        write_destination_entry(out, dest);
    }
    out.extend_from_slice(&d.subaddr_account.to_le_bytes());
    put_varint(out, d.subaddr_indices.len() as u64);
    for i in &d.subaddr_indices {
        put_varint(out, *i as u64);
    }
}

// ============ PendingTx / SignedTxSet ============

/// A signed transaction and its metadata (aligned with keystone PendingTx)
pub struct PendingTx {
    /// Full tx wire bytes (including rct signatures)
    pub tx_bytes: Vec<u8>,
    pub dust: u64,
    pub fee: u64,
    pub dust_added_to_fee: bool,
    pub change_dts: TxDestinationEntry,
    /// ptx top level: byte per u8 (not varint)
    pub selected_transfers: Vec<u8>,
    /// Key image list joined as `<hex> `
    pub key_images_str: String,
    /// tx_key (forced to ONE before writing to the wire — r is not returned to the host; see module docs)
    /// Z2.1 S4 (2026-09-24): tx secret keys — zeroized on drop.
    pub additional_tx_keys: zeroize::Zeroizing<Vec<[u8; 32]>>,
    pub dests: Vec<TxDestinationEntry>,
    pub construction_data: TxConstructionData,
}

/// Output one-time address → key image (aligned with keystone tx_key_images)
pub struct TxKeyImageEntry {
    /// The output's one-time address (stealth address)
    pub output_pubkey: [u8; 32],
    /// Hs(shared_key)·Hp(output_pubkey)
    pub key_image: [u8; 32],
}

pub struct SignedTxSet {
    pub ptx: Vec<PendingTx>,
    /// One key image per transfer (outer layer, 32B each)
    pub key_images: Vec<[u8; 32]>,
    pub tx_key_images: Vec<TxKeyImageEntry>,
}

impl SignedTxSet {
    /// Aligned with keystone `SignedTxSet::serialize` (byte-for-byte identical).
    /// Audit #12 P1-02: the output contains construction_data (mask/kLRki) secret fields,
    /// Returns a Zeroizing owner.
    pub fn serialize(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut res = Vec::new();
        // signed_tx_set version 00
        res.push(0u8);
        put_varint(&mut res, self.ptx.len() as u64);
        for ptx in &self.ptx {
            // ptx version 1
            res.push(1u8);
            res.extend_from_slice(&ptx.tx_bytes);
            res.extend_from_slice(&ptx.dust.to_le_bytes());
            res.extend_from_slice(&ptx.fee.to_le_bytes());
            res.push(ptx.dust_added_to_fee as u8);
            write_destination_entry(&mut res, &ptx.change_dts);
            put_varint(&mut res, ptx.selected_transfers.len() as u64);
            // ptx top-level selected_transfers: monero reads std::vector<size_t>
            // via use_container_varint → varint elements (identical bytes to the
            // old u8 push for values < 128; correct for larger indices).
            for t in &ptx.selected_transfers {
                put_varint(&mut res, *t as u64);
            }
            let ki = ptx.key_images_str.as_bytes();
            put_varint(&mut res, ki.len() as u64);
            if !ki.is_empty() {
                res.extend_from_slice(ki);
            }
            // tx_key ZERO: keystone uses Scalar::ONE as a placeholder (r is not returned)
            res.extend_from_slice(&Scalar::ONE.to_bytes());
            put_varint(&mut res, ptx.additional_tx_keys.len() as u64);
            for k in ptx.additional_tx_keys.iter() {
                res.extend_from_slice(k);
            }
            put_varint(&mut res, ptx.dests.len() as u64);
            for dest in &ptx.dests {
                write_destination_entry(&mut res, dest);
            }
            write_construction_data(&mut res, &ptx.construction_data);
            // multisig_sigs: always empty in v1
            res.push(0u8);
            // multisig_tx_key_entropy: keystone PrivateKey::default() = all zeros
            res.extend_from_slice(&[0u8; 32]);
        }
        put_varint(&mut res, self.key_images.len() as u64);
        for ki in &self.key_images {
            res.extend_from_slice(ki);
        }
        put_varint(&mut res, self.tx_key_images.len() as u64);
        for e in &self.tx_key_images {
            res.push(2u8);
            res.extend_from_slice(&e.output_pubkey);
            res.extend_from_slice(&e.key_image);
        }
        zeroize::Zeroizing::new(res)
    }
}

// ============ key image ring signature (used by tx_key_images) ============

// Monero ring signature (aligned with keystone `generate_ring_signature`):
// outputs the [π0, π1] array; the true member's position is determined by sec_idx.
//
// returns the flat (s0, s1) pair (keystone SignatureTrait's [Scalar; 2]),
// used only for key image generation in tx_key_images; unrelated to the wire (the wire stores only the image).
// in shlosilo the image is already computed by the sign path; this function is only for host-side consistency checking,
// hence not exported as pub — keeps uncalled dead code out of the staticlib.

// ============ Monero Schnorr signature (trailing 64B of the encrypted blob) ============

/// Monero custom Schnorr signature (aligned with keystone `generate_signature`):
/// k random → R' = kG → c = Hs(hash ‖ P ‖ R') → r = k − c·x
/// Output (c 32B, r 32B).
///
/// exact dual of the decryption side's `check_monero_signature` (both sides of the same scheme cross-verify each other).
pub fn monero_sign(
    hash: &[u8; 32],
    view_sk: &[u8; 32],
    rng: &mut impl rand_core::RngCore,
) -> Result<[[u8; 32]; 2]> {
    // Audit #12 P1-02: secret scalars are Zeroizing owners throughout — x (view secret) / k (nonce) /
    // r(k−c·x) never lands in a plain Scalar binding; the output c/r are signature components (public values).
    // Zeroizing<Scalar> Derefs to Scalar, so field-arithmetic syntax is unchanged.
    use zeroize::Zeroizing;
    let x = Zeroizing::new(Scalar::from_bytes_mod_order(*view_sk));
    let p_bytes = (ED25519_BASEPOINT_TABLE * &*x).compress().to_bytes();

    let mut k_bytes = Zeroizing::new([0u8; 32]);
    let (mut c, mut r);
    loop {
        rng.fill_bytes(k_bytes.as_mut());
        let k = Zeroizing::new(Scalar::from_bytes_mod_order(*k_bytes));
        let k_pub = (ED25519_BASEPOINT_TABLE * &*k).compress().to_bytes();

        let mut data = Vec::with_capacity(96);
        data.extend_from_slice(hash);
        data.extend_from_slice(&p_bytes);
        data.extend_from_slice(&k_pub);
        let c_bytes = hash_to_scalar(&data)?;
        c = Scalar::from_bytes_mod_order(c_bytes);
        if c == Scalar::ZERO {
            continue;
        }
        r = Zeroizing::new(*k - c * *x);
        if *r == Scalar::ZERO {
            continue;
        }
        break;
    }
    Ok([c.to_bytes(), r.to_bytes()])
}

// ============ Encrypted output ============

/// Encrypt a signed txset (aligned with keystone `encrypt_data_with_pvk`, SIGNED_TX_PREFIX path):
///
/// ```text
/// output = magic(23B) ‖ nonce(8B BE) ‖ ChaCha20Legacy(H(cn_v0(view_sk)), nonce)(plain) ‖ sig(64B)
/// plain  = txset bytes (the SIGNED_TX_PREFIX path has no spend/view pubkey prefix)
/// sig    = Monero Schnorr(keccak256(nonce ‖ ciphertext), view_pub, view_sk)
/// ```
///
/// rng usage: nonce (next_u64) + signing k — provided by the §B.5 purpose RNG.
pub fn encrypt_signed_txset(
    plain: Vec<u8>,
    view_sk: &[u8; 32],
    rng: &mut impl rand_core::RngCore,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let key = crate::chain::xmr::unsigned_txset::chacha_key_from_view_sk(view_sk);
    encrypt_signed_txset_with_chacha_key(zeroize::Zeroizing::new(plain), view_sk, &key, rng)
}

/// same as `encrypt_signed_txset`; the ChaCha key is injected by the caller (avoids recomputing CN).
/// Audit #12 P1-02: accepts an owner key, returns Zeroizing (the output as a whole = ciphertext; on encryption failure
/// path's nonce/plaintext intermediates are covered by the owner's Drop).
pub fn encrypt_signed_txset_with_chacha_key(
    plain: zeroize::Zeroizing<Vec<u8>>,
    view_sk: &[u8; 32],
    chacha_key: &zeroize::Zeroizing<[u8; 32]>,
    rng: &mut impl rand_core::RngCore,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20Legacy;

    let nonce_num = rng.next_u64();
    let nonce_num_bytes = nonce_num.to_be_bytes();

    let mut buffer = plain;
    let nonce: chacha20::LegacyNonce = nonce_num_bytes.into();
    let mut cipher = ChaCha20Legacy::new_from_slices(&**chacha_key, &nonce).map_err(|_| err())?;
    cipher.apply_keystream(&mut buffer);

    // 3. Signature = Monero Schnorr over keccak256(nonce ‖ ciphertext), public key = view_pub
    let mut unsigned = Vec::with_capacity(NONCE_LEN + buffer.len());
    unsigned.extend_from_slice(&nonce_num_bytes);
    unsigned.extend_from_slice(&buffer);
    let msg_hash = crate::encoding::keccak256::hash(&unsigned)?;
    let [c, r] = monero_sign(&msg_hash, view_sk, rng)?;

    // 4. magic ‖ nonce ‖ ciphertext ‖ sig
    let mut out = Vec::with_capacity(SIGNED_TX_PREFIX.len() + NONCE_LEN + buffer.len() + SIG_LEN);
    out.extend_from_slice(SIGNED_TX_PREFIX);
    out.extend_from_slice(&nonce_num_bytes);
    out.extend_from_slice(&buffer);
    out.extend_from_slice(&c);
    out.extend_from_slice(&r);
    Ok(zeroize::Zeroizing::new(out))
}

/// Encrypt an unsigned txset (isomorphic to `encrypt_signed_txset`, with the magic swapped to `UNSIGNED_TX_PREFIX`).
/// For feeding self-made TxConstructionData into `business::sign` / `sign_ur_ffi`.
pub fn encrypt_unsigned_txset(
    plain: zeroize::Zeroizing<Vec<u8>>,
    view_sk: &[u8; 32],
    rng: &mut impl rand_core::RngCore,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use crate::chain::xmr::unsigned_txset::UNSIGNED_TX_PREFIX;
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20Legacy;

    // Audit #12 P1-02: the CN key is an owner from creation (no longer wrapping a bare local CN afterwards).
    let key = crate::chain::xmr::unsigned_txset::chacha_key_from_view_sk(view_sk);
    let nonce_num_bytes = rng.next_u64().to_be_bytes();
    let mut buffer = plain;
    let nonce: chacha20::LegacyNonce = nonce_num_bytes.into();
    let mut cipher = ChaCha20Legacy::new_from_slices(&*key, &nonce).map_err(|_| err())?;
    cipher.apply_keystream(&mut buffer);

    let mut unsigned = Vec::with_capacity(NONCE_LEN + buffer.len());
    unsigned.extend_from_slice(&nonce_num_bytes);
    unsigned.extend_from_slice(&buffer);
    let msg_hash = crate::encoding::keccak256::hash(&unsigned)?;
    let [c, r] = monero_sign(&msg_hash, view_sk, rng)?;

    let mut out = Vec::with_capacity(UNSIGNED_TX_PREFIX.len() + NONCE_LEN + buffer.len() + SIG_LEN);
    out.extend_from_slice(UNSIGNED_TX_PREFIX);
    out.extend_from_slice(&nonce_num_bytes);
    out.extend_from_slice(&buffer);
    out.extend_from_slice(&c);
    out.extend_from_slice(&r);
    Ok(zeroize::Zeroizing::new(out))
}

/// Decrypt a signed txset (for self-verification round-trips; aligned with keystone `decrypt_data_with_pvk`).
///
/// magic check → nonce → Schnorr verification (view_pub over keccak256(nonce‖ciphertext)) → decrypt.
pub fn decrypt_signed_txset(
    data: &[u8],
    view_sk: &[u8; 32],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20Legacy;

    if data.len() < SIGNED_TX_PREFIX.len() + NONCE_LEN + SIG_LEN {
        return Err(err());
    }
    if &data[..SIGNED_TX_PREFIX.len()] != SIGNED_TX_PREFIX {
        return Err(err());
    }
    let raw = &data[SIGNED_TX_PREFIX.len()..data.len() - SIG_LEN];
    let nonce_bytes = &raw[..NONCE_LEN];
    let sig = &data[data.len() - SIG_LEN..];

    // verify (reuses the unsigned_txset.rs implementation — both sides of the same scheme stay symmetric)
    use curve25519_dalek::scalar::Scalar;
    // Audit #12 P1-02: v_scalar (view secret) is an owner from creation.
    let v_scalar = zeroize::Zeroizing::new(Scalar::from_bytes_mod_order(*view_sk));
    let view_pub = (ED25519_BASEPOINT_TABLE * &*v_scalar).compress().to_bytes();
    let msg_hash = crate::encoding::keccak256::hash(raw)?;
    if !super::unsigned_txset::verify_monero_signature_pubkey(&msg_hash, &view_pub, sig)? {
        return Err(err());
    }

    // Audit #12 P1-02: the CN key is an owner from creation; plaintext in Zeroizing (error/early-return
    // paths are covered by Drop).
    let key = crate::chain::xmr::unsigned_txset::chacha_key_from_view_sk(view_sk);
    let mut plain = zeroize::Zeroizing::new(raw[NONCE_LEN..].to_vec());
    let mut nb = [0u8; 8];
    nb.copy_from_slice(nonce_bytes);
    let nonce: chacha20::LegacyNonce = nb.into();
    let mut cipher = ChaCha20Legacy::new_from_slices(&*key, &nonce).map_err(|_| err())?;
    cipher.apply_keystream(&mut plain);
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec, vec::Vec};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_view_sk() -> [u8; 32] {
        let mut sk = [0u8; 32];
        for (i, b) in sk.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        sk
    }

    /// Monero Schnorr sign/verify round-trip (both sides of the same scheme stay symmetric)
    #[test]
    fn monero_sign_verify_round_trip() {
        let sk = test_view_sk();
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let sig = monero_sign(&[0xAAu8; 32], &sk, &mut rng).unwrap();
        let mut sig_bytes = Vec::new();
        sig_bytes.extend_from_slice(&sig[0]);
        sig_bytes.extend_from_slice(&sig[1]);

        let x = Scalar::from_bytes_mod_order(sk);
        let pub_key = (ED25519_BASEPOINT_TABLE * &x).compress().to_bytes();
        assert!(
            super::super::unsigned_txset::verify_monero_signature_pubkey(
                &[0xAAu8; 32],
                &pub_key,
                &sig_bytes
            )
            .unwrap()
        );
        // tamper the hash → verification fails
        assert!(
            !super::super::unsigned_txset::verify_monero_signature_pubkey(
                &[0xBBu8; 32],
                &pub_key,
                &sig_bytes
            )
            .unwrap()
        );
    }

    /// Encrypt/decrypt round-trip + tamper rejection
    #[test]
    fn encrypt_decrypt_round_trip() {
        let sk = test_view_sk();
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let plain = b"Monero signed tx set payload here".to_vec();
        let enc = encrypt_signed_txset(plain.clone(), &sk, &mut rng).unwrap();
        assert_eq!(&enc[..SIGNED_TX_PREFIX.len()], SIGNED_TX_PREFIX);
        assert_eq!(enc.len(), SIGNED_TX_PREFIX.len() + 8 + plain.len() + 64);
        let dec = decrypt_signed_txset(&enc, &sk).unwrap();
        assert_eq!(*dec, plain);

        // tamper a middle ciphertext byte → verification rejects
        let mut tampered = enc.clone();
        tampered[SIGNED_TX_PREFIX.len() + 20] ^= 0x01;
        assert!(decrypt_signed_txset(&tampered, &sk).is_err());

        // wrong view key → verification rejects
        assert!(decrypt_signed_txset(&enc, &[0xEEu8; 32]).is_err());
    }

    /// Determinism: same (plain, view_sk, seed) → same output (§B.5 test model)
    #[test]
    fn encrypt_deterministic() {
        let sk = test_view_sk();
        let mut rng1 = ChaCha20Rng::from_seed([9u8; 32]);
        let mut rng2 = ChaCha20Rng::from_seed([9u8; 32]);
        let e1 = encrypt_signed_txset(b"data".to_vec(), &sk, &mut rng1).unwrap();
        let e2 = encrypt_signed_txset(b"data".to_vec(), &sk, &mut rng2).unwrap();
        assert_eq!(e1, e2);
    }

    /// key serialization layout anchors: version/ptx count/tx_key=ONE/multisig placeholders
    #[test]
    fn serialize_layout_anchors() {
        use crate::chain::xmr::unsigned_txset::RctConfig;
        let dest = TxDestinationEntry {
            original: b"4Ae44ncK".to_vec(),
            amount: 1000,
            spend_public_key: [1u8; 32],
            view_public_key: [2u8; 32],
            is_subaddress: false,
            is_integrated: false,
        };
        let ptx = PendingTx {
            tx_bytes: vec![0xABu8; 5],
            dust: 0,
            fee: 30640000,
            dust_added_to_fee: false,
            change_dts: dest.clone(),
            selected_transfers: vec![0u8],
            key_images_str: "<aabb> ".to_string(),
            additional_tx_keys: zeroize::Zeroizing::new(vec![]),
            dests: vec![dest.clone()],
            construction_data: TxConstructionData {
                sources: vec![],
                change_dts: dest.clone(),
                splitted_dsts: vec![dest],
                selected_transfers: vec![0usize],
                extra: vec![],
                unlock_time: 0,
                use_rct: 1,
                rct_config: RctConfig::default(),
                dests: vec![],
                subaddr_account: 0,
                subaddr_indices: vec![1],
            },
        };
        let set = SignedTxSet {
            ptx: vec![ptx],
            key_images: vec![[3u8; 32]],
            tx_key_images: vec![TxKeyImageEntry {
                output_pubkey: [4u8; 32],
                key_image: [5u8; 32],
            }],
        };
        let bytes = set.serialize();
        let mut off = 0usize;
        // version
        assert_eq!(bytes[off], 0x00);
        off += 1;
        // ptx count = 1
        assert_eq!(bytes[off], 0x01);
        off += 1;
        // ptx version
        assert_eq!(bytes[off], 0x01);
        off += 1;
        // tx_bytes
        assert_eq!(&bytes[off..off + 5], &[0xABu8; 5]);
        off += 5;
        // dust(8) + fee(8) + dust_added(1)
        assert_eq!(&bytes[off..off + 8], &0u64.to_le_bytes());
        off += 8;
        assert_eq!(&bytes[off..off + 8], &30640000u64.to_le_bytes());
        off += 8;
        assert_eq!(bytes[off], 0);
        off += 1;
        // change_dts: varint(8) + "4Ae44ncK" + amount varint(2) + pk(32)×2 + 2 flags
        assert_eq!(bytes[off], 8);
        off += 1 + 8 + 2 + 32 + 32 + 2;
        // selected_transfers count=1, byte per u8
        assert_eq!(bytes[off], 1);
        off += 1;
        assert_eq!(bytes[off], 0);
        off += 1;
        // key_images_str len varint(7) + "<aabb> "
        assert_eq!(bytes[off], 7);
        off += 1;
        assert_eq!(&bytes[off..off + 7], b"<aabb> ");
        off += 7;
        // tx_key = Scalar::ONE
        assert_eq!(&bytes[off..off + 32], &Scalar::ONE.to_bytes());
        off += 32;
        // additional_tx_keys count = 0
        assert_eq!(bytes[off], 0);
        off += 1;
        // dests count = 1 (ptx top level)
        assert_eq!(bytes[off], 1);
        off += 1;
        off += 1 + 8 + 2 + 32 + 32 + 2; // dest entry
                                        // construction_data: sources=0 → change_dts → splitted=1 → …
        assert_eq!(bytes[off], 0); // sources count
        off += 1;
        off += 1 + 8 + 2 + 32 + 32 + 2; // change_dts
        assert_eq!(bytes[off], 1); // splitted count
        off += 1;
        off += 1 + 8 + 2 + 32 + 32 + 2; // splitted[0]
        assert_eq!(bytes[off], 1); // selected_transfers count
        off += 1;
        assert_eq!(bytes[off], 0); // varint(0)
        off += 1;
        assert_eq!(bytes[off], 0); // extra len
        off += 1;
        off += 8; // unlock_time
        assert_eq!(bytes[off], 1); // use_rct
        off += 1;
        off += 3; // rct_config version/range/bp varint(0)×3
        assert_eq!(bytes[off], 0); // dests count
        off += 1;
        off += 4; // subaddr_account u32
        assert_eq!(bytes[off], 1); // subaddr_indices count
        off += 1;
        assert_eq!(bytes[off], 1); // varint(1)
        off += 1;
        // multisig_sigs = 0 + 32B of zero entropy
        assert_eq!(bytes[off], 0);
        off += 1;
        assert_eq!(&bytes[off..off + 32], &[0u8; 32]);
        off += 32;
        // outer key_images count=1 + 32B
        assert_eq!(bytes[off], 1);
        off += 1;
        assert_eq!(&bytes[off..off + 32], &[3u8; 32]);
        off += 32;
        // tx_key_images count=1 + 0x02 + 32 + 32
        assert_eq!(bytes[off], 1);
        off += 1;
        assert_eq!(bytes[off], 2);
        off += 1;
        assert_eq!(&bytes[off..off + 32], &[4u8; 32]);
        off += 32;
        assert_eq!(&bytes[off..off + 32], &[5u8; 32]);
        off += 32;
        assert_eq!(off, bytes.len());
    }
}
