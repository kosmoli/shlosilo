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

#[cfg(feature = "alloc-fallback")]
extern crate alloc;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;

use crate::chain::xmr::subaddress::hash_to_scalar;
use crate::chain::xmr::unsigned_txset::{TxConstructionData, TxDestinationEntry};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

// Alloc surface: consumers behind alloc-fallback / cfg(test).
#[cfg(feature = "alloc-fallback")]
use alloc::vec::Vec;

/// magic symmetric with the decryption side
pub const SIGNED_TX_PREFIX: &[u8] = b"Monero signed tx set\x05";

pub(crate) const NONCE_LEN: usize = 8;
pub(crate) const SIG_LEN: usize = 64;

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

// Z2.4d-2: writers are generic over `Sink` — one implementation feeds the
// zero-heap cursor backend (caller buffer) or the Vec staging backend.
use crate::types::push::{EncryptingSink, Sink};

fn put_varint<S: Sink>(out: &mut S, n: u64) -> Result<()> {
    let mut tmp = [0u8; 10];
    let mut pos = 0usize;
    crate::chain::xmr::transaction::monero_encode_varint_at(&mut tmp, &mut pos, n)?;
    out.put(&tmp[..pos])
}

// ============ Sub-struct serialization (aligned with keystone utils/io.rs) ============

pub(crate) fn write_destination_entry<S: Sink>(out: &mut S, e: &TxDestinationEntry) -> Result<()> {
    put_varint(out, e.original.len() as u64)?;
    out.put(&e.original)?;
    // monero `tx_destination_entry`: VARINT_FIELD(amount) — the amount here is a
    // varint, unlike `tx_source_entry.amount` which is a fixed u64 (both in
    // cryptonote_tx_utils.h). Writing a fixed u64 shifted every following field
    // by 7 bytes and made monero's `parse_tx_from_str` reject the whole file
    // (`submit_transfer`: "Failed to deserialize signed transaction"); fixed
    // 2026-09-15, broadcast re-verified.
    put_varint(out, e.amount)?;
    out.put(&e.spend_public_key)?;
    out.put(&e.view_public_key)?;
    out.put_u8(e.is_subaddress as u8)?;
    out.put_u8(e.is_integrated as u8)
}

fn write_output_entry<S: Sink>(
    out: &mut S,
    index: u64,
    dest: &[u8; 32],
    mask: &[u8; 32],
) -> Result<()> {
    // std::pair is a class in binary_archive, prefixed with a field-count 0x02
    out.put_u8(2)?;
    put_varint(out, index)?;
    out.put(dest)?;
    out.put(mask)
}

fn write_source_entry<S: Sink>(
    out: &mut S,
    s: &crate::chain::xmr::unsigned_txset::TxSourceEntry,
) -> Result<()> {
    put_varint(out, s.outputs.len() as u64)?;
    for o in &s.outputs {
        write_output_entry(out, o.index, &o.dest, &o.mask)?;
    }
    out.put(&s.real_output.to_le_bytes())?;
    out.put(s.real_out_tx_key.as_slice())?;
    put_varint(out, s.real_out_additional_tx_keys.len() as u64)?;
    for k in s.real_out_additional_tx_keys.iter() {
        out.put(&**k)?;
    }
    out.put(&s.real_output_in_tx_index.to_le_bytes())?;
    out.put(&s.amount.to_le_bytes())?;
    out.put_u8(s.rct as u8)?;
    out.put(s.mask.expose())?;
    out.put(&s.multisig_kLRki.k)?;
    out.put(&s.multisig_kLRki.l)?;
    out.put(&s.multisig_kLRki.r)?;
    out.put(&s.multisig_kLRki.ki)
}

pub(crate) fn write_construction_data<S: Sink>(
    out: &mut S,
    d: &TxConstructionData<'_>,
) -> Result<()> {
    put_varint(out, d.sources.len() as u64)?;
    for s in d.sources.iter().flatten() {
        write_source_entry(out, s)?;
    }
    write_destination_entry(out, &d.change_dts)?;
    put_varint(out, d.splitted_dsts.len() as u64)?;
    for dst in d.splitted_dsts.iter() {
        write_destination_entry(out, dst)?;
    }
    put_varint(out, d.selected_transfers.len() as u64)?;
    // in construction_data, selected_transfers is varint (unlike the byte-per-u8 at the ptx top level!)
    for t in d.selected_transfers.iter() {
        put_varint(out, *t as u64)?;
    }
    put_varint(out, d.extra.len() as u64)?;
    out.put(&d.extra[..])?;
    out.put(&d.unlock_time.to_le_bytes())?;
    out.put_u8(d.use_rct)?;
    put_varint(out, d.rct_config.version)?;
    put_varint(out, d.rct_config.range_proof_type)?;
    put_varint(out, d.rct_config.bp_version)?;
    put_varint(out, d.dests.len() as u64)?;
    for dest in d.dests.iter() {
        write_destination_entry(out, dest)?;
    }
    out.put(&d.subaddr_account.to_le_bytes())?;
    put_varint(out, d.subaddr_indices.len() as u64)?;
    for i in d.subaddr_indices.iter() {
        put_varint(out, *i as u64)?;
    }
    Ok(())
}

// ============ PendingTx / SignedTxSet ============

use crate::types::SliceVec;

/// A signed transaction and its metadata (aligned with keystone PendingTx)
/// Z2.3 C3b-3 (2026-09-24, option 2): flat lists are caller-storage SliceVecs;
/// `construction_data` (nested aggregates) landed in C3c, `tx_bytes` in Z2.4d-4
/// (now a borrow — the wire blob is PUBLIC data, no zeroize duty; storage belongs
/// to the caller workspace like every other aggregate).
pub struct PendingTx<'a> {
    /// Full tx wire bytes (including rct signatures)
    pub tx_bytes: &'a [u8],
    pub dust: u64,
    pub fee: u64,
    pub dust_added_to_fee: bool,
    pub change_dts: TxDestinationEntry,
    /// ptx top level: byte per u8 (not varint)
    pub selected_transfers: SliceVec<'a, u8>,
    /// Key image list joined as `<hex> ` (pre-built string bytes; serialized verbatim)
    pub key_images_str: SliceVec<'a, u8>,
    /// tx_key (forced to ONE before writing to the wire — r is not returned to the host; see module docs)
    /// Z2.1 S4 (2026-09-24): tx secret keys — zeroized on drop. Z2.3: element-zeroized heapless leaf.
    pub additional_tx_keys:
        heapless::Vec<zeroize::Zeroizing<[u8; 32]>, { crate::types::caps::EXTRA_KEYS_MAX }>,
    pub dests: SliceVec<'a, TxDestinationEntry>,
    pub construction_data: TxConstructionData<'a>,
}

/// Output one-time address → key image (aligned with keystone tx_key_images)
#[derive(Clone, Copy, Debug, Default)]
pub struct TxKeyImageEntry {
    /// The output's one-time address (stealth address)
    pub output_pubkey: [u8; 32],
    /// Hs(shared_key)·Hp(output_pubkey)
    pub key_image: [u8; 32],
}

/// Z2.3 C3b-3: `ptx` slots are `Option` (PendingTx holds SliceVecs and has no
/// Default placeholder; None = empty slot).
pub struct SignedTxSet<'a> {
    pub ptx: SliceVec<'a, Option<PendingTx<'a>>>,
    /// One key image per transfer (outer layer, 32B each)
    pub key_images: SliceVec<'a, [u8; 32]>,
    pub tx_key_images: SliceVec<'a, TxKeyImageEntry>,
}

impl SignedTxSet<'_> {
    /// Aligned with keystone `SignedTxSet::serialize` (byte-for-byte identical).
    /// Audit #12 P1-02: the output contains construction_data (mask/kLRki) secret fields,
    /// Returns a Zeroizing owner.
    /// Core writer (Z2.4d-2): feeds any `Sink` — cursor (zero-heap) or Vec (staging).
    /// Audit #12 P1-02: the stream contains construction_data (mask/kLRki) secret fields.
    /// Z2.4d-3: in production this only ever feeds `EncryptingSink` (ciphertext leaves,
    /// no plaintext buffer) or the self-zeroizing `serialize()` owner.
    fn write_all<S: crate::types::push::Sink>(&self, out: &mut S) -> Result<()> {
        // signed_tx_set version 00
        out.put_u8(0u8)?;
        put_varint(out, self.ptx.len() as u64)?;
        for ptx in self.ptx.iter().flatten() {
            // ptx version 1
            out.put_u8(1u8)?;
            out.put(ptx.tx_bytes)?;
            out.put(&ptx.dust.to_le_bytes())?;
            out.put(&ptx.fee.to_le_bytes())?;
            out.put_u8(ptx.dust_added_to_fee as u8)?;
            write_destination_entry(out, &ptx.change_dts)?;
            put_varint(out, ptx.selected_transfers.len() as u64)?;
            // ptx top-level selected_transfers: monero reads std::vector<size_t>
            // via use_container_varint → varint elements (identical bytes to the
            // old u8 push for values < 128; correct for larger indices).
            for t in ptx.selected_transfers.iter() {
                put_varint(out, *t as u64)?;
            }
            // Z2.3 C3b-3: pre-built `<hex> ` string bytes, verbatim (byte-compatible
            // with the former String field including synthetic fixtures)
            let ki: &[u8] = &ptx.key_images_str;
            put_varint(out, ki.len() as u64)?;
            if !ki.is_empty() {
                out.put(ki)?;
            }
            // tx_key ZERO: keystone uses Scalar::ONE as a placeholder (r is not returned)
            out.put(&Scalar::ONE.to_bytes())?;
            put_varint(out, ptx.additional_tx_keys.len() as u64)?;
            for k in ptx.additional_tx_keys.iter() {
                out.put(&**k)?;
            }
            put_varint(out, ptx.dests.len() as u64)?;
            for dest in ptx.dests.iter() {
                write_destination_entry(out, dest)?;
            }
            write_construction_data(out, &ptx.construction_data)?;
            // multisig_sigs: always empty in v1
            out.put_u8(0u8)?;
            // multisig_tx_key_entropy: keystone PrivateKey::default() = all zeros
            out.put(&[0u8; 32])?;
        }
        put_varint(out, self.key_images.len() as u64)?;
        for ki in self.key_images.iter() {
            out.put(ki)?;
        }
        put_varint(out, self.tx_key_images.len() as u64)?;
        for e in self.tx_key_images.iter() {
            out.put_u8(2u8)?;
            out.put(&e.output_pubkey)?;
            out.put(&e.key_image)?;
        }
        Ok(())
    }

    /// Test-only: materializes the secret-bearing plaintext into `out`.
    /// Z2.4d-3: production never calls this — `encrypt_signed_txset_into` streams the
    /// plaintext through the keystream so it never exists as a buffer, and `serialize`
    /// returns a self-zeroizing owner. Any user of this face owns zeroization of `out`.
    #[cfg(test)]
    pub fn serialize_into(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = crate::types::push::SinkCursor::new(out);
        self.write_all(&mut w)?;
        Ok(w.pos())
    }

    /// Z2.4d-3 per-export RNG context: `Keccak(EXPORT_CTX_DOMAIN ‖ serialized container)`,
    /// absorbed through the sponge — the plaintext streams from the model into the hash
    /// and is never materialized (pass 1 of the two-pass export encryption; pass 2 is
    /// `encrypt_signed_txset_into` under the derived stream). Binding the full container
    /// (not any single tx's digest) keeps multi-transaction sets separated: two sets
    /// sharing one member cannot collide on the export stream.
    pub fn export_encrypt_context(&self) -> Result<[u8; 32]> {
        use crate::types::push::Sink as _;
        let mut h = crate::encoding::keccak256::KeccakSink::new();
        h.put(crate::chain::xmr::signing_rng::EXPORT_CTX_DOMAIN)?;
        self.write_all(&mut h)?;
        Ok(h.finalize())
    }

    /// Exact serialized length (CountSink pre-pass; nothing is materialized).
    pub fn serialized_len(&self) -> usize {
        let mut c = crate::types::push::CountSink(0);
        let _ = self.write_all(&mut c); // CountSink is infallible by construction
        c.0
    }

    /// Aligned with keystone `SignedTxSet::serialize` (byte-for-byte identical).
    /// Audit #12 P1-02: the output contains construction_data (mask/kLRki) secret fields,
    /// Returns a Zeroizing owner (self-zeroizing; forms-internal secret duty).
    /// Staging/test convenience (allocates). Production paths use
    /// `encrypt_signed_txset_into` (fused — the plaintext never materializes).
    #[cfg(feature = "alloc-fallback")]
    pub fn serialize(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut res = Vec::new();
        self.write_all(&mut res)
            .expect("Vec sink is infallible by construction");
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

        // Z2.4d-3: stack buffer (was a 96B Vec on the sign path)
        let mut data = [0u8; 96];
        data[..32].copy_from_slice(hash);
        data[32..64].copy_from_slice(&p_bytes);
        data[64..].copy_from_slice(&k_pub);
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

impl SignedTxSet<'_> {
    /// Fused serialize+encrypt (Z2.4d-3): writes
    /// `magic ‖ nonce ‖ ChaCha20Legacy(key,nonce)(write_all(self)) ‖ sig` straight into `out`.
    /// The plaintext container is streamed through the keystream and never exists as a
    /// buffer; `out` receives ciphertext only (not sensitive). Byte-identical to
    /// `encrypt_signed_txset_with_chacha_key(self.serialize(), ...)` under the same RNG.
    /// rng usage order preserved: nonce (next_u64) then signing k.
    pub fn encrypt_signed_txset_into(
        &self,
        view_sk: &[u8; 32],
        chacha_key: &zeroize::Zeroizing<[u8; 32]>,
        rng: &mut impl rand_core::RngCore,
        out: &mut [u8],
    ) -> Result<usize> {
        use crate::types::push::{push_slice, Sink as _, SinkCursor};
        use chacha20::cipher::KeyIvInit;
        let nonce_num = rng.next_u64();
        let nonce_bytes = nonce_num.to_be_bytes();

        // stage 1: magic ‖ nonce ‖ ciphertext
        let ct_end = {
            let mut w = SinkCursor::new(out);
            w.put(SIGNED_TX_PREFIX)?;
            w.put(&nonce_bytes)?;
            let nonce: chacha20::LegacyNonce = nonce_bytes.into();
            let cipher = chacha20::ChaCha20Legacy::new_from_slices(&**chacha_key, &nonce)
                .map_err(|_| err())?;
            let mut enc = EncryptingSink::new(w, cipher);
            self.write_all(&mut enc)?;
            enc.pos()
        };
        // stage 2: sig = Monero Schnorr over keccak256(nonce ‖ ciphertext);
        // nonce and ciphertext are contiguous in `out` after the magic.
        let msg_hash = crate::encoding::keccak256::hash(&out[SIGNED_TX_PREFIX.len()..ct_end])?;
        let [c, r] = monero_sign(&msg_hash, view_sk, rng)?;
        let mut n = 0usize;
        push_slice(&mut out[ct_end..], &mut n, &c)?;
        push_slice(&mut out[ct_end..], &mut n, &r)?;
        Ok(ct_end + n)
    }
}

/// Encrypt a signed txset (aligned with keystone `encrypt_data_with_pvk`, SIGNED_TX_PREFIX path):
///
/// ```text
/// output = magic(23B) ‖ nonce(8B BE) ‖ ChaCha20Legacy(H(cn_v0(view_sk)), nonce)(plain) ‖ sig(64B)
/// plain  = txset bytes (the SIGNED_TX_PREFIX path has no spend/view pubkey prefix)
/// sig    = Monero Schnorr(keccak256(nonce ‖ ciphertext), view_pub, view_sk)
/// ```
///
/// rng usage: nonce (next_u64) + signing k — provided by the §B.5 purpose RNG.
#[cfg(feature = "alloc-fallback")]
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
#[cfg(feature = "alloc-fallback")]
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
#[cfg(feature = "alloc-fallback")]
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
#[cfg(feature = "alloc-fallback")]
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
    use crate::chain::xmr::unsigned_txset::TxSourceEntry;
    // Alloc surface: consumers behind alloc-fallback / cfg(test).
    #[cfg(feature = "alloc-fallback")]
    use alloc::vec::Vec;
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
            original: heapless::Vec::from_slice(b"4Ae44ncK").unwrap(),
            amount: 1000,
            spend_public_key: [1u8; 32],
            view_public_key: [2u8; 32],
            is_subaddress: false,
            is_integrated: false,
        };
        let mut e_src: [Option<TxSourceEntry>; 0] = [];
        let mut e_sd =
            core::array::from_fn::<TxDestinationEntry, 1, _>(|_| TxDestinationEntry::default());
        let mut e_sd_f = SliceVec::new(&mut e_sd);
        e_sd_f.push(dest.clone()).unwrap();
        let mut e_sel = [0usize; 1];
        let mut e_sel_f = SliceVec::new(&mut e_sel);
        e_sel_f.push(0usize).unwrap();
        let mut e_extra: [u8; 0] = [];
        let mut e_dests: [TxDestinationEntry; 0] = [];
        let mut e_sub = [0u32; 1];
        let mut e_sub_f = SliceVec::new(&mut e_sub);
        e_sub_f.push(1u32).unwrap();
        let mut st_backing = [0u8; 1];
        let mut ks_backing = [0u8; 67];
        let mut dst_backing =
            core::array::from_fn::<TxDestinationEntry, 1, _>(|_| TxDestinationEntry::default());
        let mut selected_transfers = SliceVec::new(&mut st_backing);
        selected_transfers.push(0u8).unwrap();
        let mut key_images_str = SliceVec::new(&mut ks_backing);
        for b in b"<aabb> " {
            key_images_str.push(*b).unwrap();
        }
        let mut dests = SliceVec::new(&mut dst_backing);
        dests.push(dest.clone()).unwrap();
        let ptx_tx_bytes = [0xABu8; 5];
        let ptx = PendingTx {
            tx_bytes: &ptx_tx_bytes,
            dust: 0,
            fee: 30640000,
            dust_added_to_fee: false,
            change_dts: dest.clone(),
            selected_transfers,
            key_images_str,
            additional_tx_keys: heapless::Vec::new(),
            dests,
            construction_data: TxConstructionData {
                sources: SliceVec::new(&mut e_src),
                change_dts: dest.clone(),
                splitted_dsts: e_sd_f,
                selected_transfers: e_sel_f,
                extra: SliceVec::new(&mut e_extra),
                unlock_time: 0,
                use_rct: 1,
                rct_config: RctConfig::default(),
                dests: SliceVec::new(&mut e_dests),
                subaddr_account: 0,
                subaddr_indices: e_sub_f,
            },
        };
        let mut ptx_slot: [Option<PendingTx<'_>>; 1] = core::array::from_fn(|_| None);
        let mut ki_backing = core::array::from_fn::<[u8; 32], 1, _>(|_| [0u8; 32]);
        let mut tki_backing =
            core::array::from_fn::<TxKeyImageEntry, 1, _>(|_| TxKeyImageEntry::default());
        let mut ptx_sv = SliceVec::new(&mut ptx_slot);
        ptx_sv.push(Some(ptx)).unwrap();
        let mut key_images = SliceVec::new(&mut ki_backing);
        key_images.push([3u8; 32]).unwrap();
        let mut tx_key_images = SliceVec::new(&mut tki_backing);
        tx_key_images
            .push(TxKeyImageEntry {
                output_pubkey: [4u8; 32],
                key_image: [5u8; 32],
            })
            .unwrap();
        let set = SignedTxSet {
            ptx: ptx_sv,
            key_images,
            tx_key_images,
        };
        let bytes = set.serialize();
        // Z2.4d-2 twin: into-core byte-identical to the staging convenience
        let mut twin = alloc::vec![0u8; 4096];
        let twin_n = set.serialize_into(&mut twin).unwrap();
        assert_eq!(&twin[..twin_n], &bytes[..], "serialize_into twin");
        // Z2.4d-3 twin: fused serialize+encrypt == classical pipeline, same RNG stream
        let sk = test_view_sk();
        let key = crate::chain::xmr::unsigned_txset::chacha_key_from_view_sk(&sk);
        let mut r1 = ChaCha20Rng::from_seed([0x5Au8; 32]);
        let classical =
            encrypt_signed_txset_with_chacha_key(set.serialize(), &sk, &key, &mut r1).unwrap();
        let mut r2 = ChaCha20Rng::from_seed([0x5Au8; 32]);
        let mut fused_buf = alloc::vec![0u8; 8192];
        let fused_n = set
            .encrypt_signed_txset_into(&sk, &key, &mut r2, &mut fused_buf)
            .unwrap();
        assert_eq!(&fused_buf[..fused_n], &classical[..], "fused != classical");
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

    /// Z2.4d-3 (GPT review, strengthened): forced mid-stream failure must leave the
    /// already-written prefix byte-identical to the normal encryption's ciphertext
    /// prefix (no plaintext fallback anywhere), and the tail must be untouched
    /// (SinkCursor writes are all-or-nothing).
    #[test]
    fn fused_encrypt_failure_prefix_is_ciphertext() {
        use crate::chain::xmr::unsigned_txset::chacha_key_from_view_sk;
        use crate::chain::xmr::unsigned_txset::RctConfig;
        use crate::chain::xmr::unsigned_txset::{TxConstructionData, TxDestinationEntry};
        use crate::types::SliceVec;
        let mut e_src: [Option<TxSourceEntry>; 0] = [];
        let mut e_sd: [TxDestinationEntry; 0] = [];
        let mut e_sel = [0usize; 1];
        let mut e_sel_b = [0u8; 1];
        let mut e_extra = [0x01u8, 0x02];
        let mut e_dests: [TxDestinationEntry; 0] = [];
        let mut e_sub: [u32; 0] = [];
        let mut ks = [0u8; 67];
        let mut dsts =
            core::array::from_fn::<TxDestinationEntry, 1, _>(|_| TxDestinationEntry::default());
        let tb = [0xABu8; 700]; // long enough to span many chunks
        let ptx = PendingTx {
            tx_bytes: &tb,
            dust: 0,
            fee: 30640000,
            dust_added_to_fee: false,
            change_dts: TxDestinationEntry::default(),
            selected_transfers: SliceVec::new(&mut e_sel_b),
            key_images_str: SliceVec::new(&mut ks),
            additional_tx_keys: heapless::Vec::new(),
            dests: SliceVec::new(&mut dsts),
            construction_data: TxConstructionData {
                sources: SliceVec::new(&mut e_src),
                change_dts: TxDestinationEntry::default(),
                splitted_dsts: SliceVec::new(&mut e_sd),
                selected_transfers: SliceVec::new(&mut e_sel),
                extra: SliceVec::new(&mut e_extra),
                unlock_time: 0,
                use_rct: 1,
                rct_config: RctConfig::default(),
                dests: SliceVec::new(&mut e_dests),
                subaddr_account: 0,
                subaddr_indices: SliceVec::new(&mut e_sub),
            },
        };
        let mut ptx_slot: [Option<PendingTx<'_>>; 1] = core::array::from_fn(|_| None);
        let mut ptx_sv = SliceVec::new(&mut ptx_slot);
        ptx_sv.push(Some(ptx)).unwrap();
        let mut ki_backing = core::array::from_fn::<[u8; 32], 1, _>(|_| [0u8; 32]);
        let mut tki_backing =
            core::array::from_fn::<TxKeyImageEntry, 1, _>(|_| TxKeyImageEntry::default());
        let set = SignedTxSet {
            ptx: ptx_sv,
            key_images: SliceVec::new(&mut ki_backing),
            tx_key_images: SliceVec::new(&mut tki_backing),
        };
        let sk = test_view_sk();
        let key = chacha_key_from_view_sk(&sk);

        let mut full = alloc::vec![0u8; 8192];
        let mut r1 = ChaCha20Rng::from_seed([0xC3u8; 32]);
        let n = set
            .encrypt_signed_txset_into(&sk, &key, &mut r1, &mut full)
            .unwrap();
        assert!(n > 700);

        for &cut in &[1usize, 20, 28, 100, 400, 750] {
            let mut small = alloc::vec![0xEEu8; cut]; // sentinel
            let mut r2 = ChaCha20Rng::from_seed([0xC3u8; 32]);
            let err = set
                .encrypt_signed_txset_into(&sk, &key, &mut r2, &mut small)
                .expect_err("forced overflow must error");
            assert!(
                matches!(
                    err.kind,
                    crate::error::ShlosiloErrorKind::BufferTooSmall
                        | crate::error::ShlosiloErrorKind::EncodingInvalidFormat
                ),
                "cut={cut}"
            );
            let written = small.iter().rposition(|&b| b != 0xEE).map_or(0, |i| i + 1);
            assert!(written <= cut, "cut={cut}"); // == happens when the buffer fills exactly
            assert_eq!(
                &small[..written],
                &full[..written],
                "cut={cut}: partial output must be the ciphertext prefix"
            );
            assert!(
                small[written..].iter().all(|&b| b == 0xEE),
                "cut={cut}: tail must be untouched (all-or-nothing writes)"
            );
        }
    }

    /// Z2.4d-3: export stream domain separation + deterministic retry property.
    #[test]
    fn export_stream_separates_domains_and_binds_ctx() {
        use crate::chain::xmr::signing_rng::{export_encrypt_rng, purpose_rng, RngPurpose};
        use rand_chacha::rand_core::RngCore as _;
        let e = [0x42u8; 32];
        let c1 = [0x01u8; 32];
        let c2 = [0x02u8; 32];
        let mut s1 = [0u8; 32];
        let mut s2 = [0u8; 32];
        let mut s3 = [0u8; 32];
        let mut s4 = [0u8; 32];
        export_encrypt_rng(&e, &c1).unwrap().fill_bytes(&mut s1);
        purpose_rng(&e, RngPurpose::BulletproofPlus, &c1)
            .unwrap()
            .fill_bytes(&mut s2);
        assert_ne!(
            s1, s2,
            "ExportEncrypt domain must differ from BulletproofPlus"
        );
        export_encrypt_rng(&e, &c1).unwrap().fill_bytes(&mut s3);
        assert_eq!(s1, s3, "same (entropy, domain, ctx) must reproduce (retry)");
        export_encrypt_rng(&e, &c2).unwrap().fill_bytes(&mut s4);
        assert_ne!(s1, s4, "different ctx must give different streams");
    }

    /// Z2.4d-3: envelope type binding. Cryptographic authentication covers
    /// nonce ‖ ciphertext ONLY (legacy keystone scheme; changing the hash input
    /// would break wallet interop):
    ///
    /// ```text
    /// Cryptographic authentication:    nonce || ciphertext
    /// Semantic type authentication:   NOT PROVIDED BY LEGACY ENVELOPE
    /// Type enforcement:               parser + inner version + UR type tag
    /// ```
    #[test]
    fn envelope_type_swap_sig_survives_but_parser_rejects() {
        use crate::chain::xmr::unsigned_txset::{
            chacha_key_from_view_sk, decrypt_unsigned_txset, deserialize_unsigned_tx,
            TxDestinationEntry, UnsignedTxPools,
        };
        let sk = test_view_sk();
        let key = chacha_key_from_view_sk(&sk);
        let mut rng = ChaCha20Rng::from_seed([0x77u8; 32]);
        let enc = encrypt_signed_txset_with_chacha_key(
            zeroize::Zeroizing::new(alloc::vec![0xAAu8; 40]),
            &sk,
            &key,
            &mut rng,
        )
        .unwrap();

        // type swap with length shift: UNSIGNED magic(23B) over the same raw+sig
        let mut swapped = alloc::vec::Vec::new();
        swapped.extend_from_slice(crate::chain::xmr::unsigned_txset::UNSIGNED_TX_PREFIX);
        swapped.extend_from_slice(&enc[SIGNED_TX_PREFIX.len()..]);

        // (1) signature verification SURVIVES the swap — the documented legacy gap
        let dec = decrypt_unsigned_txset(&swapped, &sk)
            .expect("sig survives magic swap (type is unauthenticated)");
        // (2) wrong-type plaintext must fail parser checks (signed container starts
        //     0x00; unsigned expects varint version 2)
        let mut t = [None; 1];
        let mut s = [None; 1];
        let mut sd =
            core::array::from_fn::<TxDestinationEntry, 1, _>(|_| TxDestinationEntry::default());
        let mut sel = [0usize; 1];
        let mut ex = [0u8; 32];
        let mut de: [TxDestinationEntry; 0] = [];
        let mut su: [u32; 0] = [];
        let parse = deserialize_unsigned_tx(
            &dec,
            UnsignedTxPools {
                txes: &mut t,
                sources: &mut s,
                splitted_dsts: &mut sd,
                selected_transfers: &mut sel,
                extra: &mut ex,
                dests: &mut de,
                subaddr_indices: &mut su,
            },
        );
        assert!(
            parse.is_err(),
            "wrong-type plaintext must fail parser checks"
        );

        // (3) in-place magic replacement (no shift) breaks the framing/signature
        let mut swapped2 = enc.clone();
        let um = crate::chain::xmr::unsigned_txset::UNSIGNED_TX_PREFIX;
        swapped2[..SIGNED_TX_PREFIX.len()].copy_from_slice(&um[..SIGNED_TX_PREFIX.len()]);
        assert!(decrypt_signed_txset(&swapped2, &sk).is_err());
    }

    /// Test fixture macro: a minimal SignedTxSet whose tx_bytes carry `$txbyte`
    /// (statement form — bindings live in the caller scope with macro hygiene).
    macro_rules! mk_export_set {
        ($name:ident, $txbyte:expr) => {
            let mut e_src: [Option<TxSourceEntry>; 0] = [];
            let mut e_sd: [crate::chain::xmr::unsigned_txset::TxDestinationEntry; 0] = [];
            let mut e_sel = [0usize; 1];
            let mut e_sel_b = [0u8; 1];
            let mut e_extra = [0x01u8, 0x02];
            let mut e_dests: [crate::chain::xmr::unsigned_txset::TxDestinationEntry; 0] = [];
            let mut e_sub: [u32; 0] = [];
            let mut ks = [0u8; 67];
            let mut dsts = core::array::from_fn::<
                crate::chain::xmr::unsigned_txset::TxDestinationEntry,
                1,
                _,
            >(|_| {
                crate::chain::xmr::unsigned_txset::TxDestinationEntry::default()
            });
            let mut ptx_slot: [Option<PendingTx<'_>>; 1] = core::array::from_fn(|_| None);
            let mut ki_backing = core::array::from_fn::<[u8; 32], 1, _>(|_| [0u8; 32]);
            let mut tki_backing =
                core::array::from_fn::<TxKeyImageEntry, 1, _>(|_| TxKeyImageEntry::default());
            let tb = [$txbyte; 700];
            let $name = {
                use crate::chain::xmr::unsigned_txset::{
                    RctConfig, TxConstructionData, TxDestinationEntry,
                };
                use crate::types::SliceVec;
                let ptx = PendingTx {
                    tx_bytes: &tb,
                    dust: 0,
                    fee: 30640000,
                    dust_added_to_fee: false,
                    change_dts: TxDestinationEntry::default(),
                    selected_transfers: SliceVec::new(&mut e_sel_b),
                    key_images_str: SliceVec::new(&mut ks),
                    additional_tx_keys: heapless::Vec::new(),
                    dests: SliceVec::new(&mut dsts),
                    construction_data: TxConstructionData {
                        sources: SliceVec::new(&mut e_src),
                        change_dts: TxDestinationEntry::default(),
                        splitted_dsts: SliceVec::new(&mut e_sd),
                        selected_transfers: SliceVec::new(&mut e_sel),
                        extra: SliceVec::new(&mut e_extra),
                        unlock_time: 0,
                        use_rct: 1,
                        rct_config: RctConfig::default(),
                        dests: SliceVec::new(&mut e_dests),
                        subaddr_account: 0,
                        subaddr_indices: SliceVec::new(&mut e_sub),
                    },
                };
                let mut ptx_sv = SliceVec::new(&mut ptx_slot);
                ptx_sv.push(Some(ptx)).unwrap();
                SignedTxSet {
                    ptx: ptx_sv,
                    key_images: SliceVec::new(&mut ki_backing),
                    tx_key_images: SliceVec::new(&mut tki_backing),
                }
            };
        };
    }

    fn env_nonce(env: &[u8]) -> &[u8] {
        &env[SIGNED_TX_PREFIX.len()..SIGNED_TX_PREFIX.len() + 8]
    }

    /// Property 1 (Z2.4d-3): same entropy + DIFFERENT transactions must produce
    /// different ExportEncrypt nonces (and different contexts).
    #[test]
    fn export_nonce_separates_transactions() {
        use crate::chain::xmr::signing_rng::export_encrypt_rng;
        use crate::chain::xmr::unsigned_txset::chacha_key_from_view_sk;
        let sk = test_view_sk();
        let key = chacha_key_from_view_sk(&sk);
        let entropy = [0x42u8; 32];

        mk_export_set!(set_a, 0xAAu8);
        let ctx_a = set_a.export_encrypt_context().unwrap();
        let mut out_a = alloc::vec![0u8; 8192];
        let na = {
            let mut r = export_encrypt_rng(&entropy, &ctx_a).unwrap();
            set_a
                .encrypt_signed_txset_into(&sk, &key, &mut r, &mut out_a)
                .unwrap()
        };

        mk_export_set!(set_b, 0xBBu8); // only the tx_bytes differ
        let ctx_b = set_b.export_encrypt_context().unwrap();
        let mut out_b = alloc::vec![0u8; 8192];
        let nb = {
            let mut r = export_encrypt_rng(&entropy, &ctx_b).unwrap();
            set_b
                .encrypt_signed_txset_into(&sk, &key, &mut r, &mut out_b)
                .unwrap()
        };

        assert_ne!(
            ctx_a, ctx_b,
            "different transactions must bind different contexts"
        );
        assert_ne!(
            env_nonce(&out_a[..na]),
            env_nonce(&out_b[..nb]),
            "same entropy + different transactions must NOT share the export nonce"
        );
        assert_ne!(
            &out_a[..na],
            &out_b[..nb],
            "different transactions must produce different envelopes"
        );
    }

    /// Property 2 (Z2.4d-3): same entropy + SAME transaction must stay byte-identical
    /// (deterministic retry property is preserved by the fix).
    #[test]
    fn export_retry_deterministic() {
        use crate::chain::xmr::signing_rng::export_encrypt_rng;
        use crate::chain::xmr::unsigned_txset::chacha_key_from_view_sk;
        let sk = test_view_sk();
        let key = chacha_key_from_view_sk(&sk);
        let entropy = [0x42u8; 32];

        mk_export_set!(set_a, 0xAAu8);
        let mut outs = [alloc::vec![0u8; 8192], alloc::vec![0u8; 8192]];
        let mut lens = [0usize; 2];
        for run in 0..2 {
            let ctx = set_a.export_encrypt_context().unwrap();
            let mut r = export_encrypt_rng(&entropy, &ctx).unwrap();
            lens[run] = set_a
                .encrypt_signed_txset_into(&sk, &key, &mut r, &mut outs[run])
                .unwrap();
        }
        assert_eq!(
            &outs[0][..lens[0]],
            &outs[1][..lens[1]],
            "same entropy + same transaction must reproduce byte-identically"
        );
    }
}
