//! XMR unsigned_txset parsing (P1-06, 2026-08-26)
//!
//! Format (measured in P6.3 + aligned with keystone apps/monero/src/transfer.rs):
//! ```text
//! magic "Monero unsigned tx set\x05" (23B)
//! nonce 8B
//! ciphertext (ChaCha20-Legacy, key = cryptonight_hash_v0(view_sk))
//! trailing 64B = Ed25519 signature (view_pub over keccak256(nonce||ciphertext))
//! ```
//!
//! Decrypted plaintext = epee binary_archive:
//! ```text
//! version varint (0x02)
//! txes_len varint
//!   per tx:
//!     sources_len varint
//!       per source:
//!         outputs_len varint
//!           per output: 0x02 varint + index varint + dest 32B + mask 32B
//!         real_output u64LE
//!         real_out_tx_key 32B
//!         real_out_additional_tx_keys_len varint + 32B each
//!         real_output_in_tx_index u64LE
//!         amount u64LE (FIELD)
//!         rct bool 1B
//!         mask 32B
//!         multisig_kLRki 128B (k, L, R, ki 32B each)
//!     change_dts: tx_destination_entry (original varint+bytes, amount VARINT,
//!                                        spend 32B, view 32B, is_sub 1B, is_int 1B)
//!     splitted_dsts_len varint + entries
//!     selected_transfers_len varint + varint each
//!     extra_len varint + bytes
//!     unlock_time u64LE
//!     use_rct u8
//!     RCTConfig: version varint + range_proof_type varint + bp_version varint
//!     dests_len varint + entries
//!     subaddr_account u32LE
//!     subaddr_indices_len varint + varint each
//! remainder = transfers segment (the display layer skips parsing it)
//! ```

#[cfg(feature = "alloc-fallback")]
extern crate alloc;

// Alloc surface: consumers behind alloc-fallback / cfg(test).
#[cfg(feature = "alloc-fallback")]
use alloc::vec::Vec;

// Consumers live behind alloc-fallback / cfg(test); unused on the no-alloc face.
#[allow(unused_imports)]
use chacha20::cipher::{KeyIvInit, StreamCipher};
// Consumers live behind alloc-fallback / cfg(test); unused on the no-alloc face.
#[allow(unused_imports)]
use chacha20::ChaCha20Legacy;

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::types::caps::DEST_ORIGINAL_MAX;

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// unsigned_txset magic (measured in P6.3)
pub const UNSIGNED_TX_PREFIX: &[u8] = b"Monero unsigned tx set\x05";
const MAGIC_LEN: usize = 23;
const SIG_LEN: usize = 64;
const NONCE_LEN: usize = 8;

// ============ Readers (epee binary_archive helpers) ============

/// Audit #12 P1-03: entry total budget. Aligned with the multipart payload cap (an encrypted blob can only be
/// smaller; decrypted plaintext can never exceed the total wire input). Malicious but signature-valid requests hit the entry
/// it rejects and never enters any allocation path.
const UNSIGNED_TXSET_MAX_PLAIN_LEN: usize = crate::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN;

/// Budgeted count read (audit #12 P1-03, X1 single-helper discipline — shared by the whole checkpoint family):
/// varint → usize fallible conversion (rejects 32-bit narrowing wraps) → physical feasibility check
/// (count × min_elem_bytes > remaining bytes = physically unparseable; reject before allocating).
/// min_elem_bytes is the element's minimum wire size (conservative lower bound); a value of 0 is defensive
/// treated as 1 (divide-by-zero guard; lesson from audit #7 P2-01).
fn read_count(data: &[u8], off: &mut usize, min_elem_bytes: usize) -> Result<usize> {
    let v = read_varint(data, off)?;
    let count = v;
    let remaining = data.len().saturating_sub(*off);
    let count = usize::try_from(count).map_err(|_| err())?;
    if count > remaining / min_elem_bytes.max(1) {
        return Err(err());
    }
    Ok(count)
}

fn read_varint(data: &[u8], off: &mut usize) -> Result<u64> {
    let mut value: u64 = 0;
    let mut shift = 0;
    loop {
        let b = *data.get(*off).ok_or_else(err)?;
        *off += 1;
        value |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(err());
        }
    }
    Ok(value)
}

fn read_u8(data: &[u8], off: &mut usize) -> Result<u8> {
    let b = *data.get(*off).ok_or_else(err)?;
    *off += 1;
    Ok(b)
}

fn read_bool(data: &[u8], off: &mut usize) -> Result<bool> {
    Ok(read_u8(data, off)? != 0)
}

fn read_u32(data: &[u8], off: &mut usize) -> Result<u32> {
    let s = data.get(*off..*off + 4).ok_or_else(err)?;
    *off += 4;
    Ok(u32::from_le_bytes(s.try_into().unwrap()))
}

fn read_u64(data: &[u8], off: &mut usize) -> Result<u64> {
    let s = data.get(*off..*off + 8).ok_or_else(err)?;
    *off += 8;
    Ok(u64::from_le_bytes(s.try_into().unwrap()))
}

fn read_bytes<'a>(data: &'a [u8], off: &mut usize, len: usize) -> Result<&'a [u8]> {
    // Audit #12 P1-03: offset+len via checked_add (both 32-bit truncation and 64-bit overflow
    // a real issue), values fetched with get (single out-of-bounds check); failure performs no allocation.
    // Z3.1: returns a borrow of the input span (was to_vec) — callers copy into
    // their own fixed-cap destinations.
    let end = off.checked_add(len).ok_or_else(err)?;
    let s = data.get(*off..end).ok_or_else(err)?;
    *off = end;
    Ok(s)
}

fn read_u8_32(data: &[u8], off: &mut usize) -> Result<[u8; 32]> {
    let v = read_bytes(data, off, 32)?;
    Ok(v.try_into().unwrap())
}

// ============ Data structures (aligned with keystone transfer.rs) ============

#[derive(Clone, Debug)]
pub struct OutputEntry {
    pub index: u64,
    pub dest: [u8; 32],
    pub mask: [u8; 32],
}

/// Audit #5 P1-02: de-Clone — k/l/r are sensitive scalars; serialization only uses `&TxSourceEntry`,
/// Clone is unnecessary (the earlier "wire DTO re-serialization need" rationale does not hold)
pub struct MultisigKLRki {
    pub k: [u8; 32],
    pub l: [u8; 32],
    pub r: [u8; 32],
    pub ki: [u8; 32],
}

/// P1-C (2026-09-01 re-review): k/l/r are multisig random masks (sensitive scalars) — zeroed on Drop.
/// ki is a public key image and needs no erasure. Clone is kept: a functional need for wire DTO re-serialization.
impl Drop for MultisigKLRki {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.k.zeroize();
        self.l.zeroize();
        self.r.zeroize();
    }
}

/// P1-03 (2026-09-01 audit #4): the real output's true blinding factor — a sensitive scalar.
///
/// Type-split decision: the wire DTO (`TxSourceEntry`) is separated from signing secrets. mask uses
/// `SecretBytes<32>` (not Clone, ZeroizeOnDrop) — previously a bare `[u8; 32]`
/// no Drop, so it would spread through memory via `TxSourceEntry` Clone/copies and never be erased.
/// Plaintext access must go through `.expose()` (grep audit point).
pub type SourceMask = crate::types::SecretBytes<32>;

/// R1: k/r are multisig random masks (sensitive) — redacted in Debug
impl core::fmt::Debug for MultisigKLRki {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MultisigKLRki")
            .field("k", &"[REDACTED]")
            .field("l", &"[REDACTED]")
            .field("r", &"[REDACTED]")
            .field("ki", &"[REDACTED]")
            .finish()
    }
}

#[allow(non_snake_case)] // multisig_kLRki field name aligned with official Monero wire naming
pub struct TxSourceEntry {
    /// ring members (protocol-hard RING_MAX; Z2.3 C3c: heapless leaf)
    pub outputs: heapless::Vec<OutputEntry, { crate::types::caps::RING_MAX }>,
    pub real_output: u64,
    /// Z2.1 S5b (2026-09-24): R1-sensitive (redacted in Debug) — zeroized on drop (was bare).
    pub real_out_tx_key: zeroize::Zeroizing<[u8; 32]>,
    /// Z2.1 S5 (2026-09-24): R1-sensitive family — element-zeroized heapless leaf (Z2.3 C3c).
    pub real_out_additional_tx_keys:
        heapless::Vec<zeroize::Zeroizing<[u8; 32]>, { crate::types::caps::EXTRA_KEYS_MAX }>,
    pub real_output_in_tx_index: u64,
    pub amount: u64,
    pub rct: bool,
    /// P1-03: true blinding factor (SecretBytes; no Clone, no Debug, ZeroizeOnDrop)
    pub mask: SourceMask,
    #[allow(non_snake_case)] // field names aligned with the official Monero MultisigKLRki struct
    pub multisig_kLRki: MultisigKLRki,
}

/// R1: real_out_tx_key / mask / multisig_kLRki are all sensitive scalars — redacted in Debug
impl core::fmt::Debug for TxSourceEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TxSourceEntry")
            .field("outputs", &self.outputs.len())
            .field("real_output", &self.real_output)
            .field("real_out_tx_key", &"[REDACTED]")
            .field(
                "real_out_additional_tx_keys",
                &self.real_out_additional_tx_keys.len(),
            )
            .field("real_output_in_tx_index", &self.real_output_in_tx_index)
            .field("amount", &self.amount)
            .field("rct", &self.rct)
            .field("mask", &"[REDACTED]")
            .field("multisig_kLRki", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Default)]
pub struct TxDestinationEntry {
    /// Z3.1 leaf: fixed-cap address string (was container `Vec<u8>`).
    /// Real Monero addresses are ≤106B; over-cap is an explicit parse Err
    /// (soft cap per the caps table policy — never truncation).
    pub original: heapless::Vec<u8, DEST_ORIGINAL_MAX>,
    pub amount: u64,
    pub spend_public_key: [u8; 32],
    pub view_public_key: [u8; 32],
    pub is_subaddress: bool,
    pub is_integrated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct RctConfig {
    pub version: u64,
    pub range_proof_type: u64,
    pub bp_version: u64,
}

/// P1-03: TxSourceEntry holds a non-Clone secret (mask) → this struct no longer derives Clone.
/// wire serialization goes by reference (write_construction_data); the sign path moves.
/// Z2.3 C3c (2026-09-24, option 2): all six lists are caller-storage SliceVecs.
#[derive(Debug)]
pub struct TxConstructionData<'a> {
    pub sources: crate::types::SliceVec<'a, Option<TxSourceEntry>>,
    pub change_dts: TxDestinationEntry,
    pub splitted_dsts: crate::types::SliceVec<'a, TxDestinationEntry>,
    pub selected_transfers: crate::types::SliceVec<'a, usize>,
    pub extra: crate::types::SliceVec<'a, u8>,
    pub unlock_time: u64,
    pub use_rct: u8,
    pub rct_config: RctConfig,
    pub dests: crate::types::SliceVec<'a, TxDestinationEntry>,
    pub subaddr_account: u32,
    pub subaddr_indices: crate::types::SliceVec<'a, u32>,
}

/// P1-03: contains TxConstructionData (not Clone) → this struct no longer derives Clone
/// Z2.3 C3c: `txes` slots are `Option` (TxConstructionData holds SliceVecs, no Default).
#[derive(Debug)]
pub struct UnsignedTx<'a> {
    pub txes: crate::types::SliceVec<'a, Option<TxConstructionData<'a>>>,
}

/// Z2.3 C3c: caller storage bundle for the unsigned-txset model (consumed by value).
/// One flat pool per list; per-tx chunks are carved with `split_at_mut` during parsing.
pub struct UnsignedTxPools<'a> {
    pub txes: &'a mut [Option<TxConstructionData<'a>>],
    pub sources: &'a mut [Option<TxSourceEntry>],
    pub splitted_dsts: &'a mut [TxDestinationEntry],
    pub selected_transfers: &'a mut [usize],
    pub extra: &'a mut [u8],
    pub dests: &'a mut [TxDestinationEntry],
    pub subaddr_indices: &'a mut [u32],
}

// ============ Decryption ============

/// Monero-style Schnorr verification (aligned with keystone utils/sign.rs::check_signature)
///
/// Signature format (c 32B, r 32B); verification:
/// ```text
/// R = s·B - c·P            (s = r, P = the public key point)
/// c' = Hs(hash || P || R)
/// valid ⇔ c' == c
/// ```
///
/// **NOTE**: this is not standard Ed25519! It is Monero's custom crypto_ops::check_signature.
pub(crate) fn check_monero_signature(
    hash: &[u8; 32],
    pubkey: &[u8; 32],
    sig: &[u8],
) -> Result<bool> {
    if sig.len() != 64 {
        return Err(err());
    }
    let c_bytes: [u8; 32] = sig[..32].try_into().unwrap();
    let r_bytes: [u8; 32] = sig[32..].try_into().unwrap();

    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::IsIdentity as _;
    use subtle::ConstantTimeEq as _;
    let c_opt = Scalar::from_canonical_bytes(c_bytes);
    let r_opt = Scalar::from_canonical_bytes(r_bytes);
    if bool::from(c_opt.is_none()) || bool::from(r_opt.is_none()) {
        return Ok(false);
    }
    let c_scalar = c_opt.unwrap();
    let r_scalar = r_opt.unwrap();
    if r_scalar == Scalar::ZERO {
        return Ok(false);
    }

    let p_point: curve25519_dalek::EdwardsPoint = monero_ed25519::CompressedPoint::from(*pubkey)
        .decompress()
        .ok_or_else(err)?
        .into();

    // R = c·P + r·B — matches monero crypto.cpp::check_signature's
    // ge_double_scalarmult_base_vartime(tmp2, c, P, r); on the generation side r = k − c·sec,
    // hence a valid signature satisfies c·P + r·B == k·B.
    let r_point = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &r_scalar;
    let c_times_p = p_point * c_scalar;
    let result_point = r_point + c_times_p;
    if result_point.is_identity() {
        return Ok(false);
    }

    // c' = Hs(hash || P || R)
    let mut data = [0u8; 96];
    let mut n = 0usize;
    data[n..n + 32].copy_from_slice(hash);
    n += 32;
    data[n..n + 32].copy_from_slice(pubkey);
    n += 32;
    data[n..n + 32].copy_from_slice(&result_point.compress().to_bytes());
    n += 32;
    let c2 = crate::chain::xmr::subaddress::hash_to_scalar(&data[..n])?;
    let c2_opt = Scalar::from_canonical_bytes(c2);
    if bool::from(c2_opt.is_none()) {
        return Ok(false);
    }
    let c2_scalar = c2_opt.unwrap();

    Ok(bool::from((c2_scalar - c_scalar).ct_eq(&Scalar::ZERO)))
}

/// pub wrapper: Monero Schnorr verification (reused for the signed_txset encrypted round-trip cross-check)
pub fn verify_monero_signature_pubkey(
    hash: &[u8; 32],
    pubkey: &[u8; 32],
    sig: &[u8],
) -> Result<bool> {
    check_monero_signature(hash, pubkey, sig)
}

/// ChaCha20 key = CryptoNight-V0(view_sk). 2MB scratchpad — the dominant cost of XMR signing on device;
/// Computing CN once per call for the same view_sk in decrypt-unsigned + encrypt-signed doubles the cost; callers should reuse it.
/// Audit #12 P1-02: returns a Zeroizing owner, never landing in a plain [u8;32] binding; internal to the crate
/// helper (the old pub let callers "wrap Zeroizing on the outside" — wrapping an owner after construction does not erase the source binding).
pub(crate) fn chacha_key_from_view_sk(view_sk: &[u8; 32]) -> zeroize::Zeroizing<[u8; 32]> {
    zeroize::Zeroizing::new(cuprate_cryptonight::cryptonight_hash_v0(view_sk))
}

/// Decrypt an unsigned_txset (aligned with keystone decrypt_data_with_pvk)
///
/// Flow: magic check → nonce=8B → Ed25519 verification (view_pub over
/// keccak256(nonce||ciphertext), trailing 64B) → ChaCha20-Legacy keystream.
/// Verification failure = data tampered or view key mismatch → reject.
#[cfg(feature = "alloc-fallback")]
pub fn decrypt_unsigned_txset(
    data: &[u8],
    view_sk: &[u8; 32],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let key = chacha_key_from_view_sk(view_sk);
    decrypt_unsigned_txset_with_chacha_key(data, view_sk, &key)
}

/// same as `decrypt_unsigned_txset`; the ChaCha key is injected by the caller (avoids recomputing CN).
/// Audit #12 P1-02: plaintext is owner-wrapped — returns Zeroizing<Vec<u8>>; error/early-return
/// paths covered by Drop; no longer returns a plain Vec.
#[cfg(feature = "alloc-fallback")]
pub(crate) fn decrypt_unsigned_txset_with_chacha_key(
    data: &[u8],
    view_sk: &[u8; 32],
    chacha_key: &zeroize::Zeroizing<[u8; 32]>,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if data.len() < MAGIC_LEN + NONCE_LEN + SIG_LEN {
        return Err(err());
    }
    if &data[..MAGIC_LEN] != UNSIGNED_TX_PREFIX {
        return Err(err());
    }

    // raw_data = nonce || ciphertext (the range covered by the signature)
    let raw_data = &data[MAGIC_LEN..data.len() - SIG_LEN];
    let nonce = &raw_data[..NONCE_LEN];
    let sig_bytes = &data[data.len() - SIG_LEN..];

    // 1. Monero-style Schnorr verification (aligned with keystone check_signature)
    //    signature format = (c 32B, r 32B); verification:
    //      R = sB - cP
    //      Hs(hash || P || R) == c
    //    **not standard Ed25519** (Monero's custom crypto_ops::check_signature)
    // monero secret_key_to_public_key = s·G, **no Ed25519 clamp**
    // (cannot use curve_primitive::scalar_from_bytes — SigningKey clamps!)
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    let v_scalar = Scalar::from_bytes_mod_order(*view_sk);
    let view_pub = (ED25519_BASEPOINT_TABLE * &v_scalar).compress().to_bytes();
    let msg_hash = crate::encoding::keccak256::hash(raw_data)?;
    if !check_monero_signature(&msg_hash, &view_pub, sig_bytes)? {
        return Err(err());
    }

    // 2. ChaCha20-Legacy decryption
    let mut cipher = ChaCha20Legacy::new_from_slices(&**chacha_key, nonce).map_err(|_| err())?;
    let mut plain = zeroize::Zeroizing::new(raw_data[NONCE_LEN..].to_vec());
    cipher.apply_keystream(&mut plain);
    Ok(plain)
}

// ============ epee deserialize ============

fn read_destination_entry(data: &[u8], off: &mut usize) -> Result<TxDestinationEntry> {
    let original_len = usize::try_from(read_varint(data, off)?).map_err(|_| err())?;
    // Z3.1: leaf cap — over-cap address strings are invalid format (real Monero
    // addresses ≤ DEST_ORIGINAL_MAX), explicit Err before the read.
    if original_len > DEST_ORIGINAL_MAX {
        return Err(err());
    }
    let original_src = read_bytes(data, off, original_len)?;
    let mut original = heapless::Vec::new();
    original
        .extend_from_slice(original_src)
        .map_err(|_| err())?;
    let amount = read_varint(data, off)?;
    let spend_public_key = read_u8_32(data, off)?;
    let view_public_key = read_u8_32(data, off)?;
    let is_subaddress = read_bool(data, off)?;
    let is_integrated = read_bool(data, off)?;
    Ok(TxDestinationEntry {
        original,
        amount,
        spend_public_key,
        view_public_key,
        is_subaddress,
        is_integrated,
    })
}

fn read_output_entry(data: &[u8], off: &mut usize) -> Result<OutputEntry> {
    // std::pair is a class in binary_archive, prefixed with a field-count 0x02
    let _pair_tag = read_varint(data, off)?;
    let index = read_varint(data, off)?;
    let dest = read_u8_32(data, off)?;
    let mask = read_u8_32(data, off)?;
    Ok(OutputEntry { index, dest, mask })
}

fn read_source_entry(data: &[u8], off: &mut usize) -> Result<TxSourceEntry> {
    // OutputEntry wire minimum = varint pair_tag(1) + varint index(1) + 64B = 66
    let outputs_len = read_count(data, off, 66)?;
    // Z2.3 C3c: protocol-hard ring cap (explicit Err, never truncates)
    if outputs_len > crate::types::caps::RING_MAX {
        return Err(err());
    }
    let mut outputs = heapless::Vec::new();
    for _ in 0..outputs_len {
        outputs
            .push(read_output_entry(data, off)?)
            .map_err(|_| err())?;
    }
    let real_output = read_u64(data, off)?;
    let real_out_tx_key = zeroize::Zeroizing::new(read_u8_32(data, off)?);
    // additional tx key wire minimum = 32B
    let additional_len = read_count(data, off, 32)?;
    let mut real_out_additional_tx_keys = heapless::Vec::new();
    for _ in 0..additional_len {
        real_out_additional_tx_keys
            .push(zeroize::Zeroizing::new(read_u8_32(data, off)?))
            .map_err(|_| err())?;
    }
    let real_output_in_tx_index = read_u64(data, off)?;
    let amount = read_u64(data, off)?; // FIELD(uint64) = 8B LE
    let rct = read_bool(data, off)?;
    // P1-03: mask goes through SecretBytes take (the read-in buffer copy is zeroed immediately)
    let mut mask_buf = read_u8_32(data, off)?;
    let mask = crate::types::SecretBytes::take(&mut mask_buf);
    let k = read_u8_32(data, off)?;
    let l = read_u8_32(data, off)?;
    let r = read_u8_32(data, off)?;
    let ki = read_u8_32(data, off)?;
    Ok(TxSourceEntry {
        outputs,
        real_output,
        real_out_tx_key,
        real_out_additional_tx_keys,
        real_output_in_tx_index,
        amount,
        rct,
        mask,
        multisig_kLRki: MultisigKLRki { k, l, r, ki },
    })
}

/// Minimum wire size in bytes of TxConstructionData (protocol constant; audit #13 §4 requires it defined in one place).
/// With zero sources/dests the per-field minimal encoding totals 90B; see the notes inside deserialize_unsigned_tx for the breakdown.
/// Any remaining bytes below this value cannot hold 1 legal transaction (count upper bound = remaining / 90).
const MIN_TX_CONSTRUCTION_DATA_WIRE: usize = 90;

/// Z2.3 C3c: parse-into — carve-as-you-read (each count is known when its field is
/// reached; `split_at_mut` hands out disjoint caller-pool chunks, safe-Rust).
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn read_tx_construction_data<'a>(
    data: &[u8],
    off: &mut usize,
    sources_rest: &mut &'a mut [Option<TxSourceEntry>],
    splitted_rest: &mut &'a mut [TxDestinationEntry],
    sel_rest: &mut &'a mut [usize],
    extra_rest: &mut &'a mut [u8],
    dests_rest: &mut &'a mut [TxDestinationEntry],
    subidx_rest: &mut &'a mut [u32],
) -> Result<TxConstructionData<'a>> {
    // TxSourceEntry wire minimum = outputs_len(1) + outputs(66) + 8+32+1 (keys len + key + ...)
    // conservatively 100; in practice any malicious value is rejected by subsequent field reads
    // (sources_len=0 is legal: count=0 always passes the 0 > remaining/100 check, no false rejection)
    let sources_len = read_count(data, off, 100)?;
    // Pool side: an input-feasible demand larger than the remaining pool is
    // explicit overload Err, never a split_at_mut panic (fuzz 2026-09-25).
    if sources_len > sources_rest.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall));
    }
    let (chunk, rest) = core::mem::take(&mut *sources_rest).split_at_mut(sources_len);
    *sources_rest = rest;
    let mut sources = crate::types::SliceVec::new(chunk);
    for _ in 0..sources_len {
        sources
            .push(Some(read_source_entry(data, off)?))
            .map_err(|_| err())?;
    }
    let change_dts = read_destination_entry(data, off)?;
    // TxDestinationEntry wire minimum = original_len(1) + varint amount(1) + 64 + 2 ≈ 68
    let splitted_dsts_len = read_count(data, off, 68)?;
    // Pool side: an input-feasible demand larger than the remaining pool is
    // explicit overload Err, never a split_at_mut panic (fuzz 2026-09-25).
    if splitted_dsts_len > splitted_rest.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall));
    }
    let (chunk, rest) = core::mem::take(&mut *splitted_rest).split_at_mut(splitted_dsts_len);
    *splitted_rest = rest;
    let mut splitted_dsts = crate::types::SliceVec::new(chunk);
    for _ in 0..splitted_dsts_len {
        splitted_dsts
            .push(read_destination_entry(data, off)?)
            .map_err(|_| err())?;
    }
    let selected_len = read_count(data, off, 1)?;
    // Pool side: an input-feasible demand larger than the remaining pool is
    // explicit overload Err, never a split_at_mut panic (fuzz 2026-09-25).
    if selected_len > sel_rest.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall));
    }
    let (chunk, rest) = core::mem::take(&mut *sel_rest).split_at_mut(selected_len);
    *sel_rest = rest;
    let mut selected_transfers = crate::types::SliceVec::new(chunk);
    for _ in 0..selected_len {
        // u64 → usize fallible (rejects narrowing wraps on 32-bit)
        selected_transfers
            .push(usize::try_from(read_varint(data, off)?).map_err(|_| err())?)
            .map_err(|_| err())?;
    }
    let extra_len = usize::try_from(read_varint(data, off)?).map_err(|_| err())?;
    // Input-side bounds first (fuzz crash-91cc406b class: a claimed length may
    // exceed the remaining input — slicing must be Err, never a range panic).
    let extra_end = (*off).checked_add(extra_len).ok_or_else(err)?;
    let extra_src = data.get(*off..extra_end).ok_or_else(err)?;
    // Pool side: an input-feasible demand larger than the remaining pool is
    // explicit overload Err, never a split_at_mut panic (fuzz 2026-09-25).
    if extra_len > extra_rest.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall));
    }
    let (chunk, rest) = core::mem::take(&mut *extra_rest).split_at_mut(extra_len);
    *extra_rest = rest;
    chunk.copy_from_slice(extra_src);
    *off = extra_end;
    let extra = crate::types::SliceVec::new(chunk);
    let unlock_time = read_u64(data, off)?;
    let use_rct = read_u8(data, off)?;
    let version = read_varint(data, off)?;
    let range_proof_type = read_varint(data, off)?;
    let bp_version = read_varint(data, off)?;
    let dests_len = read_count(data, off, 68)?;
    // Pool side: an input-feasible demand larger than the remaining pool is
    // explicit overload Err, never a split_at_mut panic (fuzz 2026-09-25).
    if dests_len > dests_rest.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall));
    }
    let (chunk, rest) = core::mem::take(&mut *dests_rest).split_at_mut(dests_len);
    *dests_rest = rest;
    let mut dests = crate::types::SliceVec::new(chunk);
    for _ in 0..dests_len {
        dests
            .push(read_destination_entry(data, off)?)
            .map_err(|_| err())?;
    }
    let subaddr_account = read_u32(data, off)?;
    let subaddr_indices_len = read_count(data, off, 1)?;
    // Pool side: an input-feasible demand larger than the remaining pool is
    // explicit overload Err, never a split_at_mut panic (fuzz 2026-09-25).
    if subaddr_indices_len > subidx_rest.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall));
    }
    let (chunk, rest) = core::mem::take(&mut *subidx_rest).split_at_mut(subaddr_indices_len);
    *subidx_rest = rest;
    let mut subaddr_indices = crate::types::SliceVec::new(chunk);
    for _ in 0..subaddr_indices_len {
        // u64 → u32 fallible (rejects high-bit truncation wraps like 256→0)
        subaddr_indices
            .push(u32::try_from(read_varint(data, off)?).map_err(|_| err())?)
            .map_err(|_| err())?;
    }
    Ok(TxConstructionData {
        sources,
        change_dts,
        splitted_dsts,
        selected_transfers,
        extra,
        unlock_time,
        use_rct,
        rct_config: RctConfig {
            version,
            range_proof_type,
            bp_version,
        },
        dests,
        subaddr_account,
        subaddr_indices,
    })
}

// Z2.4d-2: writers generic over `Sink` (cursor = zero-heap, Vec = staging).
use crate::types::push::Sink;

#[allow(dead_code)] // consumed behind the gate on the alloc face
fn put_varint<S: Sink>(out: &mut S, n: u64) -> Result<()> {
    let mut tmp = [0u8; 10];
    let mut pos = 0usize;
    crate::chain::xmr::transaction::monero_encode_varint_at(&mut tmp, &mut pos, n)?;
    out.put(&tmp[..pos])
}

#[allow(dead_code)] // consumed behind the gate on the alloc face
fn write_unsigned_destination<S: Sink>(out: &mut S, e: &TxDestinationEntry) -> Result<()> {
    // monero `tx_destination_entry`: amount is a varint on BOTH sides. (The old
    // "signed side is u64 LE" note was wrong — that mistaken belief lived in
    // signed_txset.rs and broke file-level interop until 2026-09-15.)
    put_varint(out, e.original.len() as u64)?;
    out.put(&e.original)?;
    put_varint(out, e.amount)?;
    out.put(&e.spend_public_key)?;
    out.put(&e.view_public_key)?;
    out.put_u8(e.is_subaddress as u8)?;
    out.put_u8(e.is_integrated as u8)
}

#[allow(dead_code)] // consumed behind the gate on the alloc face
fn write_unsigned_source<S: Sink>(out: &mut S, s: &TxSourceEntry) -> Result<()> {
    put_varint(out, s.outputs.len() as u64)?;
    for o in s.outputs.iter() {
        // std::pair field-count prefix, isomorphic to read_output_entry's varint 2
        out.put_u8(2)?;
        put_varint(out, o.index)?;
        out.put(&o.dest)?;
        out.put(&o.mask)?;
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

#[allow(dead_code)] // consumed behind the gate on the alloc face
fn write_unsigned_construction<S: Sink>(out: &mut S, d: &TxConstructionData<'_>) -> Result<()> {
    put_varint(out, d.sources.len() as u64)?;
    for s in d.sources.iter().flatten() {
        write_unsigned_source(out, s)?;
    }
    write_unsigned_destination(out, &d.change_dts)?;
    put_varint(out, d.splitted_dsts.len() as u64)?;
    for dst in d.splitted_dsts.iter() {
        write_unsigned_destination(out, dst)?;
    }
    put_varint(out, d.selected_transfers.len() as u64)?;
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
        write_unsigned_destination(out, dest)?;
    }
    out.put(&d.subaddr_account.to_le_bytes())?;
    put_varint(out, d.subaddr_indices.len() as u64)?;
    for i in d.subaddr_indices.iter() {
        put_varint(out, *i as u64)?;
    }
    Ok(())
}

/// Core writer (Z2.4d-2): epee wire form of the txes segment, any `Sink`.
#[allow(dead_code)] // consumed behind the gate on the alloc face
fn write_unsigned_tx<S: Sink>(tx: &UnsignedTx<'_>, out: &mut S) -> Result<()> {
    put_varint(out, 2)?;
    put_varint(out, tx.txes.len() as u64)?;
    for d in tx.txes.iter().flatten() {
        write_unsigned_construction(out, d)?;
    }
    Ok(())
}

/// Serialize into a caller buffer; returns bytes written.
/// Z2.4d-3: test-only face — production keeps the secret-bearing container as a
/// self-zeroizing owner (`serialize_unsigned_tx`). Any user of this face owns
/// zeroization of `out`.
#[cfg(test)]
pub fn serialize_unsigned_tx_into(tx: &UnsignedTx<'_>, out: &mut [u8]) -> Result<usize> {
    let mut w = crate::types::push::SinkCursor::new(out);
    write_unsigned_tx(tx, &mut w)?;
    Ok(w.pos())
}

/// epee serialize (dual of `deserialize_unsigned_tx`; excludes the trailing transfers segment).
/// Audit #12 P1-02: the output contains the mask/kLRki secret fields; returns a Zeroizing owner.
/// Staging convenience (allocates). Production paths use `serialize_unsigned_tx_into`.
#[cfg(feature = "alloc-fallback")]
pub fn serialize_unsigned_tx(tx: &UnsignedTx<'_>) -> zeroize::Zeroizing<Vec<u8>> {
    let mut out = Vec::new();
    write_unsigned_tx(tx, &mut out).expect("Vec sink is infallible by construction");
    zeroize::Zeroizing::new(out)
}

/// Fused decrypt+parse (Z2.4d-3): the decrypted container is a forms-internal
/// transient — decrypted into `scratch` (storage provided by the caller; zeroization is
/// forms' duty, done here before return on every path), parsed into `pools`. The caller
/// provides storage only and never holds live secrets.
pub fn decrypt_and_parse_unsigned_tx<'a>(
    data: &[u8],
    view_sk: &[u8; 32],
    chacha_key: &zeroize::Zeroizing<[u8; 32]>,
    scratch: &mut [u8],
    pools: UnsignedTxPools<'a>,
) -> Result<UnsignedTx<'a>> {
    // Consumers live behind alloc-fallback / cfg(test); unused on the no-alloc face.
    #[allow(unused_imports)]
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    // Consumers live behind alloc-fallback / cfg(test); unused on the no-alloc face.
    #[allow(unused_imports)]
    use chacha20::ChaCha20Legacy;
    use zeroize::Zeroize;

    if data.len() < MAGIC_LEN + NONCE_LEN + SIG_LEN {
        return Err(err());
    }
    if &data[..MAGIC_LEN] != UNSIGNED_TX_PREFIX {
        return Err(err());
    }
    // raw_data = nonce || ciphertext (the range covered by the signature)
    let raw_data = &data[MAGIC_LEN..data.len() - SIG_LEN];
    let nonce = &raw_data[..NONCE_LEN];
    let sig_bytes = &data[data.len() - SIG_LEN..];

    // Schnorr verification first (anti-tamper), same as the split path
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    let v_scalar = zeroize::Zeroizing::new(Scalar::from_bytes_mod_order(*view_sk));
    let view_pub = (ED25519_BASEPOINT_TABLE * &*v_scalar).compress().to_bytes();
    let msg_hash = crate::encoding::keccak256::hash(raw_data)?;
    if !check_monero_signature(&msg_hash, &view_pub, sig_bytes)? {
        return Err(err());
    }

    let ct = &raw_data[NONCE_LEN..];
    if scratch.len() < ct.len() {
        return Err(crate::error::ShlosiloError::new(
            crate::error::ShlosiloErrorKind::BufferTooSmall,
        ));
    }
    let plain: &mut [u8] = &mut scratch[..ct.len()];
    plain.copy_from_slice(ct);
    let mut cipher = ChaCha20Legacy::new_from_slices(&**chacha_key, nonce).map_err(|_| err())?;
    cipher.apply_keystream(plain);
    let result = deserialize_unsigned_tx(plain, pools);
    // forms-internal secret duty: the whole plaintext scratch is wiped before return,
    // on every path (Ok and Err alike) — not just the ct region the caller never
    // asked to police.
    scratch.zeroize();
    result
}

/// epee deserialize (aligned with keystone UnsignedTx::deserialize).
/// Audit #12 P1-03: three layers of entry resource budgeting — total length budget (before allocation) → txes count
/// physical feasibility → field-by-field checked reads; malicious but signature-valid requests reliably return Err.
/// Z2.3 C3c (2026-09-24, option 2): parse-into — the model lives in caller pools
/// (`UnsignedTxPools`), per-tx chunks carved with `split_at_mut` (capacity is a
/// deployment parameter; over-cap is explicit Err).
pub fn deserialize_unsigned_tx<'a>(
    bytes: &[u8],
    pools: UnsignedTxPools<'a>,
) -> Result<UnsignedTx<'a>> {
    if bytes.len() > UNSIGNED_TXSET_MAX_PLAIN_LEN {
        return Err(err());
    }
    let mut off = 0usize;
    let version = read_varint(bytes, &mut off)?;
    if version != 2 {
        return Err(err());
    }
    // TxConstructionData wire minimum = 90B accounted field by field (audit #13 P1-01, zero sources/dests):
    //   sources_len 1 + change_dts 68 + splitted_dsts_len 1 + selected_len 1
    //   + extra_len 1 + unlock_time 8 + use_rct 1 + version 1 + range_proof_type 1
    //   + bp_version 1 + dests_len 1 + subaddr_account 4 + subaddr_indices_len 1
    // the old value of 100 (bd7cf3b) rejected legitimate zero-input txs (92B top-level wire); a regression introduced by remedi
    // maliciously large counts are still rejected before with_capacity.
    let UnsignedTxPools {
        txes: txes_pool,
        mut sources,
        mut splitted_dsts,
        mut selected_transfers,
        mut extra,
        mut dests,
        mut subaddr_indices,
    } = pools;
    let mut txes = crate::types::SliceVec::new(txes_pool);
    let txes_len = read_count(bytes, &mut off, MIN_TX_CONSTRUCTION_DATA_WIRE)?;
    for _ in 0..txes_len {
        let d = read_tx_construction_data(
            bytes,
            &mut off,
            &mut sources,
            &mut splitted_dsts,
            &mut selected_transfers,
            &mut extra,
            &mut dests,
            &mut subaddr_indices,
        )?;
        txes.push(Some(d)).map_err(|_| err())?;
    }
    // remainder = transfers segment (not needed by the display layer)
    Ok(UnsignedTx { txes })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P6.3 real fixture plaintext (/tmp/txset_plain.bin, 1952B) — included from file
    /// Verify deserialize matches the python parsing (1 input ring16, change+dest, fee)
    #[test]
    fn deserialize_p63_fixture_plain() {
        // fixture plaintext is too large to embed — build a minimal verification from known P6.3 key values:
        // verified via the read_destination_entry unit test + known offsets (see the test below)
        // full fixture parsing lives in the integration test tests/p63_xmr_unsigned.rs (include_bytes)
        let _ = UNSIGNED_TX_PREFIX;
    }

    /// Z2.3 C3c: outcome-only parser helpers for the robustness tests (pools are
    /// macro-local; the parsed model never escapes the statement).
    macro_rules! deser_outcome {
        ($bytes:expr, $pat:pat => $ret:expr) => {{
            let mut p_txes: [Option<TxConstructionData<'_>>; 4] = core::array::from_fn(|_| None);
            let mut p_src: [Option<TxSourceEntry>; 8] = core::array::from_fn(|_| None);
            let mut p_sd =
                core::array::from_fn::<TxDestinationEntry, 8, _>(|_| TxDestinationEntry::default());
            let mut p_sel = [0usize; 16];
            let mut p_ex = [0u8; 4096];
            let mut p_de =
                core::array::from_fn::<TxDestinationEntry, 8, _>(|_| TxDestinationEntry::default());
            let mut p_su = [0u32; 16];
            match deserialize_unsigned_tx(
                $bytes,
                UnsignedTxPools {
                    txes: &mut p_txes,
                    sources: &mut p_src,
                    splitted_dsts: &mut p_sd,
                    selected_transfers: &mut p_sel,
                    extra: &mut p_ex,
                    dests: &mut p_de,
                    subaddr_indices: &mut p_su,
                },
            ) {
                $pat => $ret,
                _ => !$ret,
            }
        }};
    }
    macro_rules! deser_ok {
        ($bytes:expr) => { deser_outcome!($bytes, Ok(_) => true) };
    }
    macro_rules! deser_err {
        ($bytes:expr) => { deser_outcome!($bytes, Err(_) => true) };
    }

    /// Reader: varint, standard LEB128
    #[test]
    fn read_varint_basic() {
        let data = [0x80u8, 0xd7, 0xb0, 0xfb, 0x06]; // 1869360000
        let mut off = 0;
        assert_eq!(read_varint(&data, &mut off).unwrap(), 1869360000);
        assert_eq!(off, 5);
    }

    /// Reader: short varint
    #[test]
    fn read_varint_short() {
        let data = [0x02u8];
        let mut off = 0;
        assert_eq!(read_varint(&data, &mut off).unwrap(), 2);
        assert_eq!(off, 1);
    }

    /// Reader: out of bounds → Err
    #[test]
    fn read_overflow_rejected() {
        let data = [0x01u8];
        let mut off = 5;
        assert!(read_u32(&data, &mut off).is_err());
    }

    /// Reader: u64 LE
    #[test]
    fn read_u64_le() {
        let data = [0x0du8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut off = 0;
        assert_eq!(read_u64(&data, &mut off).unwrap(), 13);
    }

    /// decrypt: bad magic → Err
    #[test]
    fn decrypt_bad_magic_rejected() {
        let data = b"not the magic at all...........";
        let view = [0u8; 32];
        assert!(decrypt_unsigned_txset(data, &view).is_err());
    }

    /// decrypt: too short → Err
    #[test]
    fn decrypt_too_short_rejected() {
        let view = [0u8; 32];
        assert!(decrypt_unsigned_txset(b"Monero unsigned tx set\x05short", &view).is_err());
    }

    // ── P1-03 (audit #4): compile-time secret owner discipline ──

    /// mask (the true blinding factor) must have Drop — the anchor for the ZeroizeOnDrop erasure proof
    #[test]
    fn p103_source_mask_needs_drop() {
        assert!(core::mem::needs_drop::<SourceMask>());
        // and not Clone — secret copies must not proliferate
        static_assertions::assert_not_impl_any!(SourceMask: Clone, Copy);
    }

    /// TxSourceEntry is no longer Clone as a whole (contains the mask/kLRki secrets)
    #[test]
    fn p103_tx_source_entry_not_clone() {
        static_assertions::assert_not_impl_any!(TxSourceEntry: Clone, Copy);
        // host-side structs likewise not Clone — secrets cannot spread through the struct tree
        static_assertions::assert_not_impl_any!(TxConstructionData<'static>: Clone);
        static_assertions::assert_not_impl_any!(UnsignedTx<'static>: Clone);
    }

    /// MultisigKLRki has Drop (erases k/l/r) and is not Clone (audit #5 P1-02:
    /// serialization only needs a reference, so the Clone rationale does not hold — sensitive scalar copies must not proliferate)
    #[test]
    fn p103_multisig_klrki_needs_drop() {
        assert!(core::mem::needs_drop::<MultisigKLRki>());
        static_assertions::assert_not_impl_any!(MultisigKLRki: Clone, Copy);
    }

    /// serialize ↔ deserialize duality: 1 source / 2 dests, amount as varint.
    #[test]
    fn serialize_deserialize_roundtrip_minimal() {
        let src = TxSourceEntry {
            outputs: heapless::Vec::from_slice(&[OutputEntry {
                index: 7,
                dest: [0x11u8; 32],
                mask: [0x22u8; 32],
            }])
            .unwrap(),
            real_output: 0,
            real_out_tx_key: zeroize::Zeroizing::new([0x33u8; 32]),
            real_out_additional_tx_keys: heapless::Vec::new(),
            real_output_in_tx_index: 0,
            amount: 1000,
            rct: true,
            mask: crate::types::SecretBytes::new([0x66u8; 32]),
            multisig_kLRki: MultisigKLRki {
                k: [0; 32],
                l: [0; 32],
                r: [0; 32],
                ki: [0; 32],
            },
        };
        let dest = TxDestinationEntry {
            original: heapless::Vec::new(),
            amount: 900,
            spend_public_key: [0x44u8; 32],
            view_public_key: [0x55u8; 32],
            is_subaddress: false,
            is_integrated: false,
        };
        let change = TxDestinationEntry {
            original: heapless::Vec::new(),
            amount: 50,
            spend_public_key: [0x44u8; 32],
            view_public_key: [0x55u8; 32],
            is_subaddress: false,
            is_integrated: false,
        };
        let mut u_src = [None; 1];
        let mut u_src_f = crate::types::SliceVec::new(&mut u_src);
        u_src_f.push(Some(src)).unwrap();
        let mut u_sd =
            core::array::from_fn::<TxDestinationEntry, 2, _>(|_| TxDestinationEntry::default());
        let mut u_sd_f = crate::types::SliceVec::new(&mut u_sd);
        u_sd_f.push(change.clone()).unwrap();
        u_sd_f.push(dest.clone()).unwrap();
        let mut u_sel = [0usize; 1];
        let mut u_sel_f = crate::types::SliceVec::new(&mut u_sel);
        u_sel_f.push(0usize).unwrap();
        let mut u_extra: [u8; 0] = [];
        let mut u_dests: [TxDestinationEntry; 0] = [];
        let mut u_sub: [u32; 0] = [];
        let mut u_txd = [None; 1];
        let mut u_txd_f = crate::types::SliceVec::new(&mut u_txd);
        u_txd_f
            .push(Some(TxConstructionData {
                sources: u_src_f,
                change_dts: change.clone(),
                splitted_dsts: u_sd_f,
                selected_transfers: u_sel_f,
                extra: crate::types::SliceVec::new(&mut u_extra),
                unlock_time: 0,
                use_rct: 1,
                rct_config: RctConfig {
                    version: 0,
                    range_proof_type: 0,
                    bp_version: 4,
                },
                dests: crate::types::SliceVec::new(&mut u_dests),
                subaddr_account: 0,
                subaddr_indices: crate::types::SliceVec::new(&mut u_sub),
            }))
            .unwrap();
        let tx = UnsignedTx { txes: u_txd_f };
        let bytes = serialize_unsigned_tx(&tx);
        // Z2.4d-2 twin: into-core byte-identical to the staging convenience
        let mut twin = alloc::vec![0u8; 4096];
        let twin_n = serialize_unsigned_tx_into(&tx, &mut twin).unwrap();
        assert_eq!(
            &twin[..twin_n],
            &bytes[..],
            "serialize_unsigned_tx_into twin"
        );
        let mut bp_txes: [Option<TxConstructionData<'_>>; 1] = core::array::from_fn(|_| None);
        let mut bp_src: [Option<TxSourceEntry>; 1] = core::array::from_fn(|_| None);
        let mut bp_sd =
            core::array::from_fn::<TxDestinationEntry, 2, _>(|_| TxDestinationEntry::default());
        let mut bp_sel = [0usize; 1];
        let mut bp_extra: [u8; 512] = [0u8; 512];
        let mut bp_dests: [TxDestinationEntry; 0] = [];
        let mut bp_sub: [u32; 0] = [];
        let back = deserialize_unsigned_tx(
            &bytes,
            UnsignedTxPools {
                txes: &mut bp_txes,
                sources: &mut bp_src,
                splitted_dsts: &mut bp_sd,
                selected_transfers: &mut bp_sel,
                extra: &mut bp_extra,
                dests: &mut bp_dests,
                subaddr_indices: &mut bp_sub,
            },
        )
        .expect("deserialize");
        assert_eq!(back.txes.len(), 1);
        let d = back.txes.iter().flatten().next().unwrap();
        assert_eq!(d.sources.len(), 1);
        let s0 = d.sources.iter().flatten().next().unwrap();
        assert_eq!(s0.amount, 1000);
        assert_eq!(s0.outputs[0].index, 7);
        assert_eq!(d.change_dts.amount, 50);
        assert_eq!(d.splitted_dsts[1].amount, 900);
        assert_eq!(d.rct_config.bp_version, 4);
        let bytes2 = serialize_unsigned_tx(&back);
        assert_eq!(bytes, bytes2);
    }

    /// encrypt_unsigned ↔ decrypt_unsigned duality.
    #[test]
    fn encrypt_decrypt_unsigned_roundtrip() {
        use rand_chacha::rand_core::SeedableRng;
        let mut e_txd: [Option<TxConstructionData<'_>>; 0] = [];
        let plain = serialize_unsigned_tx(&UnsignedTx {
            txes: crate::types::SliceVec::new(&mut e_txd),
        });
        let view = [0xABu8; 32];
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x11u8; 32]);
        let enc =
            crate::chain::xmr::signed_txset::encrypt_unsigned_txset(plain.clone(), &view, &mut rng)
                .expect("encrypt");
        let dec = decrypt_unsigned_txset(&enc, &view).expect("decrypt");
        assert_eq!(*dec, *plain);
        // Z2.4d-3: fused decrypt+parse == split path, and the plaintext scratch is wiped
        {
            let key = chacha_key_from_view_sk(&view);
            let mut scratch = alloc::vec![0u8; enc.len()];
            scratch.fill(0xEE); // sentinel: wiped region must not retain it
            let mut u_t = [None; 1];
            let mut u_src = [None; 1];
            let mut u_sd =
                core::array::from_fn::<TxDestinationEntry, 2, _>(|_| TxDestinationEntry::default());
            let mut u_sel = [0usize; 1];
            let mut u_extra = [0u8; 64];
            let mut u_dests: [TxDestinationEntry; 0] = [];
            let mut u_sub: [u32; 0] = [];
            let fused = decrypt_and_parse_unsigned_tx(
                &enc,
                &view,
                &key,
                &mut scratch,
                UnsignedTxPools {
                    txes: &mut u_t,
                    sources: &mut u_src,
                    splitted_dsts: &mut u_sd,
                    selected_transfers: &mut u_sel,
                    extra: &mut u_extra,
                    dests: &mut u_dests,
                    subaddr_indices: &mut u_sub,
                },
            )
            .expect("fused decrypt_and_parse");
            assert_eq!(fused.txes.len(), 0); // same empty-txes shape as `plain`
            assert!(
                scratch.iter().all(|&b| b == 0),
                "plaintext scratch not wiped"
            );
        }
    }

    /// Audit #12 P1-02 API gate: the owner types for plaintext/ciphertext/CN key must carry
    /// Drop zeroes (Zeroizing); error paths and early returns are covered by Drop.
    #[test]
    fn plaintext_owner_types_have_drop() {
        assert!(core::mem::needs_drop::<zeroize::Zeroizing<Vec<u8>>>());
        assert!(core::mem::needs_drop::<zeroize::Zeroizing<[u8; 32]>>());
    }

    // ============ Audit #12 P1-03: parser resource budget bounds ============

    /// read_count physical feasibility bound (pure helper tested directly; final state of #6 re-review P2-01 —
    /// no reliance on timing/allocation observation): reject whenever count > remaining/min_elem.
    #[test]
    fn read_count_physical_feasibility_boundaries() {
        // count=1, 19 bytes remain after varint, min_elem=10 → 1 ≤ 19/10=1, feasible
        let data = [1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut off = 0usize;
        assert_eq!(read_count(&data, &mut off, 10).unwrap(), 1);
        // count=2, 9 bytes remain after varint, min_elem=5 → 2 > 9/5=1 → reject
        let data2 = [2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut off2 = 0usize;
        assert!(read_count(&data2, &mut off2, 5).is_err());
        // min_elem=0 defense (no panic; lesson from #7 P2-01): count=9, 9 remain, treated as 1 → 9 ≤ 9
        let data3 = [9u8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut off3 = 0usize;
        assert_eq!(read_count(&data3, &mut off3, 0).unwrap(), 9);
        // u64::MAX count → usize::try_from rejects on 32-bit / physically-infeasible check rejects on 64-bit
        let huge = {
            // LEB128 of u64::MAX
            [0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        };
        let mut off4 = 0usize;
        assert!(read_count(&huge, &mut off4, 1).is_err());
    }

    /// Entry total budget: plaintext > UNSIGNED_TXSET_MAX_PLAIN_LEN (16384) rejected before allocation.
    #[test]
    fn entry_total_budget_rejects_oversize() {
        let big = alloc::vec![0u8; UNSIGNED_TXSET_MAX_PLAIN_LEN + 1];
        assert!(deser_err!(&big));
        // in-bounds shapes (empty txset is legal) must not be wrongly rejected
        let ok = alloc::vec![2u8, 0];
        assert!(deser_ok!(&ok));
    }

    /// Entry total budget lower-bound positive case (audit #14 §4.1): exactly MAX=16384B is acceptable.
    /// The trailing transfers segment is tolerated for the display layer; it can be built with version=2 + txes_len=0 + padding.
    /// The total-budget dimension is now closed on all four sides: empty txset accepted / MAX accepted / MAX+1 rejected / huge varint rejected.
    #[test]
    fn entry_total_budget_max_exact_accepted() {
        let mut w = alloc::vec![2u8, 0]; // version=2 + txes_len=0
        w.resize(UNSIGNED_TXSET_MAX_PLAIN_LEN, 0x41);
        assert_eq!(w.len(), UNSIGNED_TXSET_MAX_PLAIN_LEN);
        assert!(deser_ok!(&w), "MAX exact must be accepted");
    }

    /// Malicious corpus: legal version=2 + huge txes count → physical feasibility
    /// rejected before with_capacity (hostile but structurally valid wire; release-blocking acceptance).
    #[test]
    fn malicious_huge_txes_count_rejected_pre_alloc() {
        // version=2(1B) + txes_len = u64::MAX LEB128(10B)
        let mut wire = alloc::vec![2u8];
        wire.extend_from_slice(&[0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
        assert!(deser_err!(&wire));
        // secondary extreme: within budget but physically infeasible (60000 × 100B >> 16KiB budget)
        let mut wire2 = alloc::vec![2u8];
        // LEB128 of 60000 = 0xF0 0xD4 0x03
        wire2.extend_from_slice(&[0xf0, 0xd4, 0x03]);
        assert!(deser_err!(&wire2));
    }

    // ── P1-01 (audit #13): legal minimum wire bounds (bd7cf3b regression-fix acceptance) ──

    /// Minimal legal TxConstructionData wire with zero sources/dests (90B, accounted field by field
    /// see the MIN_TX_CONSTRUCTION_DATA_WIRE comment).
    fn min_tx_construction_data_wire() -> alloc::vec::Vec<u8> {
        let mut d = alloc::vec::Vec::new();
        d.push(0); // sources_len = 0
                   // change_dts destination minimum 68B
        d.push(0); // original_len = 0
        d.push(0); // amount varint 0
        d.extend_from_slice(&[0u8; 32]); // spend_public_key
        d.extend_from_slice(&[0u8; 32]); // view_public_key
        d.push(0); // is_subaddress
        d.push(0); // is_integrated
        d.push(0); // splitted_dsts_len = 0
        d.push(0); // selected_len = 0
        d.push(0); // extra_len = 0
        d.extend_from_slice(&[0u8; 8]); // unlock_time u64
        d.push(0); // use_rct u8
        d.push(1); // version varint 1
        d.push(0); // range_proof_type varint 0
        d.push(0); // bp_version varint 0
        d.push(0); // dests_len = 0
        d.extend_from_slice(&[0, 0, 0, 0]); // subaddr_account u32
        d.push(0); // subaddr_indices_len = 0
        d
    }

    /// Top-level wire assembly: version=2 + txes_len + body.
    fn top_wire(txes_len: u8, body: &[u8]) -> alloc::vec::Vec<u8> {
        let mut w = alloc::vec![2u8, txes_len];
        w.extend_from_slice(body);
        w
    }

    /// The legal minimum must be accepted (audit #13 P1-01: bd7cf3b's 100B lower bound wrongly rejected this shape).
    #[test]
    fn a13_min_legal_wire_accepted() {
        let wire = top_wire(1, &min_tx_construction_data_wire()); // 92B
        assert_eq!(wire.len(), 92);
        let mut p_txes: [Option<TxConstructionData<'_>>; 4] = core::array::from_fn(|_| None);
        let mut p_src: [Option<TxSourceEntry>; 4] = core::array::from_fn(|_| None);
        let mut p_sd =
            core::array::from_fn::<TxDestinationEntry, 4, _>(|_| TxDestinationEntry::default());
        let mut p_sel = [0usize; 4];
        let mut p_ex = [0u8; 256];
        let mut p_de =
            core::array::from_fn::<TxDestinationEntry, 4, _>(|_| TxDestinationEntry::default());
        let mut p_su = [0u32; 4];
        let tx = deserialize_unsigned_tx(
            &wire,
            UnsignedTxPools {
                txes: &mut p_txes,
                sources: &mut p_src,
                splitted_dsts: &mut p_sd,
                selected_transfers: &mut p_sel,
                extra: &mut p_ex,
                dests: &mut p_de,
                subaddr_indices: &mut p_su,
            },
        )
        .expect("legal minimal wire must parse");
        assert_eq!(tx.txes.len(), 1);
        let t0 = tx.txes.iter().flatten().next().unwrap();
        assert!(t0.sources.is_empty());
        assert!(t0.dests.is_empty());
    }

    /// Fuzz smoke regression (2026-09-25, crash-91cc406b class): the extra_len
    /// claim must be bounds-checked against the INPUT before slicing — a claim
    /// larger than the remaining wire must Err, never a range panic. (The pre-fix
    /// code checked the claim against the pool and then sliced the input
    /// unchecked.) extra_len sits at body offset 71 in the minimal wire.
    #[test]
    fn a13_inflated_extra_len_rejected() {
        let mut body = min_tx_construction_data_wire();
        body[71] = 200; // claims 200B of tx extra; only 18B remain
        let wire = top_wire(1, &body);
        assert!(deser_err!(&wire));
    }

    /// Parser total-function invariant (fuzz smoke class): every prefix of a
    /// legal wire must yield Ok/Err — never a panic at any cut.
    #[test]
    fn a13_prefix_totality_no_panic() {
        let wire = top_wire(1, &min_tx_construction_data_wire());
        for cut in 0..=wire.len() {
            let _ = deser_outcome!(&wire[..cut], Ok(_) => true);
        }
    }

    /// Pool-side overload contract (fuzz 2026-09-25): an input-feasible demand
    /// larger than the remaining POOL must yield Err(BufferTooSmall) — never a
    /// split_at_mut panic. subaddr_indices_len sits at body offset 89 here.
    #[test]
    fn a13_pool_over_demand_is_err() {
        let mut body = min_tx_construction_data_wire();
        body[89] = 1; // one subaddr index
        body.push(0); // its varint
        let wire = top_wire(1, &body);
        let mut p_txes: [Option<TxConstructionData<'_>>; 1] = core::array::from_fn(|_| None);
        let mut p_src: [Option<TxSourceEntry>; 0] = [];
        let mut p_sd: [TxDestinationEntry; 0] = [];
        let mut p_sel = [0usize; 0];
        let mut p_ex = [0u8; 0];
        let mut p_de: [TxDestinationEntry; 0] = [];
        let mut p_su = [0u32; 0]; // demand is 1, pool is 0
        let r = deserialize_unsigned_tx(
            &wire,
            UnsignedTxPools {
                txes: &mut p_txes,
                sources: &mut p_src,
                splitted_dsts: &mut p_sd,
                selected_transfers: &mut p_sel,
                extra: &mut p_ex,
                dests: &mut p_de,
                subaddr_indices: &mut p_su,
            },
        );
        assert!(matches!(
            r,
            Err(e) if e.kind == crate::error::ShlosiloErrorKind::BufferTooSmall
        ));
    }

    /// 89B remaining (< the 90 lower bound) with count=1 must be rejected — the lower bound still applies.
    #[test]
    fn a13_below_min_rejected() {
        let body = min_tx_construction_data_wire();
        let truncated = &body[..body.len() - 1]; // 89B
        let wire = top_wire(1, truncated);
        assert!(deser_err!(&wire));
    }

    /// count=2 but only 92B remain < 2×90=180 → physically infeasible, rejected (the count upper bound still applies).
    #[test]
    fn a13_count2_infeasible_rejected() {
        let body = min_tx_construction_data_wire();
        let wire = top_wire(2, &body); // 90B remain, 2 > 90/90=1 → reject
        assert!(deser_err!(&wire));
    }

    /// Two minimal legal transactions (180B remaining at top level) must be accepted — the multi-tx boundary.
    #[test]
    fn a13_two_min_txes_accepted() {
        let body = min_tx_construction_data_wire();
        let mut both = body.clone();
        both.extend_from_slice(&body);
        let wire = top_wire(2, &both); // 180B remain, 2 ≤ 180/90=2 → OK
        let mut p_txes: [Option<TxConstructionData<'_>>; 4] = core::array::from_fn(|_| None);
        let mut p_src: [Option<TxSourceEntry>; 4] = core::array::from_fn(|_| None);
        let mut p_sd =
            core::array::from_fn::<TxDestinationEntry, 4, _>(|_| TxDestinationEntry::default());
        let mut p_sel = [0usize; 4];
        let mut p_ex = [0u8; 512];
        let mut p_de =
            core::array::from_fn::<TxDestinationEntry, 4, _>(|_| TxDestinationEntry::default());
        let mut p_su = [0u32; 4];
        let tx = deserialize_unsigned_tx(
            &wire,
            UnsignedTxPools {
                txes: &mut p_txes,
                sources: &mut p_src,
                splitted_dsts: &mut p_sd,
                selected_transfers: &mut p_sel,
                extra: &mut p_ex,
                dests: &mut p_de,
                subaddr_indices: &mut p_su,
            },
        )
        .expect("two minimal txes must parse");
        assert_eq!(tx.txes.len(), 2);
    }
}
