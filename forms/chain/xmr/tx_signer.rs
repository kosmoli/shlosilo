//! P1-06 real signing path: unsigned_txset → signed tx
//!
//! Aligned with keystone transfer.rs::construct_tx + transfer_key.rs + monero wallet2 genRctSimple:
//! 1. tx_key = random scalar r; with a subaddress output, tx_pub = r·B_sub (keystone transaction_keys)
//! 2. per-output: ECDH → shared_key = Hs(8Ra || varint(o))；
//!    mask = Hs("commitment_mask" || shared_key); amount encryption = Hs("amount"||shared_key)[..8] XOR
//! 3. extra = txpub (+ r·B_sub if subaddress and no additional keys) + payment_id XOR(change)
//! 4. BP+ over output commitments（bp_version=4 → RCTTypeBulletproofPlus, wire type=6）
//! 5. pseudo_out_i: genRctSimple chain `a[i]=rng (i<last), a[last]=Σout_masks−Σprev`; single input = Σout_masks
//! 6. assemble prefix → msg_hash = keccak(prefix) → CLSAG → full tx

extern crate alloc;

use crate::chain::xmr::rct_sig::prove_bulletproofs_plus;
use alloc::vec::Vec;
use monero_ed25519::CompressedPoint;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Drop guard for the real mask working set — the single responsible party for zeroizing secrets.
/// The guard holds the Vec from creation until the function exits (normal return or any `?` path);
/// Drop erases it uniformly. Reads go only through the `get()` read-only borrow; there is no API that takes data away
/// (audit #6 re-review P1-01: into_inner used to unwrap before the CLSAG section, letting the last
/// error-path segment skip zeroization — eliminated per re-review recommendation).
struct ZeroizingMaskGuard {
    masks: Vec<[u8; 32]>,
    /// Audit #9 P2-01: owner identity tag — shadow records carry kind so tests can attribute precisely
    /// (closes the attribution gap where "the global latest slot cannot distinguish input_sk/real_mask")
    #[cfg(test)]
    kind: &'static str,
}
impl ZeroizingMaskGuard {
    #[allow(unused_variables)] // kind is used only by the cfg(test) shadow observer
    fn new(kind: &'static str) -> Self {
        Self {
            masks: Vec::new(),
            #[cfg(test)]
            kind,
        }
    }
    /// Take-over semantics: after copying into the owner, **immediately zero the caller's buffer** — audit #8 P1-01,
    /// eliminating the "second live copy caused by [u8;32] being Copy"
    fn push_take(&mut self, mask: &mut [u8; 32]) {
        self.masks.push(*mask);
        mask.zeroize();
    }
    /// Read-only borrow — data is never taken away; zeroization is fully handled by Drop
    /// (audit #6 re-review P1-01: into_inner would release protection before the last error-path segment)
    fn get(&self, idx: usize) -> Option<&[u8; 32]> {
        self.masks.get(idx)
    }
}
/// Audit #7 Gate2 #1: test shadow buffer — landing spot for the real backing copy after Drop zeroization.
/// Compiled only under test; the static lifetime lets "observe Drop effects after consuming the guard" be UB-free.
#[cfg(test)]
mod shadow {
    // Test env = host (std feature); introduce std locally per existing convention inside this no_std crate
    extern crate std;
    use std::sync::{Mutex, MutexGuard};
    pub struct ShadowRecord {
        pub kind: &'static str,
        pub masks: alloc::vec::Vec<[u8; 32]>,
    }
    pub static SHADOW_RECORDS: Mutex<alloc::vec::Vec<ShadowRecord>> =
        Mutex::new(alloc::vec::Vec::new());
    static SHADOW_TX_LOCK: Mutex<()> = Mutex::new(());

    /// Audit #12 P2-01 transaction isolation: begin = clear before the call + hold the transaction lock; the
    /// returned Invocation holds the lock until Drop (parallel tests serialize into their own transactions);
    /// take_last = consumed-once marker after the call (record removed; cannot be consumed twice).
    pub struct Invocation {
        _lock: MutexGuard<'static, ()>,
    }

    impl Invocation {
        /// Take (consumptively) the last record in this transaction matching kind.
        pub fn take_last(self, kind: &str) -> Option<ShadowRecord> {
            let mut v = SHADOW_RECORDS.lock().unwrap_or_else(|e| e.into_inner());
            let idx = v.iter().rposition(|r| r.kind == kind)?;
            Some(v.remove(idx))
            // the transaction lock is released when self drops
        }
    }

    pub fn begin_invocation() -> Invocation {
        let lock = SHADOW_TX_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        SHADOW_RECORDS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        Invocation { _lock: lock }
    }
}

/// Official genRctSimple pseudo-output mask chain:
/// `a[i] = random` (i < last), `a[last] = Σout_masks − Σ_{j<last} a[j]`.
/// Single input ⇒ last=0 ⇒ a[0] = Σout_masks, byte-for-byte identical to the existing `sum_outputs` semantics,
/// and consumes no extra rng (locks single-input determinism).
fn derive_pseudo_masks<R: RngCore>(
    n_in: usize,
    sum_out_masks: &crate::types::secret_scalar::SecretScalar,
    rng: &mut R,
) -> Result<ZeroizingMaskGuard> {
    if n_in == 0 {
        return Err(err());
    }
    let mut dest = ZeroizingMaskGuard::new("pseudo_mask");
    let mut sum_prev = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order([0u8; 32]);
    for i in 0..n_in {
        let mask = if i + 1 == n_in {
            sum_out_masks.sub_secret(&sum_prev)
        } else {
            let mut raw = zeroize::Zeroizing::new([0u8; 32]);
            rng.fill_bytes(raw.as_mut());
            let m = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(*raw);
            sum_prev = sum_prev.add_secret(&m);
            m
        };
        let mut bytes = mask.to_bytes();
        dest.push_take(&mut bytes);
    }
    sum_prev.zeroize_now();
    Ok(dest)
}

impl Drop for ZeroizingMaskGuard {
    fn drop(&mut self) {
        for m in self.masks.iter_mut() {
            m.zeroize();
        }
        // Audit #7 Gate2 #1: test visibility — copy the zeroized real backing into the static shadow;
        // tests consume records by kind within a transaction (begin_invocation holds the lock + clears first)
        // = observing the real Drop effect, no UB, no parallel clobbering (audit #12 P2-01)
        #[cfg(test)]
        {
            shadow::SHADOW_RECORDS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(shadow::ShadowRecord {
                    kind: self.kind,
                    masks: self.masks.clone(),
                });
        }
    }
}

use crate::chain::xmr::clsag::{self as clsag_mod};
use crate::chain::xmr::subaddress::hash_to_scalar;
use crate::chain::xmr::transaction::{
    bytes_to_monerod_scalar, monero_encode_varint, monerod_scalar_to_bytes, TransactionPrefix,
    TxExtra, TxInput, TxOutput,
};
use crate::chain::xmr::unsigned_txset::{TxConstructionData, TxDestinationEntry};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
#[cfg(feature = "tx-phase-timing-ffi")]
use crate::tx_phase_hook::PhaseProbe;

// monero-ed25519 Pedersen commitment (same type as tx_builder)
type MonCommitment = monero_ed25519::Commitment;

/// RingCT wire type: aligned with monero genRctSimple, bp_version∈{0,4} → BulletproofPlus(6),
/// 3 → CLSAG/Bulletproof(5). keystone construct_tx likewise uses prove_plus at bp4.
pub fn resolve_rct_type(bp_version: u64) -> Result<u8> {
    match bp_version {
        0 | 4 => Ok(6), // RCTTypeBulletproofPlus
        3 => Ok(5),     // RCTTypeCLSAG
        _ => Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)),
    }
}

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

#[cfg(test)]
fn bytes_to_scalar(bytes: &[u8; 32]) -> curve25519_dalek::scalar::Scalar {
    curve25519_dalek::scalar::Scalar::from_bytes_mod_order(*bytes)
}

/// per-output derivation (shared key + mask + encrypted amount) — keystone commitments_and_encrypted_amounts
///
/// Audit #9 P1-03: shared_key/commitment_mask are ECDH-derived secrets — fields use a SecretBytes
/// owner (ZeroizeOnDrop) directly, protected from the moment of creation (eliminating both the
/// pre-construction `?` and the Copy source-copy problem). encrypted_amount/stealth/view_tag/
/// additional_tx_key are on-chain-visible data, not secrets, and are not erased.
struct OutputDerivation {
    /// 8Ra = r·A_v·8 (or change: view_sec·tx_pub·8)
    /// Audit #9 P1-03: secret fields use a SecretBytes owner from creation (ZeroizeOnDrop;
    /// previously a plain [u8;32] Copy field copied at construction — pre-construction `?` and source copies were never erased)
    #[allow(dead_code)] // reserved for later P2 output verification
    shared_key: crate::types::SecretBytes<32>,
    commitment_mask: crate::types::SecretBytes<32>,
    encrypted_amount: [u8; 8],
    stealth_address: [u8; 32],
    /// On-chain-visible data (public point), not a secret — no owner needed (audit #9 recheck:
    /// erasing it in the hand-written Drop last round was over-erasure; restored to array type)
    additional_tx_key: Option<[u8; 32]>,
    view_tag: u8,
}

/// Derive the ECDH, shared_key and other derived values for a single output
///
/// Aligned with keystone transfer_key.rs::ecdhs + serai output_derivations:
/// - non-change, non-subaddress: ecdh = r · A_v(dest)
/// - non-change, subaddress: ecdh = r_i · A_v_sub (r_i is the additional key; shlosilo's single
///   additional-key mode = reuse of the main r; see the tx_builder resolve_tx_output comment)
/// - change (back to self): ecdh = view_sec · TxPub (receiver-side derivation, Keystone is_change_dest branch)
fn derive_output(
    r: &crate::types::secret_scalar::SecretScalar,
    _view_sec: &[u8; 32],
    dest: &TxDestinationEntry,
    _tx_pub: &[u8; 32],
    index: usize,
) -> Result<OutputDerivation> {
    // ecdh = r · A_v (both branches currently use the same formula; additional-key derivation scheduled for later)
    // Audit #10 P1-03: whitelisted point multiplication — r is never exposed as &Scalar; decompression/multiplication happen internally
    let ecdh_bytes = r.mul_point(&dest.view_public_key)?;
    let ecdh_point: curve25519_dalek::EdwardsPoint = CompressedPoint::from(ecdh_bytes)
        .decompress()
        .ok_or_else(err)?
        .into();

    // 8Ra = ecdh · cofactor(8), compressed then || varint(index)
    let eight_ra_pt = ecdh_point.mul_by_cofactor();
    let eight_ra = eight_ra_pt.compress().to_bytes();

    // Audit #8 P0-01: temporary buffers go into Zeroizing from creation (avoiding manual cleanup ordering
    // affecting protocol semantics — previously od_data was zeroized before its consumers, so stealth used
    // Hs(empty) and the output address was wrong; zeroize on a Vec = clear + erase capacity)
    let mut od_data = zeroize::Zeroizing::new(Vec::with_capacity(33));
    od_data.extend_from_slice(&eight_ra);
    monero_encode_varint(&mut od_data, index as u64);

    let shared_key = crate::types::SecretBytes::new(hash_to_scalar(&od_data)?);

    // mask = Hs("commitment_mask" || shared_key)
    let mut mask_data = zeroize::Zeroizing::new(Vec::with_capacity(16 + 32));
    mask_data.extend_from_slice(b"commitment_mask");
    mask_data.extend_from_slice(shared_key.expose());
    let commitment_mask = crate::types::SecretBytes::new(hash_to_scalar(&mask_data)?);

    // enc amount = amount XOR Hs("amount"||shared_key)[..8] (LE)
    let mut amt_data = zeroize::Zeroizing::new(Vec::with_capacity(6 + 32));
    amt_data.extend_from_slice(b"amount");
    amt_data.extend_from_slice(shared_key.expose());
    let amt_mask = zeroize::Zeroizing::new(crate::encoding::keccak256::hash(&amt_data)?);
    let mask8 = zeroize::Zeroizing::new(<[u8; 8]>::try_from(&amt_mask[..8]).unwrap());
    let xor_val = u64::from_le_bytes(*mask8);
    let encrypted_amount = (dest.amount ^ xor_val).to_le_bytes();

    // stealth = B_dest + Hs(8Ra||varint(idx))·G(monero one-time address)
    // Audit #8 P0-01: Hs(8Ra||o) = shared_key (same hash) — reuse it directly
    // Audit #11 P1-02: Hs(shared_key) goes into a SecretScalar owner (the previous version's
    // hs_z = hs_scalar only zeroized the Copy copy, and decompression `?` happened before zeroization — two gaps);
    // spend key decompression moved before any secret derivation; all `?`s are covered by the owner's Drop
    let b_dest: curve25519_dalek::EdwardsPoint = CompressedPoint::from(dest.spend_public_key)
        .decompress()
        .ok_or_else(err)?
        .into();
    let hs = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(*shared_key.expose());
    let stealth_address = hs.mul_basepoint_add_point(&b_dest);

    // view tag = keccak("view_tag" || 8Ra || varint(o))[0]
    let mut vt_data = zeroize::Zeroizing::new(Vec::with_capacity(9 + 33));
    vt_data.extend_from_slice(b"view_tag");
    vt_data.extend_from_slice(&eight_ra);
    monero_encode_varint(&mut vt_data, index as u64);
    let vtag_full = zeroize::Zeroizing::new(crate::encoding::keccak256::hash(&vt_data)?);
    let view_tag = vtag_full[0];

    // For subaddresses the additional key = r·B_sub (keystone should_use_additional_keys=false path:
    // tx_pub itself = r·B_sub. Here we follow the shlosilo tx_builder convention: the additional key records r·B_sub)
    let additional_tx_key = if dest.is_subaddress {
        // r·B_sub — dest.spend_public_key is exactly B_sub compressed bytes
        Some(r.mul_point(&dest.spend_public_key)?)
    } else {
        None
    };

    Ok(OutputDerivation {
        shared_key,
        commitment_mask,
        encrypted_amount,
        stealth_address,
        additional_tx_key,
        view_tag,
    })
}

/// payment_id_xor = keccak(8Ra || 0x8d)[..8]
fn payment_id_xor(ecdh_view_times_tx_pub: &[u8; 32]) -> [u8; 8] {
    let mut data = Vec::with_capacity(33);
    data.extend_from_slice(ecdh_view_times_tx_pub);
    data.push(0x8d);
    let h = crate::encoding::keccak256::hash(&data).unwrap_or([0u8; 32]);
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}

/// Construct and sign a full transaction from TxConstructionData (P1-06 core entry point)
///
/// **Input**:
/// - tx_data: parsed unsigned tx construction data (one tx)
/// - spend_sec / view_sec: derived wallet keys
/// - rng: randomness source (L3 injected; on device = TRNG)
///
/// **Output**: fully signed Transaction (wire format ready to use)
pub fn sign_tx_from_construction<R: RngCore + CryptoRng + Clone>(
    tx_data: &TxConstructionData,
    spend_sec: &[u8; 32],
    view_sec: &[u8; 32],
    rng: &mut R,
) -> Result<Vec<u8>> {
    // Convenience wrapper: r is generated randomly on the spot (use the _with_rngs variant when the §B.5 purpose subdomain is caller-determined).
    // With a single rng, consume in order: first 32B for r, the remaining stream for BP+/CLSAG (backwards compatible).
    // Audit #7 Gate1 #3: r is a Monero transaction secret key — Zeroizing along the whole path
    let mut r_bytes = zeroize::Zeroizing::new([0u8; 32]);
    rng.fill_bytes(r_bytes.as_mut());
    // Audit #8 P1-02: r is no longer materialized as a plain Copy Scalar — _with_rngs now takes a
    // Zeroizing byte owner, converted to a Scalar on demand at internal use sites (temporary, never lands)
    let mut rng2 = rng.clone();
    sign_tx_from_construction_with_rngs(tx_data, spend_sec, view_sec, &r_bytes, rng, &mut rng2)
}

/// Core signing (§B.5 decision): tx_key r is injected by the caller (purpose subdomain derivation),
/// bp_rng feeds Bulletproof+, clsag_rng feeds CLSAG (per-input subdomains split by the caller;
/// for v1 single input, pass a Clsag(0)-derived stream).
pub fn sign_tx_from_construction_with_rngs<B: RngCore + CryptoRng, C: RngCore + CryptoRng>(
    tx_data: &TxConstructionData,
    spend_sec: &[u8; 32],
    view_sec: &[u8; 32],
    r_bytes: &zeroize::Zeroizing<[u8; 32]>,
    bp_rng: &mut B,
    clsag_rng: &mut C,
) -> Result<Vec<u8>> {
    // Audit #9 P1-02: r is a transaction secret key — SecretScalar owner
    // (dalek Scalar is Copy with no Drop; plain bindings on `?` paths would never be zeroized);
    // consumption goes through with_scalar borrows; no plain Scalar bindings at the outer layer
    let r = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(**r_bytes);
    if tx_data.splitted_dsts.is_empty() || tx_data.sources.is_empty() {
        return Err(err());
    }
    let rct_type = resolve_rct_type(tx_data.rct_config.bp_version)?;

    // r is injected by the caller (§B.5: TxKey purpose subdomain derivation)
    // With a subaddress output and no additional keys: tx_pub = r·B_sub
    // (keystone transaction_keys has_payments_to_subaddresses branch)
    let has_subaddress_dest = tx_data.splitted_dsts.iter().any(|d| d.is_subaddress);
    let tx_pub_point = if has_subaddress_dest {
        // keystone uses the B of the first subaddress output
        let b_sub_bytes = tx_data
            .splitted_dsts
            .iter()
            .find(|d| d.is_subaddress)
            .map(|d| d.spend_public_key)
            .unwrap();
        // Whitelisted point multiplication takes compressed bytes directly — no decompression needed
        r.mul_point(&b_sub_bytes)?
    } else {
        r.mul_basepoint()
    };
    let tx_pub = tx_pub_point; // mul_point/mul_basepoint already return compressed bytes

    #[cfg(feature = "tx-phase-timing-ffi")]
    let mut px2 = PhaseProbe::start(2);
    // ---- 2. per-output derivation (keystone commitments_and_encrypted_amounts) ----
    // change_dts is "back to self" — ecdh = view_sec · TxPub (is_change_dest branch)
    // Audit #9 P1-02 + #10 P1-04: v_scalar derives from the long-term view secret — whitelisted point multiplication
    let change_ecdh_pt = {
        let v_scalar = crate::types::secret_scalar::SecretScalar::from_slice(view_sec);
        let pt_bytes = v_scalar.mul_point(&tx_pub_point)?;
        let decompressed: curve25519_dalek::EdwardsPoint = CompressedPoint::from(pt_bytes)
            .decompress()
            .ok_or_else(err)?
            .into();
        decompressed
    };
    let change_eight_ra = change_ecdh_pt.mul_by_cofactor().compress().to_bytes();

    let mut outs: Vec<OutInfo> = Vec::with_capacity(tx_data.splitted_dsts.len());

    for (i, dest) in tx_data.splitted_dsts.iter().enumerate() {
        let is_change = dest.amount == tx_data.change_dts.amount
            && dest.spend_public_key == tx_data.change_dts.spend_public_key;
        if is_change {
            // change uses the view_sec·TxPub path: manual derivation (derive_output's r·A_v does not apply)
            // Audit #8 P1-02: change-branch temporary buffers follow the same discipline as the main branch (Zeroizing owner)
            // Audit #11 P1-03: hashes go straight into the owner where produced (no more plain arrays landing)
            let shared_key = {
                let mut od = zeroize::Zeroizing::new(Vec::with_capacity(33));
                od.extend_from_slice(&change_eight_ra);
                monero_encode_varint(&mut od, i as u64);
                crate::types::SecretBytes::new(hash_to_scalar(&od)?)
            };
            let commitment_mask = {
                let mut md = zeroize::Zeroizing::new(Vec::with_capacity(48));
                md.extend_from_slice(b"commitment_mask");
                md.extend_from_slice(shared_key.expose());
                crate::types::SecretBytes::new(hash_to_scalar(&md)?)
            };
            let encrypted_amount = {
                let mut ad = zeroize::Zeroizing::new(Vec::with_capacity(38));
                ad.extend_from_slice(b"amount");
                ad.extend_from_slice(shared_key.expose());
                let h = crate::encoding::keccak256::hash(&ad)?;
                let m8 = u64::from_le_bytes(h[..8].try_into().unwrap());
                (dest.amount ^ m8).to_le_bytes()
            };
            // stealth (change also outputs a one-time address) — audit #11 P1-03:
            // hs goes into a SecretScalar owner; decompression moved earlier, all `?`s covered by the owner's Drop
            let b_dest: curve25519_dalek::EdwardsPoint =
                CompressedPoint::from(dest.spend_public_key)
                    .decompress()
                    .ok_or_else(err)?
                    .into();
            let hs = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(
                *shared_key.expose(),
            );
            let stealth_address = hs.mul_basepoint_add_point(&b_dest);
            // view tag
            let mut vt = zeroize::Zeroizing::new(Vec::with_capacity(42));
            vt.extend_from_slice(b"view_tag");
            vt.extend_from_slice(&change_eight_ra);
            monero_encode_varint(&mut vt, i as u64);
            let vt_full = crate::encoding::keccak256::hash(&vt)?;
            outs.push(OutInfo {
                deriv: OutputDerivation {
                    shared_key,
                    commitment_mask,
                    encrypted_amount,
                    stealth_address,
                    additional_tx_key: None,
                    view_tag: vt_full[0],
                },
                is_change: true,
                dest: dest.clone(),
                eight_ra_for_pid: Some(change_eight_ra),
            });
        } else {
            let deriv = derive_output(&r, view_sec, dest, &tx_pub, i)?;
            outs.push(OutInfo {
                deriv,
                is_change: false,
                dest: dest.clone(),
                eight_ra_for_pid: None,
            });
        }
    }

    // ---- 3. extra（txpub + additional keys + payment_id XOR(change)）----
    let mut extra = TxExtra::new().with_tx_pub_key(tx_pub);
    for o in &outs {
        if !o.is_change {
            if let Some(add) = o.deriv.additional_tx_key {
                extra = extra.with_additional_pub_key(add);
            }
        }
    }
    // splitted_dsts.len()==2 and has change → encrypted payment_id into extra (keystone extra())
    // In the fixture the change is the main address; its payment_id_xors come from the 8Ra of view_sec·TxPub XOR an all-zero pid
    if tx_data.splitted_dsts.len() == 2 {
        if let Some(o) = outs.iter().find(|o| o.is_change) {
            if let Some(e8ra) = o.eight_ra_for_pid {
                let xor = payment_id_xor(&e8ra);
                let zero_pid = [0u8; 8];
                let enc_pid = zero_pid
                    .iter()
                    .zip(xor.iter())
                    .map(|(a, b)| a ^ b)
                    .collect::<Vec<u8>>();
                let mut enc8 = [0u8; 8];
                enc8.copy_from_slice(&enc_pid);
                extra = extra.with_encrypted_payment_id(enc8);
            }
        }
    }

    // ---- 4. outputs ----
    let mut tx_outputs = Vec::with_capacity(outs.len());
    for o in &outs {
        tx_outputs.push(TxOutput::new_tagged(
            0, // in an RCT tx's wire/prefix, vout amounts are always 0 (real amounts live in ecdhInfo)
            o.deriv.stealth_address,
            o.deriv.view_tag,
        ));
    }

    // ---- 5. inputs: key_offsets(relative) + key images ----
    let mut tx_inputs = Vec::with_capacity(tx_data.sources.len());
    // Audit #6 re-review Gate1 #4: empty sources already rejected at function entry; n>=1 enters the secret
    // owner setup. Multi-input follows the genRctSimple chain; no hard rejection here anymore.
    let mut input_real_masks = ZeroizingMaskGuard::new("real_mask");
    let mut rings: Vec<Vec<(CompressedPoint, CompressedPoint)>> =
        Vec::with_capacity(tx_data.sources.len());
    // Audit #7 Gate1 #4: key_offset is a secret used to build the one-time spend key —
    // never lands in a Vec; input_sk is derived immediately inside the loop into a ZeroizingGuard (owner holds it to the end)
    let mut input_sks = ZeroizingMaskGuard::new("input_sk");
    for src in &tx_data.sources {
        // key offsets: absolute→relative (monero absolute_output_offsets_to_relative, ascending differences)
        let mut offs: Vec<u64> = src.outputs.iter().map(|o| o.index).collect();
        offs.sort_unstable();
        for i in (1..offs.len()).rev() {
            offs[i] -= offs[i - 1];
        }
        // Audit #9 P1-01: bind the tuple directly as mut — a `let mut x = x` shadow is a
        // Copy; the old (immutable) binding cannot be erased; declaring mut at the binding enables in-place zeroization
        let (key_image, mut key_offset) = crate::chain::xmr::subaddress::derive_input_from_source(
            view_sec,
            spend_sec,
            src,
            tx_data.subaddr_account,
            &tx_data.subaddr_indices,
        )?;
        tx_inputs.push(TxInput::new(offs.clone(), key_image));
        // key_offset is derived and consumed immediately (no intermediate Vec); zeroized in place after push_take
        let mut input_sk =
            crate::chain::xmr::subaddress::derive_input_spend_key(spend_sec, &key_offset)?;
        input_sks.push_take(&mut input_sk); // input_sk taken over in place into the owner
        key_offset.zeroize(); // in place (mut declared at the binding; no shadow Copy)
                              // P1-03 + audit #8 P1-01: mask written into a local buffer then taken over in place via push_take
                              // (after push the caller's buffer is zeroized immediately; no second live copy exists)
        let mut mask_copy = [0u8; 32];
        src.mask.write_into(&mut mask_copy);
        input_real_masks.push_take(&mut mask_copy); // TxSourceEntry.mask = the real output's true blinding factor
                                                    // (OutputEntry.mask is the on-chain C point; treating real_entry.mask as a blinding to recompute is wrong)
                                                    // ring members: (dest one-time address, on-chain commitment C point bytes).
                                                    // OutputEntry.mask = the on-chain outPk commitment (not a blinding factor), used directly as a point;
                                                    // monerod verify reads the same C from the chain — both sides' inputs must match byte for byte.
        let ring: Vec<(CompressedPoint, CompressedPoint)> = src
            .outputs
            .iter()
            .map(|o| (CompressedPoint::from(o.dest), CompressedPoint::from(o.mask)))
            .collect();
        rings.push(ring);
    }

    #[cfg(feature = "tx-phase-timing-ffi")]
    if let Some(p) = px2.as_mut() {
        p.end();
    }
    #[cfg(feature = "tx-phase-timing-ffi")]
    let mut px3 = PhaseProbe::start(3);
    // ---- 6. prefix hash (CLSAG message additionally needs rct base + BP elements; see step 8) ----
    let prefix = TransactionPrefix::new(0, tx_inputs.clone(), tx_outputs.clone(), extra.clone());
    // Serialize once and reuse these exact bytes for both the CLSAG message and
    // final wire. This invariant is consensus-critical: even a valid field
    // omitted only from the hash-side serializer makes the signature unverifiable.
    let prefix_bytes = prefix.serialize();
    let prefix_hash = crate::encoding::keccak256::hash(&prefix_bytes)?;

    // ---- 7. BP+ over output commitments ----
    // x8/x9/x10: rct_base drill-down sub-probes (bb3aa58 follow-up)
    #[cfg(feature = "tx-phase-timing-ffi")]
    let mut px8 = PhaseProbe::start(8);
    let commitments: Vec<MonCommitment> = outs
        .iter()
        .map(|o| {
            MonCommitment::new(
                bytes_to_monerod_scalar(o.deriv.commitment_mask.expose()),
                o.dest.amount,
            )
        })
        .collect();
    #[cfg(feature = "tx-phase-timing-ffi")]
    if let Some(p) = px8.as_mut() {
        p.end();
    }
    #[cfg(feature = "tx-phase-timing-ffi")]
    let mut px9 = PhaseProbe::start(9);
    // Audit #7 Gate1 #5: commitments are public on-chain data (Pedersen commitments are broadcast with the tx and contain
    // no mask plaintext); clone is not a secret-copy problem — but the value has no consumers after this, so move it to eliminate the copy
    let bp = prove_bulletproofs_plus(bp_rng, commitments)?;
    #[cfg(feature = "tx-phase-timing-ffi")]
    if let Some(p) = px9.as_mut() {
        p.end();
    }
    #[cfg(feature = "tx-phase-timing-ffi")]
    let mut px11 = PhaseProbe::start(11);
    // Σ out masks: curve25519_dalek scalar field arithmetic, then converted back to monero bytes
    // Audit #9 P1-02: sum of blinding masks — SecretScalar owner (zeroized by Drop on error paths;
    // m inside the loop is erased after use, never landing in a plain binding)
    let mut sum_out_masks =
        crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(monerod_scalar_to_bytes(
            &bytes_to_monerod_scalar(outs[0].deriv.commitment_mask.expose()),
        ));
    for o in &outs[1..] {
        // Audit #12 P1-01: summands are owners from creation (the old code bound m as a plain Scalar,
        // fed through add_assign(&Scalar) with cleanup relying solely on manual zeroize — early `?` returns
        // or future refactors would leak erasure; SecretScalar Drop covers the whole path)
        let m = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(
            monerod_scalar_to_bytes(&bytes_to_monerod_scalar(o.deriv.commitment_mask.expose())),
        );
        sum_out_masks.add_assign(&m);
    }

    // ---- 8. full_message = H(prefix_hash ‖ H(rct_base) ‖ H(BP+ fields)) ----
    // The official get_pre_mlsag_hash first concatenates and hashes BP+ fields A,A1,B,r1,s1,d1,L*,R*,
    // then does a final cn_fast_hash over the three 32B hashes; signature_write provides the field string without count.
    let rct_base_bytes = {
        let mut b = Vec::new();
        b.push(rct_type);
        monero_encode_varint(&mut b, compute_fee(tx_data));
        for o in &outs {
            b.extend_from_slice(&o.deriv.encrypted_amount);
        }
        for o in &outs {
            let c = MonCommitment::new(
                bytes_to_monerod_scalar(o.deriv.commitment_mask.expose()),
                o.dest.amount,
            );
            b.extend_from_slice(&c.commit().compress().to_bytes());
        }
        b
    };
    let rct_base_hash = crate::encoding::keccak256::hash(&rct_base_bytes)?;
    #[cfg(feature = "tx-phase-timing-ffi")]
    if let Some(p) = px11.as_mut() {
        p.end();
    }
    #[cfg(feature = "tx-phase-timing-ffi")]
    let mut px10 = PhaseProbe::start(10);
    let mut bp_sig_bytes = Vec::new();
    bp.signature_write(&mut bp_sig_bytes)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    // get_pre_mlsag_hash hashes the flattened BP+ fields first, then hashes
    // exactly three 32-byte keys: prefix hash, base hash, and BP+ fields hash.
    let bp_sig_hash = crate::encoding::keccak256::hash(&bp_sig_bytes)?;
    let mut full_msg_in = Vec::with_capacity(96);
    full_msg_in.extend_from_slice(&prefix_hash);
    full_msg_in.extend_from_slice(&rct_base_hash);
    full_msg_in.extend_from_slice(&bp_sig_hash);
    let msg_hash = crate::encoding::keccak256::hash(&full_msg_in)?;

    // Audit #6 re-review Gate1 #1: the guard is never unwrapped and holds the Vec until the function exits —
    // when any `?` in the CLSAG section (derive_input_spend_key / clsag sign) fails,
    // Drop still erases all masks (re-review evidence: 3 kinds of early returns after into_inner skipped zeroization)

    #[cfg(feature = "tx-phase-timing-ffi")]
    if let Some(p) = px10.as_mut() {
        p.end();
    }
    #[cfg(feature = "tx-phase-timing-ffi")]
    if let Some(p) = px3.as_mut() {
        p.end();
    }
    #[cfg(feature = "tx-phase-timing-ffi")]
    let mut px4 = PhaseProbe::start(4);
    // ---- 9. CLSAG per input: pseudo_mask follows the genRctSimple chain ----
    // Official: a[i]=skGen (i<last); a[last]=Σout_masks−Σprev_pseudo.
    // Single input ⇒ no rng consumed, a[0]=Σout_masks, consistent with the existing monero-clsag sum_outputs semantics.
    // Per input, clsag::sign is called with sum_outputs = that input's a[i] — with a single-element list
    // the library treats sum_outputs as the last mask, equivalent to using our precomputed a[i].
    let pseudo_masks = derive_pseudo_masks(tx_data.sources.len(), &sum_out_masks, clsag_rng)?;
    let mut clsag_wire: Vec<Vec<u8>> = Vec::with_capacity(tx_data.sources.len());
    let mut pseudo_outs_arr: Vec<[u8; 32]> = Vec::with_capacity(tx_data.sources.len());

    for (i, (src, ring)) in tx_data.sources.iter().zip(rings.iter()).enumerate() {
        // Audit #7 Gate1 #5: pseudo_mask is a blinding scalar — owner holds it to the end
        let pseudo_mask_bytes: &[u8; 32] = pseudo_masks.get(i).ok_or_else(err)?;
        // Gate1 #2: read-only borrow; no plain stack copies created
        let real_mask_bytes: &[u8; 32] = input_real_masks.get(i).ok_or_else(err)?;

        // CLSAG signing private key = one-time input sk (spend + key_offset) — already derived into the
        // ZeroizingMaskGuard in the collection loop; read-only borrow here (audit #7 Gate1 #4)
        let input_sk_bytes: &[u8; 32] = input_sks.get(i).ok_or_else(err)?;
        let (clsag_proof, _ki, pseudo_out_bytes) = clsag_mod::sign(
            input_sk_bytes,
            ring,
            src.real_output as u8,
            real_mask_bytes,
            src.amount,
            pseudo_mask_bytes,
            &msg_hash,
            clsag_rng,
        )?;
        // proof.bytes layout = pseudo_out(32) ‖ s[mixin+1] ‖ c1(32) ‖ D(32)
        let body: Vec<u8> = clsag_proof.wire_body().to_vec();
        debug_assert_eq!(clsag_proof.to_bytes().len(), 32 + rings[i].len() * 32 + 64);
        clsag_wire.push(body);
        pseudo_outs_arr.push(pseudo_out_bytes);
    }

    // Audit #6 re-review: the single responsible party for mask zeroization = ZeroizingMaskGuard::drop,
    // executed automatically on function exit (normal return or any `?` path); no manual cleanup points.

    // Audit #7 Gate1 #5 + #9 P1-02: sum_out_masks is the sum of output blindings —
    // no consumers after the CLSAG loop, zeroize explicitly; error paths covered by SecretScalar Drop
    // (dalek Scalar is itself Copy with no Drop — last round's comment was an incorrect safety claim)
    sum_out_masks.zeroize_now();

    #[cfg(feature = "tx-phase-timing-ffi")]
    if let Some(p) = px4.as_mut() {
        p.end();
    }
    #[cfg(feature = "tx-phase-timing-ffi")]
    let mut px5 = PhaseProbe::start(5);
    // ---- 10. official monerod wire serialization ----
    let bp_buf = {
        let mut b = Vec::new();
        bp.write(&mut b)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
        b
    };
    let wire = build_official_wire(
        &prefix_bytes,
        &rct_base_bytes,
        &bp_buf,
        &clsag_wire,
        &pseudo_outs_arr,
    );
    #[cfg(feature = "tx-phase-timing-ffi")]
    if let Some(p) = px5.as_mut() {
        p.end();
    }
    wire
}

/// fee = inputs − splitted outputs (change already included in splitted)
fn compute_fee(tx_data: &TxConstructionData) -> u64 {
    let input_sum: u64 = tx_data.sources.iter().map(|s| s.amount).sum();
    let out_sum: u64 = tx_data.splitted_dsts.iter().map(|d| d.amount).sum();
    input_sum.saturating_sub(out_sum)
}

struct OutInfo {
    deriv: OutputDerivation,
    is_change: bool,
    dest: TxDestinationEntry,
    eight_ra_for_pid: Option<[u8; 32]>,
}

/// Assemble the official monerod wire-format transaction (binary_archive layout reverse-confirmed by P1-06 oracle)
///
/// Layout: `prefix ‖ rct_base ‖ prunable`, no total-length prefix; ecdhInfo/outPk/CLSAGs/pseudoOuts
/// arrays are all **count-free** (binary_archive's no-arg `begin_array()` overload); vin has a variant
/// tag 0x02 and a VARINT amount; vout amount uses VARINT.
fn build_official_wire(
    prefix_bytes: &[u8],
    rct_base_bytes: &[u8],
    bp_buf: &[u8],
    clsag_wire: &[Vec<u8>],
    pseudo_outs: &[[u8; 32]],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(4096);
    // ---- prefix ----
    // These are the same bytes used above to compute prefix_hash.
    out.extend_from_slice(prefix_bytes);
    // ---- rct base ----
    // These are likewise the exact bytes hashed into rct_base_hash.
    out.extend_from_slice(rct_base_bytes);
    // ---- prunable ----
    // BP+: nbp(varint) + raw proof bytes
    monero_encode_varint(&mut out, 1); // single aggregated BP+
    out.extend_from_slice(bp_buf);
    // CLSAGs (no count; element count inferred from mixin+1): s[16]‖c1‖D
    for w in clsag_wire {
        out.extend_from_slice(w);
    }
    // pseudoOuts (no count)
    for po in pseudo_outs {
        out.extend_from_slice(po);
    }
    Ok(out)
}

#[cfg(test)]
mod guard_tests {
    use super::*;

    /// Drop zeroization observability: read guard.masks directly in the same module — all zeros after drop.
    /// (GPT re-review Gate1 #5: fault-injection anchors must test the owner's Drop path,
    /// not just the final error code)
    /// Audit #7 Gate2 #1: real Drop observation — after the guard's Drop zeroizes its own backing,
    /// the copy lands in the static shadow buffer SHADOW_POST_DROP; the guard is genuinely consumed via
    /// Box::into_raw + drop_in_place and the test reads the static shadow asserting all zeros (no UB: the shadow's
    /// lifetime is independent of the guard). Previous version's flaw (re-review P1-01): only ran a zeroize
    /// loop over a manual Vec, never triggering a real Drop.
    #[test]
    fn guard_drop_zeroizes_real_backing() {
        // Audit #8 P1-03 revision: an ordinary Box drop(g) consumes the guard — Drop does zeroize +
        // copy into the synchronized Mutex shadow; reading the shadow afterwards observes the real Drop effect, no UB,
        // no leaks, parallel-safe (passes Miri --test-threads=2). The old raw-pointer/deliberate-leak
        // struct approach was removed (failed Miri leak check).
        let invocation = shadow::begin_invocation();
        let g = {
            let mut g = ZeroizingMaskGuard::new("test");
            let mut a = [0xAAu8; 32];
            g.push_take(&mut a);
            let mut b = [0x55u8; 32];
            g.push_take(&mut b);
            g
        };
        drop(g); // real Drop: zeroize + Mutex shadow copy
        let shadow = invocation
            .take_last("test")
            .expect("shadow must be populated by guard Drop in this invocation");
        assert_eq!(
            shadow.masks.len(),
            2,
            "shadow must capture the dropped guard's masks"
        );
        assert!(
            shadow.masks.iter().all(|m| m.iter().all(|&b| b == 0)),
            "real guard Drop must zeroize its own backing"
        );
    }

    /// Audit #7 Gate1 #4: owner type invariants — not Clone/not Copy, needs_drop is true
    #[test]
    fn guard_owner_type_invariants() {
        assert!(core::mem::needs_drop::<ZeroizingMaskGuard>());
        static_assertions::assert_not_impl_any!(ZeroizingMaskGuard: Clone, Copy);
        // OutputDerivation is likewise a secret owner (contains shared_key/commitment_mask)
        assert!(core::mem::needs_drop::<OutputDerivation>());
        static_assertions::assert_not_impl_any!(OutputDerivation: Clone, Copy);
    }

    /// get() is a read-only borrow: returns a reference to the data without transferring ownership (the guard still holds it and still owns zeroization)
    #[test]
    fn guard_get_is_borrow_not_take() {
        let mut g = ZeroizingMaskGuard::new("test");
        let mut c = [0x42u8; 32];
        g.push_take(&mut c);
        {
            let borrowed = g.get(0).expect("idx 0 must exist");
            assert_eq!(borrowed[0], 0x42);
        }
        // the guard still holds the data (after get)
        assert_eq!(g.masks.len(), 1);
        assert_eq!(g.masks[0][0], 0x42);
    }

    /// genRctSimple: single input a[0] = Σout, and consumes no rng (locks existing determinism).
    #[test]
    fn pseudo_mask_chain_single_equals_sum_and_consumes_no_rng() {
        use rand_chacha::rand_core::{RngCore, SeedableRng};
        let mut sum_bytes = [0u8; 32];
        sum_bytes[0] = 7;
        let sum = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(sum_bytes);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x11u8; 32]);
        let mut rng_clone = rng.clone();
        let g = derive_pseudo_masks(1, &sum, &mut rng).expect("n=1");
        assert_eq!(g.get(0).expect("mask 0"), &sum.to_bytes());
        assert_eq!(g.masks.len(), 1);
        // no rng consumed: another fill should match a clone never touched by derive
        let mut a = [0u8; 8];
        let mut b = [0u8; 8];
        rng.fill_bytes(&mut a);
        rng_clone.fill_bytes(&mut b);
        assert_eq!(a, b, "n=1 must not consume clsag rng");
    }

    /// genRctSimple: n=2, a[0] comes from rng, a[1] = Σout − a[0], Σa = Σout.
    #[test]
    fn pseudo_mask_chain_two_last_equals_sum_minus_first() {
        use curve25519_dalek::Scalar;
        use rand_chacha::rand_core::{RngCore, SeedableRng};
        let mut sum_bytes = [0u8; 32];
        sum_bytes[0] = 9;
        let sum = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(sum_bytes);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x22u8; 32]);
        let mut rng_expect = rng.clone();
        let g = derive_pseudo_masks(2, &sum, &mut rng).expect("n=2");
        let mut raw = [0u8; 32];
        rng_expect.fill_bytes(&mut raw);
        let first = Scalar::from_bytes_mod_order(raw);
        let last = Scalar::from_bytes_mod_order(sum.to_bytes()) - first;
        assert_eq!(g.get(0).expect("mask 0"), &first.to_bytes());
        assert_eq!(g.get(1).expect("mask 1"), &last.to_bytes());
        let total = first + last;
        assert_eq!(total.to_bytes(), sum.to_bytes());
    }

    /// genRctSimple: any n, Σa[i] = Σout_masks (scalar form of the balance).
    #[test]
    fn pseudo_mask_chain_n3_sums_to_sum_out() {
        use curve25519_dalek::Scalar;
        use rand_chacha::rand_core::SeedableRng;
        let mut sum_bytes = [0u8; 32];
        sum_bytes[0] = 11;
        let sum = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(sum_bytes);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x33u8; 32]);
        let g = derive_pseudo_masks(3, &sum, &mut rng).expect("n=3");
        assert_eq!(g.masks.len(), 3);
        let mut acc = Scalar::ZERO;
        for i in 0..3 {
            acc += Scalar::from_bytes_mod_order(*g.get(i).expect("mask"));
        }
        assert_eq!(acc.to_bytes(), sum.to_bytes());
    }

    /// n=0 rejected (shape, before any secret owner is set up).
    #[test]
    fn pseudo_mask_chain_zero_inputs_rejected() {
        use rand_chacha::rand_core::SeedableRng;
        let sum = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order([1u8; 32]);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x44u8; 32]);
        assert!(derive_pseudo_masks(0, &sum, &mut rng).is_err());
    }

    /// Audit #11 P0-01 (second layer): a hostile destination view key ([0x02;32]
    /// undecompressible) through the public signer — must return Err, not panic (the re-review PoC
    /// observed a panic via catch_unwind; with panic=abort on device this is a full-device DoS).
    #[test]
    fn hostile_destination_point_returns_err_not_panic() {
        use crate::chain::xmr::unsigned_txset::{
            OutputEntry, RctConfig, TxDestinationEntry, TxSourceEntry,
        };
        use crate::types::SecretBytes;

        let test_seed = [0x42u8; 64];
        let path = crate::derivation::monero_reduce_scalar::MoneroPath::mainnet(0);
        let kp = crate::derivation::monero_reduce_scalar::derive(&test_seed, &path).unwrap();
        let spend_sec = crate::curve_primitive::ed25519::scalar_to_bytes(kp.spend_priv());
        let view_sec = crate::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv());

        let source = TxSourceEntry {
            outputs: alloc::vec![OutputEntry {
                index: 0,
                dest: [0x33u8; 32],
                mask: [0x33u8; 32],
            }],
            real_output: 0,
            real_out_tx_key: zeroize::Zeroizing::new([0; 32]),
            real_out_additional_tx_keys: zeroize::Zeroizing::new(alloc::vec![]),
            real_output_in_tx_index: 0,
            amount: 1000,
            rct: true,
            mask: SecretBytes::new([0x66u8; 32]),
            multisig_kLRki: crate::chain::xmr::unsigned_txset::MultisigKLRki {
                k: [0; 32],
                l: [0; 32],
                r: [0; 32],
                ki: [0; 32],
            },
        };
        // hostile destination: view_public_key = [0x02;32] (re-review PoC encoding)
        let dest = TxDestinationEntry {
            original: Vec::new(),
            amount: 900,
            spend_public_key: [0x02u8; 32],
            view_public_key: [0x02u8; 32],
            is_subaddress: false,
            is_integrated: false,
        };
        let tx_data = crate::chain::xmr::unsigned_txset::TxConstructionData {
            sources: alloc::vec![source],
            change_dts: dest.clone(),
            splitted_dsts: alloc::vec![dest],
            selected_transfers: alloc::vec![0],
            extra: alloc::vec![],
            unlock_time: 0,
            use_rct: 1,
            rct_config: RctConfig::default(),
            dests: alloc::vec![],
            subaddr_account: 0,
            subaddr_indices: alloc::vec![],
        };

        use rand_chacha::rand_core::SeedableRng;
        let rng = rand_chacha::ChaCha20Rng::from_seed([0x77u8; 32]);
        let mut bp_rng = rng.clone();
        let mut clsag_rng = rng.clone();
        let r_bytes = zeroize::Zeroizing::new([0x77u8; 32]);
        let result = sign_tx_from_construction_with_rngs(
            &tx_data,
            &spend_sec,
            &view_sec,
            &r_bytes,
            &mut bp_rng,
            &mut clsag_rng,
        );
        // hostile input → Err (no panic — this test surviving is the proof)
        let e = result.unwrap_err();
        assert_eq!(e.kind, ShlosiloErrorKind::EncodingInvalidFormat);
    }
}

#[cfg(test)]
fn test_wallet_keys() -> ([u8; 32], [u8; 32]) {
    let test_seed = [0x42u8; 64];
    let path = crate::derivation::monero_reduce_scalar::MoneroPath::mainnet(0);
    let kp = crate::derivation::monero_reduce_scalar::derive(&test_seed, &path).unwrap();
    (
        crate::curve_primitive::ed25519::scalar_to_bytes(kp.spend_priv()),
        crate::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv()),
    )
}

#[cfg(test)]
fn point_of(n: u64) -> [u8; 32] {
    (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &curve25519_dalek::Scalar::from(n))
        .compress()
        .to_bytes()
}

#[cfg(test)]
fn mask_of(b: u8) -> [u8; 32] {
    [b; 32]
}

#[cfg(test)]
fn test_dest(amount: u64, pt: [u8; 32], is_subaddress: bool) -> TxDestinationEntry {
    TxDestinationEntry {
        original: Vec::new(),
        amount,
        spend_public_key: pt,
        view_public_key: pt,
        is_subaddress,
        is_integrated: false,
    }
}

/// Build a source owned by this wallet: real dest = (spend+offset)·G, real C = Commit(mask, amount).
#[cfg(test)]
fn owned_source(
    spend_sec: &[u8; 32],
    view_sec: &[u8; 32],
    amount: u64,
    real_mask: [u8; 32],
    tx_pub: [u8; 32],
    decoy_k: u64,
) -> crate::chain::xmr::unsigned_txset::TxSourceEntry {
    use crate::chain::xmr::unsigned_txset::{OutputEntry, TxSourceEntry};
    use crate::types::SecretBytes;
    let key_offset =
        crate::chain::xmr::subaddress::calc_output_key_offset(view_sec, &tx_pub, 0, 0, 0).unwrap();
    let spend_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(*spend_sec);
    let offset_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(key_offset);
    let wallet_dest = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
        * &(spend_scalar + offset_scalar))
        .compress()
        .to_bytes();
    let c_real = MonCommitment::new(bytes_to_monerod_scalar(&real_mask), amount)
        .commit()
        .compress()
        .to_bytes();
    TxSourceEntry {
        outputs: alloc::vec![
            OutputEntry {
                index: 0,
                dest: wallet_dest,
                mask: c_real,
            },
            OutputEntry {
                index: 100,
                dest: point_of(decoy_k),
                mask: point_of(decoy_k + 10),
            },
        ],
        real_output: 0,
        real_out_tx_key: zeroize::Zeroizing::new(tx_pub),
        real_out_additional_tx_keys: zeroize::Zeroizing::new(alloc::vec![]),
        real_output_in_tx_index: 0,
        amount,
        rct: true,
        mask: SecretBytes::new(real_mask),
        multisig_kLRki: crate::chain::xmr::unsigned_txset::MultisigKLRki {
            k: [0; 32],
            l: [0; 32],
            r: [0; 32],
            ki: [0; 32],
        },
    }
}

/// Official verRctSemanticsSimple: ΣpseudoOuts = ΣoutPk + fee·H.
#[cfg(test)]
fn assert_rct_simple_balance(wire: &[u8], expect_fee: u64) {
    use crate::chain::xmr::transaction::monero_decode_varint;
    use curve25519_dalek::traits::Identity;
    let mut pos = 0;
    let prefix = TransactionPrefix::deserialize(wire, &mut pos).expect("prefix");
    let n_in = prefix.inputs.len();
    let n_out = prefix.outputs.len();
    assert!(n_in >= 1);
    assert!(n_out >= 1);
    pos += 1; // rct type
    let fee = monero_decode_varint(wire, &mut pos).expect("fee");
    assert_eq!(fee, expect_fee);
    pos += n_out * 8; // ecdhInfo
    let mut sum_out = curve25519_dalek::EdwardsPoint::identity();
    for _ in 0..n_out {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&wire[pos..pos + 32]);
        pos += 32;
        sum_out += curve25519_dalek::edwards::CompressedEdwardsY(pk)
            .decompress()
            .expect("outPk");
    }
    let fee_bytes = MonCommitment::new(bytes_to_monerod_scalar(&[0u8; 32]), fee)
        .commit()
        .compress()
        .to_bytes();
    sum_out += curve25519_dalek::edwards::CompressedEdwardsY(fee_bytes)
        .decompress()
        .expect("fee·H");
    let pseudo_start = wire.len() - n_in * 32;
    let mut sum_pseudo = curve25519_dalek::EdwardsPoint::identity();
    for i in 0..n_in {
        let off = pseudo_start + i * 32;
        let mut po = [0u8; 32];
        po.copy_from_slice(&wire[off..off + 32]);
        sum_pseudo += curve25519_dalek::edwards::CompressedEdwardsY(po)
            .decompress()
            .expect("pseudoOut");
    }
    assert_eq!(
        sum_pseudo.compress().to_bytes(),
        sum_out.compress().to_bytes(),
        "ΣpseudoOuts must equal ΣoutPk + fee·H"
    );
}

/// Audit #9 P2-03 reversal of the former "multi-input rejection": a real 2-input signer must succeed,
/// and ΣpseudoOuts = ΣoutPk + fee·H (official verRctSemanticsSimple).
/// TxConstructionData built by hand, no env dependency. Not placed in guard_tests: it contains a BP+ proof,
/// which the Miri `guard_` subset cannot finish.
#[test]
fn multi_input_signer_succeeds_and_balances() {
    let (spend_sec, view_sec) = test_wallet_keys();
    let dest_pt = point_of(1);
    let dest = test_dest(2500, dest_pt, false);
    let change = test_dest(400, dest_pt, false);
    let tx_data = crate::chain::xmr::unsigned_txset::TxConstructionData {
        sources: alloc::vec![
            owned_source(&spend_sec, &view_sec, 1000, mask_of(0x66), point_of(5), 2),
            owned_source(&spend_sec, &view_sec, 2000, mask_of(0x77), point_of(6), 3),
        ],
        change_dts: change.clone(),
        splitted_dsts: alloc::vec![change, dest],
        selected_transfers: alloc::vec![0, 1],
        extra: alloc::vec![],
        unlock_time: 0,
        use_rct: 1,
        rct_config: crate::chain::xmr::unsigned_txset::RctConfig::default(),
        dests: alloc::vec![],
        subaddr_account: 0,
        subaddr_indices: alloc::vec![],
    };

    use rand_chacha::rand_core::SeedableRng;
    let rng = rand_chacha::ChaCha20Rng::from_seed([0x77u8; 32]);
    let mut bp_rng = rng.clone();
    let mut clsag_rng = rng.clone();
    let r_bytes = zeroize::Zeroizing::new([0x77u8; 32]);
    let wire = sign_tx_from_construction_with_rngs(
        &tx_data,
        &spend_sec,
        &view_sec,
        &r_bytes,
        &mut bp_rng,
        &mut clsag_rng,
    )
    .expect("2-input signer must succeed");
    assert_rct_simple_balance(&wire, 100);
}

/// Audit #8 Gate0 #2: output derivation KAT — byte-exact formula lock-in without external keys,
/// as a normal test (previously XMR output correctness had no ordinary gate, so the P0-01 regression
/// went unnoticed). Vectors = snapshots of the implementation's protocol-formula derivation; real oracle
/// cross-validation is in p63 (ignored, needs env).
#[test]
fn output_derivation_kat() {
    // fixed inputs: r = 0x11.., dest view/spend = 0x22/0x33.., amount = 12345
    let r = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order([0x11u8; 32]);
    let dest = TxDestinationEntry {
        original: Vec::new(),
        amount: 12_345,
        spend_public_key: [0x33u8; 32],
        view_public_key: [0x22u8; 32],
        is_subaddress: false,
        is_integrated: false,
    };
    let d = derive_output(&r, &[0u8; 32], &dest, &[0u8; 32], 0).unwrap();

    // 8Ra point = 8·(r·A_v); independent recomputation (the KAT is the verifier — using dalek math directly)
    let a_v: curve25519_dalek::EdwardsPoint = CompressedPoint::from([0x22u8; 32])
        .decompress()
        .unwrap()
        .into();
    let r_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order([0x11u8; 32]);
    let eight_ra = (a_v * r_scalar).mul_by_cofactor().compress().to_bytes();
    // shared_key = Hs(8Ra || varint(0)) — varint(0) = [0]
    let mut expect_od = alloc::vec::Vec::new();
    expect_od.extend_from_slice(&eight_ra);
    expect_od.push(0);
    let expect_shared = hash_to_scalar(&expect_od).unwrap();
    assert_eq!(d.shared_key.expose(), &expect_shared);

    // stealth = B_dest + Hs(8Ra||0)·G — same hash as shared_key (P0-01 anchor)
    let hs_scalar = bytes_to_scalar(&expect_shared);
    let b_dest: curve25519_dalek::EdwardsPoint = CompressedPoint::from([0x33u8; 32])
        .decompress()
        .unwrap()
        .into();
    let expect_stealth = (b_dest
        + curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &hs_scalar)
        .compress()
        .to_bytes();
    assert_eq!(d.stealth_address, expect_stealth);

    // enc amount = amount XOR Hs("amount"||shared_key)[..8]
    let mut amt = alloc::vec::Vec::new();
    amt.extend_from_slice(b"amount");
    amt.extend_from_slice(&expect_shared);
    let h = crate::encoding::keccak256::hash(&amt).unwrap();
    let m8 = u64::from_le_bytes(h[..8].try_into().unwrap());
    assert_eq!(d.encrypted_amount, (12_345u64 ^ m8).to_le_bytes());

    // view_tag = keccak("view_tag"||8Ra||0)[0]
    let mut vt = alloc::vec::Vec::new();
    vt.extend_from_slice(b"view_tag");
    vt.extend_from_slice(&eight_ra);
    vt.push(0);
    assert_eq!(
        d.view_tag,
        crate::encoding::keccak256::hash(&vt).unwrap()[0]
    );
}

/// Audit #8 Gate2 P1-04: signer-level fault injection — reusing GPT plan 2:
/// construct a naturally reachable clsag failure point (decoy C point [0x99;32] is undecompressible; real_output=0
/// is legal for a two-element ring) so the real clsag_mod::sign fails stably after all owners (real mask/input
/// sk/rings) are set up; a static shadow proves the guard's Drop really zeroized on the error path
/// (the shadow holds the masks at Drop time).
/// Audit #12 P2-01: the shadow gains an invocation token — the test first calls begin_invocation()
/// to take a token, the guard Drop is stamped with the current token, and the test consumes records by token.
/// Parallel tests no longer clobber each other through a single slot (transaction isolation, beyond just removing data races).
#[test]
fn signer_clsag_failure_populates_then_drops_owner() {
    use crate::chain::xmr::unsigned_txset::{
        OutputEntry, RctConfig, TxDestinationEntry, TxSourceEntry,
    };
    use crate::types::SecretBytes;

    // the test's own wallet → derive_input_from_source succeeds
    let test_seed = [0x42u8; 64];
    let path = crate::derivation::monero_reduce_scalar::MoneroPath::mainnet(0);
    let kp = crate::derivation::monero_reduce_scalar::derive(&test_seed, &path).unwrap();
    let spend_sec = crate::curve_primitive::ed25519::scalar_to_bytes(kp.spend_priv());
    let view_sec = crate::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv());

    // valid curve point (decompressible): 1·G
    let pt =
        curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &curve25519_dalek::Scalar::from(1u8);
    let pt_bytes = pt.compress().to_bytes();
    // decoy C point: all 0x99, undecompressible — Edwards decompression must fail
    // → clsag sign errors at decoy decompression — all owners are set up by then
    let bad_c: [u8; 32] = [0x99u8; 32];
    // the real output dest must pass ownership validation: dest = (spend + offset)·G,
    // offset = calc_output_key_offset(view_sec, tx_pub, 0, 0, 0)
    let tx_pub_bytes: [u8; 32] = pt_bytes; // real_out_tx_key (a point; just needs to be decompressible)
    let key_offset =
        crate::chain::xmr::subaddress::calc_output_key_offset(&view_sec, &tx_pub_bytes, 0, 0, 0)
            .unwrap();
    let spend_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(spend_sec);
    let offset_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(key_offset);
    let wallet_dest = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
        * &(spend_scalar + offset_scalar))
        .compress()
        .to_bytes();
    let mk_output = move |i: u64, c: [u8; 32], d: [u8; 32]| OutputEntry {
        index: i * 100,
        dest: d,
        mask: c, // on-chain C point
    };

    let source = TxSourceEntry {
        outputs: alloc::vec![
            mk_output(0, pt_bytes, wallet_dest), // real: passes ownership validation
            mk_output(1, bad_c, pt_bytes),       // decoy: invalid C point → clsag fails
        ],
        real_output: 0, // real is legal (derive_input_from_source passes)
        real_out_tx_key: zeroize::Zeroizing::new(tx_pub_bytes),
        real_out_additional_tx_keys: zeroize::Zeroizing::new(alloc::vec![]),
        real_output_in_tx_index: 0,
        amount: 1000,
        rct: true,
        mask: SecretBytes::new([0x66u8; 32]), // real mask (will be set up by the guard)
        multisig_kLRki: crate::chain::xmr::unsigned_txset::MultisigKLRki {
            k: [0; 32],
            l: [0; 32],
            r: [0; 32],
            ki: [0; 32],
        },
    };
    let dest = TxDestinationEntry {
        original: Vec::new(),
        amount: 900,
        spend_public_key: pt_bytes,
        view_public_key: pt_bytes,
        is_subaddress: false,
        is_integrated: false,
    };
    // change uses different amount/keys — the is_change check won't misfire, outputs take the non-change
    // branch (on the same correct path before CLSAG as inputs/guard)
    let change_dest = TxDestinationEntry {
        original: Vec::new(),
        amount: 1,
        spend_public_key: [0x77u8; 32],
        view_public_key: [0x77u8; 32],
        is_subaddress: false,
        is_integrated: false,
    };
    let tx_data = crate::chain::xmr::unsigned_txset::TxConstructionData {
        sources: alloc::vec![source],
        change_dts: change_dest,
        splitted_dsts: alloc::vec![dest],
        selected_transfers: alloc::vec![0],
        extra: alloc::vec![],
        unlock_time: 0,
        use_rct: 1,
        rct_config: RctConfig::default(),
        dests: alloc::vec![],
        subaddr_account: 0,
        subaddr_indices: alloc::vec![],
    };

    use rand_chacha::rand_core::SeedableRng;
    let invocation = shadow::begin_invocation();
    let rng = rand_chacha::ChaCha20Rng::from_seed([0x77u8; 32]);
    let mut bp_rng = rng.clone();
    let mut clsag_rng = rng.clone();
    let r_bytes = zeroize::Zeroizing::new([0x77u8; 32]);
    let result = sign_tx_from_construction_with_rngs(
        &tx_data,
        &spend_sec,
        &view_sec,
        &r_bytes,
        &mut bp_rng,
        &mut clsag_rng,
    );
    // the failure must happen (fault point = decoy commitment decompression; real_output=0
    // is legal for a two-element ring); the key evidence is the shadow assertion below
    assert!(
        result.is_err(),
        "invalid decoy commitment must fail at clsag decompression"
    );

    // consumptive per-transaction record retrieval = this test's own guard Drop (audit #12 P2-01 transaction
    // isolation); kind attributes precisely — the owner closest to the failure point is the real_mask guard
    // (decoy C point undecompressible → clsag sign decompression failure)
    let inner = invocation
        .take_last("real_mask")
        .expect("guard Drop must have populated shadow in this invocation");
    assert_eq!(
        inner.kind, "real_mask",
        "shadow must attribute to the real-mask owner (P2-01)"
    );
    assert_eq!(
        inner.masks.len(),
        1,
        "guard must have held 1 real mask when clsag sign failed"
    );
    assert!(
        inner.masks[0].iter().all(|&b| b == 0),
        "error-path guard Drop must zeroize the real mask"
    );
}

/// Multi-input failure path: the second input's decoy C is undecompressible → Err, and the real_mask owner held 2 masks, all zeroized by Drop.
#[test]
fn multi_input_clsag_failure_drops_all_owners() {
    use crate::chain::xmr::unsigned_txset::{OutputEntry, RctConfig, TxSourceEntry};
    use crate::types::SecretBytes;

    let (spend_sec, view_sec) = test_wallet_keys();
    let dest_pt = point_of(1);
    let dest = test_dest(900, dest_pt, false);
    let good = owned_source(&spend_sec, &view_sec, 1000, mask_of(0x66), point_of(5), 2);

    // this test's transaction opens before any guard Drop (cleared before the call + lock held)
    let invocation = shadow::begin_invocation();

    let tx_pub = point_of(6);
    let key_offset =
        crate::chain::xmr::subaddress::calc_output_key_offset(&view_sec, &tx_pub, 0, 0, 0).unwrap();
    let spend_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(spend_sec);
    let offset_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(key_offset);
    let wallet_dest = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
        * &(spend_scalar + offset_scalar))
        .compress()
        .to_bytes();
    let c_real = MonCommitment::new(bytes_to_monerod_scalar(&mask_of(0x77)), 2000)
        .commit()
        .compress()
        .to_bytes();
    let bad = TxSourceEntry {
        outputs: alloc::vec![
            OutputEntry {
                index: 0,
                dest: wallet_dest,
                mask: c_real,
            },
            OutputEntry {
                index: 100,
                dest: point_of(3),
                mask: [0x99u8; 32], // undecompressible → clsag fails
            },
        ],
        real_output: 0,
        real_out_tx_key: zeroize::Zeroizing::new(tx_pub),
        real_out_additional_tx_keys: zeroize::Zeroizing::new(alloc::vec![]),
        real_output_in_tx_index: 0,
        amount: 2000,
        rct: true,
        mask: SecretBytes::new(mask_of(0x77)),
        multisig_kLRki: crate::chain::xmr::unsigned_txset::MultisigKLRki {
            k: [0; 32],
            l: [0; 32],
            r: [0; 32],
            ki: [0; 32],
        },
    };
    let tx_data = crate::chain::xmr::unsigned_txset::TxConstructionData {
        sources: alloc::vec![good, bad],
        change_dts: dest.clone(),
        splitted_dsts: alloc::vec![dest],
        selected_transfers: alloc::vec![0, 1],
        extra: alloc::vec![],
        unlock_time: 0,
        use_rct: 1,
        rct_config: RctConfig::default(),
        dests: alloc::vec![],
        subaddr_account: 0,
        subaddr_indices: alloc::vec![],
    };
    use rand_chacha::rand_core::SeedableRng;
    let rng = rand_chacha::ChaCha20Rng::from_seed([0x77u8; 32]);
    let mut bp_rng = rng.clone();
    let mut clsag_rng = rng.clone();
    let r_bytes = zeroize::Zeroizing::new([0x77u8; 32]);
    let result = sign_tx_from_construction_with_rngs(
        &tx_data,
        &spend_sec,
        &view_sec,
        &r_bytes,
        &mut bp_rng,
        &mut clsag_rng,
    );
    assert!(result.is_err(), "invalid decoy on input 1 must fail");
    let inner = invocation
        .take_last("real_mask")
        .expect("guard Drop must have populated shadow in this invocation");
    assert_eq!(inner.kind, "real_mask");
    assert_eq!(
        inner.masks.len(),
        2,
        "both real masks must be in the owner when clsag fails"
    );
    assert!(
        inner.masks.iter().all(|m| m.iter().all(|&b| b == 0)),
        "error-path Drop must zeroize all real masks"
    );
}

/// change-branch KAT: ecdh = view_sec · TxPub, stealth = B + Hs(8Ra||varint(i))·G.
#[test]
fn change_output_derivation_kat() {
    let (spend_sec, view_sec) = test_wallet_keys();
    let dest_pt = point_of(1);
    let change_pt = point_of(4);
    let dest = test_dest(900, dest_pt, false);
    let change = test_dest(100, change_pt, false);
    let tx_data = crate::chain::xmr::unsigned_txset::TxConstructionData {
        sources: alloc::vec![owned_source(
            &spend_sec,
            &view_sec,
            1100,
            mask_of(0x66),
            point_of(5),
            2
        )],
        change_dts: change.clone(),
        splitted_dsts: alloc::vec![change.clone(), dest],
        selected_transfers: alloc::vec![0],
        extra: alloc::vec![],
        unlock_time: 0,
        use_rct: 1,
        rct_config: crate::chain::xmr::unsigned_txset::RctConfig::default(),
        dests: alloc::vec![],
        subaddr_account: 0,
        subaddr_indices: alloc::vec![],
    };
    use rand_chacha::rand_core::SeedableRng;
    let rng = rand_chacha::ChaCha20Rng::from_seed([0x55u8; 32]);
    let mut bp_rng = rng.clone();
    let mut clsag_rng = rng.clone();
    let r_bytes = zeroize::Zeroizing::new([0x11u8; 32]);
    let wire = sign_tx_from_construction_with_rngs(
        &tx_data,
        &spend_sec,
        &view_sec,
        &r_bytes,
        &mut bp_rng,
        &mut clsag_rng,
    )
    .expect("1-input change path must succeed");
    let mut pos = 0;
    let prefix = TransactionPrefix::deserialize(&wire, &mut pos).expect("prefix");
    assert_eq!(prefix.outputs.len(), 2);

    // independently recompute change (index=0): 8Ra = 8·(view·tx_pub); tx_pub = r·G
    let r = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(*r_bytes);
    let tx_pub = r.mul_basepoint();
    let v = crate::types::secret_scalar::SecretScalar::from_slice(&view_sec);
    let ecdh = v.mul_point(&tx_pub).unwrap();
    let ecdh_pt: curve25519_dalek::EdwardsPoint =
        CompressedPoint::from(ecdh).decompress().unwrap().into();
    let eight_ra = ecdh_pt.mul_by_cofactor().compress().to_bytes();
    let mut od = alloc::vec::Vec::new();
    od.extend_from_slice(&eight_ra);
    od.push(0); // varint(0)
    let shared = hash_to_scalar(&od).unwrap();
    let hs = bytes_to_scalar(&shared);
    let b_change: curve25519_dalek::EdwardsPoint = CompressedPoint::from(change_pt)
        .decompress()
        .unwrap()
        .into();
    let expect_stealth = (b_change + curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &hs)
        .compress()
        .to_bytes();
    assert_eq!(
        prefix.outputs[0].stealth_address, expect_stealth,
        "change stealth must use view_sec·TxPub, not r·A_v"
    );
}

/// subaddress output KAT: additional_tx_key = r·B_sub.
#[test]
fn subaddress_output_derivation_kat() {
    let r = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order([0x11u8; 32]);
    let dest = TxDestinationEntry {
        original: Vec::new(),
        amount: 12_345,
        spend_public_key: [0x33u8; 32],
        view_public_key: [0x22u8; 32],
        is_subaddress: true,
        is_integrated: false,
    };
    let d = derive_output(&r, &[0u8; 32], &dest, &[0u8; 32], 0).unwrap();
    let expect_add = r.mul_point(&dest.spend_public_key).unwrap();
    assert_eq!(
        d.additional_tx_key
            .expect("subaddress must emit additional key"),
        expect_add
    );
    // the non-subaddress path emits no additional key (control, guarding against a tautological test)
    let dest_main = TxDestinationEntry {
        is_subaddress: false,
        ..dest
    };
    let d_main = derive_output(&r, &[0u8; 32], &dest_main, &[0u8; 32], 0).unwrap();
    assert!(d_main.additional_tx_key.is_none());
}
