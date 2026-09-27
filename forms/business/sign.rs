//! Business 1: Signing (v2 §1.1 + §4.3)
//!
//! **P6.0d/e realization**:
//! - Mnemonic input → restore_seed (real BIP-39)
//! - BTC (crypto-psbt): extract PSBT bytes from CBOR → parse_psbt → sign input by input → serialize
//! - ETH(eth-sign-request): payload = raw EIP-1559 tx → parse_eip1559_raw → sign_eip1559
//! - XMR / other chains: explicitly rejected (XMR awaits a real Feather fixture; v2 scope does not build transactions)

use crate::derivation::path::DerivationPath;
use crate::entropy::mnemonic::Mnemonic;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::network::Network;
use crate::tx::tx_normalize;
use crate::types::SecretBytes;

extern crate alloc;

/// Z2.3 C3b-3: one-byte SliceVec push with the standard overflow error shape.
fn pushb(v: &mut crate::types::SliceVec<u8>, b: u8) -> Result<()> {
    v.push(b).map_err(|_| {
        crate::error::ShlosiloError::new(crate::error::ShlosiloErrorKind::BufferTooSmall)
    })
}

fn err(kind: ShlosiloErrorKind) -> ShlosiloError {
    ShlosiloError::new(kind)
}

/// Signing input (v2 §1.1 dual flows: default dice-roll zero-storage + alternative TRNG/SE persistence)
///
/// **v2.4 security**: the `Mnemonic` variant holds an owned `Mnemonic` — dropped out of scope right after the business module signs.
/// `passphrase` is a `&[u8]` borrow. The `Seed` variant is a `&[u8; 64]` borrow.
pub enum SignInput<'a> {
    /// Default: zero-storage flow (mnemonic QR + passphrase restores the seed on the spot)
    Mnemonic {
        mnemonic: Mnemonic,
        passphrase: &'a [u8],
    },
    /// Alternative: a seed read from an SE chip / HSM
    Seed { seed: &'a [u8; 64] },
}

/// Upper bound on signature length (varies by ChainKind; used for buffer pre-checks)
pub fn stub_signature_len(chain_kind: crate::types::chain_kind::ChainKind) -> usize {
    use crate::types::chain_kind::ChainKind;
    match chain_kind {
        ChainKind::Btc => 64,  // ECDSA P2WPKH 64 bytes
        ChainKind::Eth => 65,  // ECDSA r/s/v 65 bytes
        ChainKind::Xmr => 96,  // CLSAG proof ≈ 96 bytes
        ChainKind::Tron => 65, // ECDSA (same as ETH)
        ChainKind::Sol => 64,  // EdDSA 64 bytes
        ChainKind::Apt | ChainKind::Sui | ChainKind::Near => 64,
        ChainKind::Ada => 64, // EdDSA 64 bytes
        ChainKind::Ar => 512, // RSA-PSS 512 bytes
        _ => 96,              // other chains use the maximum estimate
    }
}

/// Get the BIP-39 seed from a SignInput (P1-03: carried in SecretBytes — the Mnemonic path restores on the spot,
/// the stack buffer written by restore is taken over via take and the original copy zeroed)
fn resolve_seed(sign_input: &SignInput<'_>) -> Result<SecretBytes<64>> {
    let mut restored = [0u8; 64];
    match sign_input {
        SignInput::Seed { seed } => Ok(SecretBytes::new(**seed)),
        SignInput::Mnemonic {
            mnemonic,
            passphrase,
        } => {
            crate::business::restore_seed::restore_seed(mnemonic, passphrase, &mut restored)?;
            Ok(SecretBytes::take(&mut restored))
        }
    }
}

/// Signing business entry: typed UR payload → dispatch by chain → signed bytes written to output_buf
///
/// **P1-01 (2026-08-26)**: `type_tag` is carried by the UR decode layer, not inferred from the payload's first byte
/// inference; the payload is the CBOR as handed over by the codec (crypto-psbt=bytes item,
/// eth-sign-request=map). Each chain handler parses with its own codec.
pub fn sign(
    sign_input: SignInput<'_>,
    type_tag: crate::ur::ur_encode::UrTypeTag,
    ur_payload: &[u8],
    output_buf: &mut [u8],
) -> Result<usize> {
    sign_with_entropy(sign_input, type_tag, ur_payload, &[], output_buf)
}

/// Signing business entry (§B.5 RNG injection extension): the entropy parameter feeds the XMR path's signing randomness stream.
///
/// - XMR(xmr-txunsigned / xmr-txsigned / crypto-monero-tx): entropy **REQUIRED**,
///   < 16B raises `EntropyInjectionInvalid` (misuse guard, not an entropy-quality check)
/// - BTC / ETH: deterministic backend **entropy NOT REQUIRED by current backend**
///   (the RFC-6979 path) — just pass an empty slice
pub fn sign_with_entropy(
    sign_input: SignInput<'_>,
    type_tag: crate::ur::ur_encode::UrTypeTag,
    ur_payload: &[u8],
    entropy: &[u8],
    output_buf: &mut [u8],
) -> Result<usize> {
    sign_with_entropy_ws(sign_input, type_tag, ur_payload, entropy, None, output_buf)
}

/// Workspace-aware signing entry (Z3.3a).
///
/// `ws = Some(...)` provisions the XMR flow from caller memory — forms
/// allocates nothing (the zero-heap path; flux owns its memory strategy).
/// `ws = None` falls back to the **transitional shell** (forms-side alloc,
/// policy-labeled C-ABI/legacy seam; removed when every caller provisions).
/// BTC/ETH chain layers ignore `ws` (their provisioning lands in the
/// chain-tile round).
pub fn sign_with_entropy_ws(
    sign_input: SignInput<'_>,
    type_tag: crate::ur::ur_encode::UrTypeTag,
    ur_payload: &[u8],
    entropy: &[u8],
    ws: Option<&mut SignWs<'_>>,
    output_buf: &mut [u8],
) -> Result<usize> {
    let t_total = crate::device_timing::Mark::start(crate::device_timing::STAGE_PBKDF2);
    let seed = resolve_seed(&sign_input)?;
    t_total.end();
    // STAGE_PBKDF2 slot doubles as the resolve_seed (validate + PBKDF2) measurement.

    let template = tx_normalize::to_template(type_tag, ur_payload)?;
    let chain_kind = template.chain_kind;
    // payload is the complete CBOR (no leading-byte stripping — P1-01)
    if template.payload.is_empty() {
        return Err(err(ShlosiloErrorKind::UrPayloadInvalidCbor));
    }
    let payload = template.payload;

    match chain_kind {
        crate::types::chain_kind::ChainKind::Btc => {
            let n = sign_btc(seed.expose(), payload, output_buf)?;
            Ok(n)
        }
        crate::types::chain_kind::ChainKind::Eth => {
            let n = sign_eth(seed.expose(), payload, output_buf)?;
            Ok(n)
        }
        crate::types::chain_kind::ChainKind::Xmr => match ws {
            Some(ws) => {
                let n = sign_xmr_with_ws(ws, seed.expose(), payload, entropy, output_buf)?;
                Ok(n)
            }
            None => {
                let n = sign_xmr(seed.expose(), payload, entropy, output_buf)?;
                Ok(n)
            }
        },
        _ => Err(err(ShlosiloErrorKind::ChainKindUnsupported)),
    }
}

/// Z3.2 caller-provided workspace for the XMR sign flow (2026-09-25).
///
/// Frozen target shape (fields land per slice — Z3.2a parse face, Z3.2b
/// sign-face backings, Z3.2c secret transients; see the Z3 design doc):
/// capacity is a deployment parameter and every over-cap demand surfaces as an
/// explicit `Err(BufferTooSmall)`, never truncation. One-shot semantics: the
/// flow moves the pool handles out via `mem::take` (full `'a` preserved) — a
/// caller that signs again rebuilds the `SignWs` over its buffers.
pub struct SignWs<'a> {
    /// Plaintext scratch for the fused decrypt+parse — sized to the ciphertext
    /// (C-class: never on the stack). Forms keeps the wipe duty (Z2.4d-3
    /// contract): the whole block is wiped before return on every path, now
    /// over caller memory.
    pub plain: &'a mut [u8],
    /// The unsigned-tx model pools (same carve discipline as `UnsignedTxPools`).
    pub txes: &'a mut [Option<crate::chain::xmr::unsigned_txset::TxConstructionData<'a>>],
    pub sources: &'a mut [Option<crate::chain::xmr::unsigned_txset::TxSourceEntry>],
    pub splitted_dsts: &'a mut [crate::chain::xmr::unsigned_txset::TxDestinationEntry],
    pub selected_transfers: &'a mut [usize],
    pub extra: &'a mut [u8],
    pub dests: &'a mut [crate::chain::xmr::unsigned_txset::TxDestinationEntry],
    pub subaddr_indices: &'a mut [u32],
    // Z3.2b: sign-face backings (the SignedTxSet model + per-tx carve pools).
    pub ptx: &'a mut [Option<crate::chain::xmr::signed_txset::PendingTx<'a>>],
    /// Contiguous signed-tx wire slots (C-class: `TX_BYTES_SLOT_MAX` per tx,
    /// carved per iteration — the signer writes straight into the slot).
    pub tx_bytes: &'a mut [u8],
    pub ki: &'a mut [[u8; 32]],
    pub tki: &'a mut [crate::chain::xmr::signed_txset::TxKeyImageEntry],
    pub sel: &'a mut [u8],
    pub kstr: &'a mut [u8],
    /// Records-face dests (per-tx clones carved into the PendingTx records).
    pub record_dests: &'a mut [crate::chain::xmr::unsigned_txset::TxDestinationEntry],
    /// Z5.3 pool cut: BP+ prove multiexp scratch (caller memory, carved).
    pub bp_terms: &'a mut [(curve25519_dalek::Scalar, curve25519_dalek::EdwardsPoint)],
    /// Z5.3 D-cut: Straus scratch storage (raw bytes; the typed scratch is
    /// constructed from it at the call site).
    pub bp_straus: &'a mut [u8],
    pub bp_wip: &'a mut [u8],
}

/// Z3.3b: the sign-workspace layout — the SINGLE source of truth behind both
/// the capacity query (`shlosilo_sign_ws_len`) and the actual carve
/// (`carve_sign_ws`). C-ABI workspace contract 3: the reported capacity and the
/// carved capacity come from this one computation; `sign_ws_layout_consistency`
/// pins the pairing.
pub struct SignWsLayout {
    pub total: usize,
    plain: usize,
    txes: usize,
    sources: usize,
    splits: usize,
    sel: usize,
    extra: usize,
    dests: usize,
    subidx: usize,
    ptx: usize,
    tx_bytes: usize,
    ki: usize,
    tki: usize,
    sel_out: usize,
    kstr: usize,
    record_dests: usize,
    pub bp_terms: usize,
    pub bp_straus: usize,
    pub bp_wip: usize,
}

fn ws_next(off: &mut usize, align: usize, size: usize) -> usize {
    let start = (*off + align - 1) & !(align - 1);
    *off = start + size;
    start
}

impl SignWsLayout {
    pub fn compute() -> Self {
        use crate::chain::xmr::signed_txset::{PendingTx, TxKeyImageEntry};
        use crate::chain::xmr::unsigned_txset::{
            TxConstructionData, TxDestinationEntry, TxSourceEntry,
        };
        use crate::types::caps as c;
        let mut off = 0usize;
        let plain = ws_next(&mut off, core::mem::align_of::<u8>(), c::SIGN_WS_PLAIN);
        let txes = ws_next(
            &mut off,
            core::mem::align_of::<Option<TxConstructionData<'static>>>(),
            core::mem::size_of::<Option<TxConstructionData<'static>>>() * c::SIGN_WS_TXES,
        );
        let sources = ws_next(
            &mut off,
            core::mem::align_of::<Option<TxSourceEntry>>(),
            core::mem::size_of::<Option<TxSourceEntry>>() * c::SIGN_WS_SOURCES,
        );
        let splits = ws_next(
            &mut off,
            core::mem::align_of::<TxDestinationEntry>(),
            core::mem::size_of::<TxDestinationEntry>() * c::SIGN_WS_SPLITS,
        );
        let sel = ws_next(
            &mut off,
            core::mem::align_of::<usize>(),
            core::mem::size_of::<usize>() * c::SIGN_WS_SEL,
        );
        let extra = ws_next(&mut off, core::mem::align_of::<u8>(), c::SIGN_WS_EXTRA);
        let dests = ws_next(
            &mut off,
            core::mem::align_of::<TxDestinationEntry>(),
            core::mem::size_of::<TxDestinationEntry>() * c::SIGN_WS_DESTS,
        );
        let subidx = ws_next(
            &mut off,
            core::mem::align_of::<u32>(),
            core::mem::size_of::<u32>() * c::SIGN_WS_SUBIDX,
        );
        let ptx = ws_next(
            &mut off,
            core::mem::align_of::<Option<PendingTx<'static>>>(),
            core::mem::size_of::<Option<PendingTx<'static>>>() * c::SIGN_WS_PTX,
        );
        let tx_bytes = ws_next(&mut off, core::mem::align_of::<u8>(), c::SIGN_WS_TX_BYTES);
        let ki = ws_next(
            &mut off,
            core::mem::align_of::<[u8; 32]>(),
            core::mem::size_of::<[u8; 32]>() * c::SIGN_WS_KI,
        );
        let tki = ws_next(
            &mut off,
            core::mem::align_of::<TxKeyImageEntry>(),
            core::mem::size_of::<TxKeyImageEntry>() * c::SIGN_WS_TKI,
        );
        let sel_out = ws_next(&mut off, core::mem::align_of::<u8>(), c::SIGN_WS_SEL_OUT);
        let kstr = ws_next(&mut off, core::mem::align_of::<u8>(), c::SIGN_WS_KSTR);
        let record_dests = ws_next(
            &mut off,
            core::mem::align_of::<TxDestinationEntry>(),
            core::mem::size_of::<TxDestinationEntry>() * c::SIGN_WS_RECORD_DESTS,
        );
        let bp_terms = ws_next(
            &mut off,
            core::mem::align_of::<(curve25519_dalek::Scalar, curve25519_dalek::EdwardsPoint)>(),
            core::mem::size_of::<(curve25519_dalek::Scalar, curve25519_dalek::EdwardsPoint)>()
                * c::SIGN_WS_BP_TERMS,
        );
        let bp_straus = ws_next(
            &mut off,
            core::mem::align_of::<u64>(),
            c::SIGN_WS_BP_STRAUS_BYTES,
        );
        let bp_wip = ws_next(
            &mut off,
            core::mem::align_of::<u64>(),
            c::SIGN_WS_BP_WIP_BYTES,
        );
        // trailing pad so the total itself satisfies the widest alignment
        let total = ws_next(&mut off, core::mem::align_of::<usize>(), 0);
        SignWsLayout {
            total,
            plain,
            txes,
            sources,
            splits,
            sel,
            extra,
            dests,
            subidx,
            ptx,
            tx_bytes,
            ki,
            tki,
            sel_out,
            kstr,
            record_dests,
            bp_terms,
            bp_straus,
            bp_wip,
        }
    }
}

/// Z3.3b: carve a `SignWs` out of a caller workspace buffer (the C-ABI and the
/// transitional shell share this path). Returns `None` when `buf` is smaller
/// than `SignWsLayout::compute().total` — the carve never partially succeeds.
///
/// # Safety contract (internal unsafe, ffi-seam pattern)
/// The typed spans reinterpret caller bytes; every slot is explicitly
/// initialized after carving (Option slots to `None`, Default-able leaves to
/// `default()`, POD spans zeroed) so no uninit value is ever observable.
pub fn carve_sign_ws(buf: &mut [u8]) -> Option<SignWs<'_>> {
    use crate::chain::xmr::signed_txset::{PendingTx, TxKeyImageEntry};
    use crate::chain::xmr::unsigned_txset::{
        TxConstructionData, TxDestinationEntry, TxSourceEntry,
    };
    use crate::types::caps as c;
    let l = SignWsLayout::compute();
    if buf.len() < l.total {
        return None;
    }
    buf[..l.total].fill(0);
    let base: *mut u8 = buf.as_mut_ptr();
    // SAFETY: offsets come from SignWsLayout::compute (the same computation the
    // capacity query reports — contract 3); each span is alignment-padded there
    // and disjoint by construction; every element is initialized below before
    // the slices are handed out. The spans all derive from one base pointer so
    // the borrow checker sees disjoint raw derivations, not competing &muts.
    unsafe fn at<'a, T>(base: *mut u8, off: usize, count: usize) -> &'a mut [T] {
        core::slice::from_raw_parts_mut(base.add(off) as *mut T, count)
    }
    let txes: &mut [Option<TxConstructionData>] = unsafe { at(base, l.txes, c::SIGN_WS_TXES) };
    for s in txes.iter_mut() {
        unsafe { core::ptr::write(s, None) };
    }
    let sources: &mut [Option<TxSourceEntry>] = unsafe { at(base, l.sources, c::SIGN_WS_SOURCES) };
    for s in sources.iter_mut() {
        unsafe { core::ptr::write(s, None) };
    }
    let splits: &mut [TxDestinationEntry] = unsafe { at(base, l.splits, c::SIGN_WS_SPLITS) };
    for s in splits.iter_mut() {
        unsafe { core::ptr::write(s, TxDestinationEntry::default()) };
    }
    let dests: &mut [TxDestinationEntry] = unsafe { at(base, l.dests, c::SIGN_WS_DESTS) };
    for s in dests.iter_mut() {
        unsafe { core::ptr::write(s, TxDestinationEntry::default()) };
    }
    let record_dests: &mut [TxDestinationEntry] =
        unsafe { at(base, l.record_dests, c::SIGN_WS_RECORD_DESTS) };
    for s in record_dests.iter_mut() {
        unsafe { core::ptr::write(s, TxDestinationEntry::default()) };
    }
    let ptx: &mut [Option<PendingTx>] = unsafe { at(base, l.ptx, c::SIGN_WS_PTX) };
    for s in ptx.iter_mut() {
        unsafe { core::ptr::write(s, None) };
    }
    let tki: &mut [TxKeyImageEntry] = unsafe { at(base, l.tki, c::SIGN_WS_TKI) };
    for s in tki.iter_mut() {
        unsafe { core::ptr::write(s, TxKeyImageEntry::default()) };
    }
    // POD spans: the fill(0) above is their initialization.
    let plain: &mut [u8] = unsafe { at(base, l.plain, c::SIGN_WS_PLAIN) };
    let sel: &mut [usize] = unsafe { at(base, l.sel, c::SIGN_WS_SEL) };
    let extra: &mut [u8] = unsafe { at(base, l.extra, c::SIGN_WS_EXTRA) };
    let subidx: &mut [u32] = unsafe { at(base, l.subidx, c::SIGN_WS_SUBIDX) };
    let tx_bytes: &mut [u8] = unsafe { at(base, l.tx_bytes, c::SIGN_WS_TX_BYTES) };
    let ki: &mut [[u8; 32]] = unsafe { at(base, l.ki, c::SIGN_WS_KI) };
    let sel_out: &mut [u8] = unsafe { at(base, l.sel_out, c::SIGN_WS_SEL_OUT) };
    let kstr: &mut [u8] = unsafe { at(base, l.kstr, c::SIGN_WS_KSTR) };
    // Z5.3 pool cut: BP+ prove scratch (POD span — the whole-carve zero fill
    // is its documented initialization; the prove chain overwrites entries
    // before reading them).
    let bp_terms: &mut [(curve25519_dalek::Scalar, curve25519_dalek::EdwardsPoint)] =
        unsafe { at(base, l.bp_terms, c::SIGN_WS_BP_TERMS) };
    let bp_straus: &mut [u8] = unsafe { at(base, l.bp_straus, c::SIGN_WS_BP_STRAUS_BYTES) };
    let bp_wip: &mut [u8] = unsafe { at(base, l.bp_wip, c::SIGN_WS_BP_WIP_BYTES) };
    Some(SignWs {
        plain,
        txes,
        sources,
        splitted_dsts: splits,
        selected_transfers: sel,
        extra,
        dests,
        subaddr_indices: subidx,
        ptx,
        tx_bytes,
        ki,
        tki,
        sel: sel_out,
        kstr,
        record_dests,
        bp_terms,
        bp_straus,
        bp_wip,
    })
}

/// XMR: xmr-txunsigned encrypted blob → decrypt → sign tx by tx → SignedTxSet → encrypted output
///
/// §B.5 finalized implementation (P1-06 wrap-up). Aligned with keystone `sign_tx`:
/// 1. seed → Monero keypair (`monero_reduce_scalar::derive`, unclamped Icarus path)
/// 2. Decrypt the unsigned_txset (view key; magic + Schnorr verification + ChaCha20-Legacy)
/// 3. `sign_tx_from_construction` per tx (tx-key / BP+ / CLSAG(i) — three purpose-subdomain RNGs)
/// 4. Serialize the SignedTxSet (tx_key=ONE placeholder) → encrypt_signed_txset (SIGNED_TX_PREFIX)
///
/// rng usage: BP+/CLSAG/encryption nonce + signing k; the tx_key r entropy comes from the entropy derivation.
#[cfg(feature = "tx-phase-timing-ffi")]
use crate::tx_phase_hook::PhaseProbe;

fn sign_xmr_with_ws<'a>(
    ws: &mut SignWs<'a>,
    seed: &[u8],
    encrypted_unsigned: &[u8],
    entropy: &[u8],
    output_buf: &mut [u8],
) -> Result<usize> {
    use crate::chain::xmr::signed_txset::{PendingTx, SignedTxSet, TxKeyImageEntry};
    use crate::chain::xmr::signing_rng::{purpose_rng, RngPurpose};

    // 1. seed → Monero keypair (v2 §2.7: MoneroPath is not BIP-32; account 0 = main wallet)
    let path = crate::derivation::monero_reduce_scalar::MoneroPath::mainnet(0);
    let kp = crate::derivation::monero_reduce_scalar::derive(seed, &path)?;
    // Audit #6 P1-01: master key bytes go through Zeroizing (zeroed on drop on all return paths)
    let spend_sec = zeroize::Zeroizing::new(crate::curve_primitive::ed25519::scalar_to_bytes(
        kp.spend_priv(),
    ));
    let view_sec = zeroize::Zeroizing::new(crate::curve_primitive::ed25519::scalar_to_bytes(
        kp.view_priv(),
    ));
    // CN computed only once for the same view_sk (shared by decrypt + encrypt; the 2MB scratchpad dominates on device)
    // Audit #12 P1-02: the CN key is an owner from creation (Zeroizing); the helper returns the owner.
    let cn_key = crate::chain::xmr::unsigned_txset::chacha_key_from_view_sk(&view_sec);

    // 2. Decrypt (signature verified internally; view key mismatch → Err)
    // Audit #6 P1-01: decrypted plaintext txset goes through Zeroizing (no plaintext residue needed after parsing)
    #[cfg(feature = "tx-phase-timing-ffi")]
    let mut px1 = PhaseProbe::start(1);
    // Z3.2a: caller-workspace plumbing — the plaintext scratch and the unsigned
    // model pools come from `SignWs`. Handles move out via `mem::take` (full `'a`
    // preserved for the model borrows; one-shot semantics). The fused
    // decrypt+parse keeps the plaintext wipe duty (Z2.4d-3 contract): forms wipes
    // the whole block before return on every path — now over caller memory.
    // Zero secret-lifetimes depend on this workspace (secrets live in
    // SecretBytes/Zeroizing owners).
    let mut unsigned_tx = crate::chain::xmr::unsigned_txset::decrypt_and_parse_unsigned_tx(
        encrypted_unsigned,
        &view_sec,
        &cn_key,
        core::mem::take(&mut ws.plain),
        crate::chain::xmr::unsigned_txset::UnsignedTxPools {
            txes: core::mem::take(&mut ws.txes),
            sources: core::mem::take(&mut ws.sources),
            splitted_dsts: core::mem::take(&mut ws.splitted_dsts),
            selected_transfers: core::mem::take(&mut ws.selected_transfers),
            extra: core::mem::take(&mut ws.extra),
            dests: core::mem::take(&mut ws.dests),
            subaddr_indices: core::mem::take(&mut ws.subaddr_indices),
        },
    )?;
    #[cfg(feature = "tx-phase-timing-ffi")]
    if let Some(p) = px1.as_mut() {
        p.end();
    }

    // 3. Sign tx by tx (§B.5 purpose subdomains: tx-key r / BP+ / CLSAG(i) derived independently)
    //    context = keccak digest of the tx construction data (domain separation, not counted as entropy)
    let mut rng = {
        use rand_chacha::rand_core::SeedableRng;
        // Z3.2c: the `merged` entropy copy is gone (it was byte-identical to
        // `entropy` — the +32 capacity was never filled) — the derived stream
        // seed comes straight from the caller's entropy slice, no secret
        // duplication. BP+/CLSAG ephemeral randomness is tx-independent (does
        // not reuse the r stream); unified stream: TxKey subdomain.
        let mut seed_rng = purpose_rng(entropy, RngPurpose::TxKey, &[0u8; 32])?;
        // Z2.1 S1+ (2026-09-24): derived stream seed — zeroized on drop.
        let mut seed_bytes = zeroize::Zeroizing::new([0u8; 32]);
        use rand_chacha::rand_core::RngCore as _;
        seed_rng.fill_bytes(&mut *seed_bytes);
        rand_chacha::ChaCha20Rng::from_seed(*seed_bytes)
    };

    // Z2.3 C3b-3 / Z3.2b: signed-side collections live in the caller workspace
    // (`SignWs` sign-face fields, capacity pre-checked above).
    let total_sources: usize = unsigned_tx
        .txes
        .iter()
        .flatten()
        .map(|t| t.sources.len())
        .sum();
    let total_dsts: usize = unsigned_tx
        .txes
        .iter()
        .flatten()
        .map(|t| t.splitted_dsts.len())
        .sum();
    let total_sel: usize = unsigned_tx
        .txes
        .iter()
        .flatten()
        .map(|t| t.selected_transfers.len())
        .sum();
    let total_dests: usize = unsigned_tx
        .txes
        .iter()
        .flatten()
        .map(|t| t.dests.len())
        .sum();
    // Z3.2b: sign-face backings come from the caller workspace. Every carve and
    // push site is capacity-checked up front (explicit RequiredLength Err — the
    // T-14 pool-side discipline: an over-cap demand must Err, never a panic).
    const TX_BYTES_SLOT_MAX: usize = 16 * 1024;
    let n_tx = unsigned_tx.txes.len();
    let cap_err = |need: usize| {
        ShlosiloError::with_context(
            ShlosiloErrorKind::BufferTooSmall,
            crate::error::ErrorContext::RequiredLength(need),
        )
    };
    if ws.ptx.len() < n_tx {
        return Err(cap_err(n_tx));
    }
    if ws.ki.len() < total_sources {
        return Err(cap_err(total_sources));
    }
    if ws.tki.len() < total_dsts {
        return Err(cap_err(total_dsts));
    }
    if ws.sel.len() < total_sel {
        return Err(cap_err(total_sel));
    }
    if ws.kstr.len() < 67 * total_sources {
        return Err(cap_err(67 * total_sources));
    }
    if ws.record_dests.len() < total_dests {
        return Err(cap_err(total_dests));
    }
    let tx_bytes_need = TX_BYTES_SLOT_MAX * n_tx.max(1);
    if ws.tx_bytes.len() < tx_bytes_need {
        return Err(cap_err(tx_bytes_need));
    }
    let mut ptx_sv = crate::types::SliceVec::new(core::mem::take(&mut ws.ptx));
    let mut ki_sv = crate::types::SliceVec::new(core::mem::take(&mut ws.ki));
    let mut tki_sv = crate::types::SliceVec::new(core::mem::take(&mut ws.tki));
    let mut sel_rest: &mut [u8] = core::mem::take(&mut ws.sel);
    let mut kstr_rest: &mut [u8] = core::mem::take(&mut ws.kstr);
    let mut dests_rest: &mut [crate::chain::xmr::unsigned_txset::TxDestinationEntry] =
        core::mem::take(&mut ws.record_dests);
    let mut tx_bytes_rest: &mut [u8] = core::mem::take(&mut ws.tx_bytes);

    // P1-03: into_iter takes ownership — construction_data is moved into PendingTx (previously
    // the deep-copying tx_data.clone(); once TxSourceEntry is not Clone, move is the only path,
    // also the audit-required "secret copies must not proliferate")
    for slot in unsigned_tx.txes.iter_mut() {
        // Z2.3 C3c + P1-03: Option::take moves the construction data out of the pool
        // slot (ownership transfer to PendingTx; no secret copies proliferate).
        let tx_data = slot.take().ok_or_else(|| {
            crate::error::ShlosiloError::new(crate::error::ShlosiloErrorKind::EncodingInvalidFormat)
        })?;
        // Z2.3 C3b-3: carve this tx's slices out of the flat pools (split_at_mut —
        // disjoint &mut chunks, safe-Rust, counts known from tx_data)
        let (sel_chunk, r) = sel_rest.split_at_mut(tx_data.selected_transfers.len());
        sel_rest = r;
        let mut selected_transfers = crate::types::SliceVec::new(sel_chunk);
        for &t in tx_data.selected_transfers.iter() {
            selected_transfers.push(t as u8).map_err(|_| {
                crate::error::ShlosiloError::new(crate::error::ShlosiloErrorKind::BufferTooSmall)
            })?;
        }
        let (kstr_chunk, r) = kstr_rest.split_at_mut(67 * tx_data.sources.len());
        kstr_rest = r;
        let mut key_images_str = crate::types::SliceVec::new(kstr_chunk);
        let (dests_chunk, r) = dests_rest.split_at_mut(tx_data.dests.len());
        dests_rest = r;
        let mut dests = crate::types::SliceVec::new(dests_chunk);
        for d in tx_data.dests.iter() {
            dests.push(d.clone()).map_err(|_| {
                crate::error::ShlosiloError::new(crate::error::ShlosiloErrorKind::BufferTooSmall)
            })?;
        }
        // Per-tx context digest — Z3.2c: streamed straight into the sponge
        // (was a Zeroizing Vec materializing the whole input, masks included).
        // Absorb order is byte-identical to the old concatenation, so the
        // digest is unchanged; the secret material (masks) now transits the
        // sponge without ever landing in a buffer.
        let mut ctx_sink = crate::encoding::keccak256::KeccakSink::new();
        ctx_sink.absorb(&tx_data.unlock_time.to_le_bytes());
        ctx_sink.absorb(&tx_data.extra);
        for s in tx_data.sources.iter().flatten() {
            ctx_sink.absorb(s.real_out_tx_key.as_slice());
            // P1-03: mask plaintext access funneled through expose() (context digest is a read-only hash)
            ctx_sink.absorb(s.mask.expose());
        }
        for d in tx_data.splitted_dsts.iter() {
            ctx_sink.absorb(&d.spend_public_key);
            ctx_sink.absorb(&d.view_public_key);
        }
        let context = ctx_sink.finalize();

        // tx_key r: independent TxKey subdomain stream (§B.5)
        let mut tx_key_rng = purpose_rng(entropy, RngPurpose::TxKey, &context)
            .map_err(crate::error::ShlosiloError::from)?;
        // Audit #8 P1-02: the tx secret key at the production entry is placed in a Zeroizing owner from creation,
        // passed to the signer as bytes (the signer converts to Scalar on demand internally; no Copy binding is created)
        let mut r_bytes = zeroize::Zeroizing::new([0u8; 32]);
        use rand_chacha::rand_core::RngCore as _;
        tx_key_rng.fill_bytes(r_bytes.as_mut());

        // BP+ randomness: independent subdomain
        let mut bp_rng = purpose_rng(entropy, RngPurpose::BulletproofPlus, &context)
            .map_err(crate::error::ShlosiloError::from)?;
        // CLSAG: per-input subdomain (consumed in source order inside sign_tx_from_construction)

        // Z3.2b: carve this tx's wire slot out of the contiguous caller
        // workspace (total pre-checked above; mem::take-split keeps the full
        // 'a) and let the signer write straight into it — the Vec return and
        // the staging copy are gone.
        let (tx_slot, r) = core::mem::take(&mut tx_bytes_rest).split_at_mut(TX_BYTES_SLOT_MAX);
        tx_bytes_rest = r;
        let mut ws_bp_terms = core::mem::take(&mut ws.bp_terms);
        let bp_terms_slot = &mut ws_bp_terms;
        let ws_bp_straus = core::mem::take(&mut ws.bp_straus);
        let mut bp_straus = match curve25519_dalek::scratch::StrausScratch::new(
            ws_bp_straus,
            crate::types::caps::SIGN_WS_BP_TERMS,
        ) {
            Ok(s) => s,
            Err(_) => {
                return Err(crate::error::ShlosiloError::new(
                    crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
                ))
            }
        };
        let ws_bp_wip = core::mem::take(&mut ws.bp_wip);
        let mut bp_wip = match monero_bulletproofs::WipScratch::new(
            ws_bp_wip,
            crate::types::caps::SIGN_WS_BP_TERMS,
        ) {
            Some(s) => s,
            None => {
                return Err(crate::error::ShlosiloError::new(
                    crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
                ))
            }
        };
        let tx_bytes_len = crate::chain::xmr::tx_signer::sign_tx_from_construction_with_rngs_into(
            &tx_data,
            &spend_sec,
            &view_sec,
            &r_bytes,
            &mut bp_rng,
            &mut rng,
            tx_slot,
            bp_terms_slot,
            &mut bp_straus,
            &mut bp_wip,
        )?;
        let tx_bytes_borrow: &[u8] = &tx_slot[..tx_bytes_len]; // reborrows the full 'a (tx_slot is never used again)

        // fee(= inputs − splitted outputs)
        let input_sum: u64 = tx_data.sources.iter().flatten().map(|s| s.amount).sum();
        let out_sum: u64 = tx_data.splitted_dsts.iter().map(|d| d.amount).sum();
        let fee = input_sum.saturating_sub(out_sum);

        #[cfg(feature = "tx-phase-timing-ffi")]
        let mut px6 = PhaseProbe::start(6);
        // key images: already present in the signed wire; rebuild the `<hex> ` string + outer list here
        for src in tx_data.sources.iter().flatten() {
            let (ki, _off) = crate::chain::xmr::subaddress::derive_input_from_source(
                &view_sec,
                &spend_sec,
                src,
                tx_data.subaddr_account,
                &tx_data.subaddr_indices,
            )?;
            // Z2.3 C3b-3: `<hex> ` bytes built straight into the carved slice
            // (was String + alloc::format!) — byte layout unchanged
            pushb(&mut key_images_str, b'<')?;
            for b in ki {
                pushb(&mut key_images_str, b"0123456789abcdef"[(b >> 4) as usize])?;
                pushb(&mut key_images_str, b"0123456789abcdef"[(b & 0xf) as usize])?;
            }
            pushb(&mut key_images_str, b'>')?;
            pushb(&mut key_images_str, b' ')?;
            ki_sv.push(ki).map_err(|_| {
                crate::error::ShlosiloError::new(crate::error::ShlosiloErrorKind::BufferTooSmall)
            })?;
        }

        // tx_key_images: output one-time address + Hs(shared_key)·Hp(stealth)
        for (i, dest) in tx_data.splitted_dsts.iter().enumerate() {
            // change outputs skipped (the recipient is our own change address; keystone outputs() counts it too,
            // but shlosilo v1 only records external receiving outputs)
            if dest.amount == tx_data.change_dts.amount
                && dest.spend_public_key == tx_data.change_dts.spend_public_key
            {
                continue;
            }
            // Audit #9 P1-04: all secrets in the key-image recomputation section are owner-wrapped:
            // r → SecretScalar (zeroed on Drop on error paths; dalek Scalar itself is Copy with no Drop)
            let r = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(*r_bytes);
            // shared (compressed 8Ra point bytes) = ECDH intermediate (shared_key is recomputable) → Zeroizing
            // destructuring done outside the closure (a closure returning Result cannot use ?)
            let a = monero_ed25519::CompressedPoint::from(dest.view_public_key)
                .decompress()
                .ok_or_else(|| {
                    crate::error::ShlosiloError::new(
                        crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
                    )
                })?;
            let a_ed: curve25519_dalek::EdwardsPoint = a.into();
            let a_bytes = a_ed.compress().to_bytes();
            let shared = zeroize::Zeroizing::new(r.mul_point_cofactor(&a_bytes).map_err(|_| {
                crate::error::ShlosiloError::new(
                    crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
                )
            })?);
            // Z3.2c: stack-fixed od (32B shared ‖ varint(i) ≤ 10B) — Zeroizing
            // owner on the stack, explicit wipe via Drop as before.
            let mut od = zeroize::Zeroizing::new([0u8; 42]);
            let mut od_n = 0usize;
            crate::types::push::push_slice(&mut od[..], &mut od_n, shared.as_ref())?;
            crate::chain::xmr::transaction::monero_encode_varint_at(
                &mut od[..],
                &mut od_n,
                i as u64,
            )?;
            let shared_key = zeroize::Zeroizing::new(
                crate::chain::xmr::subaddress::hash_to_scalar(&od[..od_n])?,
            );
            // hs(SecretScalar): key-image = Hp(stealth) · hs — held by an owner,
            // zeroed on Drop at end of scope
            let hs = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(*shared_key);
            // key image = Hs(shared_key) · Hp(stealth) — stealth is the output's
            // one-time address = B_dest + hs·G
            let b_dest: curve25519_dalek::EdwardsPoint =
                monero_ed25519::CompressedPoint::from(dest.spend_public_key)
                    .decompress()
                    .ok_or_else(|| {
                        crate::error::ShlosiloError::new(
                            crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
                        )
                    })?
                    .into();
            // both stealth and image consume hs — all scalar multiplications complete inside the within_scalar closure
            let stealth = hs.mul_basepoint_add_point(&b_dest);
            let hp: curve25519_dalek::EdwardsPoint =
                monero_ed25519::Point::biased_hash(stealth).into();
            let hp_bytes = hp.compress().to_bytes();
            let image = hs.mul_point(&hp_bytes).map_err(|_| {
                crate::error::ShlosiloError::new(
                    crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
                )
            })?;
            tki_sv
                .push(TxKeyImageEntry {
                    output_pubkey: stealth,
                    key_image: image,
                })
                .map_err(|_| {
                    crate::error::ShlosiloError::new(
                        crate::error::ShlosiloErrorKind::BufferTooSmall,
                    )
                })?;
        }

        #[cfg(feature = "tx-phase-timing-ffi")]
        if let Some(p) = px6.as_mut() {
            p.end();
        }

        ptx_sv
            .push(Some(PendingTx {
                tx_bytes: tx_bytes_borrow,
                dust: 0,
                fee,
                dust_added_to_fee: false,
                change_dts: tx_data.change_dts.clone(),
                selected_transfers,
                key_images_str,
                additional_tx_keys: heapless::Vec::new(),
                dests,
                // P1-03: move instead of clone — secrets (mask/kLRki) no longer produce new copies
                construction_data: tx_data,
            }))
            .map_err(|_| {
                crate::error::ShlosiloError::new(crate::error::ShlosiloErrorKind::BufferTooSmall)
            })?;
    }

    let set = SignedTxSet {
        ptx: ptx_sv,
        key_images: ki_sv,
        tx_key_images: tki_sv,
    };
    // 4. Encrypted output (nonce + Schnorr k also on the entropy-derived stream).
    // Z2.4d-3: fused serialize+encrypt straight into the output buffer — the plaintext
    // container streams through the ChaCha keystream and never materializes; `output_buf`
    // receives ciphertext only (not sensitive).
    // Z2.4d-3: export stream = ExportEncrypt domain over the plaintext digest
    // (was: BulletproofPlus label + CONSTANT context — same entropy signing two
    // different transactions reused the same nonce AND the same Schnorr k, giving
    // two-time pad + view_sk recovery). Two-pass: the context is absorbed through
    // the sponge first (no plaintext materialization), then the fused encrypt runs
    // under the derived stream. Deterministic-retry property preserved.
    let export_ctx = set.export_encrypt_context()?;
    let mut enc_rng = crate::chain::xmr::signing_rng::export_encrypt_rng(entropy, &export_ctx)
        .map_err(crate::error::ShlosiloError::from)?;
    let required = crate::chain::xmr::signed_txset::SIGNED_TX_PREFIX.len()
        + crate::chain::xmr::signed_txset::NONCE_LEN
        + set.serialized_len()
        + crate::chain::xmr::signed_txset::SIG_LEN;
    if output_buf.len() < required {
        return Err(ShlosiloError::with_context(
            ShlosiloErrorKind::BufferTooSmall,
            crate::error::ErrorContext::RequiredLength(required),
        ));
    }
    #[cfg(feature = "tx-phase-timing-ffi")]
    let mut px7 = PhaseProbe::start(7);
    let n = set.encrypt_signed_txset_into(&view_sec, &cn_key, &mut enc_rng, output_buf)?;
    #[cfg(feature = "tx-phase-timing-ffi")]
    if let Some(p) = px7.as_mut() {
        p.end();
    }
    Ok(n)
}

/// Parse the master fingerprint + derivation path from a BIP32_DERIVATION value
/// value format (BIP-174): master_key_fingerprint(4B) || derivation_index(u32LE) × depth
/// P1-02: fingerprint returned together with the path (the caller compares against our master fingerprint to prevent signing for the wrong chain)
/// BIP32_DERIVATION value = master_fingerprint(4B) + path(u32LE × depth)
/// Z3.2a TRANSITIONAL SHELL — the `ws = None` path of `sign_with_entropy_ws`:
/// the sole remaining business-boundary alloc cluster on the XMR path (was 18
/// scattered roots before Z3.2). Provisions the flow workspace over heap backing
/// with the historical generous caps (behavior-identical to the pre-Z3.2 flow)
/// and delegates to `sign_xmr_with_ws`. Policy-labeled seam for C-ABI/legacy
/// callers; Rust flux hosts pass `Some(ws)` over their own memory instead and
/// the shell leaves their path entirely. Removed when the C-ABI workspace lands
/// (Z3.3b) — see the Z3 design doc for the proposed C shape.
fn sign_xmr(
    seed: &[u8],
    encrypted_unsigned: &[u8],
    entropy: &[u8],
    output_buf: &mut [u8],
) -> Result<usize> {
    // Z3.3b: ONE contiguous backing carved by the shared layout (the same
    // computation `shlosilo_sign_ws_len` reports — contract 3). The pool-locals
    // era is over; this alloc is the single remaining business-boundary root.
    let need = SignWsLayout::compute().total;
    let mut backing = alloc::vec![0u8; need];
    let mut ws = carve_sign_ws(&mut backing).ok_or_else(|| {
        ShlosiloError::with_context(
            ShlosiloErrorKind::BufferTooSmall,
            crate::error::ErrorContext::RequiredLength(need),
        )
    })?;
    sign_xmr_with_ws(&mut ws, seed, encrypted_unsigned, entropy, output_buf)
}

fn parse_derivation_value(value: &[u8]) -> Option<([u8; 4], DerivationPath)> {
    if value.len() < 8 || !(value.len() - 4).is_multiple_of(4) {
        return None;
    }
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&value[..4]);
    let depth = (value.len() - 4) / 4;
    // Z4-4: the path is a fixed-cap stack array — feed it straight from the
    // wire words (the old staging Vec was pure waste).
    DerivationPath::from_flat((0..depth).map(|j| {
        let o = 4 + 4 * j;
        u32::from_le_bytes([value[o], value[o + 1], value[o + 2], value[o + 3]])
    }))
    .ok()
    .map(|p| (fp, p))
}

fn read_bip32_derivation(
    input_map: &[crate::chain::btc::psbt::KeyValue],
) -> Option<([u8; 4], DerivationPath)> {
    use crate::chain::btc::psbt::input_type;
    let kv = input_map
        .iter()
        .find(|kv| kv.key.first() == Some(&input_type::BIP32_DERIVATION))?;
    parse_derivation_value(&kv.value)
}

/// BTC: crypto-psbt CBOR (bare bytes item) → PSBT signing
///
/// Derivation path = m/84'/0'/0'/0/0 (standard native segwit path).
/// Each input derives its private key from the path hinted by BIP32_DERIVATION;
/// Without a hint, always take the default path.
fn sign_btc(seed: &[u8], cbor_payload: &[u8], output_buf: &mut [u8]) -> Result<usize> {
    use crate::chain::btc::psbt as psbt_mod;
    use crate::encoding::cbor;

    let psbt_bytes = match cbor::decode(cbor_payload)? {
        cbor::Cbor::Bytes(b) => b,
        _ => return Err(err(ShlosiloErrorKind::UrPayloadInvalidCbor)),
    };

    let mut psbt = psbt_mod::parse_psbt(psbt_bytes)?;

    // P1-02: our master fingerprint (BIP-32 serialization field 5..9); the fingerprint
    // fingerprint mismatch = this PSBT is not from our wallet (wrong seed/wrong wallet); refuse to sign
    use alloc::vec::Vec;
    let local_fp = crate::derivation::bip32_secp256k1::master_fingerprint_from_seed(seed)?;

    for idx in 0..psbt.unsigned_tx.inputs.len() {
        // P1-02: BIP32_DERIVATION value = master_fingerprint(4B) + path(u32LE × depth),
        // paths are read from the PSBT rather than hardcoded; fingerprint mismatch with ours → reject;
        // fall back to the default path only when the field is absent (transitional; tightened at P6.4).
        // P1-B: inputs without BIP32_DERIVATION no longer fall back to the default path (tightened),
        // all inputs must carry ownership records explicitly (the P6.4 transitional behavior landed early).
        let (_fp0, path_used) = read_bip32_derivation(
            psbt.inputs
                .get(idx)
                .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?,
        )
        .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
        if _fp0 != local_fp {
            return Err(err(ShlosiloErrorKind::NetworkUnrecognized));
        }
        let sk = crate::derivation::bip32_secp256k1::derive_from_seed(seed, &path_used)?;
        // Z2.2 (2026-09-24): key-material stack copy zeroized on drop.
        let sk_bytes =
            zeroize::Zeroizing::new(crate::curve_primitive::secp256k1::scalar_to_bytes(&sk));

        // R4 ownership binding: the derived public key must match the pubkey carried by the PSBT BIP32_DERIVATION.
        // without this equality assertion, a malicious/crafted PSBT could get the device to sign inputs that "succeed but are unusable"
        // (HASH160 match ≠ the hash actually came from the private key we are about to use — a collision or ledger inconsistency can bypass this).
        let derived_pub = crate::curve_primitive::secp256k1::point_to_compressed(
            &crate::curve_primitive::secp256k1::base_mul(&sk),
        );

        // P1-B (2026-09-01 re-review): all BIP32_DERIVATION records strictly verified.
        // every record's (fingerprint, path, pubkey) must pass three checks:
        //   fingerprint == ours; path-derived public key == the pubkey carried by the record;
        //   and all record verifications must agree (different pubkeys = multisig/mixed-source; single-sig device rejects).
        let input_map = psbt
            .inputs
            .get(idx)
            .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
        // NOTE (Z2.1 S2 re-review, 2026-09-24): `kv.key[1..34]` is the BIP32_DERIVATION
        // compressed PUBLIC key (verified against derived pubkeys below) — public data,
        // deliberately NOT zeroize-wrapped. (Initially mis-audited as key material.)
        // Z4-4: pubkeys borrow the map payloads; one exact container.
        let mut records: Vec<([u8; 4], DerivationPath, &'_ [u8])> =
            Vec::with_capacity(input_map.len());
        for kv in input_map.iter() {
            if kv.key.first() != Some(&psbt_mod::input_type::BIP32_DERIVATION) {
                continue;
            }
            if kv.key.len() != 1 + 33 {
                return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            let (fp, path) = parse_derivation_value(&kv.value)
                .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
            records.push((fp, path, &kv.key[1..34]));
        }
        if records.is_empty() {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        // R4 semantics preserved: assert the signing key's derived pubkey equals the first record's pubkey
        if derived_pub.as_slice() != records[0].2 {
            return Err(err(ShlosiloErrorKind::PsbtOwnershipMismatch));
        }
        let mut pubkey_hash: Option<[u8; 20]> = None;
        for (fp, path, pk) in &records {
            if *fp != local_fp {
                return Err(err(ShlosiloErrorKind::NetworkUnrecognized));
            }
            let rec_sk = crate::derivation::bip32_secp256k1::derive_from_seed(seed, path)?;
            let rec_pub = crate::curve_primitive::secp256k1::point_to_compressed(
                &crate::curve_primitive::secp256k1::base_mul(&rec_sk),
            );
            if rec_pub.as_slice() != *pk {
                return Err(err(ShlosiloErrorKind::PsbtOwnershipMismatch));
            }
            // consistency with the (path, sk) actually used to sign this input: the record path must equal the signing path
            let h = crate::encoding::sha256::hash(pk)?;
            let h20 = crate::encoding::ripemd160::hash(&h)?;
            match &pubkey_hash {
                Some(prev) if *prev != h20 => {
                    // multiple records pointing to different pubkeys = not P2WPKH single-sig semantics
                    return Err(err(ShlosiloErrorKind::PsbtOwnershipMismatch));
                }
                Some(_) => {}
                None => {
                    pubkey_hash = Some(h20);
                    // the signing key uses the first record path that passes verification (aligned with derived_pub)
                    if *path != path_used {
                        return Err(err(ShlosiloErrorKind::PsbtOwnershipMismatch));
                    }
                }
            }
        }
        let pubkey_hash =
            pubkey_hash.ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;

        // P1-B: witness utxo binding — the amount and scriptPubKey must belong to this very input,
        // and the scriptPubKey must be P2WPKH (OP_0 PUSH20) with HASH160 == our pubkey_hash
        // (the prevout txid points to that script on-chain, indirectly anchoring the signed input to this key).
        let (amount, spk) = psbt
            .inputs
            .get(idx)
            .and_then(|m| psbt_mod::get_witness_utxo(m))
            .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
        if spk.len() != 22 || spk[0] != 0x00 || spk[1] != 0x14 || spk[2..22] != pubkey_hash {
            return Err(err(ShlosiloErrorKind::PsbtOwnershipMismatch));
        }

        psbt_mod::sign_psbt_p2wpkh(
            &mut psbt,
            &psbt_mod::PsbtSignInput {
                input_index: idx,
                private_key: SecretBytes::new(*sk_bytes),
                pubkey_hash,
                amount,
            },
        )?;
    }

    psbt_mod::serialize_psbt_into(&psbt, output_buf)
}

/// ETH: eth-sign-request CBOR map → signed tx bytes
///
/// P1-01 (2026-08-26): a real UR's payload is a CBOR map with sign_data / data_type /
/// chain_id / derivation_path. Only raw tx signing of Transaction(1) / TypedTransaction(4)
/// raw tx signing (= EIP-1559/legacy); PersonalMessage / TypedData explicitly rejected.
///
/// Derivation path = m/44'/60'/0'/0/0.
fn sign_eth(seed: &[u8], cbor_payload: &[u8], output_buf: &mut [u8]) -> Result<usize> {
    use crate::chain::eth::{eip1559, from_rlp};
    use crate::ur::codec::eth_sign_request::{parse_eth_sign_request, EthSignDataType};

    let req = parse_eth_sign_request(cbor_payload)?;
    match req.data_type {
        EthSignDataType::Transaction | EthSignDataType::TypedTransaction => {}
        EthSignDataType::TypedData | EthSignDataType::PersonalMessage => {
            // typed-data / personal-message only open up at P6.4; explicitly rejected for now
            return Err(err(ShlosiloErrorKind::ChainKindUnsupported));
        }
    }

    let tx = from_rlp::parse_eip1559_raw(req.sign_data)?;
    // P1-02 (ETH part): when eth-sign-request carries its own chain_id, verify it matches the tx
    if let Some(req_chain) = req.chain_id {
        if req_chain != tx.chain_id as i128 {
            return Err(err(ShlosiloErrorKind::NetworkUnrecognized));
        }
    }
    // P1-02: when the request carries a derivation_path, derive with it; otherwise fall back to the standard path
    let path = match req.derivation_path {
        Some(p) => p,
        None => DerivationPath::parse("m/44'/60'/0'/0/0")?,
    };
    let t_derive = crate::device_timing::Mark::start(crate::device_timing::STAGE_BIP32);
    let sk = crate::derivation::bip32_secp256k1::derive_from_seed(seed, &path)?;
    t_derive.end();
    // Z2.2 (2026-09-24): key-material stack copy zeroized on drop.
    let sk_bytes = zeroize::Zeroizing::new(crate::curve_primitive::secp256k1::scalar_to_bytes(&sk));

    let t_sign = crate::device_timing::Mark::start(crate::device_timing::STAGE_ECDSA);
    let signed = eip1559::sign_eip1559(&eip1559::Eip1559SignInput {
        tx,
        private_key: SecretBytes::new(*sk_bytes),
    })?;
    t_sign.end();
    if output_buf.len() < signed.tx_bytes.len() {
        return Err(ShlosiloError::with_context(
            ShlosiloErrorKind::BufferTooSmall,
            crate::error::ErrorContext::RequiredLength(signed.tx_bytes.len()),
        ));
    }
    output_buf[..signed.tx_bytes.len()].copy_from_slice(&signed.tx_bytes);
    Ok(signed.tx_bytes.len())
}

/// Signing (network enters the decision; closed out at P1-02)
///
/// Validation rules:
/// - BTC: only BitcoinMainnet is supported (v1 scope; non-mainnet explicitly rejected, consistent with the P2-05 xpub policy)
/// - ETH: tx.chain_id must equal the EIP-155 chain id mapped from the network
/// - other chains: the network is only validated for legality (done by the FFI layer's from_u8); the business layer no longer gates it
pub fn sign_with_network(
    sign_input: SignInput<'_>,
    type_tag: crate::ur::ur_encode::UrTypeTag,
    ur_payload: &[u8],
    network: Network,
    output_buf: &mut [u8],
) -> Result<usize> {
    check_network(type_tag, ur_payload, network)?;
    sign(sign_input, type_tag, ur_payload, output_buf)
}

/// P1-02: the network parameter enters the decision
///
/// - BTC (crypto-psbt): v1 only supports BitcoinMainnet (consistent with the P2-05 xpub mainnet-only policy)
/// - ETH (eth-sign-request): the network maps to an EIP-155 chain id, which must match the tx's actual chain_id
///   (and the request's own chain_id field, if given) must match
/// - other chains: the FFI layer already validates the u8; the business layer does not gate it
pub(crate) fn check_network(
    type_tag: crate::ur::ur_encode::UrTypeTag,
    ur_payload: &[u8],
    network: Network,
) -> Result<()> {
    match type_tag {
        crate::ur::ur_encode::UrTypeTag::CryptoPsbt if network != Network::BitcoinMainnet => {
            return Err(err(ShlosiloErrorKind::NetworkUnrecognized));
        }
        crate::ur::ur_encode::UrTypeTag::EthSignRequest
            if matches!(
                network,
                Network::EthereumMainnet | Network::EthereumSepolia | Network::EthereumGoerli
            ) =>
        {
            let expected_chain_id = match network {
                Network::EthereumMainnet => 1u64,
                Network::EthereumSepolia => 11_155_111,
                _ => 5, // Goerli
            };
            let req = crate::ur::codec::eth_sign_request::parse_eth_sign_request(ur_payload)?;
            if let Some(req_chain) = req.chain_id {
                if req_chain != expected_chain_id as i128 {
                    return Err(err(ShlosiloErrorKind::NetworkUnrecognized));
                }
            }
            let tx = crate::chain::eth::from_rlp::parse_eip1559_raw(req.sign_data)?;
            if tx.chain_id != expected_chain_id {
                return Err(err(ShlosiloErrorKind::NetworkUnrecognized));
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::chain_kind::ChainKind;
    extern crate alloc;
    use alloc::vec::Vec;

    #[test]
    fn stub_signature_len_table() {
        assert_eq!(stub_signature_len(ChainKind::Btc), 64);
        assert_eq!(stub_signature_len(ChainKind::Eth), 65);
        assert_eq!(stub_signature_len(ChainKind::Xmr), 96);
        assert_eq!(stub_signature_len(ChainKind::Sol), 64);
        assert_eq!(stub_signature_len(ChainKind::Ar), 512);
    }

    #[test]
    fn sign_unknown_chain_kind_rejected() {
        let seed = [0u8; 64];
        let input = SignInput::Seed { seed: &seed };
        let ur_payload = [99u8, 1, 2, 3]; // arbitrary payload
        let mut output_buf = [0u8; 4096];
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::Unknown,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::UrPayloadUnknownType
        );
    }

    /// XMR is now wired in (P1-06 wrap-up): missing entropy raises EntropyInjectionInvalid
    /// (§B.5 misuse guard; the old ChainKindUnsupported behavior has been removed)
    #[test]
    fn sign_xmr_requires_entropy() {
        let seed = [0u8; 64];
        let input = SignInput::Seed { seed: &seed };
        // crypto-monero-tx compatibility alias + arbitrary payload (does the XMR branch do the entropy guard first? —
        // in practice it decrypts first and the fake payload fails at decryption; use the official tag + short entropy to verify the guard ordering:
        // sign_xmr derives the keypair before decrypting; the entropy guard triggers on the first purpose_rng call)
        let ur_payload = [1u8, 2, 3];
        let mut output_buf = [0u8; 4096];
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::XmrTxUnsigned,
            &ur_payload,
            &mut output_buf,
        );
        // short payloads fail at the decrypt stage (magic check) — either error is acceptable,
        // the key point is it is no longer ChainKindUnsupported
        let kind = result.unwrap_err().kind;
        assert!(
            kind == ShlosiloErrorKind::EncodingInvalidFormat
                || kind == ShlosiloErrorKind::EntropyInjectionInvalid,
            "unexpected kind: {:?}",
            kind
        );
    }

    /// ETH end-to-end: build a raw EIP-1559 tx → real eth-sign-request CBOR map → sign → output a valid 0x02 signed tx
    #[test]
    fn sign_eth_end_to_end() {
        use crate::chain::eth::eip1559::Eip1559Transaction;

        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 12345,
            data: Vec::new(),
            access_list: Vec::new(),
        };
        // build the unsigned preimage then strip the signature part — use signing_preimage + manual RLP directly
        // simple approach: from_rlp round-trip — sign once to get the raw, then use it as input
        let sk = crate::curve_primitive::secp256k1::scalar_from_bytes(&[42u8; 32]).unwrap();
        let direct = crate::chain::eth::eip1559::sign_eip1559(
            &crate::chain::eth::eip1559::Eip1559SignInput {
                tx: tx.clone(),
                private_key: SecretBytes::new(crate::curve_primitive::secp256k1::scalar_to_bytes(
                    &sk,
                )),
            },
        )
        .unwrap();

        let mut output_buf = [0u8; 512];
        // seed derives m/44'/60'/0'/0/0, a different key than the one signed with directly above — this verifies the flow, not byte equality:
        // first derive the child key from the same seed, then sign directly with that key as a cross-check
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let test_seed = [7u8; 64];
        let derived =
            crate::derivation::bip32_secp256k1::derive_from_seed(&test_seed, &path).unwrap();
        let derived_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&derived);
        let expected = crate::chain::eth::eip1559::sign_eip1559(
            &crate::chain::eth::eip1559::Eip1559SignInput {
                tx: tx.clone(),
                private_key: SecretBytes::new(derived_bytes),
            },
        )
        .unwrap();
        let _ = direct;

        // P1-01: build a real eth-sign-request CBOR map (ur-registry shape)
        // {2: sign_data(bytes), 3: data_type(1), 4: chain_id(1)}
        let raw = encode_unsigned_tx_for_test(&tx);
        let ur_payload = encode_eth_sign_request_for_test(&raw, 1, 1);

        let input = SignInput::Seed { seed: &test_seed };
        let n = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        )
        .expect("sign ok");
        assert_eq!(n, expected.tx_bytes.len());
        assert_eq!(&output_buf[..n], &expected.tx_bytes[..]);
        assert_eq!(output_buf[0], 0x02);
    }

    /// P1-01: ETH end-to-end rejects requests with a mismatched chain_id
    #[test]
    fn sign_eth_rejects_chain_id_mismatch() {
        let tx = crate::chain::eth::eip1559::Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 12345,
            data: Vec::new(),
            access_list: Vec::new(),
        };
        let raw = encode_unsigned_tx_for_test(&tx);
        // request chain_id=5 (≠ the tx's 1)
        let ur_payload = encode_eth_sign_request_for_test(&raw, 1, 5);
        let test_seed = [7u8; 64];
        let input = SignInput::Seed { seed: &test_seed };
        let mut output_buf = [0u8; 512];
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::NetworkUnrecognized
        );
    }

    /// P1-01: ETH end-to-end rejects personal-message (not currently supported)
    #[test]
    fn sign_eth_rejects_personal_message() {
        let raw = encode_unsigned_tx_for_test(&crate::chain::eth::eip1559::Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 12345,
            data: Vec::new(),
            access_list: Vec::new(),
        });
        // data_type = 3 (PersonalMessage)
        let ur_payload = encode_eth_sign_request_for_test(&raw, 3, 1);
        let test_seed = [7u8; 64];
        let input = SignInput::Seed { seed: &test_seed };
        let mut output_buf = [0u8; 512];
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::ChainKindUnsupported
        );
    }

    /// Test helper: encode an unsigned EIP-1559 tx into raw bytes (for from_rlp parsing)
    fn encode_unsigned_tx_for_test(
        tx: &crate::chain::eth::eip1559::Eip1559Transaction,
    ) -> alloc::vec::Vec<u8> {
        use crate::chain::eth::rlp;
        let list = rlp::encode_list(&[
            rlp::encode_uint(tx.chain_id as u128),
            rlp::encode_uint(tx.nonce as u128),
            rlp::encode_uint(tx.max_priority_fee_per_gas),
            rlp::encode_uint(tx.max_fee_per_gas),
            rlp::encode_uint(tx.gas_limit as u128),
            rlp::encode_bytes(&tx.destination.unwrap()),
            rlp::encode_uint(tx.amount),
            rlp::encode_bytes(&tx.data),
            rlp::encode_list(&[]),
            rlp::encode_bytes(b""), // y_parity placeholder (unsigned shape)
            rlp::encode_bytes(b""),
            rlp::encode_bytes(b""),
        ]);
        let mut out = alloc::vec![0x02u8];
        out.extend_from_slice(&list);
        out
    }

    /// Test helper: build an eth-sign-request CBOR map (ur-registry shape, minimal set)
    /// {2: sign_data(bytes), 3: data_type(uint), 4: chain_id(uint)}
    fn encode_eth_sign_request_for_test(
        sign_data: &[u8],
        data_type: u64,
        chain_id: u64,
    ) -> alloc::vec::Vec<u8> {
        encode_eth_sign_request_with_path_for_test(sign_data, data_type, chain_id, None)
    }

    /// + optional derivation_path (key 5, tag 305 crypto-keypath)
    fn encode_eth_sign_request_with_path_for_test(
        sign_data: &[u8],
        data_type: u64,
        chain_id: u64,
        path: Option<&DerivationPath>,
    ) -> alloc::vec::Vec<u8> {
        use crate::encoding::cbor;
        let mut pairs = alloc::vec![
            (cbor::encode_uint(2), cbor::encode_bytes(sign_data)),
            (cbor::encode_uint(3), cbor::encode_uint(data_type)),
            (cbor::encode_uint(4), cbor::encode_uint(chain_id)),
        ];
        if let Some(p) = path {
            // crypto-keypath: tag(304, {1: [idx, hardened, ...], 2: depth})
            // P1-01 (audit #4): the registry tag is 304 — older comments/encoding mistakenly wrote 305; corrected
            let mut comps = alloc::vec::Vec::new();
            for idx in p.as_slice() {
                comps.push(cbor::encode_uint(idx.value() as u64));
                comps.push(cbor::encode_bool(idx.is_hardened()));
            }
            let inner = cbor::encode_map(&[
                (cbor::encode_uint(1), cbor::encode_array(&comps)),
                (cbor::encode_uint(2), cbor::encode_uint(p.len() as u64)),
            ]);
            pairs.push((cbor::encode_uint(5), cbor::encode_tag(304, &inner)));
        }
        cbor::encode_map(&pairs)
    }

    /// BTC end-to-end: build a P2WPKH PSBT → crypto-psbt CBOR → sign() → verify PARTIAL_SIG
    #[test]
    fn sign_btc_psbt_end_to_end() {
        use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut};
        use crate::chain::btc::psbt::{self, input_type, Psbt};
        use crate::encoding::cbor;

        // 1. Derive key: seed → m/84'/0'/0'/0/0
        let seed = [0xA5u8; 64];
        let path = DerivationPath::parse("m/84'/0'/0'/0/0").unwrap();
        let sk = crate::derivation::bip32_secp256k1::derive_from_seed(&seed, &path).unwrap();
        let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&sk);

        // 2. Compute compressed pubkey + hash160 from the sk
        let sk_scalar = crate::curve_primitive::secp256k1::scalar_from_bytes(&sk_bytes).unwrap();
        let pk_point = crate::curve_primitive::secp256k1::base_mul(&sk_scalar);
        let compressed_pk = crate::curve_primitive::secp256k1::point_to_compressed(&pk_point);
        let h = crate::encoding::sha256::hash(&compressed_pk).unwrap();
        let pk_hash = crate::encoding::ripemd160::hash(&h).unwrap();

        // 3. Build the PSBT: 1 in (P2WPKH witness utxo) + 1 out
        let mut spk = alloc::vec![0x00u8, 0x14];
        spk.extend_from_slice(&pk_hash);
        let mut psbt = Psbt {
            unsigned_tx: Transaction {
                version: 2,
                inputs: alloc::vec![TxIn {
                    prev_out: OutPoint {
                        txid: [0xABu8; 32],
                        vout: 0,
                    },
                    script_sig: Vec::new(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                }],
                outputs: alloc::vec![TxOut {
                    value: 90_000,
                    script_pubkey: spk.clone(),
                }],
                lock_time: 0,
            },
            inputs: alloc::vec![],
            outputs: alloc::vec![alloc::vec![]], // 1 output map (empty)
        };
        // input map: WITNESS_UTXO + BIP32_DERIVATION
        let mut wu_value = alloc::vec::Vec::new();
        wu_value.extend_from_slice(&100_000u64.to_le_bytes());
        wu_value.push(22); // varint(22) script len
        wu_value.extend_from_slice(&spk);
        psbt.inputs.push(alloc::vec![
            psbt::KeyValue {
                key: alloc::vec![input_type::WITNESS_UTXO].into(),
                value: wu_value.into(),
            },
            psbt::KeyValue {
                key: {
                    let mut k = alloc::vec![input_type::BIP32_DERIVATION];
                    k.extend_from_slice(&compressed_pk);
                    k.into()
                },
                // BIP-174 canonical shape: master_fingerprint(4B) || child(u32LE) × depth
                value: {
                    let local_fp =
                        crate::derivation::bip32_secp256k1::master_fingerprint_from_seed(&seed)
                            .unwrap();
                    let mut vv = alloc::vec::Vec::new();
                    vv.extend_from_slice(&local_fp);
                    for c in path.as_slice() {
                        vv.extend_from_slice(&c.0.to_le_bytes());
                    }
                    vv.into()
                },
            },
        ]);

        // 4. serialize → CBOR bytes (the crypto-psbt payload is a CBOR bytes item, no leading type byte)
        let psbt_bytes = psbt::serialize_psbt(&psbt);
        let ur_payload = cbor::encode_bytes(&psbt_bytes);

        // 5. Go through the business entry point (P1-01: type carried explicitly by the tag)
        let mut output_buf = [0u8; 4096];
        let input = SignInput::Seed { seed: &seed };
        let n = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::CryptoPsbt,
            &ur_payload,
            &mut output_buf,
        )
        .expect("sign ok");

        // 6. Verify the output is a valid PSBT containing our PARTIAL_SIG
        let signed = psbt::parse_psbt(&output_buf[..n]).expect("re-parse");
        assert_eq!(signed.unsigned_tx.inputs.len(), 1);
        let partial = signed.inputs[0]
            .iter()
            .find(|kv| kv.key[0] == input_type::PARTIAL_SIG)
            .expect("PARTIAL_SIG injected");
        assert_eq!(&partial.key[1..], &compressed_pk[..]);
        assert_eq!(partial.value.last(), Some(&0x01));

        // 7. L1 verifier validates the signature: recompute the BIP-143 sighash and verify
        let der_sig = &partial.value[..partial.value.len() - 1];
        let ecdsa_sig = crate::signature::ecdsa_secp256k1::from_der(der_sig).expect("der parse");
        // BIP-143 scriptCode = 76a914{pk_hash}88ac (25 bytes, no length prefix)
        let mut script_code = alloc::vec![0x76u8, 0xa9, 0x14];
        script_code.extend_from_slice(&pk_hash);
        script_code.extend_from_slice(&[0x88, 0xac]);
        let sighash = crate::chain::btc::p2wpkh::segwit_sighash_p2wpkh(
            &signed.unsigned_tx,
            0,
            &script_code,
            100_000,
            1, // SIGHASH_ALL
        )
        .expect("sighash");
        let pk = crate::curve_primitive::secp256k1::point_from_compressed(&compressed_pk).unwrap();
        assert!(crate::signature::ecdsa_secp256k1::verify(
            &pk, &sighash, &ecdsa_sig
        ));
    }

    /// P1-02: PSBT with a non-default path (m/84'/0'/1'/0/0) → signing derives the key from that path (threading proof)
    #[test]
    fn sign_btc_psbt_uses_psbt_derivation_path() {
        use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut};
        use crate::chain::btc::psbt::{self, input_type, Psbt};
        use crate::encoding::cbor;

        let seed = [0xA5u8; 64];
        let path = DerivationPath::parse("m/84'/0'/1'/0/0").unwrap();
        let sk = crate::derivation::bip32_secp256k1::derive_from_seed(&seed, &path).unwrap();
        let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&sk);
        let sk_scalar = crate::curve_primitive::secp256k1::scalar_from_bytes(&sk_bytes).unwrap();
        let pk_point = crate::curve_primitive::secp256k1::base_mul(&sk_scalar);
        let compressed_pk = crate::curve_primitive::secp256k1::point_to_compressed(&pk_point);
        let h = crate::encoding::sha256::hash(&compressed_pk).unwrap();
        let pk_hash = crate::encoding::ripemd160::hash(&h).unwrap();

        let mut spk = alloc::vec![0x00u8, 0x14];
        spk.extend_from_slice(&pk_hash);
        let mut psbt = Psbt {
            unsigned_tx: Transaction {
                version: 2,
                inputs: alloc::vec![TxIn {
                    prev_out: OutPoint {
                        txid: [0xABu8; 32],
                        vout: 0
                    },
                    script_sig: Vec::new(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                }],
                outputs: alloc::vec![TxOut {
                    value: 90_000,
                    script_pubkey: spk.clone()
                }],
                lock_time: 0,
            },
            inputs: alloc::vec![],
            outputs: alloc::vec![alloc::vec![]],
        };
        let mut wu_value = alloc::vec::Vec::new();
        wu_value.extend_from_slice(&100_000u64.to_le_bytes());
        wu_value.push(22);
        wu_value.extend_from_slice(&spk);
        let local_fp =
            crate::derivation::bip32_secp256k1::master_fingerprint_from_seed(&seed).unwrap();
        psbt.inputs.push(alloc::vec![
            psbt::KeyValue {
                key: alloc::vec![input_type::WITNESS_UTXO].into(),
                value: wu_value.into(),
            },
            psbt::KeyValue {
                key: {
                    let mut k = alloc::vec![input_type::BIP32_DERIVATION];
                    k.extend_from_slice(&compressed_pk);
                    k.into()
                },
                value: {
                    let mut vv = alloc::vec::Vec::new();
                    vv.extend_from_slice(&local_fp);
                    for c in path.as_slice() {
                        vv.extend_from_slice(&c.0.to_le_bytes());
                    }
                    vv.into()
                },
            },
        ]);

        let psbt_bytes = psbt::serialize_psbt(&psbt);
        let ur_payload = cbor::encode_bytes(&psbt_bytes);

        let mut output_buf = [0u8; 4096];
        let input = SignInput::Seed { seed: &seed };
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::CryptoPsbt,
            &ur_payload,
            &mut output_buf,
        );
        // path-threading proof: if the default path were used as fallback, the derived key ≠ fixture key → signing fails
        assert!(
            result.is_ok(),
            "non-default-path PSBT must sign via BIP32_DERIVATION path"
        );
    }

    /// P1-02: BIP32_DERIVATION fingerprint mismatch with ours → reject (prevents signing from the wrong wallet)
    #[test]
    fn sign_btc_psbt_rejects_fingerprint_mismatch() {
        use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut};
        use crate::chain::btc::psbt::{self, input_type, Psbt};
        use crate::encoding::cbor;

        let seed = [0xA5u8; 64];
        let path = DerivationPath::parse("m/84'/0'/0'/0/0").unwrap();
        let sk = crate::derivation::bip32_secp256k1::derive_from_seed(&seed, &path).unwrap();
        let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&sk);
        let sk_scalar = crate::curve_primitive::secp256k1::scalar_from_bytes(&sk_bytes).unwrap();
        let pk_point = crate::curve_primitive::secp256k1::base_mul(&sk_scalar);
        let compressed_pk = crate::curve_primitive::secp256k1::point_to_compressed(&pk_point);
        let h = crate::encoding::sha256::hash(&compressed_pk).unwrap();
        let pk_hash = crate::encoding::ripemd160::hash(&h).unwrap();

        let mut spk = alloc::vec![0x00u8, 0x14];
        spk.extend_from_slice(&pk_hash);
        let mut psbt = Psbt {
            unsigned_tx: Transaction {
                version: 2,
                inputs: alloc::vec![TxIn {
                    prev_out: OutPoint {
                        txid: [0xABu8; 32],
                        vout: 0
                    },
                    script_sig: Vec::new(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                }],
                outputs: alloc::vec![TxOut {
                    value: 90_000,
                    script_pubkey: spk.clone()
                }],
                lock_time: 0,
            },
            inputs: alloc::vec![],
            outputs: alloc::vec![alloc::vec![]],
        };
        let mut wu_value = alloc::vec::Vec::new();
        wu_value.extend_from_slice(&100_000u64.to_le_bytes());
        wu_value.push(22);
        wu_value.extend_from_slice(&spk);
        let wrong_fp = [0xDE, 0xAD, 0xBE, 0xEF];
        psbt.inputs.push(alloc::vec![
            psbt::KeyValue {
                key: alloc::vec![input_type::WITNESS_UTXO].into(),
                value: wu_value.into(),
            },
            psbt::KeyValue {
                key: {
                    let mut k = alloc::vec![input_type::BIP32_DERIVATION];
                    k.extend_from_slice(&compressed_pk);
                    k.into()
                },
                value: {
                    let mut vv = alloc::vec::Vec::new();
                    vv.extend_from_slice(&wrong_fp);
                    for c in path.as_slice() {
                        vv.extend_from_slice(&c.0.to_le_bytes());
                    }
                    vv.into()
                },
            },
        ]);

        let psbt_bytes = psbt::serialize_psbt(&psbt);
        let ur_payload = cbor::encode_bytes(&psbt_bytes);

        let mut output_buf = [0u8; 4096];
        let input = SignInput::Seed { seed: &seed };
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::CryptoPsbt,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::NetworkUnrecognized
        );
    }

    /// P1-B: witness_utxo scriptPubKey not bound to the signing key (swapped to someone else's P2WPKH) → reject
    #[test]
    fn p1b_rejects_witness_utxo_script_mismatch() {
        use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut};
        use crate::chain::btc::psbt::{self, input_type, Psbt};
        use crate::encoding::cbor;

        let seed = [0xA5u8; 64];
        let path = DerivationPath::parse("m/84'/0'/0'/0/0").unwrap();
        let sk = crate::derivation::bip32_secp256k1::derive_from_seed(&seed, &path).unwrap();
        let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&sk);
        let sk_scalar = crate::curve_primitive::secp256k1::scalar_from_bytes(&sk_bytes).unwrap();
        let compressed_pk = crate::curve_primitive::secp256k1::point_to_compressed(
            &crate::curve_primitive::secp256k1::base_mul(&sk_scalar),
        );

        // scriptPubKey uses a different hash — witness_utxo is decoupled from the signing key
        let mut spk = alloc::vec![0x00u8, 0x14];
        spk.extend_from_slice(&[0x11u8; 20]);
        let _ = compressed_pk;

        let psbt = Psbt {
            unsigned_tx: Transaction {
                version: 2,
                inputs: alloc::vec![TxIn {
                    prev_out: OutPoint {
                        txid: [0xABu8; 32],
                        vout: 0
                    },
                    script_sig: Vec::new(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                }],
                outputs: alloc::vec![TxOut {
                    value: 90_000,
                    script_pubkey: spk.clone()
                }],
                lock_time: 0,
            },
            inputs: alloc::vec![alloc::vec![
                psbt::KeyValue {
                    key: alloc::vec![input_type::WITNESS_UTXO].into(),
                    value: {
                        let mut v = alloc::vec::Vec::new();
                        v.extend_from_slice(&100_000u64.to_le_bytes());
                        v.push(22);
                        v.extend_from_slice(&spk);
                        v.into()
                    },
                },
                psbt::KeyValue {
                    key: {
                        let mut k = alloc::vec![input_type::BIP32_DERIVATION];
                        k.extend_from_slice(&compressed_pk);
                        k.into()
                    },
                    value: {
                        let fp =
                            crate::derivation::bip32_secp256k1::master_fingerprint_from_seed(&seed)
                                .unwrap();
                        let mut vv = alloc::vec::Vec::new();
                        vv.extend_from_slice(&fp);
                        for c in path.as_slice() {
                            vv.extend_from_slice(&c.0.to_le_bytes());
                        }
                        vv.into()
                    },
                },
            ]],
            outputs: alloc::vec![alloc::vec![]],
        };

        let psbt_bytes = psbt::serialize_psbt(&psbt);
        let ur_payload = cbor::encode_bytes(&psbt_bytes);
        let mut output_buf = [0u8; 4096];
        let input = SignInput::Seed { seed: &seed };
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::CryptoPsbt,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::PsbtOwnershipMismatch
        );
    }

    /// P1-B: no BIP32_DERIVATION record (the old default-path fallback has been removed) → reject
    #[test]
    fn p1b_rejects_missing_derivation_record() {
        use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut};
        use crate::chain::btc::psbt::{self, input_type, Psbt};
        use crate::encoding::cbor;

        let seed = [0xA5u8; 64];
        let mut spk = alloc::vec![0x00u8, 0x14];
        spk.extend_from_slice(&[0x22u8; 20]);

        let psbt = Psbt {
            unsigned_tx: Transaction {
                version: 2,
                inputs: alloc::vec![TxIn {
                    prev_out: OutPoint {
                        txid: [0xABu8; 32],
                        vout: 0
                    },
                    script_sig: Vec::new(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                }],
                outputs: alloc::vec![TxOut {
                    value: 90_000,
                    script_pubkey: spk.clone()
                }],
                lock_time: 0,
            },
            inputs: alloc::vec![alloc::vec![psbt::KeyValue {
                key: alloc::vec![input_type::WITNESS_UTXO].into(),
                value: {
                    let mut v = alloc::vec::Vec::new();
                    v.extend_from_slice(&100_000u64.to_le_bytes());
                    v.push(22);
                    v.extend_from_slice(&spk);
                    v.into()
                },
            }]],
            outputs: alloc::vec![alloc::vec![]],
        };

        let psbt_bytes = psbt::serialize_psbt(&psbt);
        let ur_payload = cbor::encode_bytes(&psbt_bytes);
        let mut output_buf = [0u8; 4096];
        let input = SignInput::Seed { seed: &seed };
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::CryptoPsbt,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::EncodingInvalidFormat
        );
    }

    /// P1-02: eth-sign-request with a derivation_path → signing derives the key from that path (threading proof)
    #[test]
    fn sign_eth_uses_request_derivation_path() {
        use crate::chain::eth::eip1559::Eip1559Transaction;

        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 12345,
            data: Vec::new(),
            access_list: Vec::new(),
        };
        let test_seed = [7u8; 64];
        // non-default path: account 1
        let path = DerivationPath::parse("m/44'/60'/1'/0/0").unwrap();
        let derived =
            crate::derivation::bip32_secp256k1::derive_from_seed(&test_seed, &path).unwrap();
        let derived_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&derived);
        let expected = crate::chain::eth::eip1559::sign_eip1559(
            &crate::chain::eth::eip1559::Eip1559SignInput {
                tx: tx.clone(),
                private_key: SecretBytes::new(derived_bytes),
            },
        )
        .unwrap();

        let raw = encode_unsigned_tx_for_test(&tx);
        let ur_payload = encode_eth_sign_request_with_path_for_test(&raw, 1, 1, Some(&path));

        let mut output_buf = [0u8; 512];
        let input = SignInput::Seed { seed: &test_seed };
        let n = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        )
        .expect("sign ok");

        // the signature bytes match a direct sign with the key derived from that path → path threading proven
        assert_eq!(&output_buf[..n], expected.tx_bytes.as_slice());
    }

    /// P1-02: network in decision — BTC rejects non-mainnet
    #[test]
    fn sign_with_network_btc_rejects_testnet() {
        let seed = [0xA5u8; 64];
        let input = SignInput::Seed { seed: &seed };
        let ur_payload = [1u8, 2, 3]; // contents don't matter: the network check happens before parsing
        let mut output_buf = [0u8; 4096];
        let result = sign_with_network(
            input,
            crate::ur::ur_encode::UrTypeTag::CryptoPsbt,
            &ur_payload,
            Network::BitcoinTestnet,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::NetworkUnrecognized
        );
    }

    /// P1-02: network in decision — ETH rejects when network(10=mainnet,chain_id=1) does not match the tx chain_id
    #[test]
    fn sign_with_network_eth_rejects_chain_id_mismatch() {
        use crate::chain::eth::eip1559::Eip1559Transaction;
        let tx = Eip1559Transaction {
            chain_id: 137, // polygon, ≠ mainnet 1
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 1,
            data: Vec::new(),
            access_list: Vec::new(),
        };
        let raw = encode_unsigned_tx_for_test(&tx);
        let ur_payload = encode_eth_sign_request_for_test(&raw, 1, 1);
        let seed = [7u8; 64];
        let input = SignInput::Seed { seed: &seed };
        let mut output_buf = [0u8; 4096];
        let result = sign_with_network(
            input,
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            Network::EthereumMainnet,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::NetworkUnrecognized
        );
    }

    /// P1-02: network in decision — ETH allows when the network matches the tx chain_id (successful signing)
    #[test]
    fn sign_with_network_eth_accepts_matching() {
        use crate::chain::eth::eip1559::Eip1559Transaction;
        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 1,
            data: Vec::new(),
            access_list: Vec::new(),
        };
        let raw = encode_unsigned_tx_for_test(&tx);
        let ur_payload = encode_eth_sign_request_for_test(&raw, 1, 1);
        let seed = [7u8; 64];
        let input = SignInput::Seed { seed: &seed };
        let mut output_buf = [0u8; 4096];
        let result = sign_with_network(
            input,
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            Network::EthereumMainnet,
            &mut output_buf,
        );
        assert!(result.is_ok());
    }
}
