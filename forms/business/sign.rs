//! Business 1: Signing (v2 §1.1 + §4.3)
//!
//! **P6.0d/e realization**:
//! - Mnemonic input → restore_seed (real BIP-39)
//! - BTC (crypto-psbt): extract PSBT bytes from CBOR → parse_psbt → sign input by input → serialize
//! - ETH(eth-sign-request): payload + `data_type` select the scheme — 4 = typed
//!   transaction (`0x02 || rlp([...])` → `parse_eip1559_signing_request` → `sign_eip1559_parts`),
//!   1 = legacy EIP-155 (bare preimage → `parse_eip155_signing_request` → `sign_eip155_parts`),
//!   3 = EIP-191 personal message. All three answer with a `ur:eth-signature` container.
//! - XMR / other chains: explicitly rejected (XMR awaits a real Feather fixture; v2 scope does not build transactions)

// Both coin sides parse derivation paths out of their requests (PSBT BIP32 records for
// BTC, `derivation_path` on an eth-sign-request for ETH).
#[cfg(any(feature = "chain-btc", feature = "chain-eth"))]
use crate::derivation::path::DerivationPath;
use crate::entropy::mnemonic::Mnemonic;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::network::Network;
use crate::tx::tx_normalize;
use crate::types::SecretBytes;

#[cfg(feature = "alloc-fallback")]
extern crate alloc;

/// Z2.3 C3b-3: one-byte SliceVec push with the standard overflow error shape.
#[cfg(feature = "chain-xmr")]
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
    use crate::types::sign_protocol::SignProtocol;
    // A wired chain answers from its signing protocol: the width is a property of the protocol
    // (ECDSA with or without the recovery byte, Schnorr, CLSAG), not of the chain name.
    if let Some(protocol) = SignProtocol::primary_for_chain(chain_kind) {
        return protocol.signature_len();
    }
    // Chains this product does not sign for keep a placeholder so the buffer pre-check table
    // stays total. They have no SignProtocol on purpose (`primary_for_chain` answers None) — the
    // capability vocabulary is where "the library can do it, no wired chain uses it" lives.
    match chain_kind {
        ChainKind::Tron => 65, // ECDSA (same shape as ETH)
        ChainKind::Sol | ChainKind::Apt | ChainKind::Sui | ChainKind::Near | ChainKind::Ada => 64,
        ChainKind::Ar => 512, // RSA-PSS, library-only
        _ => 96,              // maximum estimate for anything else
    }
}

/// Get the BIP-39 seed from a SignInput (P1-03: carried in SecretBytes — the Mnemonic path restores on the spot,
/// the stack buffer written by restore is taken over via take and the original copy zeroed)
/// The seed the signing path works from.
///
/// A2-07 (external audit 2026-11-19): the `SignInput::Seed` branch used to copy all 64 bytes
/// into a second `SecretBytes` owner. The audit's rule is that business code **borrows** a
/// secret it was handed (C17); manufacturing a second owner only doubles the copies to erase.
/// The mnemonic branch still owns its seed — it had to derive it from the words on the spot.
enum SeedMaterial<'a> {
    Borrowed(&'a [u8; 64]),
    Owned(SecretBytes<64>),
}

impl SeedMaterial<'_> {
    fn expose(&self) -> &[u8; 64] {
        match self {
            SeedMaterial::Borrowed(s) => s,
            SeedMaterial::Owned(s) => s.expose(),
        }
    }
}

fn resolve_seed<'a>(sign_input: &'a SignInput<'_>) -> Result<SeedMaterial<'a>> {
    let mut restored = [0u8; 64];
    match sign_input {
        SignInput::Seed { seed } => Ok(SeedMaterial::Borrowed(seed)),
        SignInput::Mnemonic {
            mnemonic,
            passphrase,
        } => {
            crate::business::restore_seed::restore_seed(mnemonic, passphrase, &mut restored)?;
            Ok(SeedMaterial::Owned(SecretBytes::take(&mut restored)))
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
///
/// XMR wallet key image records: none supplied. The XMR path then requires the
/// spent transfers to cover every wallet index below `max(selected_transfers)`
/// (see [`sign_with_entropy_records`]); anything else refuses to sign.
/// Sign a request **that was reviewed**, refusing unless the payload still hashes to the digest
/// the review face produced.
///
/// This is the "所审即所签" half of the two signing invariants (the other — "未授权不得签" — is the
/// product flow's, held by `flux/shell`; see [`crate::business::review_binding`]). The check runs
/// **before** anything else — no entropy staging, no workspace carve, no key material — so a
/// mismatch costs one SHA-256 and cannot leave a half-signed state behind.
///
/// Carriers that review and sign in one uninterrupted call, with the same buffer, get this for
/// free by construction; carriers that keep the payload across a reboot (or hand it through a
/// static buffer in C) are the ones this exists for.
///
/// # Errors
/// `InvariantViolation` when the payload is not the reviewed one. Every other error comes from
/// the underlying signing path, unchanged.
pub fn sign_reviewed(
    sign_input: SignInput<'_>,
    type_tag: crate::ur::ur_encode::UrTypeTag,
    ur_payload: &[u8],
    reviewed: crate::business::review_binding::ReviewedDigest,
    entropy: &[u8],
    output_buf: &mut [u8],
) -> Result<usize> {
    crate::business::review_binding::verify_reviewed(ur_payload, reviewed)?;
    sign_with_entropy(sign_input, type_tag, ur_payload, entropy, output_buf)
}

pub fn sign_with_entropy(
    sign_input: SignInput<'_>,
    type_tag: crate::ur::ur_encode::UrTypeTag,
    ur_payload: &[u8],
    entropy: &[u8],
    output_buf: &mut [u8],
) -> Result<usize> {
    sign_with_entropy_ws(
        sign_input,
        type_tag,
        ur_payload,
        &[],
        entropy,
        None,
        None,
        output_buf,
    )
}

/// True key image of one wallet transfer, retained from the pairing beat
/// (`xmr-output` → `xmr-keyimage`): the device derived it on-device while
/// answering the key image export and the flow hands it back to the sign leg.
///
/// `transfer_idx` is the WALLET transfer index (the position in the phone
/// wallet's `m_transfers`) — NOT the input/source position. `key_image` must
/// be the true key image of that transfer; the sign path takes non-selected
/// positions verbatim from these records (they are imported positionally into
/// the phone wallet), and cross-checks selected positions against its own
/// source derivation (mismatch = `KeyImageRecordMismatch`).
///
/// `repr(C)`: this is the C-ABI retention wire unit (the pairing leg hands
/// these to the flow, the sign leg takes them back) — the FFI casts caller
/// arrays zero-copy.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WalletKiRecord {
    pub transfer_idx: u32,
    /// fix37 wallet-fingerprint binding: first 8 bytes of
    /// keccak256(spend_pub || view_pub) of the wallet this record was computed
    /// for. The sign leg ignores records whose fingerprint does not match the
    /// signing session's wallet (treated as absent — the conservative gap
    /// filler covers), so a plate swap without a power cycle or a rescan that
    /// re-indexed transfers cannot feed another wallet's key images into this
    /// wallet's wire array.
    pub wallet_fp: [u8; 8],
    pub key_image: [u8; 32],
    /// I13 (WP3, decision 2026-10-31): the OUTPUT one-time address this
    /// key image belongs to — the mapping key `tx_key_images` ships under
    /// (keystone transfer.rs:1271 fill). Was dropped at parse time before
    /// this field existed, which capped the keystone retained leg at the
    /// spent sources (derivable out_pubs only). `repr(C)`: appending keeps
    /// in-order C initializers source-compatible (new tail zero-filled —
    /// every construction site MUST set it, the pins enforce).
    pub out_pub: [u8; 32],
}

/// Wallet fingerprint binding the pairing-beat KI retention to the wallet it
/// was computed for (fix37). `spend_pub`/`view_pub` are the request header's
/// validated `pk1`/`pk2` on the pairing side and the session-derived pubs on
/// the sign side — the same 64 bytes both ways.
pub fn wallet_fingerprint(spend_pub: &[u8; 32], view_pub: &[u8; 32]) -> [u8; 8] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(spend_pub);
    buf[32..].copy_from_slice(view_pub);
    let h = crate::encoding::keccak256::hash(&buf).expect("keccak256 64B");
    let mut fp = [0u8; 8];
    fp.copy_from_slice(&h[..8]);
    fp
}

/// Seed-facing variant (tests + any caller holding the seed): derives the
/// wallet's spend/view pubs exactly like the sign path (MoneroPath, account 0)
/// and fingerprints them. `seed` must be the SAME bytes the sign path derives
/// from (BIP-39 seed = 64B) -- derive() is length-sensitive (BIP-32 HMAC).
/// Primitive axis (S9 batch B): needs the Ed25519 key formula, so it does not exist in a
/// build without `prim-scalar-reduce`. Deliberately NOT stubbed to a zero fingerprint: this
/// value decides which wallet a retained key-image record belongs to (fix37), and a silent
/// all-zero answer would bind records to the wrong wallet instead of failing loudly.
#[cfg(feature = "prim-scalar-reduce")]
pub fn wallet_fingerprint_from_seed(seed: &[u8]) -> [u8; 8] {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    let path = crate::derivation::monero_reduce_scalar::MoneroPath::mainnet(0);
    let kp = crate::derivation::monero_reduce_scalar::derive(seed, &path)
        .expect("monero derive from seed");
    let spend_sec = crate::curve_primitive::ed25519::scalar_to_bytes(kp.spend_priv());
    let view_sec = crate::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv());
    let spend_pub = (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(spend_sec))
        .compress()
        .to_bytes();
    let view_pub = (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(view_sec))
        .compress()
        .to_bytes();
    wallet_fingerprint(&spend_pub, &view_pub)
}

/// Signing business entry with XMR wallet key image records (the tx2 wire fix:
/// `key_images` is wallet-transfer-indexed, wallet2.cpp:8074 gold semantics).
///
/// The signed container's outer `key_images` array is filled ONE TRUE key image
/// per wallet transfer position:
/// - selected (spent) transfer positions: derived from the tx sources
///   (authoritative);
/// - all other positions: taken from `ki_records` (the pairing-beat retention).
///
/// Any position below `max(selected_transfers, record indices) + 1` that
/// neither source can fill refuses the sign with `KeyImageRecordMissing` —
/// a placeholder would be written positionally into the phone wallet's
/// `m_transfers` by `import_key_images` and corrupt its spent-tracking.
pub fn sign_with_entropy_records(
    sign_input: SignInput<'_>,
    type_tag: crate::ur::ur_encode::UrTypeTag,
    ur_payload: &[u8],
    ki_records: &[WalletKiRecord],
    entropy: &[u8],
    output_buf: &mut [u8],
) -> Result<usize> {
    sign_with_entropy_ws(
        sign_input, type_tag, ur_payload, ki_records, entropy, None, None, output_buf,
    )
}

/// Workspace-aware signing entry (Z3.3a).
///
/// `ws = Some(...)` provisions the XMR flow from caller memory — forms
/// allocates nothing (the zero-heap path; flux owns its memory strategy).
/// `ws = None` falls back to the **transitional shell** (forms-side alloc,
/// policy-labeled C-ABI/legacy seam; removed when every caller provisions).
/// BTC/ETH chain layers ignore `ws` (their provisioning lands in the
/// chain-tile round).
///
/// `ki_records`: the pairing-beat wallet key image retention (XMR only; see
/// [`sign_with_entropy_records`]). Empty = no retention available.
#[allow(clippy::too_many_arguments)] // frozen legacy arg list + the scratch region
pub fn sign_with_entropy_ws(
    sign_input: SignInput<'_>,
    type_tag: crate::ur::ur_encode::UrTypeTag,
    ur_payload: &[u8],
    ki_records: &[WalletKiRecord],
    entropy: &[u8],
    ws: Option<&mut SignWs<'_>>,
    scratch: Option<&mut [u8]>,
    output_buf: &mut [u8],
) -> Result<usize> {
    sign_with_entropy_ws_views(
        crate::canonical::TailView::CAKE,
        sign_input,
        type_tag,
        ur_payload,
        ki_records,
        entropy,
        ws,
        scratch,
        output_buf,
    )
}

/// Wire-tail-view entry (WP3): the same signing flow, materializing the tail
/// per the caller's canonical view. The profile layer maps `ProfileId` onto
/// [`crate::canonical::TailView`] — the core consumes only canonical
/// (I1/C1: `profile::` never appears in core code).
#[allow(clippy::too_many_arguments)] // frozen view + the legacy arg list
pub fn sign_with_entropy_ws_views(
    tail: crate::canonical::TailView,
    sign_input: SignInput<'_>,
    type_tag: crate::ur::ur_encode::UrTypeTag,
    ur_payload: &[u8],
    ki_records: &[WalletKiRecord],
    entropy: &[u8],
    ws: Option<&mut SignWs<'_>>,
    scratch: Option<&mut [u8]>,
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

    // Chain axis (batch 1): a chain that is not compiled in has no arm, so its
    // request falls through to the trailing `_` arm below and answers the
    // PRE-EXISTING `ChainKindUnsupported` (C-ABI -10 `UnsupportedChainKind`).
    // No new error kind was introduced, and the gated-off arms are the exact
    // arms a chain-on build runs.
    match chain_kind {
        #[cfg(feature = "chain-btc")]
        crate::types::chain_kind::ChainKind::Btc => {
            // Z4-7d: the PSBT map pool lives in the caller's workspace (the
            // zero-heap path); without a ws the leaking convenience serves
            // the transitional shell.
            let (arena, recs) = match ws {
                Some(ws) => (Some(&mut *ws.psbt_arena), Some(&mut *ws.psbt_recs)),
                None => (None, None),
            };
            let finalize = matches!(type_tag, crate::ur::ur_encode::UrTypeTag::Psbt);
            let n = sign_btc(
                seed.expose(),
                payload,
                output_buf,
                arena,
                recs,
                entropy,
                finalize,
            )?;
            Ok(n)
        }
        #[cfg(feature = "chain-eth")]
        crate::types::chain_kind::ChainKind::Eth => {
            // E-3 P3: typed data is signed out of the caller's workspace (the pool the
            // EIP-712 container carves). The other ETH schemes ignore it.
            let region = match ws {
                Some(ws) => Some(&mut *ws.eip712),
                None => None,
            };
            let n = sign_eth(seed.expose(), payload, region, output_buf)?;
            Ok(n)
        }
        #[cfg(feature = "chain-xmr")]
        crate::types::chain_kind::ChainKind::Xmr => match ws {
            Some(ws) => {
                let n = sign_xmr_with_ws(
                    tail,
                    ws,
                    seed.expose(),
                    payload,
                    ki_records,
                    entropy,
                    scratch,
                    output_buf,
                )?;
                Ok(n)
            }
            #[cfg(feature = "alloc-fallback")]
            None => {
                let n = sign_xmr(
                    tail,
                    seed.expose(),
                    payload,
                    ki_records,
                    entropy,
                    output_buf,
                )?;
                Ok(n)
            }
            #[cfg(not(feature = "alloc-fallback"))]
            None => Err(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall)),
        },
        _ => {
            // Reached by the chains this build does not carry (and by the kinds
            // that never had an arm). Keep the arg list live so a build with no
            // chain at all still has one place that names what it dropped.
            // (Chain axis batch 3: `ws` is probed with `is_some()` — with every
            // chain off the workspace has no fields left to look at.)
            let _ = (
                seed.expose().len(),
                payload.len(),
                ws.is_some(),
                scratch.map(|s| s.len()),
                ki_records.len(),
                entropy.len(),
                tail.key_images,
                tail.tx_key_images,
                output_buf.len(),
            );
            Err(err(ShlosiloErrorKind::ChainKindUnsupported))
        }
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
    ///
    /// Chain axis (batch 3, §9.5-4): every region below that only the XMR flow
    /// touches is carried by `chain-xmr` — a chain-off build must not reserve
    /// caller memory for a flow it cannot reach (`types::caps` carries the
    /// matching constants, `SignWsLayout` the matching offsets, all on the same
    /// switch). BTC keeps `psbt_*`, ETH keeps `eip712`; with all three off the
    /// struct is field-less and the marker below keeps `'a` well-formed.
    #[cfg(feature = "chain-xmr")]
    pub plain: &'a mut [u8],
    /// The unsigned-tx model pools (same carve discipline as `UnsignedTxPools`).
    #[cfg(feature = "chain-xmr")]
    pub txes: &'a mut [Option<crate::chain::xmr::unsigned_txset::TxConstructionData<'a>>],
    #[cfg(feature = "chain-xmr")]
    pub sources: &'a mut [Option<crate::chain::xmr::unsigned_txset::TxSourceEntry>],
    #[cfg(feature = "chain-xmr")]
    pub splitted_dsts: &'a mut [crate::chain::xmr::unsigned_txset::TxDestinationEntry],
    #[cfg(feature = "chain-xmr")]
    pub selected_transfers: &'a mut [usize],
    #[cfg(feature = "chain-xmr")]
    pub extra: &'a mut [u8],
    #[cfg(feature = "chain-xmr")]
    pub dests: &'a mut [crate::chain::xmr::unsigned_txset::TxDestinationEntry],
    #[cfg(feature = "chain-xmr")]
    pub subaddr_indices: &'a mut [u32],
    // Z3.2b: sign-face backings (the SignedTxSet model + per-tx carve pools).
    #[cfg(feature = "chain-xmr")]
    pub ptx: &'a mut [Option<crate::chain::xmr::signed_txset::PendingTx<'a>>],
    /// Contiguous signed-tx wire slots (C-class: `TX_BYTES_SLOT_MAX` per tx,
    /// carved per iteration — the signer writes straight into the slot).
    #[cfg(feature = "chain-xmr")]
    pub tx_bytes: &'a mut [u8],
    #[cfg(feature = "chain-xmr")]
    pub ki: &'a mut [[u8; 32]],
    #[cfg(feature = "chain-xmr")]
    pub tki: &'a mut [crate::chain::xmr::signed_txset::TxKeyImageEntry],
    #[cfg(feature = "chain-xmr")]
    pub sel: &'a mut [u8],
    #[cfg(feature = "chain-xmr")]
    pub kstr: &'a mut [u8],
    /// Records-face dests (per-tx clones carved into the PendingTx records).
    #[cfg(feature = "chain-xmr")]
    pub record_dests: &'a mut [crate::chain::xmr::unsigned_txset::TxDestinationEntry],
    /// Z5.3 pool cut: BP+ prove multiexp scratch (caller memory, carved).
    #[cfg(feature = "chain-xmr")]
    pub bp_terms: &'a mut [(curve25519_dalek::Scalar, curve25519_dalek::EdwardsPoint)],
    /// Z5.3 D-cut: Straus scratch storage (raw bytes; the typed scratch is
    /// constructed from it at the call site).
    /// T-04 follow-up (2026-09-30): the straus/wip/CN storage is one
    /// `OverlayRegion` — phase-exclusive by type (see below), zeroized on the
    /// CN phase's drop.
    #[cfg(feature = "chain-xmr")]
    pub bp_overlay: OverlayRegion<'a>,
    /// Z4-7d: PSBT map pool (records + payload arena).
    #[cfg(feature = "chain-btc")]
    pub psbt_recs: &'a mut [crate::chain::btc::psbt::KvRec],
    /// E-3: the EIP-712 container region (`eip712_pool::WS_BYTES`). One span on purpose:
    /// the pool's internal divisions (nodes / types / fields / arena) are its own single
    /// home, so this layout reserves bytes and never re-derives the figure.
    #[cfg(feature = "chain-eth")]
    pub eip712: &'a mut [u8],
    /// Phase 4a: per-input signer tables (see `layout`), initialised by the carve.
    #[cfg(feature = "chain-xmr")]
    pub rings: &'a mut [[(
        monero_ed25519::CompressedPoint,
        monero_ed25519::CompressedPoint,
    ); crate::types::caps::RING_MAX]],
    #[cfg(feature = "chain-xmr")]
    pub tx_inputs: &'a mut [crate::chain::xmr::transaction::TxInput],
    #[cfg(feature = "chain-xmr")]
    pub ring_lens: &'a mut [usize],
    #[cfg(feature = "chain-btc")]
    pub psbt_arena: &'a mut [u8],
    /// Chain axis (batch 3): with every chain switched off no region is left —
    /// all of them belong to a chain. The marker keeps the lifetime parameter
    /// well-formed (a struct cannot carry an unused `'a`) at zero bytes: it is
    /// never carved and never reported by `SignWsLayout::compute()`.
    #[cfg(not(any(feature = "chain-btc", feature = "chain-eth", feature = "chain-xmr")))]
    _no_chain: core::marker::PhantomData<&'a ()>,
}

/// T-04 follow-up (2026-09-30): phase-exclusive handle over the shared
/// straus/wip/CN overlay region. `enter_cn` and `enter_bp` both re-borrow
/// `&mut self`, so the borrow checker FORBIDS holding both phases at once —
/// the overlay's exclusive lifetime is structural, not a convention. The CN
/// phase guard zeroizes on drop, covering every return/Err/unwind exit path
/// (abort and hard-fault paths end in a warm reset, which scrubs SRAM on this
/// chip — the r/p noinit experiments, 2026-09-30).
///
/// Chain axis (batch 3): the overlay is the XMR phase time-share (CN scratchpad
/// vs BP+ prove tables), so the type and its phase views follow `chain-xmr`.
#[cfg(feature = "chain-xmr")]
pub struct OverlayRegion<'a> {
    raw: &'a mut [u8],
}

/// The CN-V0 derivation phase view (the whole region; secret-bearing).
#[cfg(feature = "chain-xmr")]
pub struct CnScratch<'a>(&'a mut [u8]);

#[cfg(feature = "chain-xmr")]
impl<'a> core::ops::Deref for CnScratch<'a> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0
    }
}

#[cfg(feature = "chain-xmr")]
impl<'a> core::ops::DerefMut for CnScratch<'a> {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

#[cfg(feature = "chain-xmr")]
impl<'a> Drop for CnScratch<'a> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self.0);
    }
}

/// The BP+ prove phase view: disjoint straus + wip slices of the region.
#[cfg(feature = "chain-xmr")]
pub struct BpScratch<'a> {
    pub straus: &'a mut [u8],
    pub wip: &'a mut [u8],
}

#[cfg(feature = "chain-xmr")]
impl<'a> OverlayRegion<'a> {
    pub fn new(raw: &'a mut [u8]) -> Self {
        Self { raw }
    }

    /// CN-V0 key-derivation phase. The guard zeroizes the region on drop.
    pub fn enter_cn(&mut self) -> CnScratch<'_> {
        CnScratch(self.raw)
    }

    /// BP+ prove phase: `[straus | wip(+pad)]` views of the same region.
    pub fn enter_bp(&mut self) -> BpScratch<'_> {
        let (straus, wip) = self
            .raw
            .split_at_mut(crate::types::caps::SIGN_WS_BP_STRAUS_BYTES);
        BpScratch { straus, wip }
    }
}

/// Z3.3b: the sign-workspace layout — the SINGLE source of truth behind both
/// the capacity query (`shlosilo_sign_ws_len`) and the actual carve
/// (`carve_sign_ws`). C-ABI workspace contract 3: the reported capacity and the
/// carved capacity come from this one computation; `sign_ws_layout_consistency`
/// pins the pairing.
pub struct SignWsLayout {
    /// Bytes the caller must provide (`regions` + worst-case base shift).
    pub total: usize,
    /// Bytes the carve writes starting at the *aligned* base: `total` minus the shift
    /// allowance. Kept separate so a caller that allocates exactly `total` always fits,
    /// whatever alignment its buffer starts at.
    regions: usize,
    #[cfg(feature = "chain-xmr")]
    plain: usize,
    #[cfg(feature = "chain-xmr")]
    txes: usize,
    #[cfg(feature = "chain-xmr")]
    sources: usize,
    #[cfg(feature = "chain-xmr")]
    splits: usize,
    #[cfg(feature = "chain-xmr")]
    sel: usize,
    #[cfg(feature = "chain-xmr")]
    extra: usize,
    #[cfg(feature = "chain-xmr")]
    dests: usize,
    #[cfg(feature = "chain-xmr")]
    subidx: usize,
    #[cfg(feature = "chain-xmr")]
    ptx: usize,
    #[cfg(feature = "chain-xmr")]
    tx_bytes: usize,
    #[cfg(feature = "chain-xmr")]
    ki: usize,
    #[cfg(feature = "chain-xmr")]
    tki: usize,
    #[cfg(feature = "chain-xmr")]
    sel_out: usize,
    #[cfg(feature = "chain-xmr")]
    kstr: usize,
    #[cfg(feature = "chain-xmr")]
    record_dests: usize,
    #[cfg(feature = "chain-xmr")]
    pub bp_terms: usize,
    #[cfg(feature = "chain-xmr")]
    pub bp_straus: usize,
    #[cfg(feature = "chain-xmr")]
    pub cn_scratch: usize,
    #[cfg(feature = "chain-xmr")]
    pub bp_wip: usize,
    #[cfg(feature = "chain-btc")]
    pub psbt_recs: usize,
    #[cfg(feature = "chain-btc")]
    pub psbt_arena: usize,
    #[cfg(feature = "chain-eth")]
    pub eip712: usize,
    // Phase 4a: per-input signing tables, caller-carved so the task stack does not grow
    // with the input ceiling (`limits::XMR_INPUTS_MAX`).
    #[cfg(feature = "chain-xmr")]
    pub rings: usize,
    #[cfg(feature = "chain-xmr")]
    pub tx_inputs: usize,
    #[cfg(feature = "chain-xmr")]
    pub ring_lens: usize,
}

/// Alignment the workspace **base** must have. `ws_next` computes offsets as if the
/// buffer started here, so the carve aligns the base up to it and `total` carries the
/// worst-case slack. Without this, a caller whose buffer starts at an odd address
/// (stack slice, offset sub-slice) would get misaligned typed spans - undefined
/// behaviour, and the `tables_are_aligned_for_any_buffer_offset` pin aborted on it
/// before the fix.
pub(crate) const SIGN_WS_BASE_ALIGN: usize = 16;

fn ws_next(off: &mut usize, align: usize, size: usize) -> usize {
    let start = (*off + align - 1) & !(align - 1);
    *off = start + size;
    start
}

impl SignWsLayout {
    pub fn compute() -> Self {
        #[cfg(feature = "chain-xmr")]
        use crate::chain::xmr::signed_txset::{PendingTx, TxKeyImageEntry};
        #[cfg(feature = "chain-xmr")]
        use crate::chain::xmr::unsigned_txset::{
            TxConstructionData, TxDestinationEntry, TxSourceEntry,
        };
        use crate::types::caps as c;
        // Offsets are computed from an origin the carve aligns up to SIGN_WS_BASE_ALIGN;
        // the worst-case shift is carried by `total` (see the tail below).
        //
        // Chain axis (batch 3, §9.5-4): each region is carved only when the chain that
        // owns it is compiled in. Order is unchanged, so the all-on layout — and every
        // offset the device pins measure — is bit-identical to before; a chain-off build
        // hands the caller a smaller number because the regions it cannot reach are not
        // *there* rather than merely unused.
        let mut off = 0usize;
        #[cfg(feature = "chain-xmr")]
        let plain = ws_next(&mut off, core::mem::align_of::<u8>(), c::SIGN_WS_PLAIN);
        #[cfg(feature = "chain-xmr")]
        let txes = ws_next(
            &mut off,
            core::mem::align_of::<Option<TxConstructionData<'static>>>(),
            core::mem::size_of::<Option<TxConstructionData<'static>>>() * c::SIGN_WS_TXES,
        );
        #[cfg(feature = "chain-xmr")]
        let sources = ws_next(
            &mut off,
            core::mem::align_of::<Option<TxSourceEntry>>(),
            core::mem::size_of::<Option<TxSourceEntry>>() * c::SIGN_WS_SOURCES,
        );
        #[cfg(feature = "chain-xmr")]
        let splits = ws_next(
            &mut off,
            core::mem::align_of::<TxDestinationEntry>(),
            core::mem::size_of::<TxDestinationEntry>() * c::SIGN_WS_SPLITS,
        );
        #[cfg(feature = "chain-xmr")]
        let sel = ws_next(
            &mut off,
            core::mem::align_of::<usize>(),
            core::mem::size_of::<usize>() * c::SIGN_WS_SEL,
        );
        #[cfg(feature = "chain-xmr")]
        let extra = ws_next(&mut off, core::mem::align_of::<u8>(), c::SIGN_WS_EXTRA);
        #[cfg(feature = "chain-xmr")]
        let dests = ws_next(
            &mut off,
            core::mem::align_of::<TxDestinationEntry>(),
            core::mem::size_of::<TxDestinationEntry>() * c::SIGN_WS_DESTS,
        );
        #[cfg(feature = "chain-xmr")]
        let subidx = ws_next(
            &mut off,
            core::mem::align_of::<u32>(),
            core::mem::size_of::<u32>() * c::SIGN_WS_SUBIDX,
        );
        #[cfg(feature = "chain-xmr")]
        let ptx = ws_next(
            &mut off,
            core::mem::align_of::<Option<PendingTx<'static>>>(),
            core::mem::size_of::<Option<PendingTx<'static>>>() * c::SIGN_WS_PTX,
        );
        #[cfg(feature = "chain-xmr")]
        let tx_bytes = ws_next(&mut off, core::mem::align_of::<u8>(), c::SIGN_WS_TX_BYTES);
        #[cfg(feature = "chain-xmr")]
        let ki = ws_next(
            &mut off,
            core::mem::align_of::<[u8; 32]>(),
            core::mem::size_of::<[u8; 32]>() * c::SIGN_WS_KI,
        );
        #[cfg(feature = "chain-xmr")]
        let tki = ws_next(
            &mut off,
            core::mem::align_of::<TxKeyImageEntry>(),
            core::mem::size_of::<TxKeyImageEntry>() * c::SIGN_WS_TKI,
        );
        #[cfg(feature = "chain-xmr")]
        let sel_out = ws_next(&mut off, core::mem::align_of::<u8>(), c::SIGN_WS_SEL_OUT);
        #[cfg(feature = "chain-xmr")]
        let kstr = ws_next(&mut off, core::mem::align_of::<u8>(), c::SIGN_WS_KSTR);
        #[cfg(feature = "chain-xmr")]
        let record_dests = ws_next(
            &mut off,
            core::mem::align_of::<TxDestinationEntry>(),
            core::mem::size_of::<TxDestinationEntry>() * c::SIGN_WS_RECORD_DESTS,
        );
        #[cfg(feature = "chain-xmr")]
        let bp_terms = ws_next(
            &mut off,
            core::mem::align_of::<(curve25519_dalek::Scalar, curve25519_dalek::EdwardsPoint)>(),
            core::mem::size_of::<(curve25519_dalek::Scalar, curve25519_dalek::EdwardsPoint)>()
                * c::SIGN_WS_BP_TERMS,
        );
        // T-04 follow-up (2026-09-30): the CN-V0 scratchpad OVERLAYS the
        // straus+wip region (phase time-share: decrypt key derivation ends
        // before the prove; the CN core zeroes the region on exit, restoring
        // the carve's documented zero-fill state). u128 alignment governs the
        // shared slot; the fit is pinned by a const assert in `types::caps`.
        #[cfg(feature = "chain-xmr")]
        let bp_straus = ws_next(
            &mut off,
            core::mem::align_of::<u128>(),
            c::SIGN_WS_BP_STRAUS_BYTES,
        );
        #[cfg(feature = "chain-xmr")]
        let cn_scratch = bp_straus;
        /* wip carve padded to the overlay region tail (WipScratch::new takes
         * "at least" storage; the pad is the CN overlay's fit margin). */
        #[cfg(feature = "chain-xmr")]
        let bp_wip = ws_next(
            &mut off,
            core::mem::align_of::<u64>(),
            c::SIGN_WS_BP_OVERLAY_BYTES - c::SIGN_WS_BP_STRAUS_BYTES,
        );
        #[cfg(feature = "chain-btc")]
        let psbt_recs = ws_next(
            &mut off,
            core::mem::align_of::<crate::chain::btc::psbt::KvRec>(),
            core::mem::size_of::<crate::chain::btc::psbt::KvRec>() * c::SIGN_WS_PSBT_RECS,
        );
        #[cfg(feature = "chain-btc")]
        let psbt_arena = ws_next(&mut off, core::mem::align_of::<u8>(), c::SIGN_WS_PSBT_ARENA);
        // E-3: the typed-data container. Its own alignment (payload offsets are u32), and
        // its size comes from the pool module, which owns the record geometry.
        #[cfg(feature = "chain-eth")]
        let eip712 = ws_next(
            &mut off,
            core::mem::align_of::<crate::chain::eth::eip712_pool::Eip712Node>(),
            crate::chain::eth::eip712_pool::WS_BYTES,
        );
        // Phase 4a: the three per-input tables (previously stack arrays in the signer).
        #[cfg(feature = "chain-xmr")]
        let rings = ws_next(
            &mut off,
            core::mem::align_of::<
                [(
                    monero_ed25519::CompressedPoint,
                    monero_ed25519::CompressedPoint,
                ); c::RING_MAX],
            >(),
            core::mem::size_of::<
                [(
                    monero_ed25519::CompressedPoint,
                    monero_ed25519::CompressedPoint,
                ); c::RING_MAX],
            >() * crate::limits::XMR_INPUTS_MAX,
        );
        #[cfg(feature = "chain-xmr")]
        let tx_inputs = ws_next(
            &mut off,
            core::mem::align_of::<crate::chain::xmr::transaction::TxInput>(),
            core::mem::size_of::<crate::chain::xmr::transaction::TxInput>()
                * crate::limits::XMR_INPUTS_MAX,
        );
        #[cfg(feature = "chain-xmr")]
        let ring_lens = ws_next(
            &mut off,
            core::mem::align_of::<usize>(),
            core::mem::size_of::<usize>() * crate::limits::XMR_INPUTS_MAX,
        );
        // Trailing pad so the total satisfies the widest alignment, plus the worst-case
        // base shift: the capacity query must be a *sufficient* number, or a caller that
        // allocates exactly `total` could fail to carve an unaligned buffer.
        let regions = ws_next(&mut off, core::mem::align_of::<usize>(), 0);
        let total = regions + (SIGN_WS_BASE_ALIGN - 1);
        SignWsLayout {
            total,
            regions,
            #[cfg(feature = "chain-xmr")]
            plain,
            #[cfg(feature = "chain-xmr")]
            txes,
            #[cfg(feature = "chain-xmr")]
            sources,
            #[cfg(feature = "chain-xmr")]
            splits,
            #[cfg(feature = "chain-xmr")]
            sel,
            #[cfg(feature = "chain-xmr")]
            extra,
            #[cfg(feature = "chain-xmr")]
            dests,
            #[cfg(feature = "chain-xmr")]
            subidx,
            #[cfg(feature = "chain-xmr")]
            ptx,
            #[cfg(feature = "chain-xmr")]
            tx_bytes,
            #[cfg(feature = "chain-xmr")]
            ki,
            #[cfg(feature = "chain-xmr")]
            tki,
            #[cfg(feature = "chain-xmr")]
            sel_out,
            #[cfg(feature = "chain-xmr")]
            kstr,
            #[cfg(feature = "chain-xmr")]
            record_dests,
            #[cfg(feature = "chain-xmr")]
            bp_terms,
            #[cfg(feature = "chain-xmr")]
            bp_straus,
            #[cfg(feature = "chain-xmr")]
            cn_scratch,
            #[cfg(feature = "chain-xmr")]
            bp_wip,
            #[cfg(feature = "chain-btc")]
            psbt_recs,
            #[cfg(feature = "chain-btc")]
            psbt_arena,
            #[cfg(feature = "chain-eth")]
            eip712,
            #[cfg(feature = "chain-xmr")]
            rings,
            #[cfg(feature = "chain-xmr")]
            tx_inputs,
            #[cfg(feature = "chain-xmr")]
            ring_lens,
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
    #[cfg(feature = "chain-xmr")]
    use crate::chain::xmr::signed_txset::{PendingTx, TxKeyImageEntry};
    #[cfg(feature = "chain-xmr")]
    use crate::chain::xmr::unsigned_txset::{
        TxConstructionData, TxDestinationEntry, TxSourceEntry,
    };
    use crate::types::caps as c;
    let l = SignWsLayout::compute();
    if buf.len() < l.total {
        return None;
    }
    // Align the base up to SIGN_WS_BASE_ALIGN; `total` includes the worst-case slack, so
    // this can never run past the caller's buffer.
    let raw = buf.as_mut_ptr() as usize;
    let aligned = (raw + SIGN_WS_BASE_ALIGN - 1) & !(SIGN_WS_BASE_ALIGN - 1);
    if aligned + l.regions > raw + buf.len() {
        return None;
    }
    let base: *mut u8 = aligned as *mut u8;
    // Zero the workspace we hand out (from the aligned base, for the layout's length).
    // SAFETY: the bounds were just checked above; the span is inside `buf`.
    unsafe { core::ptr::write_bytes(base, 0u8, l.regions) };
    // SAFETY: offsets come from SignWsLayout::compute (the same computation the
    // capacity query reports — contract 3); each span is alignment-padded there
    // and disjoint by construction; every element is initialized below before
    // the slices are handed out. The spans all derive from one base pointer so
    // the borrow checker sees disjoint raw derivations, not competing &muts.
    unsafe fn at<'a, T>(base: *mut u8, off: usize, count: usize) -> &'a mut [T] {
        // SAFETY: caller (this carve) guarantees `off`/`count` come from
        // SignWsLayout::compute and stay inside one base allocation.
        unsafe { core::slice::from_raw_parts_mut(base.add(off) as *mut T, count) }
    }
    #[cfg(feature = "chain-xmr")]
    let txes: &mut [Option<TxConstructionData>] = unsafe { at(base, l.txes, c::SIGN_WS_TXES) };
    #[cfg(feature = "chain-xmr")]
    for s in txes.iter_mut() {
        unsafe { core::ptr::write(s, None) };
    }
    #[cfg(feature = "chain-xmr")]
    let sources: &mut [Option<TxSourceEntry>] = unsafe { at(base, l.sources, c::SIGN_WS_SOURCES) };
    #[cfg(feature = "chain-xmr")]
    for s in sources.iter_mut() {
        unsafe { core::ptr::write(s, None) };
    }
    #[cfg(feature = "chain-xmr")]
    let splits: &mut [TxDestinationEntry] = unsafe { at(base, l.splits, c::SIGN_WS_SPLITS) };
    #[cfg(feature = "chain-xmr")]
    for s in splits.iter_mut() {
        unsafe { core::ptr::write(s, TxDestinationEntry::default()) };
    }
    #[cfg(feature = "chain-xmr")]
    let dests: &mut [TxDestinationEntry] = unsafe { at(base, l.dests, c::SIGN_WS_DESTS) };
    #[cfg(feature = "chain-xmr")]
    for s in dests.iter_mut() {
        unsafe { core::ptr::write(s, TxDestinationEntry::default()) };
    }
    #[cfg(feature = "chain-xmr")]
    let record_dests: &mut [TxDestinationEntry] =
        unsafe { at(base, l.record_dests, c::SIGN_WS_RECORD_DESTS) };
    #[cfg(feature = "chain-xmr")]
    for s in record_dests.iter_mut() {
        unsafe { core::ptr::write(s, TxDestinationEntry::default()) };
    }
    #[cfg(feature = "chain-xmr")]
    let ptx: &mut [Option<PendingTx>] = unsafe { at(base, l.ptx, c::SIGN_WS_PTX) };
    #[cfg(feature = "chain-xmr")]
    for s in ptx.iter_mut() {
        unsafe { core::ptr::write(s, None) };
    }
    #[cfg(feature = "chain-xmr")]
    let tki: &mut [TxKeyImageEntry] = unsafe { at(base, l.tki, c::SIGN_WS_TKI) };
    #[cfg(feature = "chain-xmr")]
    for s in tki.iter_mut() {
        unsafe { core::ptr::write(s, TxKeyImageEntry::default()) };
    }
    // POD spans: the fill(0) above is their initialization. Chain axis (batch 3):
    // each span is carved only when its chain is compiled in — see
    // `SignWsLayout::compute`, which computes the matching offsets.
    #[cfg(feature = "chain-xmr")]
    let plain: &mut [u8] = unsafe { at(base, l.plain, c::SIGN_WS_PLAIN) };
    #[cfg(feature = "chain-xmr")]
    let sel: &mut [usize] = unsafe { at(base, l.sel, c::SIGN_WS_SEL) };
    #[cfg(feature = "chain-xmr")]
    let extra: &mut [u8] = unsafe { at(base, l.extra, c::SIGN_WS_EXTRA) };
    #[cfg(feature = "chain-xmr")]
    let subidx: &mut [u32] = unsafe { at(base, l.subidx, c::SIGN_WS_SUBIDX) };
    #[cfg(feature = "chain-xmr")]
    let tx_bytes: &mut [u8] = unsafe { at(base, l.tx_bytes, c::SIGN_WS_TX_BYTES) };
    #[cfg(feature = "chain-xmr")]
    let ki: &mut [[u8; 32]] = unsafe { at(base, l.ki, c::SIGN_WS_KI) };
    #[cfg(feature = "chain-xmr")]
    let sel_out: &mut [u8] = unsafe { at(base, l.sel_out, c::SIGN_WS_SEL_OUT) };
    #[cfg(feature = "chain-xmr")]
    let kstr: &mut [u8] = unsafe { at(base, l.kstr, c::SIGN_WS_KSTR) };
    // Z5.3 pool cut: BP+ prove scratch (POD span — the whole-carve zero fill
    // is its documented initialization; the prove chain overwrites entries
    // before reading them).
    #[cfg(feature = "chain-xmr")]
    let bp_terms: &mut [(curve25519_dalek::Scalar, curve25519_dalek::EdwardsPoint)] =
        unsafe { at(base, l.bp_terms, c::SIGN_WS_BP_TERMS) };
    /* T-04: one phase-exclusive region over the overlaid slot (the layout's
     * cn_scratch offset == bp_straus offset is pinned in tests). */
    #[cfg(feature = "chain-xmr")]
    let bp_overlay: OverlayRegion<'_> =
        OverlayRegion::new(unsafe { at(base, l.bp_straus, c::SIGN_WS_BP_OVERLAY_BYTES) });
    #[cfg(feature = "chain-btc")]
    let psbt_recs: &mut [crate::chain::btc::psbt::KvRec] =
        unsafe { at(base, l.psbt_recs, c::SIGN_WS_PSBT_RECS) };
    #[cfg(feature = "chain-btc")]
    let psbt_arena: &mut [u8] = unsafe { at(base, l.psbt_arena, c::SIGN_WS_PSBT_ARENA) };
    // E-3: plain bytes — the pool carves its spans out of this region itself, so the
    // workspace only has to leave it zeroed (the whole-carve fill above already did).
    #[cfg(feature = "chain-eth")]
    let eip712: &mut [u8] = unsafe { at(base, l.eip712, crate::chain::eth::eip712_pool::WS_BYTES) };
    // Phase 4a: initialise-on-carve, never read-before-write. A single pass over the
    // input ceiling buys plain `&mut` slices in the signing core instead of a
    // MaybeUninit contract.
    #[cfg(feature = "chain-xmr")]
    type RingRow = [(
        monero_ed25519::CompressedPoint,
        monero_ed25519::CompressedPoint,
    ); crate::types::caps::RING_MAX];
    #[cfg(feature = "chain-xmr")]
    let rings: &mut [RingRow] = unsafe { at(base, l.rings, crate::limits::XMR_INPUTS_MAX) };
    #[cfg(feature = "chain-xmr")]
    for row in rings.iter_mut() {
        let zero = monero_ed25519::CompressedPoint::from([0u8; 32]);
        for slot in row.iter_mut() {
            unsafe { core::ptr::write(slot, (zero, zero)) };
        }
    }
    #[cfg(feature = "chain-xmr")]
    let tx_inputs: &mut [crate::chain::xmr::transaction::TxInput] =
        unsafe { at(base, l.tx_inputs, crate::limits::XMR_INPUTS_MAX) };
    #[cfg(feature = "chain-xmr")]
    for slot in tx_inputs.iter_mut() {
        unsafe {
            core::ptr::write(
                slot,
                crate::chain::xmr::transaction::TxInput::new(heapless::Vec::new(), [0u8; 32]),
            )
        };
    }
    #[cfg(feature = "chain-xmr")]
    let ring_lens: &mut [usize] = unsafe { at(base, l.ring_lens, crate::limits::XMR_INPUTS_MAX) };
    #[cfg(feature = "chain-xmr")]
    ring_lens.fill(0);
    Some(SignWs {
        #[cfg(feature = "chain-xmr")]
        plain,
        #[cfg(feature = "chain-xmr")]
        txes,
        #[cfg(feature = "chain-xmr")]
        sources,
        #[cfg(feature = "chain-xmr")]
        splitted_dsts: splits,
        #[cfg(feature = "chain-xmr")]
        selected_transfers: sel,
        #[cfg(feature = "chain-xmr")]
        extra,
        #[cfg(feature = "chain-xmr")]
        dests,
        #[cfg(feature = "chain-xmr")]
        subaddr_indices: subidx,
        #[cfg(feature = "chain-xmr")]
        ptx,
        #[cfg(feature = "chain-xmr")]
        tx_bytes,
        #[cfg(feature = "chain-xmr")]
        ki,
        #[cfg(feature = "chain-xmr")]
        tki,
        #[cfg(feature = "chain-xmr")]
        sel: sel_out,
        #[cfg(feature = "chain-xmr")]
        kstr,
        #[cfg(feature = "chain-xmr")]
        record_dests,
        #[cfg(feature = "chain-xmr")]
        bp_terms,
        #[cfg(feature = "chain-xmr")]
        bp_overlay,
        #[cfg(feature = "chain-btc")]
        psbt_recs,
        #[cfg(feature = "chain-btc")]
        psbt_arena,
        #[cfg(feature = "chain-eth")]
        eip712,
        #[cfg(feature = "chain-xmr")]
        rings,
        #[cfg(feature = "chain-xmr")]
        tx_inputs,
        #[cfg(feature = "chain-xmr")]
        ring_lens,
        #[cfg(not(any(feature = "chain-btc", feature = "chain-eth", feature = "chain-xmr")))]
        _no_chain: core::marker::PhantomData,
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
#[cfg(all(feature = "chain-xmr", feature = "tx-phase-timing-ffi"))]
use crate::tx_phase_hook::PhaseProbe;

#[allow(clippy::too_many_arguments)] // frozen arg list + the scratch region
#[cfg(feature = "chain-xmr")]
fn sign_xmr_with_ws<'a>(
    tail: crate::canonical::TailView,
    ws: &mut SignWs<'a>,
    seed: &[u8],
    encrypted_unsigned: &[u8],
    ki_records: &[WalletKiRecord],
    entropy: &[u8],
    mut scratch: Option<&mut [u8]>,
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
    // fix37 wallet fingerprint of THIS session's wallet: retention records are
    // bound to it on the pairing leg; records with a foreign fingerprint are
    // ignored below (conservative filler covers).
    let session_fp: [u8; 8] = {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use curve25519_dalek::scalar::Scalar;
        let spend_pub = (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*spend_sec))
            .compress()
            .to_bytes();
        let view_pub = (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*view_sec))
            .compress()
            .to_bytes();
        wallet_fingerprint(&spend_pub, &view_pub)
    };
    // CN computed only once for the same view_sk (shared by decrypt + encrypt; the 2MB scratchpad dominates on device)
    // Audit #12 P1-02: the CN key is an owner from creation (Zeroizing); the helper returns the owner.
    // T-04 follow-up: the CN-V0 derivation borrows the overlay region in
    // its CN phase — the guard zeroizes the region on drop (every
    // return/Err/unwind path; abort/fault paths end in a warm reset, which
    // scrubs SRAM on this chip).
    let mut cn = ws.bp_overlay.enter_cn();
    let cn_key = crate::chain::xmr::unsigned_txset::chacha_key_from_view_sk(&view_sec, &mut cn)?;
    drop(cn);

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
    // key_images is wallet-transfer-indexed (wallet2.cpp:8074 gold: one true
    // key image per wallet transfer position; the phone's import_key_images
    // writes every entry positionally into m_transfers). ki_span covers every
    // position the wire array must carry: each tx's selected (spent) transfer
    // indices. fix37: retention records NEVER stretch the span — a stale
    // cross-wallet/cross-state record used to stretch it past the wallet's
    // transfer count, and 0.18.5.3's import_key_images silently returns false
    // on "key images greater than the number of transfers" (amplified by the
    // monero_c UR entry's Status_Ok swallow, see MrCyjaneK/monero_c#197).
    // Records beyond the span are dropped at placement time.
    let mut ki_span = 0usize;
    for slot in unsigned_tx.txes.iter().flatten() {
        for &t in slot.selected_transfers.iter() {
            if t > u8::MAX as usize {
                // ptx.selected_transfers is u8-carried on the wire (varint-
                // written copy); above 255 the copy would silently truncate.
                return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            ki_span = ki_span.max(t + 1);
        }
    }
    if ws.ki.len() < ki_span {
        return Err(cap_err(ki_span));
    }
    if ws.tki.len() < total_dsts + total_sources {
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
    // Poison pre-fill (0xAA sentinel — the zero-masking discipline: never let
    // a zero stand in for "unfilled"). Any poison survivor at the end refuses
    // the sign (KeyImageRecordMissing) instead of shipping a placeholder that
    // the phone would import into m_transfers.
    const KI_POISON: [u8; 32] = [0xAAu8; 32];
    for _ in 0..ki_span {
        ki_sv.push(KI_POISON).map_err(|_| cap_err(ki_span))?;
    }
    // Pairing-beat retention first (non-selected positions come from here).
    // fix37: records are wallet-fingerprint-bound — a record from another
    // wallet (plate swapped without a power cycle, records surviving in the
    // flux workspace) or from a stale transfer-indexing state is treated as
    // ABSENT: the conservative filler covers, and the mismatch guard below
    // still refuses a record that contradicts a freshly derived value.
    // WP3 canonical staging (I13, decision 2026-10-31): the retained
    // leg = the FULL fp-matched retention set — records carry their out_pub
    // mapping key now, so every wallet transfer (spent or not) can ship under
    // keystone's transfers.details fill shape (transfer.rs:1271). Collected
    // in the records loop (transfer_idx order), appended AFTER the new
    // outputs (keystone's 1250-then-1271 serialization order).
    let mut retained_stage =
        [crate::canonical::SignKiEntry::default(); crate::types::caps::SIGN_WS_RETAINED];
    let mut retained_n = 0usize;
    for r in ki_records {
        if r.wallet_fp != session_fp {
            continue;
        }
        // I13: every fp-matched record rides the retained leg (keystone's
        // transfer-fill map) — BEFORE the span tightening below, which only
        // bounds the positional array. Overflow refuses the sign: the pairing
        // record pool is 64 (SIGN_WS_RETAINED), a larger batch is a contract
        // violation, not something to silently truncate.
        if retained_n >= retained_stage.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall));
        }
        retained_stage[retained_n] = crate::canonical::SignKiEntry {
            one_time_pub: r.out_pub,
            key_image: r.key_image,
            wallet_idx: Some(r.transfer_idx),
        };
        retained_n += 1;
        let idx = r.transfer_idx as usize;
        if idx >= ki_span {
            continue; // fix37 span tightening: beyond this tx's reach — dropped
        }
        if ki_sv[idx] != KI_POISON && ki_sv[idx] != r.key_image {
            return Err(ShlosiloError::new(
                ShlosiloErrorKind::KeyImageRecordMismatch,
            ));
        }
        ki_sv[idx] = r.key_image;
    }
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
        // Phase 4a: take the per-input tables out of the workspace for this tx (same
        // take-split idiom as tx_bytes/bp_terms, so the 'a lifetime survives).
        let ws_rings = core::mem::take(&mut ws.rings);
        let ws_tx_inputs = core::mem::take(&mut ws.tx_inputs);
        let ws_ring_lens = core::mem::take(&mut ws.ring_lens);
        let bp_terms_slot = &mut ws_bp_terms;
        // T-04 follow-up: BP+ prove phase — the borrow checker keeps the CN
        // phase guard from overlapping this borrow (phase exclusivity is
        // structural).
        let bp = ws.bp_overlay.enter_bp();
        // The BP+ multiexp tables are transient: prefer the caller's scratch
        // region (a carrier places it in its fastest memory) and fall back to
        // carving the same capacity out of this workspace, which lives in the
        // bulk memory tier. Identical math, identical output.
        let (bp_straus_bytes, bp_straus_cap): (&mut [u8], usize) = match scratch.as_deref_mut() {
            Some(region) => (region, crate::types::caps::SIGN_BP_CHUNK_TERMS),
            None => (bp.straus, crate::types::caps::SIGN_WS_BP_CHUNK_MAX),
        };
        let mut bp_straus =
            match curve25519_dalek::scratch::StrausScratch::new(bp_straus_bytes, bp_straus_cap)
                .map(|s| s.with_chunk_terms(crate::types::caps::SIGN_BP_CHUNK_TERMS))
            {
                Ok(s) => s,
                Err(_) => {
                    return Err(crate::error::ShlosiloError::new(
                        crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
                    ))
                }
            };
        let mut bp_wip = match monero_bulletproofs::WipScratch::new(
            bp.wip,
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
            crate::chain::xmr::tx_signer::InputTables {
                rings: &mut *ws_rings,
                tx_inputs: &mut *ws_tx_inputs,
                ring_lens: &mut *ws_ring_lens,
            },
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
        // key images: already present in the signed wire; rebuild the `<hex> ` string + outer list here.
        // Wire contract (tx2 fix): the OUTER key_images array is wallet-
        // transfer-indexed — source j's key image lands at wallet index
        // selected_transfers[j], not at position j (wallet2.cpp:8074 gold).
        let src_count = tx_data.sources.iter().flatten().count();
        if src_count != tx_data.selected_transfers.len()
            || src_count > crate::chain::xmr::tx_signer::MAX_INPUTS_TRACKED
        {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        // Pass 1: derive each source's key image exactly once (the derivation is
        // not idempotent — single call per source preserved) and stage it in a
        // fixed stack array. The outer export list keeps the wallet-transfer-
        // indexed placement (wallet2.cpp:8074 gold: one true key image per
        // wallet transfer position).
        let mut ki_src = [[0u8; 32]; crate::chain::xmr::tx_signer::MAX_INPUTS_TRACKED];
        let mut n_src = 0usize;
        // Phase 12 splits phase 6: this loop is the only arithmetic in the window (per-source
        // `derive_input_from_source`), so `6 - 12` is everything else (sort + `<hex> ` string).
        #[cfg(feature = "tx-phase-timing-ffi")]
        let mut px12 = PhaseProbe::start(12);
        for (src, &sel) in tx_data
            .sources
            .iter()
            .flatten()
            .zip(tx_data.selected_transfers.iter())
        {
            let (ki, _off) = crate::chain::xmr::subaddress::derive_input_from_source(
                &view_sec,
                &spend_sec,
                src,
                tx_data.subaddr_account,
                &tx_data.subaddr_indices,
            )?;
            ki_src[n_src] = ki;
            n_src += 1;
            // Authoritative placement at the wallet transfer index. A record
            // already at that index must agree (misalignment guard) — the
            // source derivation wins if it never saw one.
            let idx = sel; // < ki_span by construction
            if ki_sv[idx] != KI_POISON && ki_sv[idx] != ki {
                return Err(ShlosiloError::new(
                    ShlosiloErrorKind::KeyImageRecordMismatch,
                ));
            }
            ki_sv[idx] = ki;
        }
        #[cfg(feature = "tx-phase-timing-ffi")]
        if let Some(p) = px12.as_mut() {
            p.end();
        }

        // Pass 2: `key_images_str` must be in canonical vin order — strictly
        // DESCENDING key images (memcmp), the same order tx_signer sorts the
        // vins into (2026-10-24 unsorted-inputs fix). monero 0.18.5.3's
        // pending_tx_validation.cpp:561 compares this string against the tx's
        // vin order LITERALLY (2026-10-26 phone-silence incident: a
        // construction-order string is rejected and the UI swallows the error).
        let mut str_order = [0u8; crate::chain::xmr::tx_signer::MAX_INPUTS_TRACKED];
        for (i, slot) in str_order[..n_src].iter_mut().enumerate() {
            *slot = i as u8;
        }
        for i in 0..n_src {
            let mut best = i;
            for j in (i + 1)..n_src {
                if ki_src[str_order[j] as usize] > ki_src[str_order[best] as usize] {
                    best = j;
                }
            }
            str_order.swap(i, best);
        }
        for &oi in str_order[..n_src].iter() {
            let ki = ki_src[oi as usize];
            // Z2.3 C3b-3: `<hex> ` bytes built straight into the carved slice
            // (was String + alloc::format!) — byte layout unchanged
            pushb(&mut key_images_str, b'<')?;
            for b in ki {
                pushb(&mut key_images_str, b"0123456789abcdef"[(b >> 4) as usize])?;
                pushb(&mut key_images_str, b"0123456789abcdef"[(b & 0xf) as usize])?;
            }
            pushb(&mut key_images_str, b'>')?;
            pushb(&mut key_images_str, b' ')?;
        }

        // tx_key_images: output one-time address + Hs(shared_key)·Hp(stealth)
        // wallet2 fill semantics (wallet2.cpp:8055-8070 is_out_to_acc loop):
        // record every output BACK TO THIS WALLET — change and self-pay
        // INCLUDED, external recipients EXCLUDED. Ownership = the
        // m_subaddresses map test on subaddress spend pubs (derived identity;
        // the amount is never consulted) — I12, WP1 interface freeze. The old
        // (amount, spend_pub) skip was the inverted filter pinned by
        // tests/tx_key_images_wallet2_view.rs (landed red 2026-10-31, GREEN
        // since this WP2 first-batch fix).
        let our_spend_pub = {
            use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
            use curve25519_dalek::scalar::Scalar;
            (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*spend_sec))
                .compress()
                .to_bytes()
        };
        #[cfg(feature = "tx-phase-timing-ffi")]
        let mut px13 = PhaseProbe::start(13);
        for (i, dest) in tx_data.splitted_dsts.iter().enumerate() {
            let owned = crate::chain::xmr::subaddress::wallet_owns_destination(
                &our_spend_pub,
                &view_sec,
                dest,
            );
            // Wire-tail view (canonical enum; I1 — no profile import here):
            // Cake = wallet-owned only (I12), keystone = every new output.
            let include = match tail.tx_key_images {
                crate::canonical::TxKeyImagesView::Wallet2Owned => owned,
                crate::canonical::TxKeyImagesView::AllPlusRetained => true,
            };
            if !include {
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
            #[cfg(feature = "tx-phase-timing-ffi")]
            let mut px14 = PhaseProbe::start(14);
            let shared = zeroize::Zeroizing::new(r.mul_point_cofactor(&a_bytes).map_err(|_| {
                crate::error::ShlosiloError::new(
                    crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
                )
            })?);
            // Z3.2c: stack-fixed od (32B shared ‖ varint(i) ≤ 10B) — Zeroizing
            // owner on the stack, explicit wipe via Drop as before.
            #[cfg(feature = "tx-phase-timing-ffi")]
            if let Some(p) = px14.as_mut() {
                p.end();
            }
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
            #[cfg(feature = "tx-phase-timing-ffi")]
            let mut px15 = PhaseProbe::start(15);
            let stealth = hs.mul_basepoint_add_point(&b_dest);
            #[cfg(feature = "tx-phase-timing-ffi")]
            if let Some(p) = px15.as_mut() {
                p.end();
            }
            #[cfg(feature = "tx-phase-timing-ffi")]
            let mut px16 = PhaseProbe::start(16);
            let hp: curve25519_dalek::EdwardsPoint =
                monero_ed25519::Point::biased_hash(stealth).into();
            #[cfg(feature = "tx-phase-timing-ffi")]
            if let Some(p) = px16.as_mut() {
                p.end();
            }
            let hp_bytes = hp.compress().to_bytes();
            #[cfg(feature = "tx-phase-timing-ffi")]
            let mut px17 = PhaseProbe::start(17);
            let image = hs.mul_point(&hp_bytes).map_err(|_| {
                crate::error::ShlosiloError::new(
                    crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
                )
            })?;
            #[cfg(feature = "tx-phase-timing-ffi")]
            if let Some(p) = px17.as_mut() {
                p.end();
            }
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
        if let Some(p) = px13.as_mut() {
            p.end();
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

    // WP3 keystone two-fill tail: the retained transfer KIs go AFTER the
    // per-tx new outputs (keystone's transfer.rs:1250-then-:1271 order).
    if tail.tx_key_images == crate::canonical::TxKeyImagesView::AllPlusRetained {
        for e in &retained_stage[..retained_n] {
            tki_sv
                .push(TxKeyImageEntry {
                    output_pubkey: e.one_time_pub,
                    key_image: e.key_image,
                })
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
        }
    }
    // Gap policy v2 (pool #32/#48, 2026-10-21 — red pins 5/6, option A):
    // an uncovered position REFUSES the sign (KeyImageRecordMissing). The v1
    // conservative gap filler (d22ec10 — a derived key image of a spent input
    // stamped into every gap slot) is retired: wallet2's
    // `import_key_images(signed_txs.key_images)` writes every entry
    // POSITIONALLY into `m_transfers[i]` ("trusting imported one", mirror-
    // replay-proven), so an unrelated filler corrupts the phone's spent
    // tracking for whichever transfer owns that slot — the exact pollution
    // vector pins 5/6 refuse to let ship. Recordless signing is a deliberate
    // UX cost: pair first (xmr-output beat, the `Outputs (all)` variant);
    // the recordless-signing endgames (persistent record store / keystone-
    // shape empty array) are the LuckyFox phase. A record/source mismatch
    // still refuses earlier (KeyImageRecordMismatch): the selected-index
    // cross-check is the cross-wallet contamination guard.
    for i in 0..ki_span {
        if ki_sv[i] == KI_POISON {
            return Err(ShlosiloError::new(ShlosiloErrorKind::KeyImageRecordMissing));
        }
    }

    // The tail materializes per the canonical view: the positional `key_images`
    // array ships wallet-indexed on the Cake view and stays EMPTY on the
    // keystone view (the pre-fill/records/gap validation above still ran —
    // the sign's safety policy is view-independent).
    let empty_ki: &mut [[u8; 32]] = &mut [];
    let set = SignedTxSet {
        ptx: ptx_sv,
        key_images: match tail.key_images {
            crate::canonical::KeyImagesPositionalView::WalletIndexedFull => ki_sv,
            crate::canonical::KeyImagesPositionalView::Empty => {
                crate::types::SliceVec::new(empty_ki)
            }
        },
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
#[cfg(all(feature = "alloc-fallback", feature = "chain-xmr"))]
fn sign_xmr(
    tail: crate::canonical::TailView,
    seed: &[u8],
    encrypted_unsigned: &[u8],
    ki_records: &[WalletKiRecord],
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
    sign_xmr_with_ws(
        tail,
        &mut ws,
        seed,
        encrypted_unsigned,
        ki_records,
        entropy,
        None,
        output_buf,
    )
}

#[cfg(feature = "chain-btc")]
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

#[cfg(feature = "chain-btc")]
fn read_bip32_derivation(
    input_map: crate::chain::btc::psbt::KvMap<'_>,
) -> Option<([u8; 4], DerivationPath)> {
    use crate::chain::btc::psbt::input_type;
    let kv = input_map
        .iter()
        .find(|kv| kv.key.first() == Some(&input_type::BIP32_DERIVATION))?;
    parse_derivation_value(kv.value)
}

/// Sign one P2TR keypath input from the PSBT's own records (device path).
///
/// Ownership comes from `PSBT_IN_TAP_BIP32_DERIVATION` (0x16): its fingerprint
/// must be ours and the path must re-derive the x-only key the record names.
/// The BIP-341 sighash, the output-key/prevout comparison and the signature
/// injection live in `chain/btc/psbt.rs` (same parsing face as the rest of the
/// PSBT code, so review and signing cannot drift apart).
#[cfg(feature = "chain-btc")]
fn sign_btc_taproot_input(
    seed: &[u8],
    psbt: &mut crate::chain::btc::psbt::Psbt<'_>,
    idx: usize,
    local_fp: [u8; 4],
    entropy: &[u8],
) -> Result<()> {
    use crate::chain::btc::psbt as psbt_mod;
    use crate::types::secret_bytes::SecretBytes;

    let (fp, record) = psbt_mod::get_tap_bip32_derivation(
        psbt.input_map_checked(idx)
            .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?,
    )?
    .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
    if fp != local_fp && !psbt_mod::fingerprint_is_unspecified(fp) {
        // Ownership, not network: the record names a fingerprint that is neither
        // ours nor the "unspecified" placeholder. -12 here told the user the
        // network was wrong (2026-11-12).
        return Err(err(ShlosiloErrorKind::PsbtOwnershipMismatch));
    }
    let depth = record.depth as usize;
    if depth > record.elements.len() {
        return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let path = DerivationPath::from_flat(record.elements[..depth].iter().copied())
        .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
    // R4 for taproot: the record's x-only key is the binding, and the declared path
    // is only a label — a watch-only wallet that holds a single account key
    // relabels the purpose level to match the address type it offered, so deriving
    // from the path alone would reject our own key (same class as the 44'/84'
    // relabelling measured on legacy inputs, 2026-11-14).
    let key_bytes = resolve_owned_key(seed, &path, RecordPub::XOnly(&record.key_x))?
        .ok_or_else(|| err(ShlosiloErrorKind::PsbtOwnershipMismatch))?;
    let sk_bytes = zeroize::Zeroizing::new(key_bytes);

    // BIP-340 aux randomness: the caller's entropy channel when it carries a
    // full 32 bytes, else all zeros (BIP-340 permits this; the resulting
    // signature is then deterministic, which is what a device without an RNG
    // should produce rather than inventing randomness).
    let mut aux = [0u8; 32];
    if entropy.len() >= 32 {
        aux.copy_from_slice(&entropy[..32]);
    }

    psbt_mod::sign_psbt_p2tr_keypath_with_key(psbt, idx, &SecretBytes::new(*sk_bytes), &aux)
}

/// BTC: crypto-psbt CBOR (bare bytes item) → PSBT signing
///
/// Derivation path = m/84'/0'/0'/0/0 (standard native segwit path).
/// Each input derives its private key from the path hinted by BIP32_DERIVATION;
/// Without a hint, always take the default path.
/// Every purpose we hand out an account key for. A watch-only wallet derives
/// under whichever account key it received and *labels* the address path with its
/// own purpose level, so the same suffix has to be tried under each of these.
#[cfg(feature = "chain-btc")]
const OWNED_PURPOSES: [u32; 4] = [
    84 | 0x8000_0000,
    49 | 0x8000_0000,
    44 | 0x8000_0000,
    86 | 0x8000_0000,
];

/// Resolve a PSBT derivation record to a key **we** own.
///
/// The record's pubkey is the binding; its path is a label. A wallet that holds
/// only an account key derives children under that account and then writes the
/// path it believes it is using: Cake hands us a legacy address built from our
/// BIP-84 account key labelled `m/44'/0'/0'/0/i` (measured 2026-11-14 — the
/// pubkey in that record is `m/84'/0'/0'/0/0`'s). Deriving from the declared path
/// alone therefore rejects a request that is ours.
///
/// Bounded: the declared path, then the same suffix under each exported purpose.
/// A record whose pubkey no candidate reproduces is refused, so a mislabelled
/// path can only stop a legitimate request — never make us sign with a key the
/// record does not name.
/// The pubkey form a derivation record names: a full compressed key (0x06
/// records) or an x-only key (0x16 TAP_BIP32_DERIVATION).
#[cfg(feature = "chain-btc")]
enum RecordPub<'a> {
    Full(&'a [u8; 33]),
    XOnly(&'a [u8; 32]),
}

#[cfg(feature = "chain-btc")]
fn key_at_path_if_matches(
    seed: &[u8],
    path: &DerivationPath,
    want: RecordPub<'_>,
) -> Result<Option<[u8; 32]>> {
    let sk = crate::derivation::bip32_secp256k1::derive_from_seed(seed, path)?;
    let pk = crate::curve_primitive::secp256k1::point_to_compressed(
        &crate::curve_primitive::secp256k1::base_mul(&sk),
    );
    let hit = match want {
        RecordPub::Full(full) => pk.as_slice() == full,
        // An x-only record names the key's x coordinate, so parity is irrelevant:
        // a taproot spend of the same key still belongs to it.
        RecordPub::XOnly(x) => &pk[1..] == x,
    };
    if hit {
        Ok(Some(crate::curve_primitive::secp256k1::scalar_to_bytes(
            &sk,
        )))
    } else {
        Ok(None)
    }
}

/// Resolve a PSBT derivation record to a key **we** own.
///
/// The record's pubkey is the binding; its path is a label. A wallet that holds only
/// one account key derives children under that account and then writes the path it
/// believes it is using: a watch-only wallet hands us a legacy address built from our
/// BIP-84 account key labelled `m/44'/0'/0'/0/i` (measured 2026-11-14 — the pubkey in
/// that record is `m/84'/0'/0'/0/0`'s), and the same relabelling applies to the other
/// address types it offers. Deriving from the declared path alone therefore rejects a
/// request that is ours.
///
/// Bounded: the declared path first, then the same suffix under each exported purpose.
/// A record whose pubkey no candidate reproduces is refused, so a mislabelled path can
/// only stop a legitimate request — never make us sign with a key the record does not
/// name.
#[cfg(feature = "chain-btc")]
fn resolve_owned_key(
    seed: &[u8],
    path: &DerivationPath,
    want: RecordPub<'_>,
) -> Result<Option<[u8; 32]>> {
    let first = match &want {
        RecordPub::Full(f) => key_at_path_if_matches(seed, path, RecordPub::Full(f))?,
        RecordPub::XOnly(x) => key_at_path_if_matches(seed, path, RecordPub::XOnly(x))?,
    };
    if first.is_some() {
        return Ok(first);
    }
    let declared = path.as_slice();
    if declared.len() < 2 {
        return Ok(None);
    }
    for purpose in OWNED_PURPOSES {
        if declared[0].0 == purpose {
            continue;
        }
        // BIP-32 paths cap at 16 components (same bound the keypath codecs use)
        let mut buf = [0u32; 16];
        let n = declared.len().min(buf.len());
        for (i, idx) in declared.iter().take(n).enumerate() {
            buf[i] = if i == 0 { purpose } else { idx.0 };
        }
        let Ok(candidate) = DerivationPath::from_flat(buf[..n].iter().copied()) else {
            continue;
        };
        let hit = match &want {
            RecordPub::Full(f) => key_at_path_if_matches(seed, &candidate, RecordPub::Full(f))?,
            RecordPub::XOnly(x) => key_at_path_if_matches(seed, &candidate, RecordPub::XOnly(x))?,
        };
        if hit.is_some() {
            return Ok(hit);
        }
    }
    Ok(None)
}

#[cfg(feature = "chain-btc")]
fn sign_btc<'a>(
    seed: &[u8],
    cbor_payload: &'a [u8],
    output_buf: &mut [u8],
    arena: Option<&'a mut [u8]>,
    recs: Option<&'a mut [crate::chain::btc::psbt::KvRec]>,
    entropy: &[u8],
    finalize: bool,
) -> Result<usize> {
    use crate::chain::btc::psbt as psbt_mod;
    use crate::encoding::cbor;

    // Payload semantics (2026-10-12): the UR exits strip the CBOR byte-string
    // shell, so a registry-shaped crypto-psbt arrives as the RAW PSBT. Both
    // shapes are accepted: a Bytes item (legacy direct callers passing the
    // wrapped form) or bare PSBT bytes (shell already stripped).
    let psbt_bytes: &[u8] = match cbor::decode(cbor_payload) {
        Ok(cbor::Cbor::Bytes(b)) => b,
        _ => cbor_payload,
    };

    let mut psbt = psbt_mod::parse_psbt_any(psbt_bytes, arena, recs)?;

    // P1-02: our master fingerprint (BIP-32 serialization field 5..9); the fingerprint
    // fingerprint mismatch = this PSBT is not from our wallet (wrong seed/wrong wallet); refuse to sign
    let local_fp = crate::derivation::bip32_secp256k1::master_fingerprint_from_seed(seed)?;

    for idx in 0..psbt.unsigned_tx.inputs.len() {
        // S2/B-3: dispatch on the spent script. A Taproot input carries its
        // ownership record in TAP_BIP32_DERIVATION (0x16) and is signed with a
        // Schnorr signature over the BIP-341 sighash; everything else keeps the
        // ECDSA/BIP-143 path below.
        let spent_spk_is_p2tr = psbt
            .input_map_checked(idx)
            .and_then(|m| {
                let prev_out = psbt.unsigned_tx.inputs[idx].prev_out.clone();
                psbt_mod::get_utxo_any(m, &prev_out)
            })
            .map(|(_, spk)| spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20)
            .unwrap_or(false);
        if spent_spk_is_p2tr {
            sign_btc_taproot_input(seed, &mut psbt, idx, local_fp, entropy)?;
            continue;
        }

        // P1-02: BIP32_DERIVATION value = master_fingerprint(4B) + path(u32LE × depth),
        // paths are read from the PSBT rather than hardcoded; fingerprint mismatch with ours → reject;
        // fall back to the default path only when the field is absent (transitional; tightened at P6.4).
        // P1-B: inputs without BIP32_DERIVATION no longer fall back to the default path (tightened),
        // all inputs must carry ownership records explicitly (the P6.4 transitional behavior landed early).
        let (_fp0, path_used) = read_bip32_derivation(
            psbt.input_map_checked(idx)
                .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?,
        )
        .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
        // Cake's view-only airgap PSBT stamps 00000000 (it never learned our
        // fingerprint); the ownership proof is the pubkey re-derivation below.
        if _fp0 != local_fp && !psbt_mod::fingerprint_is_unspecified(_fp0) {
            return Err(err(ShlosiloErrorKind::PsbtOwnershipMismatch));
        }
        // P1-B (2026-09-01 re-review): all BIP32_DERIVATION records strictly verified.
        // every record's (fingerprint, path, pubkey) must pass three checks:
        //   fingerprint == ours; path-derived public key == the pubkey carried by the record;
        //   and all record verifications must agree (different pubkeys = multisig/mixed-source; single-sig device rejects).
        let input_map = psbt
            .input_map_checked(idx)
            .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
        // NOTE (Z2.1 S2 re-review, 2026-09-24): `kv.key[1..34]` is the BIP32_DERIVATION
        // compressed PUBLIC key (verified against derived pubkeys below) — public data,
        // deliberately NOT zeroize-wrapped. (Initially mis-audited as key material.)
        // Z4-4: pubkeys borrow the map payloads; one exact container.
        let mut records: heapless::Vec<
            ([u8; 4], DerivationPath, [u8; 33]),
            { crate::types::caps::BT_BIP32_RECORDS_MAX },
        > = heapless::Vec::new();
        for kv in input_map.iter() {
            if kv.key.first() != Some(&psbt_mod::input_type::BIP32_DERIVATION) {
                continue;
            }
            if kv.key.len() != 1 + 33 {
                return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            let (fp, path) = parse_derivation_value(kv.value)
                .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
            // Z4-7e: the record carries the pubkey inline (no borrow of the
            // map outlives the read view).
            let mut pk = [0u8; 33];
            pk.copy_from_slice(&kv.key[1..34]);
            records
                .push((fp, path, pk))
                .map_err(|_| err(ShlosiloErrorKind::BufferTooSmall))?;
        }
        if records.is_empty() {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        // R4 ownership binding, B-9 correction: the record's **pubkey** is the
        // binding, not its path string. A wallet holding only an account key
        // derives under that account and labels the path with its own purpose
        // level (measured: Cake labels a legacy address built from our BIP-84
        // account key as m/44'/0'/0'/0/i, while the pubkey is 84'/0'/0'/0/0's).
        // `resolve_owned_key` tries the declared path, then the same suffix under
        // every purpose we export; a pubkey no candidate reproduces is refused, so
        // we still never sign with a key the PSBT does not name.
        let key_bytes = resolve_owned_key(seed, &path_used, RecordPub::Full(&records[0].2))?
            .ok_or_else(|| err(ShlosiloErrorKind::PsbtOwnershipMismatch))?;
        // Z2.2 (2026-09-24): key-material stack copy zeroized on drop.
        // A2-08 (external audit 2026-11-19): one owner instead of three — the derived bytes
        // used to live in `sk` (a Copy scalar with no Drop), in this `Zeroizing`, and in a
        // fresh `SecretBytes` minted for every input. The signing inputs borrow the owner now.
        let mut key_bytes = key_bytes;
        let sk_bytes = SecretBytes::take(&mut key_bytes);

        let mut pubkey_hash: Option<[u8; 20]> = None;
        for (fp, path, pk) in &records {
            if *fp != local_fp && !psbt_mod::fingerprint_is_unspecified(*fp) {
                return Err(err(ShlosiloErrorKind::PsbtOwnershipMismatch));
            }
            // Every record must name a key we own (same bounded lookup).
            if resolve_owned_key(seed, path, RecordPub::Full(pk))?.is_none() {
                return Err(err(ShlosiloErrorKind::PsbtOwnershipMismatch));
            }
            let h = crate::encoding::sha256::hash(pk)?;
            let h20 = crate::encoding::ripemd160::hash(&h)?;
            match &pubkey_hash {
                Some(prev) if *prev != h20 => {
                    // multiple records pointing to different pubkeys = not single-sig semantics
                    return Err(err(ShlosiloErrorKind::PsbtOwnershipMismatch));
                }
                Some(_) => {}
                None => pubkey_hash = Some(h20),
            }
        }
        let pubkey_hash =
            pubkey_hash.ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;

        // P1-B: witness utxo binding — the amount and scriptPubKey must belong to this very input,
        // and the scriptPubKey must be P2WPKH (OP_0 PUSH20) with HASH160 == our pubkey_hash
        // (the prevout txid points to that script on-chain, indirectly anchoring the signed input to this key).
        // BIP-174: a non-witness input carries NON_WITNESS_UTXO (0x00) — the whole
        // previous transaction — because the legacy sighash needs the spent script
        // and the txid binding. `get_utxo_any` reads 0x01 first and falls back to
        // 0x00 with full txid/vout verification, so both wallet shapes work.
        let utxo = psbt.input_map_checked(idx).and_then(|m| {
            let prev_out = psbt.unsigned_tx.inputs[idx].prev_out.clone();
            psbt_mod::get_utxo_any(m, &prev_out)
        });
        let Some((amount, spk)) = utxo else {
            // No prevout data for this input. We cannot tell which script we would
            // be satisfying (nor compute the fee), so the request is refused with a
            // dedicated code: the wallet failed to fetch the previous transaction
            // (a failing upstream node is the observed cause), and guessing a
            // template on its behalf would be signing something we cannot describe.
            // The review page shows `warn: prevout not supplied`, and the failure
            // word table maps this code to "request input data missing".
            return Err(err(ShlosiloErrorKind::PrevoutMissing));
        };

        // S2/B-9: a legacy P2PKH prevout (`76a914…88ac`) signs the pre-BIP-143
        // digest. The spent script must hash to the key derived above — the
        // signer re-checks that binding and refuses a foreign prevout. A legacy
        // input carries no witness, so only FINAL_SCRIPT_SIG is written.
        if crate::chain::btc::p2pkh::is_p2pkh_spk(
            crate::types::wire_bytes::wire_slice(&spk),
            &pubkey_hash,
        ) {
            psbt_mod::sign_psbt_p2pkh(
                &mut psbt,
                &psbt_mod::PsbtP2PKHSignInput {
                    input_index: idx,
                    private_key: &sk_bytes,
                    pubkey_hash,
                },
            )?;
            continue;
        }
        // S2/B-4: a P2SH-wrapped P2WPKH prevout (BIP49) goes through the wrapper
        // finalization, which re-derives the redeem script from this same key and
        // refuses if it does not hash into the prevout.
        let is_p2sh_p2wpkh = spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87;
        if is_p2sh_p2wpkh {
            psbt_mod::sign_psbt_p2sh_p2wpkh(
                &mut psbt,
                &psbt_mod::PsbtP2SHP2WPKHSignInput {
                    input_index: idx,
                    private_key: &sk_bytes,
                    pubkey_hash,
                    amount,
                },
            )?;
            continue;
        }
        if spk.len() != 22 || spk[0] != 0x00 || spk[1] != 0x14 || spk[2..22] != pubkey_hash {
            return Err(err(ShlosiloErrorKind::PsbtOwnershipMismatch));
        }

        psbt_mod::sign_psbt_p2wpkh(
            &mut psbt,
            &psbt_mod::PsbtSignInput {
                input_index: idx,
                private_key: &sk_bytes,
            },
        )?;
    }

    // Dialect split: the legacy `psbt` type (Cake/Cupcake) extracts the final
    // transaction itself and needs BIP-174 final records; `crypto-psbt`
    // (Sparrow) finalizes on its own and expects the partial records only.
    if finalize {
        psbt_mod::finalize_signed_inputs(&mut psbt)?;
    }

    psbt_mod::serialize_psbt_into(&psbt, output_buf)
}

/// ETH: eth-sign-request CBOR map → `ur:eth-signature` container (E-1)
///
/// P1-01 (2026-08-26): a real UR's payload is a CBOR map with sign_data / data_type /
/// chain_id / derivation_path. `data_type` selects the scheme before the payload is read:
/// 4 (TypedTransaction) → first-byte dispatch (0x02 = EIP-1559, the only typed scheme we
/// sign); 1 (Transaction) → legacy EIP-155 (bare RLP preimage, no type byte); 3
/// (PersonalMessage) → EIP-191 over the raw message, `v` = 27/28; TypedData is rejected
/// until it has a fixed-size container. See the data_type table in
/// docs/eth-signature-codec.md.
///
/// E-1 (2026-11-24): the exit returns the `ur:eth-signature` CBOR map
/// (`r ‖ s ‖ v`) instead of the signed raw transaction. The wallet assembles and
/// broadcasts; no wallet in this dialect consumes a signed raw tx, and the tx encoding
/// sized the caller's buffer for a transaction rather than for the ~100 B container.
///
/// E-1 legacy leg (2026-11-25): `data_type` 1 is wired in. Its `v` is
/// `chain_id * 2 + 35 + y_parity` — a u64, so the container's signature slot is
/// 65..=72 bytes and `v` goes on the wire as minimal big-endian bytes
/// (`eip155::write_v_be`).
///
/// Derivation path = m/44'/60'/0'/0/0.
///
/// E-3 P3 (typed data): `data_type` 2 is signed from the zero-heap EIP-712 pool. The
/// pool's storage is the caller's `region` (one `eip712_pool::WS_BYTES` span carved out
/// of the sign workspace); without a region there is no container to parse into and the
/// request is refused rather than parsed into a second, allocating one.
#[cfg(feature = "chain-eth")]
fn sign_eth(
    seed: &[u8],
    cbor_payload: &[u8],
    region: Option<&mut [u8]>,
    output_buf: &mut [u8],
) -> Result<usize> {
    use crate::chain::eth::{eip155, eip1559, eip712_pool, from_rlp};
    use crate::ur::codec::eth_sign_request::parse_eth_sign_request;
    use crate::ur::codec::eth_signature::{
        encode_eth_signature_into, EthSignature, SIGNATURE_MAX_LEN, SIGNATURE_MIN_LEN,
    };

    /// Which scheme the request asked for, with its parsed transaction (if any).
    ///
    /// Three-shaped because the two transaction schemes have different models and
    /// different request parsers: a legacy request is the EIP-155 preimage
    /// (`from_rlp::parse_eip155_signing_request`), a typed one is `0x02 || rlp([...])`.
    /// Typed data carries the digest instead of a model: the pool it was computed from
    /// borrows the caller's region, so it cannot outlive this dispatch.
    enum Scheme<'a> {
        Legacy(eip155::Eip155Transaction<'a>),
        Eip1559(eip1559::Eip1559Transaction<'a>),
        Personal,
        /// EIP-712: `keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(message))`.
        TypedData([u8; 32]),
    }

    let req = parse_eth_sign_request(cbor_payload)?;
    // data_type selects the scheme BEFORE the payload is read (reference dialect:
    // `rust_c/src/ethereum/mod.rs::eth_sign_tx_dynamic` dispatches on data_type first).
    // One mapping, read by this face and by `review::build_eth` (see `chain::eth::scheme`): the
    // scheme decides which preimage gets signed, so the two faces must not carry their own copies.
    let eth_scheme = crate::chain::eth::scheme::EthScheme::for_data_type(req.data_type)
        .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let scheme = match eth_scheme {
        // data_type 1 = legacy, EIP-155 protected (bare RLP, no type byte). The
        // unprotected 6-item shape has no replay protection and is refused by the
        // parser with its own code (FeatureNotImplemented), never as a format error.
        crate::chain::eth::scheme::EthScheme::Legacy => {
            let tx = from_rlp::parse_eip155_signing_request(req.sign_data)?;
            // P1-02 (ETH part), same rule as the typed path below: when the request
            // carries its own chain_id, it must agree with the transaction.
            if let Some(req_chain) = req.chain_id {
                if req_chain != tx.chain_id as i128 {
                    return Err(err(ShlosiloErrorKind::NetworkUnrecognized));
                }
            }
            Scheme::Legacy(tx)
        }
        crate::chain::eth::scheme::EthScheme::FeeMarket => {
            // The first payload byte selects the scheme. Only EIP-1559 (0x02) is
            // signable today; the other valid type bytes are named so they do not
            // degrade into a generic format error.
            match req.sign_data.first() {
                Some(0x02) => {}
                // EIP-2930 / 4844 / 7702: valid types we do not sign
                Some(0x01) | Some(0x03) | Some(0x04) => {
                    return Err(err(ShlosiloErrorKind::FeatureNotImplemented));
                }
                // unknown type byte or empty payload
                _ => return Err(err(ShlosiloErrorKind::EncodingInvalidFormat)),
            }
            // Signing policy: refuse a payload that already carries a signature.
            let tx = from_rlp::parse_eip1559_signing_request(req.sign_data)?;
            // P1-02 (ETH part): when eth-sign-request carries its own chain_id, verify it matches the tx
            if let Some(req_chain) = req.chain_id {
                if req_chain != tx.chain_id as i128 {
                    return Err(err(ShlosiloErrorKind::NetworkUnrecognized));
                }
            }
            Scheme::Eip1559(tx)
        }
        // data_type 3 = personal_sign (EIP-191): the payload is the raw message,
        // not a transaction, so none of the transaction gates apply.
        crate::chain::eth::scheme::EthScheme::Personal => Scheme::Personal,
        // data_type 2 = EIP-712 typed data: `sign_data` IS the typed-data JSON document
        // (borrowed, never copied). The digest comes from the zero-heap container; the
        // pool borrows `req.sign_data` and the caller's region, so both stay alive here
        // and only the 32-byte digest leaves this arm.
        crate::chain::eth::scheme::EthScheme::TypedData => {
            // Envelope-vs-document chain consistency, before the container is even built:
            // `check_network` compares the payload against the network the CALLER declared,
            // which a carrier without a network selection never reaches, so the check that
            // must hold on every face lives here (and in the review gate, same function).
            crate::business::review::typed_data_request_chain_gate(req.chain_id, req.sign_data)?;
            let region = region.ok_or_else(|| err(ShlosiloErrorKind::BufferTooSmall))?;
            let t_hash = crate::device_timing::Mark::start(crate::device_timing::STAGE_KECCAK);
            let pool = eip712_pool::parse_in(req.sign_data, region)?;
            // One gate, two faces: the review page refuses what it cannot show, and the
            // signer refuses the same documents so a direct sign call cannot sign a
            // request the operator was never shown (see `review::typed_data_fold_gate`).
            crate::business::review::typed_data_fold_gate(&pool)?;
            let digest = eip712_pool::signing_hash_pool(&pool)?;
            t_hash.end();
            Scheme::TypedData(digest)
        }
    };

    // E-1: the reply must echo the request's id — the container never mints one.
    // A signature the sender cannot correlate is worse than no answer, so a
    // request without key 1 is refused here. Ordered after the request-shape
    // gates above on purpose: a wrong data_type or chain_id keeps reporting its
    // own error kind (those pins predate the request-id requirement).
    let request_id = match req.request_id {
        Some(id) => id,
        None => return Err(err(ShlosiloErrorKind::EncodingInvalidFormat)),
    };
    // P1-02: when the request carries a derivation_path, derive with it; otherwise fall back to the standard path
    let path = match req.derivation_path {
        Some(p) => p,
        None => DerivationPath::parse("m/44'/60'/0'/0/0")?,
    };
    let t_derive = crate::device_timing::Mark::start(crate::device_timing::STAGE_BIP32);
    // A2-08: the derived scalar is a Copy type with no Drop — own it so it is erased.
    let sk = zeroize::Zeroizing::new(crate::derivation::bip32_secp256k1::derive_from_seed(
        seed, &path,
    )?);
    t_derive.end();
    // Z2.2 (2026-09-24): key-material stack copy zeroized on drop.
    // A2-08: and a single owner for it — the sign input borrows this instead of minting a
    // third copy of the same private key.
    let mut raw_key = crate::curve_primitive::secp256k1::scalar_to_bytes(&sk);
    let private_key = SecretBytes::take(&mut raw_key);

    let t_sign = crate::device_timing::Mark::start(crate::device_timing::STAGE_ECDSA);
    // `r ‖ s ‖ v`: the `v` segment carries each scheme's own convention and is never
    // normalized here. EIP-1559 carries the bare yParity (0/1) — a 27-offset byte
    // there is a signature every peer drops — while personal_sign carries 27/28,
    // which is what EIP-191 consumers hand to ecrecover. EIP-155 carries the
    // protected `v = chain_id*2 + 35 + y_parity` as 1..=8 big-endian bytes, so the
    // slot is 72 bytes wide and `signature_len` says how much of it is real.
    let mut signature = [0u8; SIGNATURE_MAX_LEN];
    let signature_len = match scheme {
        Scheme::Eip1559(tx) => {
            let parts = eip1559::sign_eip1559_parts(&eip1559::Eip1559SignInput {
                tx,
                private_key: &private_key,
            })?;
            signature[..32].copy_from_slice(&parts.r);
            signature[32..64].copy_from_slice(&parts.s);
            signature[64] = parts.y_parity;
            SIGNATURE_MIN_LEN
        }
        Scheme::Legacy(tx) => {
            let parts = eip155::sign_eip155_parts(&eip155::Eip155SignInput {
                tx,
                private_key: &private_key,
            })?;
            signature[..32].copy_from_slice(&parts.r);
            signature[32..64].copy_from_slice(&parts.s);
            // Minimal big-endian v (keystone `EthereumSignature::serialize`'s rule):
            // 1 byte on mainnet (37/38), 2 on Polygon (309/310), 4 on Sepolia.
            let v_len = eip155::write_v_be(parts.v, &mut signature[64..])?;
            SIGNATURE_MIN_LEN - 1 + v_len
        }
        Scheme::Personal => {
            // data_type 3: EIP-191 over the raw message (`sign_data`), borrowed.
            let sig =
                crate::chain::eth::personal_sign::personal_sign_bytes(req.sign_data, &private_key)?;
            signature[..32].copy_from_slice(&sig.r);
            signature[32..64].copy_from_slice(&sig.s);
            signature[64] = sig.v;
            SIGNATURE_MIN_LEN
        }
        Scheme::TypedData(digest) => {
            // data_type 2: the digest was computed from the pool above; the signature is
            // the same primitive personal_sign uses (ECDSA over a 32-byte digest, low-s
            // normalized), because `v` follows the same convention.
            let sk = crate::chain::eth::sign::sk_from_pk(private_key.expose())?;
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            let y_parity = crate::chain::eth::sign::apply_low_s(&digest, &sk, &mut r, &mut s)?;
            signature[..32].copy_from_slice(&r);
            signature[32..64].copy_from_slice(&s);
            // `v` is 27/28 for typed data, not the bare yParity EIP-1559 carries: the
            // reference signer serializes `(rec_id + 27, rs)` for typed data exactly as
            // it does for personal_sign (keystone3-firmware
            // `rust/apps/ethereum/src/lib.rs`, `sign_typed_data_message`). A 27-offset
            // byte is what `ecrecover`/`eth_signTypedData` consumers expect.
            signature[64] = 27 + y_parity;
            SIGNATURE_MIN_LEN
        }
    };
    t_sign.end();

    encode_eth_signature_into(
        &EthSignature {
            request_id,
            signature,
            signature_len,
            origin: req.origin,
        },
        output_buf,
    )
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
///
/// **Scope — what this gate is NOT.** It compares the payload against the network the
/// *caller declared*. A carrier with no network selection never reaches the ETH arm (the
/// product firmware passes a placeholder 0, and `shlosilo_sign_session_view_ffi` has no
/// network parameter at all), so on a device this function gates nothing. What protects the
/// operator there is (a) the chain the payload itself names, which the review page prints,
/// and (b) the payload-internal consistency checks in `sign_eth`
/// (`req.chain_id` vs the transaction, and `review::typed_data_request_chain_gate` for
/// typed data). Do not add a rule here that must hold on every carrier — put it with the
/// payload instead.
pub(crate) fn check_network(
    type_tag: crate::ur::ur_encode::UrTypeTag,
    ur_payload: &[u8],
    network: Network,
) -> Result<()> {
    // A build with neither BTC nor ETH compiled in has no arm below; the pair stays
    // named so the ABI-shaped signature does not sprout `_` prefixes per feature.
    let _ = (&ur_payload, network);
    match type_tag {
        #[cfg(feature = "chain-btc")]
        crate::ur::ur_encode::UrTypeTag::CryptoPsbt if network != Network::BitcoinMainnet => {
            return Err(err(ShlosiloErrorKind::NetworkUnrecognized));
        }
        #[cfg(feature = "chain-eth")]
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
            // Dispatch on `data_type` exactly like the sign path does: a legacy
            // request is the EIP-155 preimage (item 6 is its chain id), a typed one
            // is `0x02 || rlp([...])` (its first field is the chain id). Reading a
            // legacy payload with the 1559 parser would report a format error for a
            // wrong-chain request — the operator would see "malformed" where the
            // truth is "this is not the network you asked for".
            use crate::ur::codec::eth_sign_request::EthSignDataType;
            let tx_chain_id = match req.data_type {
                EthSignDataType::Transaction => {
                    crate::chain::eth::from_rlp::parse_eip155_signing_request(req.sign_data)?
                        .chain_id
                }
                EthSignDataType::TypedTransaction => {
                    crate::chain::eth::from_rlp::parse_eip1559_raw(req.sign_data)?.chain_id
                }
                // E-3 P3: typed data carries no transaction, so its chain lives in the
                // document's own `domain.chainId`. Read it without a workspace (the
                // pre-check only scans; it fills no pool), and compare it under the same
                // rule the two transaction schemes use. A document without a readable
                // `chainId` has nothing to compare: the gate is skipped rather than
                // turned into a format error, because the digest layer already refuses a
                // domain whose declared fields have no values.
                EthSignDataType::TypedData => {
                    match crate::chain::eth::eip712_pool::domain_chain_id(req.sign_data)? {
                        Some(id) => id,
                        None => return Ok(()),
                    }
                }
                // data_type 3 signs a raw message: no chain id to compare, so the
                // network gate has nothing to check and must not turn it into a format
                // error.
                EthSignDataType::PersonalMessage => return Ok(()),
            };
            if tx_chain_id != expected_chain_id {
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
    #[cfg(feature = "chain-btc")]
    use crate::chain::btc::p2wpkh::bt_vec;
    #[cfg(feature = "chain-btc")]
    use crate::chain::btc::psbt::psbt_from_maps_leaky;
    use crate::types::chain_kind::ChainKind;
    #[cfg(feature = "alloc-fallback")]
    extern crate alloc;
    // (alloc::vec import dropped — test literals use the qualified form)
    // BTC fixtures build `Vec::new()` inside `bt_vec!` too, so gating this on chain-eth alone
    // broke the btc-only and btc-xmr test faces (chain-subset batch S7).
    #[cfg(any(feature = "chain-btc", feature = "chain-eth"))]
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
    #[cfg(feature = "chain-xmr")]
    #[test]
    #[cfg(feature = "alloc-fallback")]
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

    /// ETH end-to-end: raw EIP-1559 tx → real eth-sign-request CBOR map → sign →
    /// a `ur:eth-signature` container carrying the oracle's r/s/v.
    ///
    /// E-1 (2026-11-24): this pin used to assert the signed raw transaction
    /// (`out == expected.tx_bytes`, `out[0] == 0x02`). No wallet in this dialect
    /// consumes a signed raw tx — the wallet assembles and broadcasts — so the
    /// assertion moved to the container: the fields must match an independent
    /// `sign_eip1559` call, and the output must no longer be a transaction.
    #[cfg(feature = "chain-eth")]
    #[test]
    fn sign_eth_end_to_end() {
        use crate::chain::eth::eip1559::Eip1559Transaction;
        use crate::ur::codec::eth_signature::parse_eth_signature;

        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 12345,
            data: Vec::new().into(),
        };

        // seed derives m/44'/60'/0'/0/0, a different key than any key literal used
        // in this test: derive the child key here and sign with it directly, so the
        // expectation is independent of the exit path (container layout + echo).
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let test_seed = [7u8; 64];
        let derived =
            crate::derivation::bip32_secp256k1::derive_from_seed(&test_seed, &path).unwrap();
        let derived_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&derived);
        let expected = crate::chain::eth::eip1559::sign_eip1559(
            &crate::chain::eth::eip1559::Eip1559SignInput {
                tx: tx.clone(),
                private_key: &SecretBytes::new(derived_bytes),
            },
        )
        .unwrap();

        // P1-01: build a real eth-sign-request CBOR map (ur-registry shape)
        // {1: request_id, 2: sign_data(bytes), 3: data_type(4), 4: chain_id(1)}
        let raw = encode_unsigned_tx_for_test(&tx);
        let ur_payload = encode_eth_sign_request_for_test(&raw, 4, 1);

        let input = SignInput::Seed { seed: &test_seed };
        let mut output_buf = [0u8; 512];
        let n = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        )
        .expect("sign ok");

        // E-1: the exit is no longer a signed raw transaction (0x02 || rlp([...]));
        // it is the CBOR map of the eth-signature container.
        assert_ne!(output_buf[0], 0x02, "E-1: the exit must not return a tx");
        let sig = parse_eth_signature(&output_buf[..n]).expect("eth-signature container");
        assert_eq!(
            sig.request_id, TEST_ETH_REQUEST_ID,
            "the container must echo the request's id"
        );
        assert_eq!(&sig.signature[..32], &expected.r[..], "r");
        assert_eq!(&sig.signature[32..64], &expected.s[..], "s");
        assert_eq!(sig.signature[64], expected.y_parity, "v = yParity");
        assert_eq!(
            sig.origin, None,
            "no origin in the request, none in the reply"
        );
    }

    /// E-1 pin: the request id reaches the wire and is the request's, not a
    /// freshly minted one.
    ///
    /// The container has no way to invent an id (and must not): the sender
    /// correlates the reply by it. Two requests that differ only in key 1 must
    /// produce two encodings, each parsing back to its own id.
    #[cfg(feature = "chain-eth")]
    #[test]
    fn sign_eth_echoes_request_id_from_the_request() {
        let tx = crate::chain::eth::eip1559::Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 12345,
            data: Vec::new().into(),
        };
        let raw = encode_unsigned_tx_for_test(&tx);
        let test_seed = [7u8; 64];

        let mut outs = [([0u8; 512], 0usize), ([0u8; 512], 0usize)];
        let ids = [[0x11u8; 16], [0x22u8; 16]];
        for (i, id) in ids.iter().enumerate() {
            let ur_payload = encode_eth_sign_request_full_for_test(&raw, 4, 1, None, Some(*id));
            let input = SignInput::Seed { seed: &test_seed };
            let n = sign(
                input,
                crate::ur::ur_encode::UrTypeTag::EthSignRequest,
                &ur_payload,
                &mut outs[i].0,
            )
            .expect("sign ok");
            outs[i].1 = n;
            let sig =
                crate::ur::codec::eth_signature::parse_eth_signature(&outs[i].0[..n]).unwrap();
            assert_eq!(sig.request_id, *id, "the reply must echo request id {i}");
        }
        assert_eq!(
            outs[0].1, outs[1].1,
            "the id is the only difference, so the two replies have the same length"
        );
        assert_ne!(
            &outs[0].0[..outs[0].1],
            &outs[1].0[..outs[1].1],
            "a different request id must produce a different encoding"
        );
    }

    /// E-1 pin: the wire `v` byte for EIP-1559 is the yParity (0/1) and the
    /// container is laid out `r ‖ s ‖ v`, never `r ‖ s ‖ v+27`.
    ///
    /// The 27/28 offset belongs to the legacy and personal-sign paths. The
    /// container codec treats `v` as opaque (it does not normalize it), so a
    /// 27-offset byte would reach the wallet as-is and the signature would be
    /// rejected or mis-recovered. Field positions are pinned by comparing against
    /// the oracle's r/s, so a shifted layout fails here too.
    #[cfg(feature = "chain-eth")]
    #[test]
    fn sign_eth_1559_v_is_yparity_not_27_offset() {
        use crate::ur::codec::eth_signature::parse_eth_signature;

        let tx = crate::chain::eth::eip1559::Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 12345,
            data: Vec::new().into(),
        };
        let test_seed = [7u8; 64];
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let derived =
            crate::derivation::bip32_secp256k1::derive_from_seed(&test_seed, &path).unwrap();
        let derived_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&derived);
        let expected = crate::chain::eth::eip1559::sign_eip1559(
            &crate::chain::eth::eip1559::Eip1559SignInput {
                tx: tx.clone(),
                private_key: &SecretBytes::new(derived_bytes),
            },
        )
        .unwrap();
        assert!(
            expected.y_parity <= 1,
            "the oracle's yParity is 0/1, got {}",
            expected.y_parity
        );

        let raw = encode_unsigned_tx_for_test(&tx);
        let ur_payload = encode_eth_sign_request_for_test(&raw, 4, 1);
        let mut output_buf = [0u8; 512];
        let n = sign(
            SignInput::Seed { seed: &test_seed },
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        )
        .expect("sign ok");

        let sig = parse_eth_signature(&output_buf[..n]).expect("eth-signature container");
        // layout: r at [0..32], s at [32..64], v at [64]
        assert_eq!(&sig.signature[..32], &expected.r[..], "r must come first");
        assert_eq!(&sig.signature[32..64], &expected.s[..], "s must follow r");
        // the value itself: 0/1, and explicitly not the 27-offset form
        assert_eq!(
            sig.signature[64], expected.y_parity,
            "v must be the yParity"
        );
        assert!(
            sig.signature[64] <= 1,
            "EIP-1559 v is 0/1, got {}",
            sig.signature[64]
        );
        assert_ne!(
            sig.signature[64],
            expected.y_parity.wrapping_add(27),
            "E-1: a 1559 container must not carry the legacy 27/28 offset"
        );
    }

    /// E-1 pin: a request without key 1 is refused.
    ///
    /// The container echoes the id and never mints one, so signing would produce a
    /// reply the sender cannot correlate — worse than no answer. `EncodingInvalidFormat`
    /// (not a new error kind) is the module's format rejection.
    #[cfg(feature = "chain-eth")]
    #[test]
    fn sign_eth_requires_request_id() {
        let tx = crate::chain::eth::eip1559::Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 12345,
            data: Vec::new().into(),
        };
        let raw = encode_unsigned_tx_for_test(&tx);
        // key 1 omitted — the pre-E-1 fixture shape
        let ur_payload = encode_eth_sign_request_full_for_test(&raw, 4, 1, None, None);
        let test_seed = [7u8; 64];
        let mut output_buf = [0u8; 512];
        let result = sign(
            SignInput::Seed { seed: &test_seed },
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::EncodingInvalidFormat,
            "a request without a request id must be refused"
        );
    }

    /// P1-01: ETH end-to-end rejects requests with a mismatched chain_id
    #[cfg(feature = "chain-eth")]
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
            data: Vec::new().into(),
        };
        let raw = encode_unsigned_tx_for_test(&tx);
        // request chain_id=5 (≠ the tx's 1)
        let ur_payload = encode_eth_sign_request_for_test(&raw, 4, 5);
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

    /// `data_type` 3 = personal_sign (EIP-191). It is signed now, and the wire byte is
    /// the EIP-191 convention (v = 27/28 — the bytes an `ecrecover` consumer expects),
    /// which is the opposite of the 1559 yParity rule. The signature must equal an
    /// independent `personal_sign_bytes` call over the same message and key, and the
    /// payload must NOT be parsed as a transaction.
    #[cfg(feature = "chain-eth")]
    #[test]
    fn sign_eth_personal_message_signs_with_27_28_v() {
        use crate::chain::eth::personal_sign;

        let message = b"Example `personal_sign` message";
        let ur_payload = encode_eth_sign_request_for_test(message, 3, 1);
        let test_seed = [7u8; 64];
        let mut output_buf = [0u8; 512];
        let n = sign(
            SignInput::Seed { seed: &test_seed },
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        )
        .expect("personal_sign is signed");

        // Independent oracle: the same seed/path key fed straight into the signer.
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let derived =
            crate::derivation::bip32_secp256k1::derive_from_seed(&test_seed, &path).unwrap();
        let key = SecretBytes::new(crate::curve_primitive::secp256k1::scalar_to_bytes(&derived));
        let expected = personal_sign::personal_sign_bytes(message, &key).expect("oracle");

        let sig = crate::ur::codec::eth_signature::parse_eth_signature(&output_buf[..n])
            .expect("eth-signature container");
        assert_eq!(&sig.signature[..32], &expected.r[..], "r");
        assert_eq!(&sig.signature[32..64], &expected.s[..], "s");
        assert_eq!(sig.signature[64], expected.v, "v");
        assert!(
            sig.signature[64] == 27 || sig.signature[64] == 28,
            "EIP-191 carries v = 27/28, got {}",
            sig.signature[64]
        );
        assert_eq!(sig.request_id, TEST_ETH_REQUEST_ID, "request id echoed");
    }

    /// ERC-20 `approve` (unlimited allowance) through the whole exit.
    ///
    /// The E-2 acceptance list names approve — including the unlimited case — and the
    /// review layer already calls an unlimited allowance out. What was never pinned is
    /// the pair: the screen the operator approves and the bytes that get signed are the
    /// same transaction. Poison-pill shaped: the calldata selector and the spender word
    /// are asserted directly, so a decoder/encoder drift shows up here rather than as a
    /// plausible-looking signature over the wrong call.
    #[cfg(feature = "chain-eth")]
    #[test]
    fn sign_eth_erc20_approve_unlimited_reaches_the_container() {
        use crate::chain::eth::eip1559::{self, Eip1559Transaction};

        // approve(address,uint256) with 2^256-1 — the unlimited allowance.
        let mut data = alloc::vec::Vec::new();
        data.extend_from_slice(&[0x09, 0x5e, 0xa7, 0xb3]); // approve(address,uint256)
        data.extend_from_slice(&[0u8; 12]); // left-pad the spender address
        data.extend_from_slice(&[0x7au8; 20]); // spender
        data.extend_from_slice(&[0xffu8; 32]); // unlimited amount
        assert_eq!(data.len(), 68, "approve calldata is selector + two words");

        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 7,
            max_priority_fee_per_gas: 1_500_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 60_000,
            destination: Some([0xa0u8; 20]), // the token contract
            amount: 0,
            data: data.clone().into(),
        };

        // The review of this very request must call the allowance out as unlimited.
        let review_payload =
            encode_eth_sign_request_for_test(&encode_unsigned_tx_for_test(&tx), 4, 1);
        // the page needs a typed-data workspace even for an EIP-1559 request (the region
        // belongs to the container; the send pages do not touch it)
        let mut td_ws = alloc::vec![0u8; crate::business::review::TYPED_DATA_WS_BYTES];
        let view = crate::business::review::build_eth(&review_payload, &mut td_ws).expect("review");
        let mut text = alloc::string::String::new();
        for l in view.lines() {
            text.push_str(l.as_str());
            text.push('\n');
        }
        assert!(
            text.contains("unlimited"),
            "the review must name an unlimited allowance: {text}"
        );

        // …and the exit signs exactly that transaction.
        let test_seed = [7u8; 64];
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let derived =
            crate::derivation::bip32_secp256k1::derive_from_seed(&test_seed, &path).unwrap();
        let expected = eip1559::sign_eip1559(&eip1559::Eip1559SignInput {
            tx: tx.clone(),
            private_key: &SecretBytes::new(crate::curve_primitive::secp256k1::scalar_to_bytes(
                &derived,
            )),
        })
        .expect("oracle");

        let mut output_buf = [0u8; 512];
        let n = sign(
            SignInput::Seed { seed: &test_seed },
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &review_payload,
            &mut output_buf,
        )
        .expect("sign ok");
        let sig = crate::ur::codec::eth_signature::parse_eth_signature(&output_buf[..n])
            .expect("eth-signature container");
        assert_eq!(&sig.signature[..32], &expected.r[..], "r");
        assert_eq!(&sig.signature[32..64], &expected.s[..], "s");
        assert_eq!(sig.signature[64], expected.y_parity, "v = yParity");
        assert_eq!(sig.request_id, TEST_ETH_REQUEST_ID, "request id echoed");
    }

    /// `data_type` 1 (`Transaction`, E-1 2026-11-25): legacy EIP-155. The exit must
    /// carry the oracle's `r ‖ s` and the protected `v = chain_id*2 + 35 + parity`
    /// (37/38 on mainnet), not a bare yParity and not a 27/28 offset.
    ///
    /// The payload is the EIP-155 **preimage**
    /// `rlp([nonce, gas_price, gas_limit, to, value, data, chain_id, [], []])` — the
    /// shape a wallet sends for a legacy transaction. Feeding the signed-transaction
    /// reader instead would take `chain_id` for a `v` and sign for the wrong chain
    /// (see `from_rlp::parse_eip155_signing_request`).
    #[cfg(feature = "chain-eth")]
    #[test]
    fn sign_eth_legacy_mainnet_reaches_the_container_with_v37() {
        use crate::chain::eth::eip155;
        use crate::ur::codec::eth_signature::parse_eth_signature;

        let tx = eip155::Eip155Transaction {
            chain_id: 1,
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new().into(),
        };
        // the preimage IS the wire shape, and the gold vector's preimage
        let sign_data = eip155::signing_preimage(&tx);
        assert_eq!(
            hex_lower(&sign_data),
            "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080",
            "the request payload must be the EIP-155 preimage"
        );

        let test_seed = [7u8; 64];
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let derived =
            crate::derivation::bip32_secp256k1::derive_from_seed(&test_seed, &path).unwrap();
        let expected = eip155::sign_eip155_parts(&eip155::Eip155SignInput {
            tx,
            private_key: &SecretBytes::new(crate::curve_primitive::secp256k1::scalar_to_bytes(
                &derived,
            )),
        })
        .unwrap();

        let ur_payload = encode_eth_sign_request_for_test(&sign_data, 1, 1);
        let mut output_buf = [0u8; 512];
        let n = sign(
            SignInput::Seed { seed: &test_seed },
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        )
        .expect("legacy signs");

        let sig = parse_eth_signature(&output_buf[..n]).expect("eth-signature container");
        assert_eq!(sig.request_id, TEST_ETH_REQUEST_ID, "request id echoed");
        // mainnet v = 37/38 → one byte → the classic 65-byte container
        assert_eq!(sig.signature_len, 65, "mainnet legacy stays 65 bytes");
        assert_eq!(&sig.signature_bytes()[..32], &expected.r[..], "r");
        assert_eq!(&sig.signature_bytes()[32..64], &expected.s[..], "s");
        assert_eq!(
            &sig.signature_bytes()[64..],
            &[0x25],
            "v = chain_id*2 + 35 + parity = 37 (0x25)"
        );
        assert_eq!(expected.v, 37, "the oracle agrees on v");
    }

    /// The container's `v` segment follows the chain id, and it is what makes the
    /// signature usable at all: Sepolia (11155111 → 22310257) needs 4 bytes and Polygon
    /// (137 → 309) needs 2, which a fixed 65-byte field could not carry.
    #[cfg(feature = "chain-eth")]
    #[test]
    fn sign_eth_legacy_v_segment_follows_the_chain_id() {
        use crate::chain::eth::eip155;
        use crate::ur::codec::eth_signature::parse_eth_signature;

        let test_seed = [7u8; 64];
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let derived =
            crate::derivation::bip32_secp256k1::derive_from_seed(&test_seed, &path).unwrap();
        let key = SecretBytes::new(crate::curve_primitive::secp256k1::scalar_to_bytes(&derived));

        // (chain id, expected container length, expected v for parity 0, label)
        let cases: [(u64, usize, &[u8], &str); 3] = [
            (1, 65, &[0x25], "mainnet → v = 37"),
            (137, 66, &[0x01, 0x35], "polygon → v = 309"),
            (
                11_155_111,
                68,
                &[0x01, 0x54, 0x6d, 0x71],
                "sepolia → v = 22310257",
            ),
        ];
        for (chain_id, want_len, v_parity0, label) in cases {
            let tx = eip155::Eip155Transaction {
                chain_id,
                nonce: 0,
                gas_price: 1_000_000_000,
                gas_limit: 21_000,
                destination: Some([0x11u8; 20]),
                amount: 0,
                data: Vec::new().into(),
            };
            let sign_data = eip155::signing_preimage(&tx);
            let expected = eip155::sign_eip155_parts(&eip155::Eip155SignInput {
                tx,
                private_key: &key,
            })
            .unwrap();
            // v = chain_id*2 + 35 + parity. `v_parity0` is the parity-0 form, so the
            // expected bytes are that value plus the parity the oracle produced.
            let parity = (expected.v - (chain_id * 2 + 35)) as u8;
            assert!(parity <= 1, "{label}: v must be the protected form");
            let mut full = [0u8; 8];
            full[8 - v_parity0.len()..].copy_from_slice(v_parity0);
            let v_value = u64::from_be_bytes(full) + u64::from(parity);
            let mut want_v = [0u8; 8];
            let want_v_len = eip155::write_v_be(v_value, &mut want_v).expect("write v");
            let want_v = &want_v[..want_v_len];

            let ur_payload = encode_eth_sign_request_for_test(&sign_data, 1, chain_id);
            let mut output_buf = [0u8; 512];
            let n = sign(
                SignInput::Seed { seed: &test_seed },
                crate::ur::ur_encode::UrTypeTag::EthSignRequest,
                &ur_payload,
                &mut output_buf,
            )
            .expect("legacy signs");
            let sig = parse_eth_signature(&output_buf[..n]).expect("container");
            assert_eq!(sig.signature_len, want_len, "{label}: container width");
            assert_eq!(&sig.signature_bytes()[..32], &expected.r[..], "{label}: r");
            assert_eq!(
                &sig.signature_bytes()[32..64],
                &expected.s[..],
                "{label}: s"
            );
            assert_eq!(
                &sig.signature_bytes()[64..],
                want_v,
                "{label}: v bytes must be minimal big-endian"
            );
        }
    }

    /// An unprotected legacy request (6 items, no chain id) is refused as
    /// unimplemented — a stable code for a shape we know and will not sign — never as a
    /// malformed request, and never signed with a 27/28 `v`.
    #[cfg(feature = "chain-eth")]
    #[test]
    fn sign_eth_legacy_unprotected_six_item_shape_is_refused() {
        use crate::chain::eth::rlp;
        // rlp([nonce, gas_price, gas_limit, to, value, data]) — no chain id at all
        let sign_data = rlp::encode_list(&[
            rlp::encode_uint(9),
            rlp::encode_uint(20_000_000_000),
            rlp::encode_uint(21_000),
            rlp::encode_bytes(&[0x35u8; 20]),
            rlp::encode_uint(1_000_000_000_000_000_000),
            rlp::encode_bytes(b""),
        ]);
        let ur_payload = encode_eth_sign_request_for_test(&sign_data, 1, 1);
        let test_seed = [7u8; 64];
        let mut output_buf = [0u8; 512];
        let result = sign(
            SignInput::Seed { seed: &test_seed },
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::FeatureNotImplemented,
            "pre-EIP-155 has no replay protection: refused, and not as a format error"
        );
    }

    /// A typed transaction body with its `0x02` byte stripped is NOT a legacy request:
    /// legacy carries a chain id in item 6 and empty signature slots, this carries
    /// neither. It must fail as malformed instead of being signed as something else.
    #[cfg(feature = "chain-eth")]
    #[test]
    fn sign_eth_legacy_rejects_a_typed_body_without_its_type_byte() {
        use crate::chain::eth::eip1559::Eip1559Transaction;

        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 12345,
            data: Vec::new().into(),
        };
        let typed = encode_unsigned_tx_for_test(&tx);
        let legacy = &typed[1..];
        let ur_payload = encode_eth_sign_request_for_test(legacy, 1, 1);

        let test_seed = [7u8; 64];
        let mut output_buf = [0u8; 512];
        let result = sign(
            SignInput::Seed { seed: &test_seed },
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::EncodingInvalidFormat,
            "a 12-item body is not a legacy request"
        );
    }

    /// The request's own `chain_id` (key 4) must agree with the transaction, exactly as
    /// on the typed path: a legacy request that names chain 5 while carrying a chain-1
    /// transaction is a request this device must not sign.
    #[cfg(feature = "chain-eth")]
    #[test]
    fn sign_eth_legacy_rejects_a_chain_id_mismatch() {
        use crate::chain::eth::eip155;

        let tx = eip155::Eip155Transaction {
            chain_id: 1,
            nonce: 0,
            gas_price: 1_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 0,
            data: Vec::new().into(),
        };
        let sign_data = eip155::signing_preimage(&tx);
        // request says Goerli (5), the transaction says mainnet (1)
        let ur_payload = encode_eth_sign_request_for_test(&sign_data, 1, 5);
        let test_seed = [7u8; 64];
        let mut output_buf = [0u8; 512];
        let result = sign(
            SignInput::Seed { seed: &test_seed },
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::NetworkUnrecognized
        );
    }

    /// `data_type` 4 (`TypedTransaction`) dispatches on the FIRST payload byte. Only `0x02`
    /// (EIP-1559) is signable here; the other *valid* type bytes (EIP-2930 / 4844 / 7702)
    /// must report "unimplemented" rather than "malformed", while a byte that is not a
    /// transaction type at all (`0x99`) — or no byte at all — is a format error.
    #[cfg(feature = "chain-eth")]
    #[test]
    fn sign_eth_typed_transaction_first_byte_selects_the_scheme() {
        use crate::chain::eth::eip1559::Eip1559Transaction;

        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 12345,
            data: Vec::new().into(),
        };
        let typed = encode_unsigned_tx_for_test(&tx);
        // Same 1559 body, different leading type byte.
        let retype = |b: u8| {
            let mut v = typed.clone();
            v[0] = b;
            v
        };

        let cases: [(Vec<u8>, ShlosiloErrorKind, &str); 5] = [
            (
                retype(0x01),
                ShlosiloErrorKind::FeatureNotImplemented,
                "0x01 (EIP-2930) is a real transaction type we do not sign",
            ),
            (
                retype(0x03),
                ShlosiloErrorKind::FeatureNotImplemented,
                "0x03 (EIP-4844) is a real transaction type we do not sign",
            ),
            (
                retype(0x04),
                ShlosiloErrorKind::FeatureNotImplemented,
                "0x04 (EIP-7702) is a real transaction type we do not sign",
            ),
            (
                retype(0x99),
                ShlosiloErrorKind::EncodingInvalidFormat,
                "0x99 is not a transaction type",
            ),
            (
                Vec::new(),
                ShlosiloErrorKind::EncodingInvalidFormat,
                "an empty payload has no type byte",
            ),
        ];

        let test_seed = [7u8; 64];
        for (sign_data, expected, why) in cases {
            let ur_payload = encode_eth_sign_request_for_test(&sign_data, 4, 1);
            let mut output_buf = [0u8; 512];
            let result = sign(
                SignInput::Seed { seed: &test_seed },
                crate::ur::ur_encode::UrTypeTag::EthSignRequest,
                &ur_payload,
                &mut output_buf,
            );
            assert_eq!(result.unwrap_err().kind, expected, "{why}");
        }
    }

    /// Test helper: lowercase hex, for comparing a built payload with a published one.
    #[cfg(feature = "chain-eth")]
    fn hex_lower(bytes: &[u8]) -> alloc::string::String {
        use core::fmt::Write as _;
        let mut s = alloc::string::String::new();
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Test helper: encode an unsigned EIP-1559 tx into raw bytes (for from_rlp parsing)
    #[cfg(feature = "chain-eth")]
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

    /// Fixed request id used by the ETH request fixtures — the ur-registry test
    /// vector's `requestId` (9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d), so the
    /// encodings stay comparable with the gold vector in
    /// `docs/eth-signature-codec.md`.
    ///
    /// E-1: the exit echoes this id into the `eth-signature` container, so every
    /// fixture that expects a *signature* must carry key 1.
    const TEST_ETH_REQUEST_ID: [u8; 16] = [
        0x9b, 0x1d, 0xeb, 0x4d, 0x3b, 0x7d, 0x4b, 0xad, 0x9b, 0xdd, 0x2b, 0x0d, 0x7b, 0x3d, 0xcb,
        0x6d,
    ];

    /// Test helper: build an eth-sign-request CBOR map (ur-registry shape, minimal set)
    /// {1: request_id(tag 37 UUID), 2: sign_data(bytes), 3: data_type(uint), 4: chain_id(uint)}
    #[cfg(feature = "chain-eth")]
    fn encode_eth_sign_request_for_test(
        sign_data: &[u8],
        data_type: u64,
        chain_id: u64,
    ) -> alloc::vec::Vec<u8> {
        encode_eth_sign_request_full_for_test(
            sign_data,
            data_type,
            chain_id,
            None,
            Some(TEST_ETH_REQUEST_ID),
        )
    }

    /// + optional derivation_path (key 5, tag 305 crypto-keypath)
    #[cfg(feature = "chain-eth")]
    fn encode_eth_sign_request_with_path_for_test(
        sign_data: &[u8],
        data_type: u64,
        chain_id: u64,
        path: Option<&DerivationPath>,
    ) -> alloc::vec::Vec<u8> {
        encode_eth_sign_request_full_for_test(
            sign_data,
            data_type,
            chain_id,
            path,
            Some(TEST_ETH_REQUEST_ID),
        )
    }

    /// Full control over the optional keys. `request_id = None` omits key 1 — the
    /// shape the E-1 exit refuses, since a reply it cannot correlate is useless.
    #[cfg(feature = "chain-eth")]
    fn encode_eth_sign_request_full_for_test(
        sign_data: &[u8],
        data_type: u64,
        chain_id: u64,
        path: Option<&DerivationPath>,
        request_id: Option<[u8; 16]>,
    ) -> alloc::vec::Vec<u8> {
        use crate::encoding::cbor;
        let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        if let Some(id) = request_id {
            // request_id: key 1, tag(37 UUID) over exactly 16 bytes
            pairs.push((
                cbor::encode_uint(1),
                cbor::encode_tag(37, &cbor::encode_bytes(&id)),
            ));
        }
        pairs.push((cbor::encode_uint(2), cbor::encode_bytes(sign_data)));
        pairs.push((cbor::encode_uint(3), cbor::encode_uint(data_type)));
        pairs.push((cbor::encode_uint(4), cbor::encode_uint(chain_id)));
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
    #[cfg(feature = "chain-btc")]
    #[test]
    #[cfg(feature = "alloc-fallback")]
    fn sign_btc_psbt_end_to_end() {
        use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut};
        use crate::chain::btc::psbt::{self, input_type};
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
        let mut psbt = psbt_from_maps_leaky(
            Transaction {
                version: 2,
                inputs: bt_vec![TxIn {
                    prev_out: OutPoint {
                        txid: [0xABu8; 32],
                        vout: 0,
                    },
                    script_sig: Vec::new().into(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                }],
                outputs: bt_vec![TxOut {
                    value: 90_000,
                    script_pubkey: spk.clone().into(),
                }],
                lock_time: 0,
            },
            &[],
            &[alloc::vec![]], // 1 output map (empty)
        );
        // input map: WITNESS_UTXO + BIP32_DERIVATION
        let mut wu_value = alloc::vec::Vec::new();
        wu_value.extend_from_slice(&100_000u64.to_le_bytes());
        wu_value.push(22); // varint(22) script len
        wu_value.extend_from_slice(&spk);
        let extra_map = alloc::vec![
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
        ];
        for kv in extra_map {
            psbt.set_input_kv(0, kv.key.as_ref(), kv.value.as_ref())
                .unwrap();
        }

        // 4. serialize → CBOR bytes (the crypto-psbt payload is a CBOR bytes item, no leading type byte)
        let psbt_bytes = psbt::serialize_psbt(&psbt).expect("fits");
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
        let partial = signed
            .input_map(0)
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
    #[cfg(feature = "chain-btc")]
    #[test]
    #[cfg(feature = "alloc-fallback")]
    fn sign_btc_psbt_uses_psbt_derivation_path() {
        use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut}; // keep
        use crate::chain::btc::psbt::{self, input_type};
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
        let mut psbt = psbt_from_maps_leaky(
            Transaction {
                version: 2,
                inputs: bt_vec![TxIn {
                    prev_out: OutPoint {
                        txid: [0xABu8; 32],
                        vout: 0
                    },
                    script_sig: Vec::new().into(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                }],
                outputs: bt_vec![TxOut {
                    value: 90_000,
                    script_pubkey: spk.clone().into(),
                }],
                lock_time: 0,
            },
            &[],
            &[alloc::vec![]],
        );
        let mut wu_value = alloc::vec::Vec::new();
        wu_value.extend_from_slice(&100_000u64.to_le_bytes());
        wu_value.push(22);
        wu_value.extend_from_slice(&spk);
        let local_fp =
            crate::derivation::bip32_secp256k1::master_fingerprint_from_seed(&seed).unwrap();
        let extra_map = alloc::vec![
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
        ];
        for kv in extra_map {
            psbt.set_input_kv(0, kv.key.as_ref(), kv.value.as_ref())
                .unwrap();
        }

        let psbt_bytes = psbt::serialize_psbt(&psbt).expect("fits");
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
    #[cfg(feature = "chain-btc")]
    #[test]
    #[cfg(feature = "alloc-fallback")]
    fn sign_btc_psbt_rejects_fingerprint_mismatch() {
        use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut}; // keep
        use crate::chain::btc::psbt::{self, input_type};
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
        let mut psbt = psbt_from_maps_leaky(
            Transaction {
                version: 2,
                inputs: bt_vec![TxIn {
                    prev_out: OutPoint {
                        txid: [0xABu8; 32],
                        vout: 0
                    },
                    script_sig: Vec::new().into(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                }],
                outputs: bt_vec![TxOut {
                    value: 90_000,
                    script_pubkey: spk.clone().into(),
                }],
                lock_time: 0,
            },
            &[],
            &[alloc::vec![]],
        );
        let mut wu_value = alloc::vec::Vec::new();
        wu_value.extend_from_slice(&100_000u64.to_le_bytes());
        wu_value.push(22);
        wu_value.extend_from_slice(&spk);
        let wrong_fp = [0xDE, 0xAD, 0xBE, 0xEF];
        let extra_map = alloc::vec![
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
        ];
        for kv in extra_map {
            psbt.set_input_kv(0, kv.key.as_ref(), kv.value.as_ref())
                .unwrap();
        }

        let psbt_bytes = psbt::serialize_psbt(&psbt).expect("fits");
        let ur_payload = cbor::encode_bytes(&psbt_bytes);

        let mut output_buf = [0u8; 4096];
        let input = SignInput::Seed { seed: &seed };
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::CryptoPsbt,
            &ur_payload,
            &mut output_buf,
        );
        // Ownership class, not network: a record naming someone else's fingerprint
        // says nothing about which chain this is. The old -12 mapping sent the
        // operator to the wrong setting entirely (2026-11-12).
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::PsbtOwnershipMismatch
        );
    }

    /// P1-B: witness_utxo scriptPubKey not bound to the signing key (swapped to someone else's P2WPKH) → reject
    #[cfg(feature = "chain-btc")]
    #[test]
    #[cfg(feature = "alloc-fallback")]
    fn p1b_rejects_witness_utxo_script_mismatch() {
        use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut}; // keep
        use crate::chain::btc::psbt::{self, input_type};
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

        let psbt = psbt_from_maps_leaky(
            Transaction {
                version: 2,
                inputs: bt_vec![TxIn {
                    prev_out: OutPoint {
                        txid: [0xABu8; 32],
                        vout: 0
                    },
                    script_sig: Vec::new().into(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                }],
                outputs: bt_vec![TxOut {
                    value: 90_000,
                    script_pubkey: spk.clone().into(),
                }],
                lock_time: 0,
            },
            &[alloc::vec![
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
            &[alloc::vec![]],
        );

        let psbt_bytes = psbt::serialize_psbt(&psbt).expect("fits");
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
    #[cfg(feature = "chain-btc")]
    #[test]
    #[cfg(feature = "alloc-fallback")]
    fn p1b_rejects_missing_derivation_record() {
        use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut}; // keep
        use crate::chain::btc::psbt::{self, input_type};
        use crate::encoding::cbor;

        let seed = [0xA5u8; 64];
        let mut spk = alloc::vec![0x00u8, 0x14];
        spk.extend_from_slice(&[0x22u8; 20]);

        let psbt = psbt_from_maps_leaky(
            Transaction {
                version: 2,
                inputs: bt_vec![TxIn {
                    prev_out: OutPoint {
                        txid: [0xABu8; 32],
                        vout: 0
                    },
                    script_sig: Vec::new().into(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                }],
                outputs: bt_vec![TxOut {
                    value: 90_000,
                    script_pubkey: spk.clone().into(),
                }],
                lock_time: 0,
            },
            &[alloc::vec![psbt::KeyValue {
                key: alloc::vec![input_type::WITNESS_UTXO].into(),
                value: {
                    let mut v = alloc::vec::Vec::new();
                    v.extend_from_slice(&100_000u64.to_le_bytes());
                    v.push(22);
                    v.extend_from_slice(&spk);
                    v.into()
                },
            }]],
            &[alloc::vec![]],
        );

        let psbt_bytes = psbt::serialize_psbt(&psbt).expect("fits");
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
    #[cfg(feature = "chain-eth")]
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
            data: Vec::new().into(),
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
                private_key: &SecretBytes::new(derived_bytes),
            },
        )
        .unwrap();

        let raw = encode_unsigned_tx_for_test(&tx);
        let ur_payload = encode_eth_sign_request_with_path_for_test(&raw, 4, 1, Some(&path));

        let mut output_buf = [0u8; 512];
        let input = SignInput::Seed { seed: &test_seed };
        let n = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        )
        .expect("sign ok");

        // E-1: compare the container's r/s/v against a direct sign with the key
        // derived from that path → path threading proven. (Before E-1 this compared
        // the signed raw transaction, which is no longer the exit shape.)
        let sig = crate::ur::codec::eth_signature::parse_eth_signature(&output_buf[..n])
            .expect("eth-signature container");
        assert_eq!(&sig.signature[..32], &expected.r[..], "r");
        assert_eq!(&sig.signature[32..64], &expected.s[..], "s");
        assert_eq!(sig.signature[64], expected.y_parity, "v = yParity");
        assert_eq!(sig.request_id, TEST_ETH_REQUEST_ID, "request id echoed");

        // …and it is really *that* path: the default account would sign differently.
        let default_path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let default_derived =
            crate::derivation::bip32_secp256k1::derive_from_seed(&test_seed, &default_path)
                .unwrap();
        let default_expected = crate::chain::eth::eip1559::sign_eip1559(
            &crate::chain::eth::eip1559::Eip1559SignInput {
                tx: tx.clone(),
                private_key: &SecretBytes::new(crate::curve_primitive::secp256k1::scalar_to_bytes(
                    &default_derived,
                )),
            },
        )
        .unwrap();
        assert_ne!(
            &sig.signature[..32],
            &default_expected.r[..],
            "the request's path (m/44'/60'/1'/0/0) must win over the default"
        );
    }

    /// P1-02: network in decision — BTC rejects non-mainnet
    #[cfg(feature = "chain-btc")]
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
    #[cfg(feature = "chain-eth")]
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
            data: Vec::new().into(),
        };
        let raw = encode_unsigned_tx_for_test(&tx);
        let ur_payload = encode_eth_sign_request_for_test(&raw, 4, 1);
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
    #[cfg(feature = "chain-eth")]
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
            data: Vec::new().into(),
        };
        let raw = encode_unsigned_tx_for_test(&tx);
        let ur_payload = encode_eth_sign_request_for_test(&raw, 4, 1);
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

#[cfg(test)]
mod t04_overlay_pins {
    //! T-04 follow-up pins for the overlay region. The PHASE EXCLUSIVITY
    //! (enter_cn / enter_bp never coexist) is enforced by the borrow checker —
    //! compile-time, no test needed. These pins fire the two runtime claims:
    //! the CN phase zeroizes on every drop path, and the region is fully
    //! written before it is read (the poison pin lives in
    //! tests/xmr_sign_reuse_determinism.rs).
    extern crate alloc;
    use super::*;

    #[cfg(feature = "chain-xmr")]
    #[test]
    fn cn_phase_zeroizes_overlay_on_drop() {
        let mut raw = alloc::vec![0xAAu8; crate::types::caps::SIGN_WS_BP_OVERLAY_BYTES];
        let mut region = OverlayRegion::new(&mut raw);
        {
            let mut cn = region.enter_cn();
            let _ =
                crate::chain::xmr::unsigned_txset::chacha_key_from_view_sk(&[0x11u8; 32], &mut cn);
        }
        assert!(
            raw.iter().all(|&b| b == 0),
            "the CN phase guard must zeroize the overlay on drop"
        );
    }

    #[cfg(feature = "chain-xmr")]
    #[test]
    fn cn_phase_zeroizes_overlay_on_unwind() {
        extern crate alloc;
        extern crate std;
        let mut raw = alloc::vec![0xAAu8; crate::types::caps::SIGN_WS_BP_OVERLAY_BYTES];
        {
            let mut region = OverlayRegion::new(&mut raw);
            let mut cn = region.enter_cn();
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = &mut *cn;
                panic!("forced unwind through the CN phase");
            }));
            assert!(res.is_err(), "the forced panic must unwind");
        }
        assert!(
            raw.iter().all(|&b| b == 0),
            "the CN phase guard must zeroize the overlay even on unwind"
        );
    }
}
