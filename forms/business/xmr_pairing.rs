//! Cake direct pairing — output-export receive leg (T3).
//!
//! One business chain (isomorphic to keystone `generate_export_ur_data`):
//! 1. `xmr-output` UR payload (the `Monero output export\x04` encrypted container)
//!    → `decrypt_export_payload` (signature first, then decrypt)
//! 2. epee parse (`ExportedTransferDetails`) + pk1/pk2 ownership validation
//!    (pk1 must equal spend_pub, pk2 must equal view_pub derived from the
//!    session keys — a foreign request is rejected before any key image exists)
//! 3. per-output key image + accompanying signature → `Monero key image export\x03`
//!    encrypted container — the `xmr-keyimage` UR payload bytes, written to the
//!    caller's output buffer verbatim.
//!
//! Key source: the caller (FFI) borrows the keys from a [`KeySession`] read
//! port (`KeySession::monero`) — plaintext key bytes never cross the FFI
//! boundary (v2 §4.1). Intermediate buffers are wiped before return (the
//! request plaintext transient is wiped inside the chain core; the workspace
//! scratch is wiped here).

use rand_core::{CryptoRng, RngCore};

use crate::chain::xmr::key_image_export::{
    generate_key_image_export_into, KEY_IMAGE_EXPORT_MAGIC, OUTPUT_EXPORT_MAGIC,
};
use crate::chain::xmr::output_export::{ExportedTransferDetail, KEY_IMAGE_RECORD_LEN};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::types::key_session::KeySession;

/// Worst-case wire size of one parsed detail record: the output/tx pubkeys and
/// flags byte, every varint at u64 worst case (10 B), and EXTRA_KEYS_MAX
/// additional keys. The scratch sizing derives from this so a max-size record
/// stream cannot overflow the decrypted-request transient.
const DETAIL_WIRE_MAX: usize = 10
    + 32 // version varint + output pubkey
    + 10 + 10 // internal / global output index varints
    + 32 // tx pubkey
    + 1 // flags
    + 10 // amount varint
    + 10 // additional-keys count varint
    + 32 * crate::types::caps::EXTRA_KEYS_MAX
    + 10 + 10; // major / minor varints
/// Request plaintext scratch cap (decrypted request transient + response wire
/// staging — whichever is larger). The encrypted request itself is budgeted
/// upstream at `MULTIPART_PAYLOAD_MAX_LEN`. Derived, not tuned: request =
/// 4-byte offset + pk1/pk2 + the header varints + worst-case records; response
/// = 24+8 header + offset + pk1/pk2 + 96 B records + 64 B signature.
const PAIRING_SCRATCH_LEN: usize = {
    let request = 104 + PAIRING_DETAILS_MAX * DETAIL_WIRE_MAX;
    let response = 164 + PAIRING_RECORDS_MAX * KEY_IMAGE_RECORD_LEN;
    if request > response {
        request
    } else {
        response
    }
};
/// Output-detail pool (deployment parameter; over-cap surfaces as an explicit
/// `Err(BufferTooSmall)`, never truncation). 32 = 4x the largest observed real
/// wallet (8 transfers, the tx2 fixture — built at the old cap); >32 transfers
/// is a documented -20 boundary (pool §37). Dynamic/streaming sizing remains
/// the LuckyFox-era candidate if real wallets outgrow this.
// REVISIT 2026-10-29: the 38-record live case failed HERE (the parse-side
// cap is separate from the store/response cap) — raised to 64 in lockstep.
// Same endgame note as PAIRING_RECORDS_MAX (pool #55 C/D decision).
const PAIRING_DETAILS_MAX: usize = 64;
/// Key-image record pool (one 96 B record per output) — mirrors the details
/// cap so every parsed output is answered. The C-side retention mirror is
/// `PAIRING_KI_MAX` in flux/forgebox/src/tasks/product_task.c.
/// KI pairing record cap. Origin (2026-10-21): 4x the largest observed
/// wallet (the 1021 test wallet = 8 transfers) under the zero-heap rule of
/// fixed static caps. REVISIT LOG (2026-10-29): a Cake `Outputs (all)` of
/// 38 records broke the 32 cap (pairing leg refused with BufferTooSmall,
/// surfaced to the user as a silent failure); raised to 64 for headroom.
/// 64 only buys — real wallets hold hundreds of outputs, and the real wall is
/// the positional full-array protocol shape itself (wallet2
/// `import_key_images` semantics). Endgames (persistent store + paged sync
/// vs keystone-shape empty-array + keyed map) are the LuckyFox-phase C/D
/// decision (pool #55). Rule regardless of cap: an over-cap refusal MUST be
/// visibly reported (拆码红线). Mirror: flux/forgebox product_task.c
/// PAIRING_KI_MAX.
const PAIRING_RECORDS_MAX: usize = 64;

/// Caller-provisioned workspace for the receive leg (Z3 caller-workspace
/// discipline — forms allocates nothing on this path). Carved from raw caller
/// bytes by [`carve_pairing_ws`].
pub struct PairingWs<'a> {
    /// Decrypted-request transient + response wire staging (wiped before return).
    scratch: &'a mut [u8],
    /// CryptoNight-V0 key-derivation scratchpad (algorithm-defined 2MB — the
    /// same `types::caps::SIGN_WS_CN_SCRATCH` constant as the sign ws slot).
    /// Secret-bearing (key-derivation intermediate): the CN core zeroes it on
    /// every exit path, restoring the carve's documented zero-fill state.
    cn_scratch: &'a mut [u8],
    /// Parsed output details (public material).
    details: &'a mut [ExportedTransferDetail],
    /// Computed (image, sig) records (public material).
    records: &'a mut [([u8; 32], [u8; 64])],
}

fn align_up(off: usize, align: usize) -> usize {
    (off + align - 1) & !(align - 1)
}

fn ws_next(off: &mut usize, align: usize, size: usize) -> usize {
    let start = align_up(*off, align);
    *off = start + size;
    start
}

/// Workspace layout — ONE computation shared by [`pairing_ws_len`] and
/// [`carve_pairing_ws`] (the probe and the carve must never disagree; each
/// slot's offset comes from this struct only).
struct PairingWsLayout {
    scratch: usize,
    cn_scratch: usize,
    details: usize,
    records: usize,
    total: usize,
}

impl PairingWsLayout {
    fn compute() -> Self {
        let mut off = 0usize;
        let scratch = ws_next(&mut off, 1, PAIRING_SCRATCH_LEN);
        // CN-V0 scratchpad: u128 alignment governs the slot (the CN core
        // validates it — same slot rule as `SignWsLayout`'s cn overlay).
        let cn_scratch = ws_next(
            &mut off,
            core::mem::align_of::<u128>(),
            crate::types::caps::SIGN_WS_CN_SCRATCH,
        );
        let a_d = core::mem::align_of::<ExportedTransferDetail>().max(8);
        let details = ws_next(
            &mut off,
            a_d,
            core::mem::size_of::<ExportedTransferDetail>() * PAIRING_DETAILS_MAX,
        );
        let a_r = core::mem::align_of::<([u8; 32], [u8; 64])>().max(8);
        let records = ws_next(
            &mut off,
            a_r,
            core::mem::size_of::<([u8; 32], [u8; 64])>() * PAIRING_RECORDS_MAX,
        );
        let total = align_up(off, 8);
        PairingWsLayout {
            scratch,
            cn_scratch,
            details,
            records,
            total,
        }
    }
}

/// Total caller-workspace bytes required by [`carve_pairing_ws`].
pub fn pairing_ws_len() -> usize {
    PairingWsLayout::compute().total
}

/// Carve a [`PairingWs`] out of a caller workspace buffer (the same pattern as
/// `business::sign::carve_sign_ws`). Returns `None` when `buf` is smaller than
/// [`pairing_ws_len`] — the carve never partially succeeds.
///
/// # Safety contract (internal unsafe, ffi-seam pattern)
/// The typed spans reinterpret caller bytes; every slot is explicitly
/// initialized after carving (`ExportedTransferDetail::default()`, records
/// zeroed) so no uninit value is ever observable.
pub fn carve_pairing_ws(buf: &mut [u8]) -> Option<PairingWs<'_>> {
    let l = PairingWsLayout::compute();
    if buf.len() < l.total {
        return None;
    }
    buf[..l.total].fill(0);
    let base: *mut u8 = buf.as_mut_ptr();
    // SAFETY: offsets are disjoint by construction (the same computation
    // `pairing_ws_len` reports); every element is initialized below before the
    // slices are handed out; all spans derive from one base pointer.
    unsafe fn at<'a, T>(base: *mut u8, off: usize, count: usize) -> &'a mut [T] {
        core::slice::from_raw_parts_mut(base.add(off) as *mut T, count)
    }
    let scratch: &mut [u8] = unsafe { at(base, l.scratch, PAIRING_SCRATCH_LEN) };
    let cn_scratch: &mut [u8] =
        unsafe { at(base, l.cn_scratch, crate::types::caps::SIGN_WS_CN_SCRATCH) };
    let details: &mut [ExportedTransferDetail] =
        unsafe { at(base, l.details, PAIRING_DETAILS_MAX) };
    for s in details.iter_mut() {
        unsafe { core::ptr::write(s, ExportedTransferDetail::default()) };
    }
    let records: &mut [([u8; 32], [u8; 64])] = unsafe { at(base, l.records, PAIRING_RECORDS_MAX) };
    for r in records.iter_mut() {
        unsafe { core::ptr::write(r, ([0u8; 32], [0u8; 64])) };
    }
    Some(PairingWs {
        scratch,
        cn_scratch,
        details,
        records,
    })
}

/// Receive-leg outcome.
#[derive(Clone, Copy, Debug)]
pub struct OutputExportOutcome {
    /// Bytes written to `out` — the `Monero key image export\x03` container,
    /// i.e. the `xmr-keyimage` UR payload (encode with `UrTypeTag::XmrKeyImage`).
    pub written: usize,
    /// Outputs parsed from the request (= key images produced).
    pub output_count: usize,
}

/// The Cake direct pairing receive leg: `xmr-output` payload in,
/// `xmr-keyimage` container bytes out.
///
/// `view_sk`/`spend_sk` are borrows (no copies leave the key holder — see the
/// module docs); `payload` is the raw decrypted-container bytes of the
/// `xmr-output` UR; `out` receives the response container.
pub fn process_output_export<R: RngCore + CryptoRng>(
    view_sk: &[u8; 32],
    spend_sk: &[u8; 32],
    payload: &[u8],
    ws: &mut PairingWs<'_>,
    out: &mut [u8],
    rng: &mut R,
) -> Result<OutputExportOutcome> {
    process_output_export_with_records(view_sk, spend_sk, payload, ws, out, rng, &mut [], &mut 0)
}

/// Records-retention face (tx2 wire fix): in addition to the response
/// container, hands back the (wallet transfer index, true key image) pairs
/// the device just derived — the sign leg fills the signed container's
/// wallet-transfer-indexed `key_images` array from these
/// ([`crate::business::sign::WalletKiRecord`]).
///
/// `ki_out` is caller storage: empty = no retention requested (skipped);
/// non-empty but smaller than the export's record count = `BufferTooSmall`.
/// Record `i` is the true key image of wallet transfer `offset + i` (the
/// phone imports the response positionally at the export offset).
#[allow(clippy::too_many_arguments)] // caller-storage records face (8 args, one call site each)
pub fn process_output_export_with_records<R: RngCore + CryptoRng>(
    view_sk: &[u8; 32],
    spend_sk: &[u8; 32],
    payload: &[u8],
    ws: &mut PairingWs<'_>,
    out: &mut [u8],
    rng: &mut R,
    ki_out: &mut [crate::business::sign::WalletKiRecord],
    ki_written: &mut usize,
) -> Result<OutputExportOutcome> {
    use zeroize::Zeroize as _;
    // The fused chain core: decrypt (signature first) → parse → pk1/pk2
    // ownership check → key images → KEY_IMAGE_EXPORT encryption. The request
    // plaintext transient is wiped inside the core before the response is
    // built; the CN scratchpad is wiped by the CN core on every exit path.
    let (written, offset) = generate_key_image_export_into(
        view_sk,
        spend_sk,
        payload,
        ws.scratch,
        ws.details,
        ws.records,
        out,
        rng,
        ws.cn_scratch,
    )?;
    // forms wipe duty: the scratch staged the response wire records (public
    // material) — wipe regardless before the workspace leaves this function.
    ws.scratch.zeroize();
    // Container shape pin: `magic ‖ nonce(8) ‖ ChaCha(u32le tag ‖ pk1 ‖ pk2 ‖
    // count×96B records) ‖ sig(64)` — count derived from the exact length so
    // the caller learns how many outputs were answered (asserted in tests).
    let overhead = KEY_IMAGE_EXPORT_MAGIC.len() + 8 + 4 + 64 + 64;
    if written < overhead || !(written - overhead).is_multiple_of(KEY_IMAGE_RECORD_LEN) {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let output_count = (written - overhead) / KEY_IMAGE_RECORD_LEN;
    // Records retention: response record `i` = wallet transfer `offset + i`.
    *ki_written = 0;
    if !ki_out.is_empty() {
        if ki_out.len() < output_count {
            return Err(ShlosiloError::with_context(
                ShlosiloErrorKind::BufferTooSmall,
                crate::error::ErrorContext::RequiredLength(output_count),
            ));
        }
        // fix37: bind every record to THIS wallet's fingerprint. The ownership
        // check inside the core already pinned the request's pk1/pk2 to this
        // session's spend/view pubs, so re-deriving them here yields exactly
        // the pubs the records were computed under.
        let wfp = {
            use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
            use curve25519_dalek::scalar::Scalar;
            let spend_pub = (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*spend_sk))
                .compress()
                .to_bytes();
            let view_pub = (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*view_sk))
                .compress()
                .to_bytes();
            crate::business::sign::wallet_fingerprint(&spend_pub, &view_pub)
        };
        for (i, (image, _sig)) in ws.records[..output_count].iter().enumerate() {
            let transfer_idx = u32::try_from(offset + i as u64)
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
            ki_out[i] = crate::business::sign::WalletKiRecord {
                transfer_idx,
                wallet_fp: wfp,
                key_image: *image,
            };
            *ki_written = i + 1;
        }
    }
    Ok(OutputExportOutcome {
        written,
        output_count,
    })
}

/// Session-bound face: keys are borrowed from the [`KeySession`] read port
/// (`KeySession::monero`) — the FFI layer calls this so plaintext key bytes
/// never cross the boundary. `ki_out`/`ki_written` see
/// [`process_output_export_with_records`].
pub fn process_output_export_session<R: RngCore + CryptoRng>(
    session: &KeySession,
    payload: &[u8],
    ws: &mut PairingWs<'_>,
    out: &mut [u8],
    rng: &mut R,
    ki_out: &mut [crate::business::sign::WalletKiRecord],
    ki_written: &mut usize,
) -> Result<OutputExportOutcome> {
    let keys = session.monero();
    process_output_export_with_records(
        keys.view_sk.expose(),
        keys.spend_sk.expose(),
        payload,
        ws,
        out,
        rng,
        ki_out,
        ki_written,
    )
}

/// Re-export for the receive-side callers that only need the request magic
/// (decode routing / pre-flight checks).
pub const REQUEST_MAGIC: &[u8] = OUTPUT_EXPORT_MAGIC;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::chain::xmr::key_image_export::{
        decrypt_export_payload, encrypt_export_payload_into,
    };
    use crate::chain::xmr::output_export::deserialize_key_images_into;
    use alloc::vec;
    use alloc::vec::Vec;
    use rand_chacha::rand_core::SeedableRng;

    fn rng_from(seed: u64) -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::seed_from_u64(seed)
    }

    fn make_keypair(seed: u8) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use curve25519_dalek::scalar::Scalar;
        let sk = Scalar::from_bytes_mod_order([seed; 32]);
        let sk_b = sk.to_bytes();
        let pk = (ED25519_BASEPOINT_TABLE * &sk).compress().to_bytes();
        (sk_b, pk, sk_b, pk) // (spend_sk, spend_pub, view_sk, view_pub)
    }

    /// One main-address output with the key-image-request bit set (the same
    /// plaintext shape the real wallet emits).
    fn request_plain(view_sk: &[u8; 32], spend_sk: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use curve25519_dalek::scalar::Scalar;
        let mut plain = Vec::new();
        plain.extend_from_slice(&[0x01]); // has_transfers
        plain.extend_from_slice(&[0x00]); // offset
        plain.extend_from_slice(&[0x01]); // total
        plain.extend_from_slice(&[0x01]); // record_count (ignored)
        plain.extend_from_slice(&[0x01]); // version
        let offset =
            crate::chain::xmr::subaddress::calc_output_key_offset(view_sk, &[0x22u8; 32], 0, 0, 0)
                .unwrap();
        let input_sk =
            Scalar::from_bytes_mod_order(*spend_sk) + Scalar::from_bytes_mod_order(offset);
        let out_pub = (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes();
        plain.extend_from_slice(&out_pub);
        plain.extend_from_slice(&[0x00]); // idx=0
        plain.extend_from_slice(&[0x64]); // gidx=100
        plain.extend_from_slice(&[0x22u8; 32]); // tx_pubkey
        plain.push(0b0001_0100); // rct + key_image_request
        plain.extend_from_slice(&[0x80, 0x89, 0x2f]); // amount
        plain.extend_from_slice(&[0x00]); // no additional keys
        plain.extend_from_slice(&[0x00, 0x00]); // major=0 minor=0
        (plain, out_pub)
    }

    fn make_request(view_sk: &[u8; 32], spend_sk: &[u8; 32], seed: u64) -> (Vec<u8>, [u8; 32]) {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use curve25519_dalek::scalar::Scalar;
        let (plain, out_pub) = request_plain(view_sk, spend_sk);
        let spend_pub = (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*spend_sk))
            .compress()
            .to_bytes();
        let view_pub = (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*view_sk))
            .compress()
            .to_bytes();
        let mut rng = rng_from(seed);
        let mut buf = vec![0u8; 2048];
        let mut cn = vec![0u8; crate::types::caps::SIGN_WS_CN_SCRATCH];
        let n = encrypt_export_payload_into(
            OUTPUT_EXPORT_MAGIC,
            view_sk,
            &spend_pub,
            &view_pub,
            0u32,
            &plain,
            &mut rng,
            &mut buf,
            &mut cn,
        )
        .unwrap();
        buf.truncate(n);
        (buf, out_pub)
    }

    fn ws_buf() -> Vec<u8> {
        vec![0u8; pairing_ws_len()]
    }

    /// Shared with the FFI end-to-end test (c_abi): build a valid encrypted
    /// output-export request under the given wallet keys.
    pub(crate) fn make_request_pub(
        view_sk: &[u8; 32],
        spend_sk: &[u8; 32],
        seed: u64,
    ) -> (Vec<u8>, [u8; 32]) {
        make_request(view_sk, spend_sk, seed)
    }

    /// End-to-end: request container → process_output_export → decrypt the
    /// response → 1 record, key image matches the independent recomputation.
    #[test]
    fn process_output_export_end_to_end() {
        let (spend_sk, _, view_sk, _) = make_keypair(5);
        let (req, out_pub) = make_request(&view_sk, &spend_sk, 7);
        let mut ws_raw = ws_buf();
        let mut ws = carve_pairing_ws(&mut ws_raw).unwrap();
        let mut rng = rng_from(11);
        let mut out = vec![0u8; 2048];
        let outcome =
            process_output_export(&view_sk, &spend_sk, &req, &mut ws, &mut out, &mut rng).unwrap();
        assert_eq!(outcome.output_count, 1);
        assert_eq!(
            outcome.written,
            KEY_IMAGE_EXPORT_MAGIC.len() + 140 + KEY_IMAGE_RECORD_LEN
        );

        // Hot-side read-back
        let (_, _, resp_plain) =
            decrypt_export_payload(&out[..outcome.written], KEY_IMAGE_EXPORT_MAGIC, &view_sk)
                .unwrap();
        let mut recs = [([0u8; 32], [0u8; 64]); 8];
        let n = deserialize_key_images_into(&resp_plain, &mut recs).unwrap();
        assert_eq!(n, 1);
        // Independent key image recomputation
        use curve25519_dalek::scalar::Scalar;
        use monero_ed25519::Point;
        let offset =
            crate::chain::xmr::subaddress::calc_output_key_offset(&view_sk, &[0x22u8; 32], 0, 0, 0)
                .unwrap();
        let input_sk =
            Scalar::from_bytes_mod_order(spend_sk) + Scalar::from_bytes_mod_order(offset);
        let hp: curve25519_dalek::EdwardsPoint = Point::biased_hash(out_pub).into();
        let expect: [u8; 32] = (hp * input_sk).compress().to_bytes();
        assert_eq!(recs[0].0, expect);
    }

    /// Foreign request (pk1/pk2 not derived from these keys) is rejected
    /// before any key image is produced — and the decrypted request plaintext
    /// does not survive the rejection.
    #[test]
    fn foreign_request_rejected() {
        let (spend_sk, _, view_sk, _) = make_keypair(5);
        let (other_spend, _, other_view, _) = make_keypair(9);
        // Encrypt a request under the OTHER wallet's envelope
        let (req, _) = make_request(&other_view, &other_spend, 3);
        let mut ws_raw = ws_buf();
        let mut ws = carve_pairing_ws(&mut ws_raw).unwrap();
        let mut rng = rng_from(1);
        let mut out = vec![0u8; 2048];
        let r = process_output_export(&view_sk, &spend_sk, &req, &mut ws, &mut out, &mut rng);
        assert!(r.is_err(), "foreign pk1/pk2 must be rejected");

        // Case 2: OUR envelope (signature + ChaCha verify) but foreign pk1/pk2
        // — the ownership rejection fires AFTER decryption, i.e. the request
        // plaintext is fully resident when the error path runs.
        let (_, f_spend_pub, _, f_view_pub) = make_keypair(9);
        let (plain, _) = request_plain(&view_sk, &spend_sk);
        let mut rng = rng_from(4);
        let mut buf = vec![0u8; 2048];
        let mut cn = vec![0u8; crate::types::caps::SIGN_WS_CN_SCRATCH];
        let n = encrypt_export_payload_into(
            OUTPUT_EXPORT_MAGIC,
            &view_sk,
            &f_spend_pub,
            &f_view_pub,
            0u32,
            &plain,
            &mut rng,
            &mut buf,
            &mut cn,
        )
        .unwrap();
        buf.truncate(n);
        let mut ws_raw = ws_buf();
        let mut ws = carve_pairing_ws(&mut ws_raw).unwrap();
        let mut out = vec![0u8; 2048];
        let r = process_output_export(&view_sk, &spend_sk, &buf, &mut ws, &mut out, &mut rng);
        assert!(
            r.is_err(),
            "foreign pk1/pk2 must be rejected (post-decrypt)"
        );
        // Error-path wipe duty: the decrypted request plaintext must not
        // survive the rejection (the chain core's zeroize-on-drop guard).
        assert!(
            ws.scratch.iter().all(|&b| b == 0),
            "error path must wipe the pairing ws scratch"
        );
    }

    /// Session face: keys only enter through the KeySession read port.
    #[test]
    fn session_face_matches_raw_keys() {
        let session = KeySession::from_entropy(&[0x11u8; 16], b"").unwrap();
        let keys = session.monero();
        let view_sk = *keys.view_sk.expose();
        let spend_sk = *keys.spend_sk.expose();
        let (req, _) = make_request(&view_sk, &spend_sk, 7);

        let mut ws_a = ws_buf();
        let mut wa = carve_pairing_ws(&mut ws_a).unwrap();
        let mut ws_b = ws_buf();
        let mut wb = carve_pairing_ws(&mut ws_b).unwrap();
        let mut out_a = vec![0u8; 2048];
        let mut out_b = vec![0u8; 2048];
        let a = process_output_export_session(
            &session,
            &req,
            &mut wa,
            &mut out_a,
            &mut rng_from(3),
            &mut [],
            &mut 0,
        )
        .unwrap();
        let b = process_output_export(
            &view_sk,
            &spend_sk,
            &req,
            &mut wb,
            &mut out_b,
            &mut rng_from(3),
        )
        .unwrap();
        assert_eq!(a.written, b.written);
        assert_eq!(
            out_a[..a.written],
            out_b[..b.written],
            "session face byte-identical"
        );
    }

    /// Workspace discipline: under-capacity never partially carves.
    #[test]
    fn carve_rejects_short_buffer() {
        let mut small = vec![0u8; pairing_ws_len() - 1];
        assert!(carve_pairing_ws(&mut small).is_none());
    }

    /// Layout pin: the carve and the probe share one layout computation — the
    /// CN scratchpad slot is exactly `SIGN_WS_CN_SCRATCH` bytes at u128
    /// alignment (the CN core's validation contract).
    #[test]
    fn ws_layout_pin() {
        use crate::types::caps::SIGN_WS_CN_SCRATCH;
        let mut raw = ws_buf();
        let ws = carve_pairing_ws(&mut raw).unwrap();
        assert_eq!(ws.cn_scratch.len(), SIGN_WS_CN_SCRATCH);
        assert_eq!(
            ws.cn_scratch.as_ptr() as usize % core::mem::align_of::<u128>(),
            0,
            "CN core requires u128-aligned scratch"
        );
        assert_eq!(ws.scratch.len(), PAIRING_SCRATCH_LEN);
        assert!(pairing_ws_len() >= PAIRING_SCRATCH_LEN + SIGN_WS_CN_SCRATCH);
    }

    /// Reuse-order pin: a second call on the SAME workspace (fixed RNG seeds)
    /// must be byte-identical — stale-scratch accumulation in the pairing chain
    /// only strikes on the second-and-later use of one ws.
    #[test]
    fn ws_reuse_deterministic() {
        let (spend_sk, _, view_sk, _) = make_keypair(6);
        let (req, _) = make_request(&view_sk, &spend_sk, 8);
        let mut ws_raw = ws_buf();
        let mut ws = carve_pairing_ws(&mut ws_raw).unwrap();
        let mut out1 = vec![0u8; 2048];
        let mut out2 = vec![0u8; 2048];
        let a = process_output_export(
            &view_sk,
            &spend_sk,
            &req,
            &mut ws,
            &mut out1,
            &mut rng_from(21),
        )
        .unwrap();
        let b = process_output_export(
            &view_sk,
            &spend_sk,
            &req,
            &mut ws,
            &mut out2,
            &mut rng_from(21),
        )
        .unwrap();
        assert_eq!(a.written, b.written);
        assert_eq!(
            &out1[..a.written],
            &out2[..b.written],
            "same ws reused must be byte-identical (stale-scratch pin)"
        );
    }
}
