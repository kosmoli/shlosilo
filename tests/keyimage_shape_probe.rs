//! Key-image derivation-shape × signature-formula divergence probe vs
//! wallet2 v0.18.5.1 (2026-10-16, "Signature check failed 0/1" regression).
//!
//! Field values (phone OCR; signature string is noisy, image/pubkey are clean):
//!   pubkey     = 79080ba1557df2dfca2c26e49f6c7d3556e9797965111c05197a241bacc73f2d
//!   key image  = ca88215e8c334ec29b6d6ece9aaa032a3cc611f622655c9bd9395b702af2c838
//!   signature  = 9147c184…edad68f06 (OCR noise — reference only)
//!
//! The 240 B real Cake request container (tests/fixtures/cake_real_frames.txt,
//! decoded by cake_real_container_probe) carries EXACTLY this pubkey as its
//! single record: internal_output_index=1, global_output_index=165116827,
//! tx_pubkey=7c0bdfa9…, flags=0x14 (rct+ki_request), amount=1677360000,
//! additional_tx_keys=0, major=0, minor=0. So the shape question is decidable
//! against real material, not synthetic guesses.
//!
//! wallet2 reference anchors (v0.18.5.1, /tmp/monero-ref):
//!   - cryptonote_format_utils.cpp::is_out_to_acc_precomp (L1065) — derivation
//!     choice: (1) main derivation against EVERY known subaddress (incl. the
//!     main address), then (2) additional_derivations[output_index] with a hard
//!     bounds check `output_index < additional_derivations.size()`.
//!   - cryptonote_format_utils.cpp::generate_key_image_helper(_precomp) (L290) —
//!     x = Hs(derivation ‖ varint(idx)) + spend + (index.is_zero() ? 0 : m).
//!   - device_default.cpp::generate_output_ephemeral_keys (L294) — SENDER side:
//!     change to one's own address is derived from the MAIN tx key even when
//!     additional tx keys exist; external subaddress dests use
//!     additional_tx_keys[output_index].
//!   - wallet2.cpp::export_key_images (L13925) — sign: ring=[td.get_public_key()],
//!     prefix=(hash&)td.m_key_image, sec=in_ephemeral.sec, and the response
//!     header carries `offset` = first m_key_image_request index.
//!   - wallet2.cpp::import_key_images (L14033/L14070) — verify:
//!     check_ring_signature((hash&)ki, ki, pkeys=[td.get_public_key()], sig);
//!     record n is paired with `m_transfers[n + offset]`, offset from the
//!     KEY_IMAGE container's u32 LE header.
//!
//! The `pin_red_…` test is INTENTIONALLY RED (the pinned divergence, not
//! fixed here — see KEYIMAGE_SIG_FAIL_REPORT.md). Everything else is green.

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use monero_ed25519::Point;
use shlosilo::chain::xmr::key_image_export::{
    encrypt_export_payload_into, generate_key_image_export_into, KEY_IMAGE_EXPORT_MAGIC,
    OUTPUT_EXPORT_MAGIC,
};
use shlosilo::chain::xmr::output_export::{ExportedTransferDetail, KEY_IMAGE_RECORD_LEN};
use shlosilo::chain::xmr::subaddress::{calc_output_key_offset, hash_to_scalar};
use shlosilo::types::key_session::KeySession;

// ─── field constants ─────────────────────────────────────────────────────────

const FIELD_PUBKEY: &str = "79080ba1557df2dfca2c26e49f6c7d3556e9797965111c05197a241bacc73f2d";
const FIELD_IMAGE_OCR: &str = "ca88215e8c334ec29b6d6ece9aaa032a3cc611f622655c9bd9395b702af2c838";
const FIELD_TX_PUBKEY: &str = "7c0bdfa929965a583b6534503ed423a4e7d1ca61a657adf4f4d154aae3957e0e";
/// First mainnet tx: this key image went on chain (the pairing flow that
/// SUCCEEDED). Proven below to be the deterministic image of FIELD_PUBKEY.
const TX1_ONCHAIN_IMAGE: &str = "ace03c045ba3d0155145e037ee6f1c9edeae976e6543fc2d11c522c2863ebf46";

const FIELD_INTERNAL_IDX: u64 = 1;
const FIELD_GLOBAL_IDX: u64 = 165_116_827;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut a = [0u8; 32];
    for i in 0..32 {
        a[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    a
}

fn point(sk: &[u8; 32]) -> [u8; 32] {
    (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*sk))
        .compress()
        .to_bytes()
}

/// Disk wallet keys: entropy 0x22×32 → BIP-39 → MoneroPath (same chain as
/// cake_real_container_probe; view_sk pinned there to the known disk value).
fn disk_keys() -> ([u8; 32], [u8; 32]) {
    let session = KeySession::from_entropy(&[0x22u8; 32], b"").expect("disk KeySession");
    let keys = session.monero();
    (*keys.spend_sk.expose(), *keys.view_sk.expose())
}

/// Monero LEB128 varint.
fn leb128(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
    out
}

/// Hs(recv_derivation ‖ varint(idx)) — the raw derivation step of wallet2
/// `derivation_to_scalar` (hashes the ×8 compressed derivation ‖ varint).
fn hs_offset(recv_bytes: &[u8; 32], idx: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(41);
    data.extend_from_slice(recv_bytes);
    data.extend_from_slice(&leb128(idx));
    hash_to_scalar(&data).unwrap()
}

fn dalek(x: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*x)
}

// ─── wallet2 check_ring_signature replica (ring = 1) ─────────────────────────
// crypto.cpp L711: c == Hs(prefix ‖ L ‖ R) with
//   L = r·B + c·pubs[i],  R = r·Hp(pubs[i]) + c·image
// ring element is the WALLET's transfer pubkey (wallet2.cpp L14060 `pkey`).
fn wallet2_check_ring_sig(
    prefix: &[u8; 32],
    image: &[u8; 32],
    ring_pub: &[u8; 32],
    sig: &[u8; 64],
) -> bool {
    let c = match Scalar::from_canonical_bytes(sig[..32].try_into().unwrap()).into_option() {
        Some(v) => v,
        None => return false,
    };
    let r = match Scalar::from_canonical_bytes(sig[32..].try_into().unwrap()).into_option() {
        Some(v) => v,
        None => return false,
    };
    let p: curve25519_dalek::EdwardsPoint = monero_ed25519::CompressedPoint::from(*ring_pub)
        .decompress()
        .expect("ring pub point")
        .into();
    let i: curve25519_dalek::EdwardsPoint = monero_ed25519::CompressedPoint::from(*image)
        .decompress()
        .expect("image point")
        .into();
    let hp_p: curve25519_dalek::EdwardsPoint = Point::biased_hash(*ring_pub).into();
    let l = (ED25519_BASEPOINT_TABLE * &r) + (p * c);
    let rr = (hp_p * r) + (i * c);
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(prefix);
    buf[32..64].copy_from_slice(&l.compress().to_bytes());
    buf[64..].copy_from_slice(&rr.compress().to_bytes());
    hash_to_scalar(&buf)
        .map(|h| h == c.to_bytes())
        .unwrap_or(false)
}

// ─── product chain driver ───────────────────────────────────────────────────

fn push_varint(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&leb128(v));
}

#[derive(Clone)]
struct SynthRec {
    pubkey: [u8; 32],
    idx: u64,
    gidx: u64,
    tx_pubkey: [u8; 32],
    flags: u8,
    amount: u64,
    add_keys: Vec<[u8; 32]>,
    major: u32,
    minor: u32,
}

/// Build the epee request plaintext: header (has_transfers, offset, total,
/// count) + records. `offset`/`total` model wallet2 partial exports.
fn synth_plain(offset: u64, total: u64, recs: &[SynthRec]) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(0x01); // has_transfers
    push_varint(&mut p, offset);
    push_varint(&mut p, total);
    push_varint(&mut p, recs.len() as u64);
    for r in recs {
        push_varint(&mut p, 1); // version
        p.extend_from_slice(&r.pubkey);
        push_varint(&mut p, r.idx);
        push_varint(&mut p, r.gidx);
        p.extend_from_slice(&r.tx_pubkey);
        p.push(r.flags);
        push_varint(&mut p, r.amount);
        push_varint(&mut p, r.add_keys.len() as u64);
        for k in &r.add_keys {
            p.extend_from_slice(k);
        }
        push_varint(&mut p, r.major as u64);
        push_varint(&mut p, r.minor as u64);
    }
    p
}

fn encrypt_request(view_sk: &[u8; 32], spend_pub: &[u8; 32], plain: &[u8], seed: u64) -> Vec<u8> {
    use rand_chacha::rand_core::SeedableRng as _;
    let view_pub = point(view_sk);
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
    let mut buf = vec![0u8; 4096];
    let mut cn = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
    let n = encrypt_export_payload_into(
        OUTPUT_EXPORT_MAGIC,
        view_sk,
        spend_pub,
        &view_pub,
        0u32, // output-export magic has no offset field (staging no-op)
        plain,
        &mut rng,
        &mut buf,
        &mut cn,
    )
    .unwrap();
    buf.truncate(n);
    buf
}

/// Run the product pairing chain; returns (response container, records).
#[allow(clippy::type_complexity)]
fn run_chain(
    req: &[u8],
    view_sk: &[u8; 32],
    spend_sk: &[u8; 32],
) -> (Vec<u8>, Vec<([u8; 32], [u8; 64])>) {
    let mut scratch = vec![0u8; 2048];
    let mut details: [ExportedTransferDetail; 8] =
        core::array::from_fn(|_| ExportedTransferDetail::default());
    let mut recs = [([0u8; 32], [0u8; 64]); 8];
    let mut out = vec![0u8; 8192];
    let mut cn = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
    let mut rng = {
        use rand_chacha::rand_core::SeedableRng as _;
        rand_chacha::ChaCha20Rng::seed_from_u64(0xC0FFEE)
    };
    let (n, _ki_offset) = generate_key_image_export_into(
        view_sk,
        spend_sk,
        req,
        &mut scratch,
        &mut details,
        &mut recs,
        &mut out,
        &mut rng,
        &mut cn,
    )
    .expect("chain run");
    out.truncate(n);
    let count = (n - (KEY_IMAGE_EXPORT_MAGIC.len() + 8 + 4 + 64 + 64)) / KEY_IMAGE_RECORD_LEN;
    (out, recs[..count].to_vec())
}

// ─── shape sweep: which derivation context reproduces P = 79080ba1… ─────────

/// Every plausible derivation shape for the field record, as (name, x).
fn shape_variants(view_sk: &[u8; 32], spend_sk: &[u8; 32]) -> Vec<(String, Scalar)> {
    let a = dalek(view_sk);
    let b = dalek(spend_sk);
    let r_pt: curve25519_dalek::EdwardsPoint =
        monero_ed25519::CompressedPoint::from(hex_to_32(FIELD_TX_PUBKEY))
            .decompress()
            .expect("R point")
            .into();
    let ar = (r_pt * a).mul_by_cofactor().compress().to_bytes(); // derivation_to_scalar input
    let ar_nocof = (r_pt * a).compress().to_bytes();

    // subaddress m(0,0) — what a (0,0)-treated-as-subaddress bug would add
    let m00 = hash_to_scalar(
        &[
            &b"SubAddr\x00"[..],
            &view_sk[..],
            &0u32.to_le_bytes(),
            &0u32.to_le_bytes(),
        ]
        .concat(),
    )
    .unwrap();

    let base = |recv: &[u8; 32], idx: u64| b + dalek(&hs_offset(recv, idx));

    vec![
        (
            "(b) baseline: 8aR‖varint(1), main".to_string(),
            base(&ar, FIELD_INTERNAL_IDX),
        ),
        ("(a) idx=0 instead of 1".to_string(), base(&ar, 0)),
        (
            "idx=gidx=165116827 (field mixup)".to_string(),
            base(&ar, FIELD_GLOBAL_IDX),
        ),
        ("idx=1 as u64 LE (no varint)".to_string(), {
            let mut d = ar.to_vec();
            d.extend_from_slice(&1u64.to_le_bytes());
            b + dalek(&hash_to_scalar(&d).unwrap())
        }),
        (
            "no cofactor: aR‖varint(1)".to_string(),
            base(&ar_nocof, FIELD_INTERNAL_IDX),
        ),
        (
            "baseline + m(0,0) (subaddr misfire)".to_string(),
            base(&ar, FIELD_INTERNAL_IDX) + dalek(&m00),
        ),
        ("pubkey-as-txkey: 8aP‖varint(1)".to_string(), {
            let p_pt: curve25519_dalek::EdwardsPoint =
                monero_ed25519::CompressedPoint::from(hex_to_32(FIELD_PUBKEY))
                    .decompress()
                    .expect("P point")
                    .into();
            let ap = (p_pt * a).mul_by_cofactor().compress().to_bytes();
            base(&ap, FIELD_INTERNAL_IDX)
        }),
        (
            "offset only (no spend_sk)".to_string(),
            dalek(&hs_offset(&ar, FIELD_INTERNAL_IDX)),
        ),
        ("spend_sk only (no offset)".to_string(), b),
    ]
}

#[test]
fn shape_sweep_reproduces_field_pubkey_and_image() {
    let (spend_sk, view_sk) = disk_keys();
    let p_field = hex_to_32(FIELD_PUBKEY);

    println!("── shape sweep vs field values ──");
    println!("  P_field   = {FIELD_PUBKEY}");
    println!("  I_ocr     = {FIELD_IMAGE_OCR}");
    let mut p_matches = Vec::new();
    let mut i_matches = Vec::new();
    for (name, x) in shape_variants(&view_sk, &spend_sk) {
        let xb = (ED25519_BASEPOINT_TABLE * &x).compress().to_bytes();
        let hp: curve25519_dalek::EdwardsPoint = Point::biased_hash(p_field).into();
        let img = (hp * x).compress().to_bytes();
        let p_hit = xb == p_field;
        let i_hit = hex(&img) == FIELD_IMAGE_OCR;
        if p_hit {
            p_matches.push(name.clone());
        }
        if i_hit {
            i_matches.push(name.clone());
        }
        println!(
            "  [{:>3}] {:<42} x·B={} I={}",
            if p_hit { "P✓" } else { "   " },
            name,
            hex(&xb),
            hex(&img)
        );
    }

    // Verdict 1: exactly ONE wallet2-plausible shape reproduces P — the record
    // as captured (main address, internal idx 1, tx_pubkey, no additional keys).
    assert_eq!(
        p_matches,
        vec!["(b) baseline: 8aR‖varint(1), main".to_string()],
        "the field pubkey must be reproduced by exactly the captured record shape"
    );

    // Verdict 2: the deterministic image of that shape is the tx1 on-chain
    // image — NOT the OCR'd field image.
    let x = shape_variants(&view_sk, &spend_sk)
        .into_iter()
        .find(|(n, _)| n.starts_with("(b)"))
        .unwrap()
        .1;
    let hp: curve25519_dalek::EdwardsPoint = Point::biased_hash(p_field).into();
    let img = (hp * x).compress().to_bytes();
    println!("  baseline image = {}", hex(&img));
    assert_eq!(
        hex(&img),
        TX1_ONCHAIN_IMAGE,
        "shape (b) must reproduce the tx1 on-chain key image"
    );

    // Verdict 3: the OCR'd field image is reproducible by NO shape variant —
    // it cannot be this record's correct image under any wallet2-plausible
    // derivation (see report §3 for the consequences).
    assert!(
        i_matches.is_empty(),
        "unexpected: OCR image reproduced by {i_matches:?}"
    );
}

// ─── per-shape cases through the PRODUCT chain (matrix) ─────────────────────

fn field_record() -> SynthRec {
    SynthRec {
        pubkey: hex_to_32(FIELD_PUBKEY),
        idx: FIELD_INTERNAL_IDX,
        gidx: FIELD_GLOBAL_IDX,
        tx_pubkey: hex_to_32(FIELD_TX_PUBKEY),
        flags: 0b0001_0100,
        amount: 1_677_360_000,
        add_keys: vec![],
        major: 0,
        minor: 0,
    }
}

/// Case (a): main address, internal_idx=0, no additional keys.
#[test]
fn case_a_main_idx0_no_addkeys() {
    let (spend_sk, view_sk) = disk_keys();
    let spend_pub = point(&spend_sk);
    let tx_pub = point(&[0x42u8; 32]);
    let offset = calc_output_key_offset(&view_sk, &tx_pub, 0, 0, 0).unwrap();
    let x = dalek(&spend_sk) + dalek(&offset);
    let out_pub = (ED25519_BASEPOINT_TABLE * &x).compress().to_bytes();
    let rec = SynthRec {
        pubkey: out_pub,
        idx: 0,
        gidx: 5,
        tx_pubkey: tx_pub,
        flags: 0b0001_0100,
        amount: 1,
        add_keys: vec![],
        major: 0,
        minor: 0,
    };
    let req = encrypt_request(&view_sk, &spend_pub, &synth_plain(0, 1, &[rec]), 0xA1);
    let (_resp, recs) = run_chain(&req, &view_sk, &spend_sk);
    assert_eq!(recs.len(), 1);
    let hp: curve25519_dalek::EdwardsPoint = Point::biased_hash(out_pub).into();
    assert_eq!(recs[0].0, (hp * x).compress().to_bytes());
    assert!(
        wallet2_check_ring_sig(&recs[0].0, &recs[0].0, &out_pub, &recs[0].1),
        "case (a): wallet2 check_ring_signature over the transfer pubkey must pass"
    );
}

/// Case (b): the field record itself — main address, internal_idx=1, no add
/// keys. The shape the real 240 B container carries.
#[test]
fn case_b_main_idx1_field_record() {
    let (spend_sk, view_sk) = disk_keys();
    let spend_pub = point(&spend_sk);
    let rec = field_record();
    let req = encrypt_request(&view_sk, &spend_pub, &synth_plain(0, 1, &[rec]), 0xB2);
    let (_resp, recs) = run_chain(&req, &view_sk, &spend_sk);
    assert_eq!(recs.len(), 1);
    // the product chain must reproduce the tx1 on-chain image for this record
    assert_eq!(hex(&recs[0].0), TX1_ONCHAIN_IMAGE);
    // and its signature must verify under wallet2's import formula with the
    // ring element = the transfer pubkey (wallet2.cpp L14060)
    assert!(
        wallet2_check_ring_sig(&recs[0].0, &recs[0].0, &hex_to_32(FIELD_PUBKEY), &recs[0].1),
        "case (b): accompanying signature must pass wallet2's import check"
    );
}

/// Case (c): external subaddress output with additional tx keys (2 keys,
/// idx=1 → additional[1]); wallet2 picks additional_derivations[output_index].
#[test]
fn case_c_subaddr_two_addkeys() {
    let (spend_sk, view_sk) = disk_keys();
    let spend_pub = point(&spend_sk);
    let k0 = point(&[0xA0u8; 32]);
    let k1 = point(&[0xA1u8; 32]);
    let idx = 1u64;
    let offset = calc_output_key_offset(&view_sk, &k1, idx, 1, 0).unwrap();
    let x = dalek(&spend_sk) + dalek(&offset);
    let out_pub = (ED25519_BASEPOINT_TABLE * &x).compress().to_bytes();
    let rec = SynthRec {
        pubkey: out_pub,
        idx,
        gidx: 7,
        tx_pubkey: point(&[0x42u8; 32]),
        flags: 0b0001_0100,
        amount: 0,
        add_keys: vec![k0, k1],
        major: 1,
        minor: 0,
    };
    let req = encrypt_request(&view_sk, &spend_pub, &synth_plain(0, 1, &[rec]), 0xC3);
    let (_resp, recs) = run_chain(&req, &view_sk, &spend_sk);
    assert_eq!(recs.len(), 1);
    let hp: curve25519_dalek::EdwardsPoint = Point::biased_hash(out_pub).into();
    assert_eq!(
        recs[0].0,
        (hp * x).compress().to_bytes(),
        "image from additional[idx]"
    );
    assert!(wallet2_check_ring_sig(
        &recs[0].0, &recs[0].0, &out_pub, &recs[0].1
    ));
}

/// Case (d): subaddress output derived via the MAIN tx key, additional keys
/// ABSENT (wallet2 is_out_to_acc_precomp branch 1 also matches subaddress
/// outputs through the shared derivation).
#[test]
fn case_d_subaddr_via_main_txkey_no_addkeys() {
    let (spend_sk, view_sk) = disk_keys();
    let spend_pub = point(&spend_sk);
    let tx_pub = point(&[0x77u8; 32]);
    let offset = calc_output_key_offset(&view_sk, &tx_pub, 2, 1, 0).unwrap();
    let x = dalek(&spend_sk) + dalek(&offset);
    let out_pub = (ED25519_BASEPOINT_TABLE * &x).compress().to_bytes();
    let rec = SynthRec {
        pubkey: out_pub,
        idx: 2,
        gidx: 9,
        tx_pubkey: tx_pub,
        flags: 0b0001_0100,
        amount: 3,
        add_keys: vec![],
        major: 1,
        minor: 0,
    };
    let req = encrypt_request(&view_sk, &spend_pub, &synth_plain(0, 1, &[rec]), 0xD4);
    let (_resp, recs) = run_chain(&req, &view_sk, &spend_sk);
    assert_eq!(recs.len(), 1);
    let hp: curve25519_dalek::EdwardsPoint = Point::biased_hash(out_pub).into();
    assert_eq!(recs[0].0, (hp * x).compress().to_bytes());
    assert!(wallet2_check_ring_sig(
        &recs[0].0, &recs[0].0, &out_pub, &recs[0].1
    ));
}

/// Signature-formula parity: for an ACCEPTED record our signature must verify
/// under wallet2's import formula with ring = detail.pubkey BYTES (not a
/// recomputed point). The generator's internal ring element is x·B
/// (key_image_export.rs generate_key_image_signature) — equal to detail.pubkey
/// only because of the input_pub gate. This test pins that the two agree for
/// the field record, and that a signature over a DIFFERENT ring element fails
/// wallet2's check (what the field "Signature check failed 0/1" looks like).
#[test]
fn signature_ring_element_parity_with_wallet2() {
    let (spend_sk, view_sk) = disk_keys();
    let spend_pub = point(&spend_sk);
    let req = encrypt_request(
        &view_sk,
        &spend_pub,
        &synth_plain(0, 1, &[field_record()]),
        0xE5,
    );
    let (_resp, recs) = run_chain(&req, &view_sk, &spend_sk);
    assert!(wallet2_check_ring_sig(
        &recs[0].0,
        &recs[0].0,
        &hex_to_32(FIELD_PUBKEY),
        &recs[0].1
    ));
    let wrong_ring = point(&[0x01u8; 32]);
    assert!(!wallet2_check_ring_sig(
        &recs[0].0,
        &recs[0].0,
        &wrong_ring,
        &recs[0].1
    ));
}

/// Additional-key len==1 shortcut — documented divergence (keystone parity):
/// ours accepts `len==1 → additional[0]` for idx>0; wallet2
/// is_out_to_acc_precomp L1080 REJECTS ("wrong number of additional
/// derivations"). wallet2's own sender cannot emit this shape
/// (additional.size() == vout.size()), so ours is strictly more permissive.
/// Current behavior is pinned as-is (accepts); flip the assertion when
/// wallet2 parity is chosen over keystone parity.
#[test]
fn len1_additional_key_shortcut_keystone_parity() {
    let (spend_sk, view_sk) = disk_keys();
    let spend_pub = point(&spend_sk);
    let only = point(&[0xB0u8; 32]);
    let idx_c = 3u64;
    let off_c = calc_output_key_offset(&view_sk, &only, idx_c, 2, 5).unwrap();
    let x = dalek(&spend_sk) + dalek(&off_c);
    let out_pub = (ED25519_BASEPOINT_TABLE * &x).compress().to_bytes();
    let rec = SynthRec {
        pubkey: out_pub,
        idx: idx_c,
        gidx: 9,
        tx_pubkey: point(&[0x42u8; 32]),
        flags: 0b0001_0100,
        amount: 15_000_000_000,
        add_keys: vec![only],
        major: 2,
        minor: 5,
    };
    let req = encrypt_request(&view_sk, &spend_pub, &synth_plain(0, 1, &[rec]), 0x17);
    let (_resp, recs) = run_chain(&req, &view_sk, &spend_sk);
    assert_eq!(
        recs.len(),
        1,
        "keystone parity: len==1 additional key accepted for idx>0 \
         (wallet2 would reject — documented divergence)"
    );
}

/// Response header offset contract (wallet2 import pairing).
///
/// wallet2 pairing (wallet2.cpp L14004/L14055): record n is checked against
/// `m_transfers[n + offset]`, `offset` being the u32 LE field of the KEY_IMAGE
/// container header that wallet2's own export_key_images writes (L13930-35:
/// first transfer with m_key_image_request). If the response header ignored
/// the request's offset, two requests differing only in the header offset
/// would produce byte-identical responses — and partial exports would import
/// records against the wrong transfers ("Signature check failed 0/1").
///
/// Observable without raw crypto: the two responses must differ (the offset
/// rides in the ciphertext).
#[test]
fn response_header_offset_follows_request_offset() {
    let (spend_sk, view_sk) = disk_keys();
    let spend_pub = point(&spend_sk);
    let rec = field_record();
    let req0 = encrypt_request(
        &view_sk,
        &spend_pub,
        &synth_plain(0, 1, std::slice::from_ref(&rec)),
        0xF6,
    );
    let req2 = encrypt_request(&view_sk, &spend_pub, &synth_plain(2, 3, &[rec]), 0xF6);
    let (resp0, recs0) = run_chain(&req0, &view_sk, &spend_sk);
    let (resp2, recs2) = run_chain(&req2, &view_sk, &spend_sk);
    assert_eq!(
        recs0, recs2,
        "derivation must not depend on the header offset"
    );
    assert_ne!(
        resp0, resp2,
        "the KEY_IMAGE response header must carry the request's offset \
         (wallet2 export_key_images L13975 / import_key_images L14055 pairing); \
         identical responses mean a hardcoded 0 → partial exports import \
         records against the wrong transfers → 'Signature check failed 0/1'"
    );
}

// ─── PINNED RED divergence (do not fix here; see report) ────────────────────

/// PINNED RED — derivation-shape divergence on change-to-OWN-SUBADDRESS with
/// additional tx keys present.
///
/// wallet2 SENDER (device_default.cpp::generate_output_ephemeral_keys L294):
/// `if (change_addr && dst_entr.addr == *change_addr) → derivation =
/// generate_key_derivation(txkey_pub, view_sk)` — change to one's own address
/// (main OR subaddress) is derived from the MAIN tx key EVEN WHEN additional
/// tx keys exist (those are only for external subaddress destinations).
/// Receiver-side wallet2 matches it through is_out_to_acc_precomp BRANCH 1
/// (main derivation + subaddress spend-key lookup).
///
/// Our key_to_use rule (key_image_export.rs compute_key_image_with_signature):
/// `major!=0||minor!=0 → additional_tx_keys[...]` — for this output it picks
/// the additional key instead of the main tx key → x·B ≠ detail.pubkey → the
/// chain REJECTS an output wallet2 both emits and re-derives.
///
/// Scenario shape: one tx paying an external subaddress (idx 0) with change to
/// the wallet's OWN subaddress (idx 1) — additional keys exist (one per
/// destination) but the change output is main-tx-key derived.
#[test]
// Was the pinned RED divergence; GREEN since the 2026-10-16 candidate-match
// fix (key selection matches x*G against the record pubkey like wallet2's
// is_out_to_acc_precomp: main tx key branch + indexed additional key branch).
fn change_to_own_subaddress_uses_main_txkey() {
    let (spend_sk, view_sk) = disk_keys();
    let spend_pub = point(&spend_sk);
    let tx_pub = point(&[0x42u8; 32]);
    let k0 = point(&[0xA0u8; 32]); // external subaddress dest (idx 0)
    let k1 = point(&[0xA1u8; 32]); // additional key slot for the change dest
    let idx = 1u64;
    // wallet2 sender semantics: change to own subaddress (1,0) derives from the
    // MAIN tx key + the subaddress base m(1,0):
    let offset = calc_output_key_offset(&view_sk, &tx_pub, idx, 1, 0).unwrap();
    let x = dalek(&spend_sk) + dalek(&offset);
    let out_pub = (ED25519_BASEPOINT_TABLE * &x).compress().to_bytes();
    let rec = SynthRec {
        pubkey: out_pub,
        idx,
        gidx: 8,
        tx_pubkey: tx_pub,
        flags: 0b0001_0100,
        amount: 0,
        add_keys: vec![k0, k1],
        major: 1,
        minor: 0,
    };
    let req = encrypt_request(&view_sk, &spend_pub, &synth_plain(0, 1, &[rec]), 0x22);
    let result = std::panic::catch_unwind(|| run_chain(&req, &view_sk, &spend_sk));
    let (_resp, recs) = match result {
        Ok(r) => r,
        Err(_) => panic!(
            "PINNED RED: chain panicked on change-to-own-subaddress (main-tx-key \
             derived) — wallet2 is_out_to_acc_precomp branch 1 matches this shape"
        ),
    };
    // Expected (wallet2 semantics): accepted, image over the main-tx-key
    // derivation. Observed: our additional[key]-by-(major,minor) rule derives
    // a different x → input_pub gate rejects → run_chain errors → panic above
    // (or, if accepted, the image below must match the wallet2 derivation).
    let hp: curve25519_dalek::EdwardsPoint = Point::biased_hash(out_pub).into();
    assert_eq!(
        recs.len(),
        1,
        "wallet2 re-derives change-to-own-subaddress outputs via the MAIN tx key \
         (device_default.cpp change_addr branch + is_out_to_acc_precomp branch 1); \
         our rule picks additional_tx_keys[idx] and REJECTS the record"
    );
    assert_eq!(recs[0].0, (hp * x).compress().to_bytes());
    assert!(wallet2_check_ring_sig(
        &recs[0].0, &recs[0].0, &out_pub, &recs[0].1
    ));
}
