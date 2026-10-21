//! Golden real-capture test: the 2026-10-20 KI-pairing case (`1020-all`).
//!
//! Provenance: phone Cake `Outputs (all)` request (4 frames) + device
//! `xmr-keyimage` response (3 frames), photographed on the real device and
//! decoded byte-exact (CRC 9d52757d / 63648bb8). Evidence and case report:
//! vault `shlosilo-调查-KI配对同步空转-2026-10-20.md`; raw frames and
//! reassembled containers under `~/works/1020-all/` and `/tmp/ki_frames2/`.
//!
//! The wallet these captures belong to is the RETIRED tx1/tx2 test wallet
//! (`49KRWBD…WRrJ`, spend `ca8b0cb5…` / view `db93ce63…`). Its keys are
//! deliberately PUBLIC-GRADE and embedded here as CI fixture material —
//! the wallet held test dust only and was retired 2026-10-20.
//!
//! What this pins:
//! - the pairing exchange shape (request header + 4 records / response 4 KI
//!   records, both at offset 0);
//! - per-record key-image derivation (independent recomputation must equal
//!   the device response byte-for-byte);
//! - the accompanying single-ring signatures;
//! - the response offset echo (fix 2026-10-16).

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use monero_ed25519::Point;
use shlosilo::chain::xmr::key_image_export::{
    decrypt_export_payload, KEY_IMAGE_EXPORT_MAGIC, OUTPUT_EXPORT_MAGIC,
};
use shlosilo::chain::xmr::output_export::{
    deserialize_key_images_into, ExportedTransferDetail, ExportedTransferDetails,
    KEY_IMAGE_RECORD_LEN,
};
use shlosilo::chain::xmr::subaddress::calc_output_key_offset;
use shlosilo::types::key_session::KeySession;
use shlosilo::ur::ur_multipart::UrMultipartDecoder;

/// Public-grade key material of the retired test wallet (see module docs).
const KNOWN_VIEW_SK: &str = "db93ce632d8d31e31bd0b4ecbdbdb833cae813928af402c5b7ffeb85769cf000";
const DISK_ENTROPY: [u8; 32] = [0x22u8; 32];

const REQ_FRAMES: &str = include_str!("fixtures/ki1020_req_frames.txt");
const RESP_FRAMES: &str = include_str!("fixtures/ki1020_resp_frames.txt");

/// Golden key images the device must reproduce, per request record.
const GOLDEN_KEY_IMAGES: [[u8; 32]; 4] = [
    [
        0xac, 0xe0, 0x3c, 0x04, 0x5b, 0xa3, 0xd0, 0x15, 0x51, 0x45, 0xe0, 0x37, 0xee, 0x6f, 0x1c,
        0x9e, 0xde, 0xae, 0x97, 0x6e, 0x65, 0x43, 0xfc, 0x2d, 0x11, 0xc5, 0x22, 0xc2, 0x86, 0x3e,
        0xbf, 0x46,
    ],
    [
        0xca, 0x88, 0x21, 0x5e, 0x8c, 0x33, 0x4e, 0xc2, 0x9b, 0x6d, 0x6e, 0xce, 0x9a, 0xaa, 0x03,
        0x2a, 0x3c, 0xc6, 0x11, 0xf6, 0x22, 0x65, 0x5c, 0x9b, 0xd9, 0x39, 0x5b, 0x70, 0x2a, 0xf2,
        0xc8, 0x38,
    ],
    [
        0xe3, 0xcb, 0x83, 0xa4, 0x0e, 0xae, 0x0d, 0x06, 0x2a, 0x36, 0x60, 0x64, 0xba, 0xbb, 0x6d,
        0x0c, 0xa2, 0x5b, 0x3c, 0x71, 0x22, 0x7f, 0x58, 0x8e, 0x37, 0x5c, 0xbb, 0x99, 0xbf, 0xd8,
        0xa9, 0x95,
    ],
    [
        0xeb, 0x12, 0x73, 0xb7, 0x51, 0x75, 0xed, 0xd7, 0x26, 0xf4, 0x4d, 0x8b, 0x0a, 0x49, 0xca,
        0x9e, 0xcd, 0xf2, 0x15, 0x1e, 0xc8, 0x96, 0xe8, 0xb1, 0x7e, 0x55, 0xea, 0xe1, 0x99, 0xe8,
        0xb9, 0x75,
    ],
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn point(sk: &[u8; 32]) -> [u8; 32] {
    (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*sk))
        .compress()
        .to_bytes()
}

/// Reassemble one multipart UR capture (newline-separated frames) to its
/// message, stripping one complete definite CBOR byte-string shell if present.
fn reassemble(frames: &str) -> Vec<u8> {
    let lines: Vec<&str> = frames
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("ur:"))
        .collect();
    assert!(!lines.is_empty(), "no ur: frames");
    let mut dec = UrMultipartDecoder::new();
    for f in &lines {
        dec.receive_frame(f).expect("frame feeds");
    }
    assert!(dec.complete(), "capture incomplete");
    let mut out = vec![0u8; 65536];
    let n = dec.payload_into(&mut out).unwrap().expect("complete");
    out.truncate(n);
    let b0 = out[0];
    let (hlen, clen) = match b0 {
        0x40..=0x57 => (1usize, (b0 - 0x40) as usize),
        0x58 => (2, out[1] as usize),
        0x59 => (3, usize::from(u16::from_be_bytes([out[1], out[2]]))),
        _ => (0, out.len()),
    };
    if hlen > 0 && hlen + clen == out.len() {
        out.drain(..hlen);
    }
    out
}

/// Match-based derivation key selection (mirrors the product semantics in
/// `compute_key_image_with_signature`): main tx key first, then the indexed
/// additional key (len==1 shortcut kept), first candidate whose x*G
/// reproduces the output pubkey wins.
fn derive(
    view_sk: &[u8; 32],
    spend_sk: &[u8; 32],
    d: &ExportedTransferDetail,
) -> ([u8; 32], Scalar) {
    let derive_candidate = |key: &[u8; 32]| -> Option<Scalar> {
        let offset =
            calc_output_key_offset(view_sk, key, d.internal_output_index, d.major, d.minor).ok()?;
        Some(Scalar::from_bytes_mod_order(*spend_sk) + Scalar::from_bytes_mod_order(offset))
    };
    let matches = |sk: &Scalar| (ED25519_BASEPOINT_TABLE * sk).compress().to_bytes() == d.pubkey;

    let mut input_sk = derive_candidate(&d.tx_pubkey).filter(matches);
    if input_sk.is_none() {
        let idx = d.internal_output_index as usize;
        let keyed = if d.additional_tx_keys.len() == 1 {
            Some(&*d.additional_tx_keys[0])
        } else {
            d.additional_tx_keys.get(idx).map(|k| &**k)
        };
        if let Some(k) = keyed {
            input_sk = derive_candidate(k).filter(matches);
        }
    }
    let input_sk = input_sk.expect("no derivation key reproduces the output pubkey");
    let hp: curve25519_dalek::EdwardsPoint = Point::biased_hash(d.pubkey).into();
    let image = (hp * input_sk).compress().to_bytes();
    (image, input_sk)
}

/// Independent verification of the key-image accompanying signature (single
/// ring): Hs(image ‖ r·B+c·P ‖ (r+c·x)·Hp(P)) == c.
fn verify_ki_sig(image: &[u8; 32], pubkey: &[u8; 32], input_sk: &Scalar, sig: &[u8; 64]) -> bool {
    use shlosilo::chain::xmr::subaddress::hash_to_scalar;
    let i_point: curve25519_dalek::EdwardsPoint = Point::biased_hash(*pubkey).into();
    let Some(c) = Scalar::from_canonical_bytes(sig[..32].try_into().unwrap()).into_option() else {
        return false;
    };
    let Some(r) = Scalar::from_canonical_bytes(sig[32..].try_into().unwrap()).into_option() else {
        return false;
    };
    let p_point = ED25519_BASEPOINT_TABLE * input_sk;
    let s1 = (ED25519_BASEPOINT_TABLE * &r) + (c * p_point);
    let s2 = (r + c * input_sk) * i_point;
    let mut vbuf = Vec::new();
    vbuf.extend_from_slice(image);
    vbuf.extend_from_slice(&s1.compress().to_bytes());
    vbuf.extend_from_slice(&s2.compress().to_bytes());
    matches!(hash_to_scalar(&vbuf), Ok(h) if h == c.to_bytes())
}

/// Manual keystream decrypt of the KEY_IMAGE response to expose the u32 LE
/// offset field (which `decrypt_export_payload` strips away).
fn response_offset(resp: &[u8], view_sk: &[u8; 32]) -> u32 {
    use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};
    let magic_len = KEY_IMAGE_EXPORT_MAGIC.len();
    let nonce = &resp[magic_len..magic_len + 8];
    let ct = &resp[magic_len + 8..resp.len() - 64];
    let mut scratch = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
    let key = cuprate_cryptonight::cryptonight_hash_v0_into(view_sk, &mut scratch).expect("cn");
    let mut cipher = chacha20::ChaCha20Legacy::new_from_slices(&key, nonce).expect("cipher");
    let mut plain = ct.to_vec();
    cipher.apply_keystream(&mut plain);
    u32::from_le_bytes(plain[0..4].try_into().unwrap())
}

#[test]
fn ki_pairing_1020_real_capture_golden() {
    let session = KeySession::from_entropy(&DISK_ENTROPY, b"").expect("disk KeySession");
    let keys = session.monero();
    let spend_sk = *keys.spend_sk.expose();
    let view_sk = *keys.view_sk.expose();
    assert_eq!(hex(&view_sk), KNOWN_VIEW_SK, "derivation-chain guard");
    let spend_pub = point(&spend_sk);
    let view_pub = point(&view_sk);

    // ── request: decrypt + parse ────────────────────────────────────────────
    let req = reassemble(REQ_FRAMES);
    let (pk1, pk2, plain) =
        decrypt_export_payload(&req, OUTPUT_EXPORT_MAGIC, &view_sk).expect("request decrypt");
    assert_eq!(pk1, spend_pub, "request pk1 = wallet spend_pub");
    assert_eq!(pk2, view_pub, "request pk2 = wallet view_pub");

    let mut pool: [ExportedTransferDetail; 16] =
        core::array::from_fn(|_| ExportedTransferDetail::default());
    let parsed = ExportedTransferDetails::from_bytes(&plain, &mut pool).expect("request parse");
    assert_eq!(parsed.offset, 0, "capture request offset");
    assert_eq!(parsed.size, 4, "capture wallet has 4 transfers");
    assert_eq!(
        parsed.details.len(),
        4,
        "all-variant request carries 4 records"
    );

    // ── response: decrypt, records, offset echo ─────────────────────────────
    let resp = reassemble(RESP_FRAMES);
    let (rpk1, rpk2, rec_bytes) =
        decrypt_export_payload(&resp, KEY_IMAGE_EXPORT_MAGIC, &view_sk).expect("response decrypt");
    assert_eq!(rpk1, spend_pub);
    assert_eq!(rpk2, view_pub);
    assert_eq!(
        u64::from(response_offset(&resp, &view_sk)),
        parsed.offset,
        "response offset must echo the request offset (2026-10-16 fix)"
    );

    let mut recs = [([0u8; 32], [0u8; 64]); 16];
    let n = deserialize_key_images_into(&rec_bytes, &mut recs).expect("response records");
    assert_eq!(n, 4, "one record per request record");
    assert_eq!(rec_bytes.len(), n * KEY_IMAGE_RECORD_LEN);

    // ── cross-check: golden values + independent derivation + signatures ────
    for (i, d) in parsed.details.iter().enumerate() {
        let (image, input_sk) = derive(&view_sk, &spend_sk, d);
        assert_eq!(recs[i].0, image, "rec[{i}] matches independent derivation");
        assert_eq!(
            recs[i].0, GOLDEN_KEY_IMAGES[i],
            "rec[{i}] matches the golden key image"
        );
        assert!(
            verify_ki_sig(&image, &d.pubkey, &input_sk, &recs[i].1),
            "rec[{i}] accompanying signature verifies"
        );
    }
}
