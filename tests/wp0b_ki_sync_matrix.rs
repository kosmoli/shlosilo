//! S1 WP0-B: KI synchronization semantic matrix — one pin per wallet-state
//! cell (design doc §6 WP0-B). The five states are wallet-side behaviors
//! (wallet2/Feather, source-defined 2026-10-28); these pins freeze OUR side
//! of each contract so every state behaves as matrixed:
//!
//! | wallet state  | wallet2/Feather semantics            | our contract pin                        |
//! |---------------|--------------------------------------|-----------------------------------------|
//! | first sync    | m_key_image_request incremental start| full coverage + offset echo (this file) |
//! | repeat        | idempotent, skips known              | replay determinism (this file)          |
//! | recovered     | rescan rebuilds the cold map         | = first sync (same full response)       |
//! | partially known | fills only unknown entries         | records self-identify (this file)       |
//! | spending      | tx_key_images -> m_cold_key_images   | F7 claim pins + tx_key_images goldens   |
//!
//! Association semantics (2026-10-28 double-source read): the sync leg is a
//! CRYPTOGRAPHIC BRUTE MATCH — each record's accompanying signature can only
//! be produced by that output's one-time key, so importers pair records to
//! transfers by verification (order-independent, offset-tolerant,
//! idempotent). The self-identification pin below is the foundation of that
//! property. The sign leg's two paths (positional array / keyed map) are
//! pinned in tests/pin_signed_key_images_wallet_indexed.rs and the F7 claim
//! pins.

// Alloc-face test: the container decrypt/record APIs are `alloc-fallback`
// gated (pool #46 face: integration tests cannot see cfg-gated APIs under
// no-default-features).
#![cfg(feature = "alloc-fallback")]

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use monero_ed25519::Point;
use rand_chacha::rand_core::SeedableRng as _;
use shlosilo::business::sign::WalletKiRecord;
use shlosilo::business::xmr_pairing::{
    carve_pairing_ws, pairing_ws_len, process_output_export_with_records,
};
use shlosilo::chain::xmr::key_image_export::{
    decrypt_export_payload, encrypt_export_payload_into, KEY_IMAGE_EXPORT_MAGIC,
    OUTPUT_EXPORT_MAGIC,
};
use shlosilo::chain::xmr::output_export::{deserialize_key_images_into, KEY_IMAGE_RECORD_LEN};
use shlosilo::chain::xmr::subaddress::{calc_output_key_offset, hash_to_scalar};

const VIEW_SK: [u8; 32] = [0x31; 32];
const SPEND_SK: [u8; 32] = [0x27; 32];

fn point(sk: &[u8; 32]) -> [u8; 32] {
    (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*sk))
        .compress()
        .to_bytes()
}

fn encode_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

/// One synthetic transfer's derivation material (main-tx-key derivation; the
/// builder emits no additional tx keys).
struct SynthOut {
    out_pub: [u8; 32],
    input_sk: Scalar,
}

/// Build an epee `export_outputs` plaintext with `count` records at wallet
/// indices `offset..offset+count` out of `total` transfers, each with a
/// wallet-faithful one-time output key. Returns the plain plus the per-record
/// derivation material (the requester-side truth for independent checks).
fn build_plain(
    count: usize,
    offset: u64,
    total: u64,
    view_sk: &[u8; 32],
    spend_sk: &[u8; 32],
) -> (Vec<u8>, Vec<SynthOut>) {
    let mut plain = Vec::new();
    encode_varint(1, &mut plain); // has_transfers
    encode_varint(offset, &mut plain);
    encode_varint(total, &mut plain);
    encode_varint(count as u64, &mut plain);
    let mut outs = Vec::new();
    for i in 0..count {
        let wallet_idx = offset + i as u64;
        let tx_sk = [0x13u8.wrapping_add(i as u8 * 7); 32];
        let tx_pub = point(&tx_sk);
        let off = calc_output_key_offset(view_sk, &tx_pub, wallet_idx, 0, 0).expect("hs offset");
        let input_sk = Scalar::from_bytes_mod_order(*spend_sk) + Scalar::from_bytes_mod_order(off);
        let out_pub = (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes();

        encode_varint(1, &mut plain); // record version
        plain.extend_from_slice(&out_pub);
        encode_varint(wallet_idx, &mut plain); // internal_output_index
        encode_varint(10 + wallet_idx, &mut plain); // global_output_index
        plain.extend_from_slice(&tx_pub);
        plain.push(0b0000_0100); // flags (main address)
        encode_varint(1_000_000 + wallet_idx, &mut plain); // amount
        encode_varint(0, &mut plain); // additional_tx_keys count
        encode_varint(0, &mut plain); // major
        encode_varint(0, &mut plain); // minor
        outs.push(SynthOut { out_pub, input_sk });
    }
    (plain, outs)
}

/// Independent key-image derivation (same math family as
/// tests/golden_ki_pairing_1020.rs): image = Hp(pubkey) * input_sk.
fn derive_key_image(out: &SynthOut) -> [u8; 32] {
    let hp: curve25519_dalek::EdwardsPoint = Point::biased_hash(out.out_pub).into();
    (hp * out.input_sk).compress().to_bytes()
}

/// Independent verification of the record's accompanying signature (single
/// ring): Hs(image || r*B+c*P || (r+c*x)*Hp(P)) == c.
fn verify_ki_sig(image: &[u8; 32], pubkey: &[u8; 32], input_sk: &Scalar, sig: &[u8; 64]) -> bool {
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

/// Run the device's pairing receive leg over `plain` with a rng seeded by
/// `seed`. Returns (response container bytes, retained records).
fn run_leg(plain: &[u8], seed: u64) -> (Vec<u8>, Vec<WalletKiRecord>) {
    let spend_pub = point(&SPEND_SK);
    let view_pub = point(&VIEW_SK);
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
    let mut req_buf = vec![0u8; 16384];
    let mut cn = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
    let req_n = encrypt_export_payload_into(
        OUTPUT_EXPORT_MAGIC,
        &VIEW_SK,
        &spend_pub,
        &view_pub,
        0u32,
        plain,
        &mut rng,
        &mut req_buf,
        &mut cn,
    )
    .expect("request container build");
    let mut out = vec![0u8; 16384];
    let mut ws_raw = vec![0u8; pairing_ws_len()];
    let mut ws = carve_pairing_ws(&mut ws_raw).expect("carve pairing ws");
    let mut ki_out = [WalletKiRecord {
        transfer_idx: u32::MAX,
        wallet_fp: [0u8; 8],
        key_image: [0u8; 32],
    }; 8];
    let mut ki_written = 0usize;
    let outcome = process_output_export_with_records(
        &VIEW_SK,
        &SPEND_SK,
        &req_buf[..req_n],
        &mut ws,
        &mut out,
        &mut rng,
        &mut ki_out,
        &mut ki_written,
    )
    .expect("pairing receive leg");
    (
        out[..outcome.written].to_vec(),
        ki_out[..ki_written].to_vec(),
    )
}

/// The response's u32le offset field (first 4 plaintext bytes; the manual
/// decrypt exposes what the parse strips away).
fn response_offset(resp: &[u8]) -> u32 {
    use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};
    let magic_len = KEY_IMAGE_EXPORT_MAGIC.len();
    let nonce = &resp[magic_len..magic_len + 8];
    let ct = &resp[magic_len + 8..resp.len() - 64];
    let mut scratch = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
    let key =
        cuprate_cryptonight::cryptonight_hash_v0_into(&VIEW_SK, &mut scratch).expect("cn key");
    let mut cipher = chacha20::ChaCha20Legacy::new_from_slices(&key, nonce).expect("cipher");
    let mut plain = ct.to_vec();
    cipher.apply_keystream(&mut plain);
    u32::from_le_bytes(plain[0..4].try_into().unwrap())
}

/// Parse the response records (KI, sig) out of the container.
fn response_records(resp: &[u8]) -> Vec<([u8; 32], [u8; 64])> {
    let (_pk1, _pk2, rec_bytes) =
        decrypt_export_payload(resp, KEY_IMAGE_EXPORT_MAGIC, &VIEW_SK).expect("response decrypt");
    let mut recs = [([0u8; 32], [0u8; 64]); 8];
    let n = deserialize_key_images_into(&rec_bytes, &mut recs).expect("response records");
    assert_eq!(rec_bytes.len(), n * KEY_IMAGE_RECORD_LEN, "record geometry");
    recs[..n].to_vec()
}

// ---------------------------------------------------------------------------
// Cell: first sync (incremental start) — full coverage + offset echo
// ---------------------------------------------------------------------------

/// The incremental request (`offset=2`, `total=5`, `count=3`) must be echoed
/// back and retained at wallet-transfer indices `offset+i`, one record per
/// requested record, each key image matching an independent derivation.
#[test]
fn ki_sync_matrix_first_sync_full_coverage_and_offset() {
    let (plain, outs) = build_plain(3, 2, 5, &VIEW_SK, &SPEND_SK);
    let (resp, ki) = run_leg(&plain, 0xB10C_0001);
    assert_eq!(
        response_offset(&resp),
        2,
        "response offset echoes the request"
    );
    assert_eq!(ki.len(), 3, "one retained record per requested record");
    let recs = response_records(&resp);
    for (i, out) in outs.iter().enumerate() {
        assert_eq!(
            ki[i].transfer_idx,
            2 + i as u32,
            "record {i} lives at wallet index offset+i"
        );
        assert_eq!(
            ki[i].key_image,
            derive_key_image(out),
            "record {i} key image matches independent derivation"
        );
        assert_eq!(recs[i].0, ki[i].key_image, "wire and retention agree");
    }
}

// ---------------------------------------------------------------------------
// Cell: repeat (idempotent re-export) — replay determinism
// ---------------------------------------------------------------------------

/// Re-exporting for the same request is replay-stable: with the same rng
/// seed the response container is byte-identical, and across seeds everything
/// except the envelope nonce is identical (the importer's "skip known" is
/// safe because a repeat carries the same self-identifying records).
#[test]
fn ki_sync_matrix_repeat_replay_determinism() {
    let (plain, _outs) = build_plain(3, 2, 5, &VIEW_SK, &SPEND_SK);
    let (resp_a, ki_a) = run_leg(&plain, 0xB10C_0002);
    let (resp_b, ki_b) = run_leg(&plain, 0xB10C_0002);
    let shape = |ki: &[WalletKiRecord]| -> Vec<(u32, [u8; 32], [u8; 8])> {
        ki.iter()
            .map(|r| (r.transfer_idx, r.key_image, r.wallet_fp))
            .collect()
    };
    assert_eq!(resp_a, resp_b, "same seed: byte-identical response");
    assert_eq!(
        shape(&ki_a),
        shape(&ki_b),
        "same seed: identical retained records"
    );

    let (resp_c, ki_c) = run_leg(&plain, 0xB10C_0003);
    assert_eq!(
        shape(&ki_a),
        shape(&ki_c),
        "across seeds: identical records (KI + identity)"
    );
    // The accompanying signature is RANDOMIZED (its nonce draws from the
    // rng): a repeat export carries fresh signatures. The importer's "skip
    // known" idempotence keys on VERIFICATION, not byte equality, so the
    // contract across repeats is: same key image, every signature valid
    // (validity is pinned in the partially-known cell below).
    let recs_a = response_records(&resp_a);
    let recs_c = response_records(&resp_c);
    for (i, (ra, rc)) in recs_a.iter().zip(recs_c.iter()).enumerate() {
        assert_eq!(ra.0, rc.0, "record {i}: same key image across seeds");
    }
}

// ---------------------------------------------------------------------------
// Cell: partially known — records self-identify (brute-match foundation)
// ---------------------------------------------------------------------------

/// Each record's accompanying signature verifies against ITS OWN output
/// pubkey and its key image matches the derivation of that output — and
/// never against a sibling's material. That uniqueness is what lets an
/// importer pair records to transfers by verification alone (order
/// independent, offset ignored), filling only the entries it does not know.
#[test]
fn ki_sync_matrix_partially_known_records_self_identify() {
    let (plain, outs) = build_plain(3, 0, 3, &VIEW_SK, &SPEND_SK);
    let (resp, ki) = run_leg(&plain, 0xB10C_0004);
    let recs = response_records(&resp);
    for (i, out) in outs.iter().enumerate() {
        let image = derive_key_image(out);
        assert_eq!(recs[i].0, image, "record {i} image matches its output");
        assert!(
            verify_ki_sig(&image, &out.out_pub, &out.input_sk, &recs[i].1),
            "record {i} signature verifies against its own output"
        );
        for (j, other) in outs.iter().enumerate() {
            if i == j {
                continue;
            }
            assert!(
                !verify_ki_sig(&recs[i].0, &other.out_pub, &other.input_sk, &recs[i].1),
                "record {i} signature must NOT verify against output {j}"
            );
            assert_ne!(recs[i].0, recs[j].0, "records carry distinct key images");
        }
        assert_eq!(ki[i].key_image, image, "wire and retention agree");
    }
}
