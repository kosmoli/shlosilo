//! P0-①/② (pool #57/#58, 2026-10-30): the fixed failure-vocabulary pins.
//!
//! 拆码红线 (Kosmo 2026-10-12/13): every user-visible failure surface is a
//! FIXED word-table entry — no rc codes, no QR-derived strings, no internal
//! detail on screen. The KI-cap case (2026-10-29) showed a -20 failure
//! wearing the -34 wording ("key images out of date"): the code→word
//! mapping had zero test face. These pins freeze the FULL mapping
//! byte-exactly and chain it to the error kinds that reach it.
//!
//! Single source of truth: `shlosilo::failure_text` (the C side renders via
//! the FFI lookups — ki_store precedent: C keeps only glue).
//!
//! Chain pinned here (the "可见报错链路"):
//!   ShlosiloErrorKind -> ShlosiloErrorCode (i32, L2b) -> fixed screen text.
//! The end-to-end leg over a REAL sign run (foreign-fp records -> refusal)
//! lives in tests/pin_signed_key_images_wallet_indexed.rs.

use shlosilo::business::sign::{wallet_fingerprint, WalletKiRecord};
use shlosilo::business::xmr_pairing::{
    carve_pairing_ws, pairing_ws_len, process_output_export_with_records,
};
use shlosilo::chain::xmr::key_image_export::{encrypt_export_payload_into, OUTPUT_EXPORT_MAGIC};
use shlosilo::chain::xmr::subaddress::calc_output_key_offset;
use shlosilo::error::{ShlosiloError, ShlosiloErrorCode, ShlosiloErrorKind};
use shlosilo::failure_text::{pairing_failure_hint, pairing_failure_reason, sign_failure_text};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::rand_core::SeedableRng as _;

// ---------------------------------------------------------------------------
// 1. Sign-page failure text: full fixed templates, byte-exact
// ---------------------------------------------------------------------------

/// Every mapped code class must render EXACTLY the fixed three-line template
/// burned into the shipped vocabulary. A mapping drift (the -20-wearing--34
/// class of bug) turns this red.
#[test]
fn sign_failure_text_matches_fixed_vocabulary() {
    assert_eq!(
        sign_failure_text(-34).to_bytes(),
        b"sign failed\nwallet key images out of date\nre-run the wallet key image sync, then retry"
    );
    assert_eq!(
        sign_failure_text(-35).to_bytes(),
        b"sign failed\nwallet key images out of date\nre-run the wallet key image sync, then retry"
    );
    assert_eq!(
        sign_failure_text(-20).to_bytes(),
        b"sign failed\nrequest too large\npay with fewer inputs, or split the payment"
    );
    assert_eq!(
        sign_failure_text(-21).to_bytes(),
        b"sign failed\nrequest data not recognized\nre-create the payment and retry"
    );
    assert_eq!(
        sign_failure_text(-2).to_bytes(),
        b"sign failed\nrequest not accepted\nre-create the payment and retry"
    );
    // unmapped codes collapse to the generic "unknown code" entry (class only)
    assert_eq!(
        sign_failure_text(-1).to_bytes(),
        b"sign failed\ninternal error (unknown code)\nreboot the device and retry"
    );
    assert_eq!(
        sign_failure_text(-99).to_bytes(),
        b"sign failed\ninternal error (unknown code)\nreboot the device and retry"
    );
    assert_eq!(
        sign_failure_text(7).to_bytes(),
        b"sign failed\ninternal error (unknown code)\nreboot the device and retry"
    );
}

// ---------------------------------------------------------------------------
// 2. Pairing failure words: reason + hint per class, byte-exact
// ---------------------------------------------------------------------------

#[test]
fn pairing_failure_words_match_fixed_vocabulary() {
    // -20: wallet too large for pairing (the 2026-10-29 record-cap class)
    assert_eq!(
        pairing_failure_reason(-20).to_bytes(),
        b"too many outputs for this device"
    );
    assert_eq!(
        pairing_failure_hint(-20).to_bytes(),
        b"device limit reached"
    );
    // -21: container shape
    assert_eq!(
        pairing_failure_reason(-21).to_bytes(),
        b"output format not recognized"
    );
    assert_eq!(
        pairing_failure_hint(-21).to_bytes(),
        b"move camera away, retry"
    );
    // -40: envelope signature
    assert_eq!(
        pairing_failure_reason(-40).to_bytes(),
        b"output signature check failed"
    );
    // -15: pk1/pk2 ownership binding
    assert_eq!(
        pairing_failure_reason(-15).to_bytes(),
        b"output not from this wallet"
    );
    // -2: data error
    assert_eq!(pairing_failure_reason(-2).to_bytes(), b"data error");
    // everything else: unrecognized output
    assert_eq!(
        pairing_failure_reason(-1).to_bytes(),
        b"unrecognized output"
    );
    assert_eq!(pairing_failure_reason(0).to_bytes(), b"unrecognized output");
    assert_eq!(
        pairing_failure_hint(-40).to_bytes(),
        b"move camera away, retry"
    );
}

// ---------------------------------------------------------------------------
// 3. Error-kind -> code -> word chain (the fp-mismatch visibility chain)
// ---------------------------------------------------------------------------

/// fix37 fp binding (pool #57): a wallet-fp mismatch surfaces as
/// `KeyImageRecordMissing` -> FFI -34 -> the fixed "wallet key images out of
/// date" word. The chain must hold end-to-end at the mapping level.
#[test]
fn fp_mismatch_chain_reaches_visible_word() {
    let err = ShlosiloError::new(ShlosiloErrorKind::KeyImageRecordMissing);
    let code = ShlosiloErrorCode::from_shlosilo_error(err);
    assert_eq!(code, -34);
    assert_eq!(
        sign_failure_text(code).to_bytes(),
        b"sign failed\nwallet key images out of date\nre-run the wallet key image sync, then retry"
    );

    let err = ShlosiloError::new(ShlosiloErrorKind::KeyImageRecordMismatch);
    let code = ShlosiloErrorCode::from_shlosilo_error(err);
    assert_eq!(code, -35);
    assert_eq!(
        sign_failure_text(code).to_bytes(),
        b"sign failed\nwallet key images out of date\nre-run the wallet key image sync, then retry"
    );
}

// ---------------------------------------------------------------------------
// 4. fp coverage pin (pool #58): the pairing leg stamps EVERY retained record
//    with this wallet's fingerprint — 100% coverage, no unstamped record may
//    leave the retention path.
// ---------------------------------------------------------------------------

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

/// Two-output main-address export plaintext (same shape family as
/// tests/pin_details_pool_over8.rs — wallet-faithful one-time output keys).
fn build_plain(count: usize, view_sk: &[u8; 32], spend_sk: &[u8; 32]) -> Vec<u8> {
    let mut plain = Vec::new();
    encode_varint(1, &mut plain); // has_transfers
    encode_varint(0, &mut plain); // offset
    encode_varint(count as u64, &mut plain); // transfers total
    encode_varint(count as u64, &mut plain); // record count
    for i in 0..count {
        let tx_sk = [0x24u8.wrapping_add(i as u8 * 5); 32];
        let tx_pub = point(&tx_sk);
        let off = calc_output_key_offset(view_sk, &tx_pub, i as u64, 0, 0).unwrap();
        let input_sk = Scalar::from_bytes_mod_order(*spend_sk) + Scalar::from_bytes_mod_order(off);
        let out_pub = (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes();

        encode_varint(1, &mut plain); // record version
        plain.extend_from_slice(&out_pub); // output pubkey
        encode_varint(i as u64, &mut plain); // internal_output_index
        encode_varint(10 + i as u64, &mut plain); // global_output_index
        plain.extend_from_slice(&tx_pub); // tx_pubkey
        plain.push(0b0000_0100); // flags (main address, no key-image request bit)
        encode_varint(1_000_000 + i as u64, &mut plain); // amount (piconero)
        encode_varint(0, &mut plain); // additional_tx_keys count
        encode_varint(0, &mut plain); // major
        encode_varint(0, &mut plain); // minor
    }
    plain
}

/// fp 覆盖率: every record produced by the pairing receive leg carries the
/// wallet fingerprint of the key session it was derived under (fix37 binding),
/// and its true wallet transfer index. No unstamped / mis-stamped record may
/// enter retention — the sign leg's fp filter depends on this coverage.
#[test]
fn pairing_records_are_wallet_fp_stamped() {
    let view_sk = [6u8; 32];
    let spend_sk = [5u8; 32];
    let spend_pub = point(&spend_sk);
    let view_pub = point(&view_sk);
    let expected_fp = wallet_fingerprint(&spend_pub, &view_pub);

    const COUNT: usize = 2;
    let plain = build_plain(COUNT, &view_sk, &spend_sk);
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(22);
    let mut req_buf = vec![0u8; 16384];
    let mut cn = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
    let req_n = encrypt_export_payload_into(
        OUTPUT_EXPORT_MAGIC,
        &view_sk,
        &spend_pub,
        &view_pub,
        0u32,
        &plain,
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
    }; COUNT];
    let mut ki_written = 0usize;

    let outcome = process_output_export_with_records(
        &view_sk,
        &spend_sk,
        &req_buf[..req_n],
        &mut ws,
        &mut out,
        &mut rng,
        &mut ki_out,
        &mut ki_written,
    )
    .expect("pairing receive leg must succeed");

    assert_eq!(outcome.output_count, COUNT);
    assert_eq!(ki_written, COUNT, "every output record must be retained");
    for (i, r) in ki_out[..ki_written].iter().enumerate() {
        assert_eq!(
            r.wallet_fp, expected_fp,
            "record {i} must be stamped with THIS wallet's fingerprint"
        );
        assert_eq!(
            r.transfer_idx, i as u32,
            "record {i} must carry its wallet transfer index"
        );
    }
}
