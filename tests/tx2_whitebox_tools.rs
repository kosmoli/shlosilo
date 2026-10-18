//! tx2 white-box host tools (2026-10-17) — replicate the mainnet tx2 scan
//! chain through monero_c's real construction path and pin what it does.
//!
//! Tools (all `#[ignore]`, run with `-- --ignored --nocapture`):
//!
//! - `tx2_decode_frames`: monero_c `commitUR` xmr-txunsigned frames -> raw
//!   `unsigned_monero_tx` container (shell stripped).
//! - `tx2_dump_unsigned_plain`: unsigned container -> plaintext (field diff).
//!
//! Frame generation (shelled + bare) lives in
//! `~/works/xmr-stagenet-lab/watchonly_probe/ur_frames.py` (validated against
//! `p64_xmr_multi_input::encode_ur_frames` byte-for-byte).

use shlosilo::ffi::c_abi::r3::{
    shlosilo_ur_decode_complete, shlosilo_ur_decode_feed, shlosilo_ur_decode_free,
    shlosilo_ur_decode_new, shlosilo_ur_decode_payload, shlosilo_ur_decode_type,
};
use shlosilo::ur::ur_multipart::ur_decode_ws_len;
use shlosilo::ur::ur_shell::ur_message_content;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}

/// Feed frames (one URI per line) through the product multipart decoder the C
/// scan flow uses; returns (type_name, message).
fn decode_frames(frames: &[String]) -> (String, Vec<u8>) {
    let ws_len = ur_decode_ws_len();
    let mut ws = vec![0u8; ws_len];
    let dec = shlosilo_ur_decode_new(ws.as_mut_ptr(), ws_len as core::ffi::c_uint);
    assert!(!dec.is_null(), "decoder placement");
    for f in frames {
        let c: Vec<u8> = f.bytes().chain(core::iter::once(0)).collect();
        let mut accepted: core::ffi::c_uint = 0;
        let rc =
            shlosilo_ur_decode_feed(dec, c.as_ptr() as *const core::ffi::c_char, &mut accepted);
        assert_eq!(rc, 0, "frame rejected: {f}");
    }
    let complete = shlosilo_ur_decode_complete(dec);
    assert_eq!(complete, 1, "frames did not reassemble");
    let mut type_buf = [0u8; 32];
    let mut tlen: core::ffi::c_uint = 0;
    let _ = shlosilo_ur_decode_type(dec, type_buf.as_mut_ptr(), 32, &mut tlen);
    let t = String::from_utf8_lossy(&type_buf)
        .trim_end_matches('\0')
        .to_string();
    let mut msg = vec![0u8; 16384];
    let mut actual: core::ffi::c_uint = 0;
    let rc = shlosilo_ur_decode_payload(
        dec,
        msg.as_mut_ptr(),
        msg.len() as core::ffi::c_uint,
        &mut actual,
    );
    assert_eq!(rc, 0, "payload extract failed");
    msg.truncate(actual as usize);
    shlosilo_ur_decode_free(dec);
    (t, msg)
}

fn read_frames(path: &str) -> Vec<String> {
    std::fs::read_to_string(path)
        .expect("read frames")
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// TX2_FRAMES_IN -> TX2_OUT: reassemble monero_c commitUR frames and store the
/// raw `unsigned_monero_tx` container.
#[test]
#[ignore = "host tool: UR frames -> unsigned container"]
fn tx2_decode_frames() {
    let frames = read_frames(&env("TX2_FRAMES_IN"));
    let (t, msg) = decode_frames(&frames);
    let content = ur_message_content(&msg);
    println!(
        "type={t} frames={} message={} content={}",
        frames.len(),
        msg.len(),
        content.len()
    );
    println!(
        "message head: {:02x?}  content head: {:02x?}",
        &msg[..8.min(msg.len())],
        &content[..8.min(content.len())]
    );
    std::fs::write(env("TX2_OUT"), content).expect("write container");
}

/// TX2_ENC_IN (unsigned container) -> TX2_OUT (plaintext). Field-level diff
/// input for the Cake-built vs CLI-built construction comparison.
#[test]
#[ignore = "host tool: unsigned container -> plaintext"]
fn tx2_dump_unsigned_plain() {
    let enc = std::fs::read(env("TX2_ENC_IN")).expect("read container");
    let s = env("SHLOSILO_TEST_XMR_VIEW_SK");
    let view: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    let view: [u8; 32] = view.try_into().unwrap();
    let plain = shlosilo::chain::xmr::unsigned_txset::decrypt_unsigned_txset(&enc, &view)
        .expect("decrypt unsigned");
    println!("plaintext: {} bytes", plain.len());
    std::fs::write(env("TX2_OUT"), &plain[..]).expect("write plain");
}

/// Differential probe: empty `real_out_additional_tx_keys` (varint len -> 0,
/// keys dropped) on the source entry whose `real_out_tx_key` equals
/// TX2_TXKEY_HEX, then re-encrypt. If the fixture then SIGNS, the input is
/// MAIN-tx-key derived and the sign-path's
/// `additional[real_output_in_tx_index]` key selection is what rejects the
/// untouched fixture (the change-to-own-subaddress red-pin family).
///
///   TX2_ENC_IN=<unsigned container> TX2_OUT=<patched container>
///   TX2_TXKEY_HEX=<32B hex of real_out_tx_key>
///   SHLOSILO_TEST_XMR_VIEW_SK=...
#[test]
#[ignore = "host tool: strip source add-keys + re-encrypt"]
fn tx2_strip_src_addkeys() {
    use rand_chacha::rand_core::SeedableRng as _;
    let enc = std::fs::read(env("TX2_ENC_IN")).expect("read container");
    let s = env("SHLOSILO_TEST_XMR_VIEW_SK");
    let view: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    let view: [u8; 32] = view.try_into().unwrap();
    let mut plain = shlosilo::chain::xmr::unsigned_txset::decrypt_unsigned_txset(&enc, &view)
        .expect("decrypt unsigned")
        .to_vec();

    let tks = env("TX2_TXKEY_HEX");
    let marker: Vec<u8> = (0..tks.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&tks[i..i + 2], 16).unwrap())
        .collect();
    let pos = plain
        .windows(marker.len())
        .position(|w| w == &marker[..])
        .expect("tx_key marker not found (must be unique enough)");
    let count = plain
        .windows(marker.len())
        .filter(|w| *w == &marker[..])
        .count();
    assert_eq!(count, 1, "tx_key marker must be unique, found {count}");

    let varint_at = pos + marker.len();
    let nkeys = plain[varint_at];
    assert!(
        (1..0x80).contains(&nkeys),
        "unexpected add-keys varint {nkeys}"
    );
    println!(
        "marker at {pos}, add_keys len={nkeys}, dropping {} bytes",
        nkeys as usize * 32
    );
    plain[varint_at] = 0;
    plain.drain(varint_at + 1..varint_at + 1 + nkeys as usize * 32);
    println!(
        "plaintext: {} -> {} bytes",
        plain.len() + 1 + nkeys as usize * 32,
        plain.len()
    );

    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x22);
    let out = shlosilo::chain::xmr::signed_txset::encrypt_unsigned_txset(
        zeroize::Zeroizing::new(plain),
        &view,
        &mut rng,
    )
    .expect("re-encrypt unsigned");
    std::fs::write(env("TX2_OUT"), &out[..]).expect("write patched container");
    println!(
        "patched container: {} bytes -> {}",
        out.len(),
        env("TX2_OUT")
    );
}

// ─── Red pin: real Cake construction shape (mainnet tx2 family) ─────────────
//
// Fixture `fixtures/tx2_cake_real_unsigned.bin` is a REAL wallet2 product from
// monero_c's Cake construction path (`MONERO_Wallet_createTransaction` +
// `commitUR(120)`, watch-only stagenet wallet, 2026-10-17): the selected input
// is the change output of a 2-subaddress-dest funding tx — main-tx-key derived
// P, but `real_out_additional_tx_keys` non-empty (3) and
// `real_output_in_tx_index = 0`. `derive_input_from_source`
// (forms/chain/xmr/subaddress.rs:459) picks `additional[0]` for such inputs and
// rejects the fixture with `EncodingInvalidFormat`, so the device can never
// sign the most common real-chain shape. This is the real-chain twin of
// `pin_red_sign_path_change_to_own_subaddress_uses_main_txkey`.
//
// Keys below are the PUBLISHED stagenet-lab test keys (BIP-39 entropy 0x22*32
// → stage_disk), the same material the lab README marks as free to publish.

const TX2_LAB_SPEND_SK: [u8; 32] = [
    0xca, 0x8b, 0x0c, 0xb5, 0x6d, 0xf7, 0x93, 0x80, 0xbb, 0x47, 0x81, 0xee, 0xfd, 0xe9, 0xdf, 0x0f,
    0x41, 0xe9, 0x8c, 0x6c, 0x3e, 0xa3, 0xd2, 0x7b, 0x9f, 0xb6, 0x18, 0x33, 0x98, 0xa3, 0x47, 0x0d,
];
const TX2_LAB_VIEW_SK: [u8; 32] = [
    0xdb, 0x93, 0xce, 0x63, 0x2d, 0x8d, 0x31, 0xe3, 0x1b, 0xd0, 0xb4, 0xec, 0xbd, 0xbd, 0xb8, 0x33,
    0xca, 0xe8, 0x13, 0x92, 0x8a, 0xf4, 0x02, 0xc5, 0xb7, 0xff, 0xeb, 0x85, 0x76, 0x9c, 0xf0, 0x00,
];
// real_out_tx_key of the fixture's single source entry
const TX2_LAB_SRC_TX_KEY: [u8; 32] = [
    0xd2, 0x3c, 0xb1, 0xc2, 0x9b, 0xd8, 0xd6, 0x25, 0xcf, 0x92, 0x2b, 0xcc, 0x13, 0xad, 0xb1, 0x1e,
    0xa7, 0x43, 0x77, 0x87, 0xb7, 0x4c, 0xaf, 0x98, 0x9c, 0x4c, 0xf4, 0x89, 0x9d, 0x09, 0x1a, 0x34,
];

fn tx2_strip_addkeys_plain(plain: &mut Vec<u8>) {
    let pos = plain
        .windows(32)
        .position(|w| w == TX2_LAB_SRC_TX_KEY)
        .expect("tx_key marker");
    let nkeys = plain[pos + 32];
    assert!((1..0x80).contains(&nkeys), "add-keys varint {nkeys}");
    plain[pos + 32] = 0;
    plain.drain(pos + 33..pos + 33 + nkeys as usize * 32);
}

fn tx2_sign_container(enc: &[u8]) -> Result<usize, shlosilo::error::ShlosiloError> {
    tx2_sign_container_records(enc, &[])
}

/// Records-aware signer: `ki_records` = pairing-beat wallet key image
/// retention (wallet-transfer-indexed; see tests/pin_signed_key_images_wallet_indexed.rs).
fn tx2_sign_container_records(
    enc: &[u8],
    ki_records: &[shlosilo::business::sign::WalletKiRecord],
) -> Result<usize, shlosilo::error::ShlosiloError> {
    use shlosilo::business::sign::{sign_with_entropy_records, SignInput};
    use shlosilo::entropy::mnemonic::Mnemonic;
    use shlosilo::ur::ur_encode::UrTypeTag;
    let m = Mnemonic::from_entropy(&[0x22u8; 32]).expect("mnemonic");
    let mut out = vec![0u8; 65536];
    sign_with_entropy_records(
        SignInput::Mnemonic {
            mnemonic: m,
            passphrase: b"",
        },
        UrTypeTag::XmrTxUnsigned,
        enc,
        ki_records,
        &[0x77u8; 32],
        &mut out,
    )
}

/// MUST-RED: the real Cake-built unsigned (change input of an add-keys funding
/// tx) must sign. Today the sign path rejects it (EncodingInvalidFormat) —
/// the input's output key derives from the MAIN tx key while
/// `real_out_additional_tx_keys` is non-empty.
#[test]
fn pin_red_sign_real_cake_unsigned_addkeys_change_input() {
    let enc = include_bytes!("fixtures/tx2_cake_real_unsigned.bin");
    match tx2_sign_container(enc) {
        Ok(n) => panic!("PINNED RED flipped GREEN: real Cake fixture signed ({n} bytes)"),
        Err(e) => panic!(
            "PINNED RED: sign path REJECTED the real Cake-built unsigned \
             (change input of add-keys funding tx, main-tx-key derived P, \
             add_keys=3, real_idx=0): {e:?}"
        ),
    }
}

/// Control for the pin above: the SAME fixture with
/// `real_out_additional_tx_keys` emptied signs fine — proving the input is
/// main-tx-key derived and the add-keys key selection is the only blocker.
#[test]
fn control_sign_real_cake_unsigned_addkeys_stripped_signs() {
    use rand_chacha::rand_core::SeedableRng as _;
    use shlosilo::chain::xmr::signed_txset::encrypt_unsigned_txset;
    use shlosilo::chain::xmr::unsigned_txset::decrypt_unsigned_txset;

    let enc = include_bytes!("fixtures/tx2_cake_real_unsigned.bin");
    let mut plain = decrypt_unsigned_txset(enc, &TX2_LAB_VIEW_SK)
        .expect("decrypt fixture")
        .to_vec();
    tx2_strip_addkeys_plain(&mut plain);
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x22);
    let patched =
        encrypt_unsigned_txset(zeroize::Zeroizing::new(plain), &TX2_LAB_VIEW_SK, &mut rng)
            .expect("re-encrypt");
    let n = tx2_sign_container_records(&patched, &fixture_gap_records())
        .expect("stripped fixture must sign");
    assert!(n > 3000, "signed container size {n}");
    let _ = TX2_LAB_SPEND_SK; // sign path derives it from the mnemonic
}

/// Gap records for the fixture wallet (spends index 5 with one source):
/// positions 0..=4 come from the pairing records face — dummies stand in for
/// the lab wallet's real records (only the selected index is source-derived).
fn fixture_gap_records() -> Vec<shlosilo::business::sign::WalletKiRecord> {
    (0..5)
        .map(|i| shlosilo::business::sign::WalletKiRecord {
            transfer_idx: i,
            key_image: [0x10 + i as u8; 32],
        })
        .collect()
}
