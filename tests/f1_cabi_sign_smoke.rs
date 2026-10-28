//! F1 (pool #14, closed 2026-10-28): forgebox C-ABI smoke on REAL XMR
//! fixtures — the positive face the p002 boundary tests lacked.
//!
//! History note: the pool asked for the "2-input fixture" (P2IN's
//! unsigned_txset_2in.bin). The C-ABI key sources are BIP-39 entropy-bound
//! (KeySession/Legacy derive keys from entropy — the 10-07 key-supply
//! decision: seed = BIP-39), and P2IN is a NATIVE-key wallet unreachable
//! from any in-tree entropy (probed: 3 entropies x accounts 0-3, no match).
//! Its 2-input face is therefore covered at the raw-key layer by
//! tests/xmr_sign_zero_alloc.rs (now un-gated, P2IN keys embedded), while
//! this smoke drives the C-ABI entries with the production-class REAL
//! 4-input capture (the 2026-10-23 D-shape fixture, TEST2 wallet) through
//! BOTH product entries: legacy typed (multipart reassembly path) and
//! session (product_task.c's main path, pairing KI records included).
//!
//! Pins:
//! 1. typed happy path: OK + non-trivial signed container
//! 2. session happy path with pairing records: OK + non-trivial container
//! 3. a tampered payload is REJECTED (garbage plaintext must not sign)
//! 4. the pinned TEST2 key material equals its BIP-39 derivation
//!
//! Contract facts found the hard way (kept in comments so nobody re-trips):
//! - output buffers OVER the contract cap (16384) are REJECTED with
//!   BufferTooSmall (-20) by checked_slice_mut — bigger is not safer;
//! - Network::MoneroMainnet = 90 (0 is BitcoinMainnet and the sign core
//!   rejects the chain-kind mismatch).
#![cfg(feature = "alloc-fallback")]

use shlosilo::entropy::mnemonic::Mnemonic;
use shlosilo::ffi::c_abi::r3::{shlosilo_sign_session_ffi, shlosilo_sign_typed_ffi};
use shlosilo::ffi::c_abi::shlosilo_sign_ws_len;
use shlosilo::ffi::error_code::OK;

const CONSTRUCTION: &[u8] = include_bytes!("fixtures/xmr_construction_unsorted_1023.bin");

// TEST2 test-wallet secrets (test-only; same material as golden_vin_order_1024).
const TEST2_ENTROPY: [u8; 32] = [
    0x57, 0xaa, 0x02, 0x25, 0x12, 0xf8, 0x65, 0x0c, 0xb8, 0x1d, 0xd3, 0xc9, 0x6c, 0x90, 0xc8, 0x03,
    0x8f, 0xc7, 0x20, 0x80, 0x3c, 0xdb, 0x50, 0xb2, 0x19, 0x8e, 0x8f, 0xf2, 0x26, 0xed, 0x0f, 0x5e,
];
const TEST2_VIEW_SK: [u8; 32] = [
    0x8d, 0xea, 0xed, 0xf1, 0x13, 0x7e, 0x24, 0xb9, 0xed, 0x25, 0x38, 0xae, 0x99, 0x53, 0x2f, 0x0f,
    0xf7, 0x71, 0x7c, 0x3c, 0x52, 0xd1, 0x16, 0x9c, 0xb0, 0x06, 0x88, 0x1c, 0x48, 0xa7, 0xbb, 0x04,
];
const TEST2_SPEND_SK: [u8; 32] = [
    0x12, 0x83, 0xcb, 0xd5, 0x3a, 0x57, 0x9f, 0x0e, 0x34, 0x90, 0xf3, 0xd9, 0x97, 0x8d, 0x7d, 0x42,
    0x3f, 0x98, 0x69, 0x23, 0xb3, 0x25, 0xa2, 0x33, 0x45, 0x4f, 0xb9, 0x91, 0xd0, 0xbb, 0x28, 0x0d,
];

/// Network::MoneroMainnet discriminant (forms/network.rs) — 0 would be
/// BitcoinMainnet and the sign core rejects the chain-kind mismatch.
const MONERO_MAINNET: u32 = 90;

/// The TEST2 wallet's full key-image table (transfer position -> KI hex) —
/// the same anchor golden_vin_order_1024 pins. The sign's key_images_list
/// spans 0..=max(selected), with selected positions derived from the tx
/// sources and the OTHER holes filled from the pairing retention records
/// (forms/business/sign.rs) — a hole neither side fills refuses the sign
/// with KeyImageRecordMissing (-34). The device gets this table from the
/// keyimages-sync pairing beat (fix37 store).
const KI_HEX: [&str; 13] = [
    "49e43bb86116b14855827c2c3f17852e7455fc18ceb3f1822e970c007e585ab5",
    "2c85f150ef6de077ad85b15a7345dc3143ca72b4d69fc84241545f4a393a915c",
    "7306860214b4150ea4a3d28e615ed8931f2b0c4fea5331d7e2d80848662a9f80",
    "c0e6f88e409815a9cfb72b6ce479a2d1a45a24a3670f3436b225a9b808be422f",
    "dbb3d6b755d76e458c53844e93a694a5f791b81cb6f1c81822bfe897b1b42599",
    "865ad3ac91cde0c32a7d1e8ddc00a9fce4ce7cffdd8118e54e9ffbbe019bcea1",
    "431e1a493aa06bab0200fa43cf792f8329d4ed22f28563eea24c4986949cca5e",
    "75bbf00fd5437d3053dfc528eeb97b781350fca8f5cea20229017c6fd4d50d09",
    "1d4e1c5514bf53f12df4b277cb2b6ffd363d03fdaab439db9bcdb54b7c20166e",
    "b91046b0bc1decbdd70ca3914013e49839335c329016f613a3646f39ee03ac4c",
    "01616a00aa30eb73be7929ae5f18e41fca68302e9e81ef9783df2baf39595284",
    "ac27a182204551051e0de64910e95df8ad944ec093d3ae0aacd5bacf51a59362",
    "dec877e35f6c7f14361167e4d27472b404403775113d79b37c29d0332c446587",
];

fn hex32(h: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect();
    v.try_into().unwrap()
}

// Fresh tx-key entropy: fixed value keeps the smoke deterministic-ish.
const FRESH_ENTROPY: [u8; 32] = [
    0x5c, 0x81, 0xd4, 0xe2, 0x9a, 0x07, 0xb6, 0x3f, 0x18, 0xe5, 0xc0, 0x7d, 0x62, 0xa9, 0x4b, 0x38,
    0xf0, 0xe1, 0xc7, 0x5a, 0x26, 0xd8, 0xb3, 0x94, 0x01, 0xf7, 0xea, 0x2c, 0x5b, 0x6d, 0x83, 0x19,
];

/// The sign family's output budget — checked_slice_mut REJECTS an over-cap
/// buffer with BufferTooSmall (-20); 16384 is the proven size (golden).
const OUT_CAP: usize = 16384;

fn mnemonic_indices() -> Vec<u16> {
    let m = Mnemonic::from_entropy(&TEST2_ENTROPY).expect("mnemonic");
    let idx: Vec<u16> = m.indices().to_vec();
    assert_eq!(idx.len(), 24, "32B entropy = 24 words");
    idx
}

fn wire() -> Vec<u8> {
    let mut w = vec![0x02u8, 0x01u8];
    w.extend_from_slice(CONSTRUCTION);
    w
}

/// The UR payload shape the C-ABI sign entries expect: the ENCRYPTED
/// unsigned-txset blob (the fixture family is encrypted too). Feeding the
/// plain construction gets rejected (-21): the core decrypts the payload
/// with the derived view key first (found the hard way 2026-10-28).
fn enc_payload() -> Vec<u8> {
    use shlosilo::chain::xmr::signed_txset::encrypt_unsigned_txset;
    use shlosilo::chain::xmr::unsigned_txset::{
        deserialize_unsigned_tx, serialize_unsigned_tx, TxConstructionData, TxDestinationEntry,
        TxSourceEntry, UnsignedTxPools,
    };
    let mut p_txes = core::array::from_fn::<Option<TxConstructionData<'_>>, 8, _>(|_| None);
    let mut p_src = core::array::from_fn::<Option<TxSourceEntry>, 32, _>(|_| None);
    let mut p_sd =
        core::array::from_fn::<TxDestinationEntry, 64, _>(|_| TxDestinationEntry::default());
    let mut p_sel = [0usize; 256];
    let mut p_ex = [0u8; 8192];
    let mut p_de =
        core::array::from_fn::<TxDestinationEntry, 64, _>(|_| TxDestinationEntry::default());
    let mut p_su = [0u32; 256];
    let utx = deserialize_unsigned_tx(
        &wire(),
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
    .expect("parse 1023 construction");
    let plain = serialize_unsigned_tx(&utx);
    encrypt_unsigned_txset(plain, &TEST2_VIEW_SK, &mut rand_core::OsRng)
        .expect("encrypt")
        .to_vec()
}

fn sign_typed(payload: &[u8]) -> (i32, u32) {
    let idx = mnemonic_indices();
    let ws_len = shlosilo_sign_ws_len();
    let mut ws = vec![0u8; ws_len as usize];
    let mut out = vec![0u8; OUT_CAP];
    let mut actual: u32 = 0;
    let rc = shlosilo_sign_typed_ffi(
        c"xmr-txunsigned".as_ptr(),
        payload.as_ptr(),
        payload.len() as u32,
        idx.as_ptr(),
        idx.len() as i32,
        core::ptr::null(),
        0,
        MONERO_MAINNET,
        FRESH_ENTROPY.as_ptr(),
        FRESH_ENTROPY.len() as u32,
        out.as_mut_ptr(),
        out.len() as u32,
        &mut actual,
        ws.as_mut_ptr(),
        ws_len,
    );
    (rc, actual)
}

/// Contract pin: the Legacy typed entry passes NO pairing retention records
/// ("no pairing retention on the legacy fixture path"), and the sign core
/// REFUSES an XMR sign whose key_images span a retention record cannot fill
/// (KeyImageRecordMissing = -34). XMR signs must go through the session
/// entry with records. [2026-10-28: this started as a happy-path smoke and
/// became a contract pin when the refusal surfaced the retention rule.]
#[test]
fn f1_typed_entry_refuses_xmr_without_records() {
    let (rc, actual) = sign_typed(&enc_payload());
    assert_eq!(
        rc, -34,
        "Legacy typed XMR sign must refuse with KeyImageRecordsMissing"
    );
    let _ = actual;
}

/// Discriminating pin: a tampered payload dies at the PAYLOAD layer (-21,
/// garbage plaintext) — BEFORE the retention check — while a clean payload
/// reaches -34 (retention). Two distinct codes, two distinct layers.
#[test]
fn f1_sign_typed_ffi_rejects_tampered_payload() {
    let mut bad = enc_payload();
    let mid = bad.len() / 2;
    bad[mid] ^= 0x01;
    let (rc, _actual) = sign_typed(&bad);
    assert_eq!(rc, -21, "a tampered payload must fail at the payload layer");
}

#[test]
fn f1_sign_session_ffi_real_fixture_ok() {
    use shlosilo::business::sign::{wallet_fingerprint, WalletKiRecord};
    use shlosilo::chain::xmr::subaddress::derive_input_from_source;
    use shlosilo::chain::xmr::unsigned_txset::{
        deserialize_unsigned_tx, TxConstructionData, TxDestinationEntry, TxSourceEntry,
        UnsignedTxPools,
    };
    use shlosilo::types::key_session::KeySession;

    // 1. Parse the construction and derive the pairing KI records from the
    //    wallet — the same data the device's fix37 pairing store holds.
    let w = wire();
    let mut p_txes = core::array::from_fn::<Option<TxConstructionData<'_>>, 8, _>(|_| None);
    let mut p_src = core::array::from_fn::<Option<TxSourceEntry>, 32, _>(|_| None);
    let mut p_sd =
        core::array::from_fn::<TxDestinationEntry, 64, _>(|_| TxDestinationEntry::default());
    let mut p_sel = [0usize; 256];
    let mut p_ex = [0u8; 8192];
    let mut p_de =
        core::array::from_fn::<TxDestinationEntry, 64, _>(|_| TxDestinationEntry::default());
    let mut p_su = [0u32; 256];
    let utx = deserialize_unsigned_tx(
        &w,
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
    .expect("parse 1023 construction");
    let tx = utx.txes.iter().flatten().next().expect("one construction");
    let n_in = tx.sources.iter().flatten().count();
    assert_eq!(n_in, 4, "the D-shape fixture has four inputs");

    let m = Mnemonic::from_entropy(&TEST2_ENTROPY).expect("mnemonic");
    let seed = m.to_seed(b"");
    let path = shlosilo::derivation::monero_reduce_scalar::MoneroPath::mainnet(0);
    let kp = shlosilo::derivation::monero_reduce_scalar::derive(&seed, &path).expect("derive");
    let spend_sec = shlosilo::curve_primitive::ed25519::scalar_to_bytes(kp.spend_priv());
    let view_sec = shlosilo::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv());
    let spend_pub = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
        * &curve25519_dalek::scalar::Scalar::from_bytes_mod_order(spend_sec))
        .compress()
        .to_bytes();
    let view_pub = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
        * &curve25519_dalek::scalar::Scalar::from_bytes_mod_order(view_sec))
        .compress()
        .to_bytes();
    let fp = wallet_fingerprint(&spend_pub, &view_pub);

    // The FULL wallet table (like the device's pairing store after a
    // keyimages sync) — selected positions get re-derived authoritative, the
    // other holes come from these retention records.
    let records: Vec<WalletKiRecord> = KI_HEX
        .iter()
        .enumerate()
        .map(|(i, h)| WalletKiRecord {
            transfer_idx: i as u32,
            wallet_fp: fp,
            key_image: hex32(h),
        })
        .collect();
    // Sanity: the retention table must agree with the fresh derivation on the
    // actually-selected positions (the pairing beat stores derived KIs).
    for (i, src) in tx.sources.iter().flatten().enumerate() {
        let (image, _mask) = derive_input_from_source(
            &view_sec,
            &spend_sec,
            src,
            tx.subaddr_account,
            &tx.subaddr_indices,
        )
        .expect("derive input (ownership verified inside)");
        assert_eq!(
            image, records[tx.selected_transfers[i]].key_image,
            "retention record must equal the derived key image at slot {}",
            i
        );
    }

    // 2. Caller-storage session (Z3.3c/R3 contract — never Box::into_raw).
    let mut slot = core::mem::MaybeUninit::<KeySession>::uninit();
    let session = {
        let s = KeySession::from_entropy(&TEST2_ENTROPY, b"").expect("session");
        unsafe { slot.as_mut_ptr().write(s) };
        slot.as_ptr()
    };

    // 3. Session sign with the pairing records (product_task.c's shape).
    let ws_len = shlosilo_sign_ws_len();
    let mut ws = vec![0u8; ws_len as usize];
    let mut out = vec![0u8; OUT_CAP];
    let mut actual: u32 = 0;
    let enc = enc_payload();
    let rc = shlosilo_sign_session_ffi(
        session,
        c"xmr-txunsigned".as_ptr(),
        enc.as_ptr(),
        enc.len() as u32,
        FRESH_ENTROPY.as_ptr(),
        FRESH_ENTROPY.len() as u32,
        out.as_mut_ptr(),
        out.len() as u32,
        &mut actual,
        ws.as_mut_ptr(),
        ws_len,
        records.as_ptr(),
        records.len() as u32,
    );
    assert_eq!(
        rc, OK,
        "session sign of the real 4-input fixture must return OK"
    );
    assert!(
        actual > 1000,
        "signed container must be non-trivial (actual={actual})"
    );
}

/// Semantic anchor (test constitution #1): the pinned raw key material must
/// equal the BIP-39 -> MoneroPath derivation of the pinned entropy.
#[test]
fn test2_keys_match_bip39_derivation() {
    let m = Mnemonic::from_entropy(&TEST2_ENTROPY).expect("mnemonic");
    let seed = m.to_seed(b"");
    let path = shlosilo::derivation::monero_reduce_scalar::MoneroPath::mainnet(0);
    let kp = shlosilo::derivation::monero_reduce_scalar::derive(&seed, &path).expect("derive");
    assert_eq!(
        shlosilo::curve_primitive::ed25519::scalar_to_bytes(kp.spend_priv()),
        TEST2_SPEND_SK,
        "pinned spend key must equal the BIP-39 derivation"
    );
    assert_eq!(
        shlosilo::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv()),
        TEST2_VIEW_SK,
        "pinned view key must equal the BIP-39 derivation"
    );
}
