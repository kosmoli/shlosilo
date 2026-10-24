//! Canonical vin order (2026-10-24 incident).
//!
//! monero's `check_tx_inputs` rejects any tx whose vin key images are not
//! strictly DESCENDING ("transaction has unsorted inputs", blockchain.cpp:
//! `memcmp(current, next) >= 0`). wallet2 sorts the sources by key image
//! before signing; the signer must do the same.
//!
//! Real regression fixture: the 2026-10-23 D-shape construction (four inputs in
//! selected-transfer order, NOT key-image sorted). Signed as-is it was rejected
//! by monerod as "invalid input"; the same construction with sorted sources is
//! accepted by the daemon (verified live 2026-10-24, `status: OK`).
//! Keys/KIs belong to the dedicated TEST wallet (embedded per the 2026-10-20
//! fixture policy — test wallets only, never production keys).

#![cfg(feature = "alloc-fallback")]

use rand_core::OsRng;
use shlosilo::business::sign::{
    sign_with_entropy_records, wallet_fingerprint, SignInput, WalletKiRecord,
};
use shlosilo::chain::xmr::signed_txset::{decrypt_signed_txset, encrypt_unsigned_txset};
use shlosilo::chain::xmr::unsigned_txset::{
    deserialize_unsigned_tx, serialize_unsigned_tx, UnsignedTxPools,
};
use shlosilo::entropy::mnemonic::Mnemonic;
use shlosilo::ur::ur_encode::UrTypeTag;

const CONSTRUCTION: &[u8] = include_bytes!("fixtures/xmr_construction_unsorted_1023.bin");
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
const FRESH_ENTROPY: [u8; 32] = [
    0x5c, 0x81, 0xd4, 0xe2, 0x9a, 0x07, 0xb6, 0x3f, 0x18, 0xe5, 0xc0, 0x7d, 0x62, 0xa9, 0x4b, 0x38,
    0xf0, 0xe1, 0xc7, 0x5a, 0x26, 0xd8, 0xb3, 0x94, 0x01, 0xf7, 0xea, 0x2c, 0x5b, 0x6d, 0x83, 0x19,
];

fn hex32(s: &str) -> [u8; 32] {
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    o
}

fn clone_source(
    s: &shlosilo::chain::xmr::unsigned_txset::TxSourceEntry,
) -> shlosilo::chain::xmr::unsigned_txset::TxSourceEntry {
    let mut outputs = heapless::Vec::new();
    for o in s.outputs.iter() {
        outputs
            .push(shlosilo::chain::xmr::unsigned_txset::OutputEntry {
                index: o.index,
                dest: o.dest,
                mask: o.mask,
            })
            .unwrap();
    }
    let mut add = heapless::Vec::new();
    for k in s.real_out_additional_tx_keys.iter() {
        add.push(zeroize::Zeroizing::new(**k)).unwrap();
    }
    shlosilo::chain::xmr::unsigned_txset::TxSourceEntry {
        outputs,
        real_output: s.real_output,
        real_out_tx_key: zeroize::Zeroizing::new(*s.real_out_tx_key),
        real_out_additional_tx_keys: add,
        real_output_in_tx_index: s.real_output_in_tx_index,
        amount: s.amount,
        rct: s.rct,
        mask: shlosilo::types::SecretBytes::new(*s.mask.expose()),
        multisig_kLRki: shlosilo::chain::xmr::unsigned_txset::MultisigKLRki {
            k: s.multisig_kLRki.k,
            l: s.multisig_kLRki.l,
            r: s.multisig_kLRki.r,
            ki: s.multisig_kLRki.ki,
        },
    }
}

/// Sign the fixture through the production path. `reverse` flips the source and
/// selected-transfer order to prove construction-order independence.
fn signed_vins(reverse: bool) -> Vec<[u8; 32]> {
    let mut wire = vec![0x02u8, 0x01u8];
    wire.extend_from_slice(CONSTRUCTION);

    let mut p_txes = core::array::from_fn::<
        Option<shlosilo::chain::xmr::unsigned_txset::TxConstructionData<'_>>,
        8,
        _,
    >(|_| None);
    let mut p_src =
        core::array::from_fn::<Option<shlosilo::chain::xmr::unsigned_txset::TxSourceEntry>, 32, _>(
            |_| None,
        );
    let mut p_sd =
        core::array::from_fn::<shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry, 64, _>(
            |_| shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry::default(),
        );
    let mut p_sel = [0usize; 256];
    let mut p_ex = [0u8; 8192];
    let mut p_de =
        core::array::from_fn::<shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry, 64, _>(
            |_| shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry::default(),
        );
    let mut p_su = [0u32; 256];
    let mut utx = deserialize_unsigned_tx(
        &wire,
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
    .expect("parse the 1023 construction");

    {
        let cd = utx
            .txes
            .iter_mut()
            .flatten()
            .next()
            .expect("one construction");
        assert_eq!(cd.sources.len(), 4, "the incident shape has four inputs");
        if reverse {
            let taken: Vec<(usize, shlosilo::chain::xmr::unsigned_txset::TxSourceEntry)> = cd
                .sources
                .iter()
                .enumerate()
                .map(|(i, s)| (i, clone_source(s.as_ref().unwrap())))
                .collect();
            let sels: Vec<usize> = cd.selected_transfers.iter().copied().collect();
            cd.sources.clear();
            for (i, s) in taken.into_iter().rev() {
                cd.sources.push(Some(s)).unwrap();
                let _ = i;
            }
            cd.selected_transfers.clear();
            for v in sels.into_iter().rev() {
                cd.selected_transfers.push(v).unwrap();
            }
        }
    }

    let unsigned_plain = serialize_unsigned_tx(&utx);
    let mut enc_rng = OsRng;
    let enc = encrypt_unsigned_txset(unsigned_plain, &TEST2_VIEW_SK, &mut enc_rng)
        .expect("encrypt unsigned");

    let spend_pub = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
        * &curve25519_dalek::scalar::Scalar::from_bytes_mod_order(TEST2_SPEND_SK))
        .compress()
        .to_bytes();
    let view_pub = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
        * &curve25519_dalek::scalar::Scalar::from_bytes_mod_order(TEST2_VIEW_SK))
        .compress()
        .to_bytes();
    let fp = wallet_fingerprint(&spend_pub, &view_pub);
    let records: Vec<WalletKiRecord> = KI_HEX
        .iter()
        .enumerate()
        .map(|(i, h)| WalletKiRecord {
            transfer_idx: i as u32,
            wallet_fp: fp,
            key_image: hex32(h),
        })
        .collect();

    let m = Mnemonic::from_entropy(&TEST2_ENTROPY).expect("mnemonic");
    let mut out = vec![0u8; 16384];
    let n = sign_with_entropy_records(
        SignInput::Mnemonic {
            mnemonic: m,
            passphrase: b"",
        },
        UrTypeTag::XmrTxUnsigned,
        &enc,
        &records,
        &FRESH_ENTROPY,
        &mut out,
    )
    .expect("sign the 1023 construction");

    let plain = decrypt_signed_txset(&out[..n], &TEST2_VIEW_SK).expect("decrypt signed");
    // the plaintext layout is 00 | varint ptx_count | 01 | tx | ...
    let mut pos = 3usize;
    let prefix =
        shlosilo::chain::xmr::transaction::TransactionPrefix::deserialize(&plain, &mut pos)
            .expect("prefix");
    prefix.inputs[..prefix.inputs_len]
        .iter()
        .map(|i| i.key_image)
        .collect()
}

#[test]
fn vins_strictly_descending_and_order_independent() {
    let kis = signed_vins(false);
    assert_eq!(kis.len(), 4, "four inputs");
    for w in kis.windows(2) {
        assert!(
            w[1] < w[0],
            "vin key images must be strictly DESCENDING: {:02x?} then {:02x?}",
            &w[0][..6],
            &w[1][..6]
        );
    }

    // construction-order independence: reversing the sources and the selected
    // transfers must produce the SAME canonical vin order.
    let kis_rev = signed_vins(true);
    assert_eq!(
        kis, kis_rev,
        "the signed vin order must not depend on the construction's source order"
    );
}
