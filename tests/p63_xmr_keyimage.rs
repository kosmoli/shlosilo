//! P1-06: key image derivation KAT against the real fixture.
//!
//! X7 un-gated (2026-10-28): derives the key images of the in-tree REAL
//! 4-in construction (tests/fixtures/xmr_construction_unsorted_1023.bin)
//! with the in-tree TEST2 test-wallet secrets and asserts them against the
//! KNOWN key-image hex table (KI_HEX, indexed by wallet transfer_idx —
//! same anchor as the golden key_images_str pin). A derivation change that
//! shifts, drops or mis-assigns any key image breaks this KAT hard.
//!
//! The P6.3-wallet env variant is retired: its keys are lost with the wallet
//! file; this KAT covers the same code path (calc_output_key_offset ->
//! derive_input_from_source -> key image) on real captured bytes.
#![cfg(feature = "alloc-fallback")]

use shlosilo::chain::xmr::subaddress::{calc_output_key_offset, derive_input_from_source};
use shlosilo::chain::xmr::unsigned_txset::{deserialize_unsigned_tx, UnsignedTxPools};

const CONSTRUCTION: &[u8] = include_bytes!("fixtures/xmr_construction_unsorted_1023.bin");

// TEST2 test-wallet secrets (test-only; same material as golden_vin_order_1024).
const TEST2_VIEW_SK: [u8; 32] = [
    0x8d, 0xea, 0xed, 0xf1, 0x13, 0x7e, 0x24, 0xb9, 0xed, 0x25, 0x38, 0xae, 0x99, 0x53, 0x2f, 0x0f,
    0xf7, 0x71, 0x7c, 0x3c, 0x52, 0xd1, 0x16, 0x9c, 0xb0, 0x06, 0x88, 0x1c, 0x48, 0xa7, 0xbb, 0x04,
];
const TEST2_SPEND_SK: [u8; 32] = [
    0x12, 0x83, 0xcb, 0xd5, 0x3a, 0x57, 0x9f, 0x0e, 0x34, 0x90, 0xf3, 0xd9, 0x97, 0x8d, 0x7d, 0x42,
    0x3f, 0x98, 0x69, 0x23, 0xb3, 0x25, 0xa2, 0x33, 0x45, 0x4f, 0xb9, 0x91, 0xd0, 0xbb, 0x28, 0x0d,
];

/// The known key-image table (wallet transfer_idx -> KI hex) — the same
/// anchor the golden key_images_str pin asserts against.
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

#[test]
fn derive_key_images_match_known_table() {
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
    let utx = deserialize_unsigned_tx(
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
    let tx = utx.txes.iter().flatten().next().expect("one construction");
    assert_eq!(tx.sources.iter().flatten().count(), 4);

    // Per-input derivation: calc_output_key_offset -> derive_input_from_source.
    // derive_input_from_source internally verifies the output pubkey against
    // the wallet's keys — success itself is the ownership proof.
    for (i, src) in tx.sources.iter().flatten().enumerate() {
        // Offsets for both branches must compute (main 0/0 and the fixture's sub).
        let offset_main = calc_output_key_offset(
            &TEST2_VIEW_SK,
            &src.real_out_tx_key,
            src.real_output_in_tx_index,
            0,
            0,
        )
        .expect("offset main");
        assert_ne!(offset_main, [0u8; 32], "main offset must be non-zero");

        let (image, _mask) = derive_input_from_source(
            &TEST2_VIEW_SK,
            &TEST2_SPEND_SK,
            src,
            tx.subaddr_account,
            &tx.subaddr_indices,
        )
        .expect("derive input from source (ownership verified inside)");
        assert_ne!(image, [0u8; 32], "key image must be non-zero");

        // KAT: this input's key image must equal the known table entry at the
        // wallet transfer index the fixture selected for this slot.
        let transfer_idx = tx.selected_transfers[i];
        let expected = hex32(KI_HEX[transfer_idx]);
        assert_eq!(
            image, expected,
            "key image of input {} (transfer {}) must match the known table",
            i, transfer_idx
        );
    }
}
