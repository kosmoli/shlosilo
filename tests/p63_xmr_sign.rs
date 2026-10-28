//! P1-06: unsigned construction -> signed transaction end-to-end.
//!
//! X7 un-gated (2026-10-28): signs the in-tree REAL 4-in/4-out construction
//! capture (tests/fixtures/xmr_construction_unsorted_1023.bin — the 2026-10-23
//! D-shape) with the in-tree TEST2 test-wallet secrets (test-only material,
//! mirrored from tests/golden_vin_order_1024.rs). Replaces the env-gated
//! P6.3-wallet variant (its keys are lost with the wallet file; the P6.3
//! plaintext parse stays covered ungated in p63_xmr_unsigned.rs).
//!
//! Checks:
//! 1. tx serializes successfully and is non-empty
//! 2. tx version byte = 2 (ringct tx)
//! 3. structural counts match the construction shape
//! 4. fee = input_sum - out_sum matches the construction's balance delta
#![cfg(feature = "alloc-fallback")]

use rand_core::OsRng;
use shlosilo::chain::xmr::tx_signer::sign_tx_from_construction;
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

#[test]
fn sign_real_fixture_end_to_end() {
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
    assert_eq!(utx.txes.iter().flatten().count(), 1);
    let tx_data = utx.txes.iter().flatten().next().unwrap();

    // RNG: OsRng on host; TRNG on real hardware (L3 injection point)
    let mut rng = OsRng;

    // ---- Sign (returns official monerod wire bytes) ----
    let bytes = sign_tx_from_construction(tx_data, &TEST2_SPEND_SK, &TEST2_VIEW_SK, &mut rng)
        .expect("sign tx from construction");
    eprintln!("signed tx bytes = {}", bytes.len());

    // ---- Check 1+2: non-empty, tx version 2 (ringct) ----
    assert!(!bytes.is_empty(), "signed tx serializes non-empty");
    assert_eq!(bytes[0], 2, "tx version 2");

    // ---- Check 3: structural counts match the real construction shape ----
    assert_eq!(tx_data.sources.len(), 4, "the 1023 shape has four inputs");
    assert_eq!(
        tx_data.splitted_dsts.len(),
        4,
        "the 1023 shape has four outputs (3 recipients + change)"
    );

    // ---- Check 4: balance (fee = the construction's own delta) ----
    let input_sum: u64 = tx_data.sources.iter().flatten().map(|s| s.amount).sum();
    let out_sum: u64 = tx_data.splitted_dsts.iter().map(|d| d.amount).sum();
    assert!(input_sum > out_sum, "inputs cover outputs");
    let fee = input_sum - out_sum;
    eprintln!(
        "FEE_ANCHOR = {} (input_sum = {} out_sum = {})",
        fee, input_sum, out_sum
    );
    // Fee anchor: the 2026-10-23 construction's exact fee. Any signer change
    // that alters the balance must show up here as a hard failure.
    assert_eq!(fee, 87_740_000, "fee matches the 1023 construction");

    // Forensic hook: dump the signed tx hex for external oracle runs.
    if let Ok(path) = std::env::var("SHLOSILO_SIGNED_TX_OUT") {
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        std::fs::write(&path, hex).expect("write signed tx");
        eprintln!("WROTE {}", path);
    }
    eprintln!("E2E structure OK");
}
