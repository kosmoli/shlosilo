//! Print the index/dest/mask of all 16 fixture ring outputs and the real_output,
//! and determine whether ring[real] at signing time really is the real idx.

use shlosilo::chain::xmr::unsigned_txset::deserialize_unsigned_tx;

const PLAIN: &[u8] = include_bytes!("fixtures/txset_plain.bin");

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

#[test]
fn diag_ring_full() {
    let mut txes = core::array::from_fn::<
        Option<shlosilo::chain::xmr::unsigned_txset::TxConstructionData<'_>>,
        2,
        _,
    >(|_| None);
    let mut sources =
        core::array::from_fn::<Option<shlosilo::chain::xmr::unsigned_txset::TxSourceEntry>, 4, _>(
            |_| None,
        );
    let mut splitted_dsts =
        core::array::from_fn::<shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry, 8, _>(
            |_| shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry::default(),
        );
    let mut selected_transfers = [0usize; 16];
    let mut extra = [0u8; 4096];
    let mut dests =
        core::array::from_fn::<shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry, 8, _>(
            |_| shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry::default(),
        );
    let mut subaddr_indices = [0u32; 16];
    let cd = deserialize_unsigned_tx(
        PLAIN,
        shlosilo::chain::xmr::unsigned_txset::UnsignedTxPools {
            txes: &mut txes,
            sources: &mut sources,
            splitted_dsts: &mut splitted_dsts,
            selected_transfers: &mut selected_transfers,
            extra: &mut extra,
            dests: &mut dests,
            subaddr_indices: &mut subaddr_indices,
        },
    )
    .unwrap();
    let src = cd
        .txes
        .iter()
        .flatten()
        .next()
        .unwrap()
        .sources
        .iter()
        .flatten()
        .next()
        .unwrap();
    {
        let m: String = src
            .mask
            .expose()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        println!("source.mask (blinding?) = {}", m);
        let rm: String = src.outputs[src.real_output as usize]
            .mask
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        println!("outputs[real].mask      = {}", rm);
    }
    println!("real_output field = {}", src.real_output);
    for (i, o) in src.outputs.iter().enumerate() {
        println!(
            "out[{:2}] idx={} dest={} mask={}",
            i,
            o.index,
            hexs(&o.dest),
            hexs(&o.mask)
        );
    }
    // 2026-10-23 pin (was print-only): ring[real_output] must be the REAL
    // ring member. The invariant is the RCT commitment relation — the ring
    // entries carry commitment POINTS (cryptonote_tx_utils.h: outputs =
    // "index + key + optional ringct commitment") while src.mask is the
    // scalar amount mask (field comment: "ringct amount mask"), so the real
    // member is the one whose commitment equals C = mask·G + amount·H.
    // A mis-indexed real_output signs against a decoy and the daemon rejects
    // the tx. Placed after the full ring printout so a failure still leaves
    // the complete evidence.
    let expect_c = monero_ed25519::Commitment::new(
        shlosilo::chain::xmr::transaction::bytes_to_monerod_scalar(src.mask.expose()),
        src.amount,
    )
    .commit()
    .compress()
    .to_bytes();
    assert_eq!(
        src.outputs[src.real_output as usize].mask, expect_c,
        "ring[real_output] must carry the real output's RCT commitment (C = mask·G + amount·H)"
    );
}
