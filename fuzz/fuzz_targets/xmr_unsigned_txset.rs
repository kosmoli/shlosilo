#![no_main]
// Audit #12 P2-03: XMR unsigned-txset parser fuzz — arbitrary byte sequences must never
// panic/OOM. Entry total budget + read_count physical feasibility + checked reads'
// final verification (same acceptance criteria as the PSBT fuzz).
//
// Z2.3 C3c: the parser is parse-into — the model lives in caller pools. The pools
// here are fixed stack arrays, so the "no over-budget allocation" invariant is now
// structural (the parse path allocates nothing at all).
use libfuzzer_sys::fuzz_target;
use shlosilo::chain::xmr::unsigned_txset::{
    deserialize_unsigned_tx, TxDestinationEntry, TxConstructionData, TxSourceEntry,
    UnsignedTxPools,
};

fuzz_target!(|data: &[u8]| {
    // result doesn't matter; only that there is no panic/abort and no over-budget allocation
    let mut txes: [Option<TxConstructionData<'_>>; 2] = core::array::from_fn(|_| None);
    let mut sources: [Option<TxSourceEntry>; 4] = core::array::from_fn(|_| None);
    let mut sd = core::array::from_fn::<TxDestinationEntry, 4, _>(|_| {
        TxDestinationEntry::default()
    });
    let mut sel = [0usize; 8];
    let mut extra = [0u8; 512];
    let mut dests = core::array::from_fn::<TxDestinationEntry, 4, _>(|_| {
        TxDestinationEntry::default()
    });
    let mut sub = [0u32; 8];
    let _ = deserialize_unsigned_tx(
        data,
        UnsignedTxPools {
            txes: &mut txes,
            sources: &mut sources,
            splitted_dsts: &mut sd,
            selected_transfers: &mut sel,
            extra: &mut extra,
            dests: &mut dests,
            subaddr_indices: &mut sub,
        },
    );
});
