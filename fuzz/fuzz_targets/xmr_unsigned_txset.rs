#![no_main]
// Audit #12 P2-03: XMR unsigned-txset parser fuzz — arbitrary byte sequences must never
// panic/OOM. Entry total budget + read_count physical feasibility + checked reads'
// final verification (same acceptance criteria as the PSBT fuzz).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
// result doesn't matter; only that there is no panic/abort and no over-budget allocation
    let _ = shlosilo::chain::xmr::unsigned_txset::deserialize_unsigned_tx(data);
});
