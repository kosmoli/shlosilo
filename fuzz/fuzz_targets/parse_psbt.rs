#![no_main]
// Audit #5 open-04: PSBT parser fuzz — arbitrary byte sequences must not panic/OOM
// (final verification of exact-consumption/duplicate keys/budget-before-unsafe validation)
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The result doesn't matter; only that there's no panic/no abort/no over-budget allocation
    let _ = shlosilo::chain::btc::psbt::parse_psbt(data);
});
