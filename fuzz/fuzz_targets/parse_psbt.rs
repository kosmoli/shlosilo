#![no_main]
// Audit #5 open-04: PSBT parser fuzz — arbitrary byte sequences must not panic/OOM
// (final verification of exact-consumption/duplicate keys/budget-before-unsafe validation)
//
// Uses the production shape (parse_psbt_into over harness-owned, dropped
// buffers — the same parse core the ws route runs). The convenience shell
// `parse_psbt` leaks its pool by design and would trip LeakSanitizer on
// every input; that shell is test-legacy surface, tracked for the
// convenience-shell campaign (batch 3).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The result doesn't matter; only that there's no panic/no abort/no over-budget allocation
    let mut arena = vec![0u8; shlosilo::types::caps::SIGN_WS_PSBT_ARENA];
    let mut recs = vec![shlosilo::chain::btc::psbt::KvRec::EMPTY; shlosilo::types::caps::SIGN_WS_PSBT_RECS];
    let _ = shlosilo::chain::btc::psbt::parse_psbt_into(data, &mut arena, &mut recs);
});
