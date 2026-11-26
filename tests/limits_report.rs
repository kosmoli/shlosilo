//! Budget report pins: the numbers the build claims are the numbers the carve will use.
//!
//! Phase 3 of the limits-knob plan is a *reporting* change - no capacity moves. Its whole
//! value rests on one property: the report must be produced by the same formulas that size
//! the real workspaces, or it becomes another comment that drifts. These tests hold that
//! line, plus the budget relation that should have caught the 2026-11-15 slot mistake
//! (a profile whose peak does not fit its heap must fail the build, not the device).

// Chain axis: this file drives the xmr surface; without that switch the
// API it uses does not exist.
#![cfg(feature = "chain-xmr")]

use shlosilo::limits;
use shlosilo::limits_report::BudgetReport;

#[test]
fn report_numbers_are_the_layout_functions() {
    let r = BudgetReport::collect();
    assert_eq!(r.profile, limits::PROFILE);
    assert_eq!(r.fingerprint, limits::LIMITS_FINGERPRINT);
    // Same calls the carrier makes - if any of these diverge, the report is lying.
    assert_eq!(
        r.sign_ws,
        shlosilo::business::sign::SignWsLayout::compute().total
    );
    assert_eq!(
        r.ur_decode_ws,
        shlosilo::ur::ur_multipart::ur_decode_ws_len()
    );
    assert_eq!(
        r.ur_encode_ws,
        shlosilo::ur::ur_multipart::ur_encode_ws_len()
    );
    assert_eq!(
        r.pairing_ws,
        shlosilo::business::xmr_pairing::pairing_ws_len()
    );
    assert_eq!(r.review_ws, shlosilo::ffi::c_abi::review_ws_len());
    assert_eq!(r.pointer_bytes, core::mem::size_of::<usize>());
}

/// The peak is the largest *phase*, not the sum: the carrier releases the decode workspace
/// before it asks for the signing one.
#[test]
fn peak_is_the_largest_phase() {
    let r = BudgetReport::collect();
    let max = [r.sign_ws, r.ur_decode_ws, r.ur_encode_ws, r.pairing_ws]
        .into_iter()
        .max()
        .unwrap_or(0);
    assert_eq!(r.max_phase(), max);
    assert_eq!(r.headroom(), r.psram_budget.saturating_sub(max));
}

/// Whatever profile this test was built with must fit the heap that profile declares.
#[test]
fn the_profile_fits_its_declared_heap() {
    let r = BudgetReport::collect();
    assert!(
        r.fits(),
        "profile {} peak {} B exceeds psram_budget {} B",
        r.profile,
        r.max_phase(),
        r.psram_budget
    );
}

/// Every production profile must hold today's ceilings on a 32-bit carrier. The numbers are
/// computed here on the host, so they are an upper bound only for count-driven parts; the
/// point is to catch an obviously impossible combination before a device does.
#[test]
fn every_carrier_profile_declares_a_heap_that_covers_the_decode_workspace() {
    let decode = shlosilo::ur::ur_multipart::ur_decode_ws_len();
    for profile in ["pico2", "forgebox", "luckyfox", "tiny-test"] {
        let path = format!("limits/{profile}.toml");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let budget: usize = text
            .lines()
            .find(|l| l.trim_start().starts_with("psram_budget_bytes"))
            .and_then(|l| l.split('=').nth(1))
            .map(|v| v.split('#').next().unwrap_or("").trim().parse().unwrap())
            .unwrap_or_else(|| panic!("{path}: psram_budget_bytes missing"));
        if profile == "tiny-test" {
            // The tiny profile is deliberately too small: that is what it exists to exercise.
            assert!(budget < decode);
            continue;
        }
        assert!(
            budget >= decode,
            "{profile}: heap {budget} B cannot hold the decode workspace {decode} B"
        );
    }
}

/// The JSON snapshot must carry the fields an operator/CI reads, and stay within the buffer
/// the example allocates for it.
#[test]
fn json_snapshot_has_the_expected_shape() {
    let r = BudgetReport::collect();
    let mut buf = [0u8; 2048];
    let n = r
        .write_json(&mut buf)
        .unwrap_or_else(|_| panic!("report does not fit 2048 B"));
    let json = core::str::from_utf8(&buf[..n]).expect("utf8");
    for needle in [
        "\"profile\":",
        "\"fingerprint\":",
        "\"computed_on\":",
        "\"pointer_bytes\":",
        "\"workspaces\":",
        "\"peak_model\":",
        "\"budgets\":",
        "\"fits\":true",
    ] {
        assert!(json.contains(needle), "missing {needle} in {json}");
    }
}
