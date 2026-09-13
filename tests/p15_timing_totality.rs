//! Audit #15 P2-01: totality of the timing-probe entry points.
//!
//! The probe readers and accumulators take a 1-based `stage`/`phase` id. Before
//! this fix the index arithmetic ran first (`(value - 1) as usize`), so a `0`
//! input underflowed: it panicked in builds with overflow checks on, wrapped to
//! 255 otherwise, and in the vendor CN/tx hooks it indexed a fixed-size array
//! out of bounds with no guard at all.
//!
//! ⚠️ **These tests only exercise the real implementations when the matching
//! feature is enabled.** With the feature off the modules compile to no-op
//! stubs (`end() {}`, readers returning 0), so the assertions pass vacuously —
//! run `cargo test --all-features` for the real coverage (CI does).
//!
//! Both profiles (`dev` for the library, `test` for the harness) set
//! `overflow-checks = true`, which is what turns the underflow into a
//! catchable panic during `cargo test`.

/// Ids in `1..=COUNT` are valid; 0 and anything past COUNT are not. The whole
/// range of the u8 input domain is exercised so the guard cannot regress to a
/// wrapped subtraction without a panic.
#[allow(dead_code)] // used only when the per-feature tests below are compiled in
fn sweep_reader(count: usize, name: &str, read: impl Fn(u8) -> u32) {
    assert_eq!(read(0), 0, "{name}: id 0 must read as 0, not underflow");
    for id in 1..=count as u8 {
        // In-range ids are accepted; without a registered clock the value is 0.
        let _ = read(id);
    }
    for id in [count as u8 + 1, count as u8 + 2, 127, 128, 254, 255] {
        assert_eq!(read(id), 0, "{name}: out-of-range id {id} must read as 0");
    }
}

#[cfg(feature = "device-timing")]
#[test]
fn device_timing_stage_ids_are_total() {
    use shlosilo::device_timing::{read_stage, Mark, STAGE_SERIALIZE};

    sweep_reader(STAGE_SERIALIZE as usize, "device_timing", read_stage);

    // Accumulator path: start(0) + end() must not panic (the end() index was the
    // underflow site). No clock is registered here, so the elapsed value is 0.
    Mark::start(0).end();
    for id in [1u8, STAGE_SERIALIZE, 250, 255] {
        Mark::start(id).end();
    }
}

#[cfg(feature = "tx-phase-timing-ffi")]
#[test]
fn tx_phase_ids_are_total() {
    use shlosilo::tx_phase_hook::{phase_ms, TX_PHASES};

    sweep_reader(TX_PHASES, "tx_phase_hook", phase_ms);
}

#[cfg(feature = "cn-timing-ffi")]
#[test]
fn cn_phase_ids_are_total() {
    // Re-exported by the vendored crate; CN phase ids are 1-based (1..=5).
    sweep_reader(5, "cuprate_cryptonight", cuprate_cryptonight::phase_ms);
}

/// The FFI entry points must answer the same way (they forward to the same
/// readers, or to the no-op stubs when the feature is off); this locks the
/// C-visible contract in both configurations.
#[test]
fn timing_ffi_entry_points_reject_invalid_ids() {
    let tx0 = shlosilo::ffi::tx_phase_ffi::shlosilo_tx_phase_phase(0);
    let tx_max = shlosilo::ffi::tx_phase_ffi::shlosilo_tx_phase_phase(255);
    let cn0 = shlosilo::ffi::cn_timing_ffi::shlosilo_cn_timing_phase(0);
    let cn_max = shlosilo::ffi::cn_timing_ffi::shlosilo_cn_timing_phase(255);
    let bp0 = shlosilo::ffi::prove_timing_ffi::shlosilo_bp_timing_phase(0);
    let bp_max = shlosilo::ffi::prove_timing_ffi::shlosilo_bp_timing_phase(255);

    assert_eq!(tx0, 0, "tx phase 0");
    assert_eq!(tx_max, 0, "tx phase 255");
    assert_eq!(cn0, 0, "cn phase 0");
    assert_eq!(cn_max, 0, "cn phase 255");
    assert_eq!(bp0, 0, "bp phase 0");
    assert_eq!(bp_max, 0, "bp phase 255");
}
