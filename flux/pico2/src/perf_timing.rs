//! XMR phase-timing probes (feature `perf-timing`; diagnostic builds only).
//!
//! Ports the forgebox probe stack to this Rust-native host. Three timing
//! hooks accumulate per-phase milliseconds, each fed by a registered
//! clock function: the L1 tx-phases (forms/tx_phase_hook.rs), the vendored
//! BP+ prove phases (prove_timing_hook.rs) and the vendored CryptoNight
//! phases (cn_timing_hook.rs). This module supplies the clock from
//! embassy-time and registers it with all three. The hooks themselves are
//! enabled by the pico2 `perf-timing` feature via the shlosilo features
//! `tx-phase-timing-ffi` / `cn-timing-ffi` (the latter pulls
//! `prove-timing-ffi`); production images never enable them.
//!
//! Phase ids: see `forms/tx_phase_hook.rs` (1..=11),
//! `vendor/monero-bulletproofs/src/prove_timing_hook.rs` (1..=9),
//! `vendor/cryptonight/src/cn_timing_hook.rs` (1..=5).

use core::fmt::Write as _;

use embassy_time::Instant;

/// Millisecond clock for the hooks (C ABI — the T-04 contract carries a typed
/// nullable `extern "C" fn() -> u32` across the boundary).
extern "C" fn now_ms_c() -> u32 {
    Instant::now().as_millis() as u32
}

/// Register this host's clock with all three timing hooks (call once at boot).
pub(crate) fn register() {
    // T-04 contract: typed nullable fn pointers, no address casting.
    // NULL would unregister; last registration wins.
    shlosilo::ffi::tx_phase_ffi::shlosilo_tx_phase_set_clock(Some(now_ms_c));
    shlosilo::ffi::cn_timing_ffi::shlosilo_cn_timing_set_clock(Some(now_ms_c));
    shlosilo::ffi::prove_timing_ffi::shlosilo_bp_timing_set_clock(Some(now_ms_c));
}

/// Zero all accumulators (call right before a timed signing run).
pub(crate) fn reset() {
    shlosilo::ffi::tx_phase_ffi::shlosilo_tx_phase_reset();
    shlosilo::ffi::cn_timing_ffi::shlosilo_cn_timing_reset();
    shlosilo::ffi::prove_timing_ffi::shlosilo_bp_timing_reset();
}

/// Log the accumulated per-phase ms as three compact lines:
/// `[xt] tx: 1=.. 2=.. .. 11=..`, `[xt] bp: ..`, `[xt] cn: ..`.
pub(crate) fn log_phases() {
    {
        let mut buf = [0u8; 320];
        let mut w = crate::sign_smoke::BufWriter::new(&mut buf);
        let _ = write!(w, "[xt] tx:");
        for p in 1..=11u8 {
            let v = shlosilo::ffi::tx_phase_ffi::shlosilo_tx_phase_phase(p);
            let _ = write!(w, " {p}={v}");
        }
        log::info!("{}", w.as_str());
    }
    {
        let mut buf = [0u8; 480];
        let mut w = crate::sign_smoke::BufWriter::new(&mut buf);
        let _ = write!(w, "[xt] bp:");
        // 1..=9 named phases; 11..=17 per-WIP-round L multiexps; 21..=27 R.
        for p in 1..=27u8 {
            let v = shlosilo::ffi::prove_timing_ffi::shlosilo_bp_timing_phase(p);
            let _ = write!(w, " {p}={v}");
        }
        log::info!("{}", w.as_str());
    }
    {
        let mut buf = [0u8; 320];
        let mut w = crate::sign_smoke::BufWriter::new(&mut buf);
        let _ = write!(w, "[xt] cn:");
        for p in 1..=5u8 {
            let v = shlosilo::ffi::cn_timing_ffi::shlosilo_cn_timing_phase(p);
            let _ = write!(w, " {p}={v}");
        }
        log::info!("{}", w.as_str());
    }
}
