//! Device-side BP+ prove-phase timing FFI (feature `prove-timing-ffi`).
//!
//! Forwards the already-registered device-timing clock to the vendored
//! monero-bulletproofs `prove-timing` hook, and exposes the accumulated
//! per-phase ms to the C smoke task. Same fptr-as-u32 pattern as
//! `device_timing` / `generator_cache_ffi`.
//!
//! C side contract:
//! - `uint32_t shlosilo_bp_timing_phase(uint8_t phase)` -> accumulated ms
//!   (1 = initial multiexp, 2 = A_hat, 3 = WIP rounds, 4 = total prove)

/// C-ABI: register the millisecond clock for prove-phase timing. Call from C init
/// right after `shlosilo_timing_set_clock_fn` (same clock function address works).
///
/// # Safety
/// `clock_fptr` must be a valid `extern "C" fn() -> u32` address (ARM thumb ok).
#[cfg(feature = "prove-timing-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_bp_timing_set_clock(clock_fptr: u32) {
    monero_bulletproofs::register_prove_timing_clock(clock_fptr);
}

/// C-ABI: reset all prove-phase counters.
#[cfg(feature = "prove-timing-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_bp_timing_reset() {
    monero_bulletproofs::reset_prove_timing();
}

/// C-ABI: read one phase's accumulated ms (0 for unknown phase).
#[cfg(feature = "prove-timing-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_bp_timing_phase(phase: u8) -> u32 {
    monero_bulletproofs::phase_ms(phase)
}

// Production no-op stubs (feature off) so the C side always links.
#[cfg(not(feature = "prove-timing-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_bp_timing_set_clock(_clock_fptr: u32) {}
#[cfg(not(feature = "prove-timing-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_bp_timing_reset() {}
#[cfg(not(feature = "prove-timing-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_bp_timing_phase(_phase: u8) -> u32 {
    0
}
