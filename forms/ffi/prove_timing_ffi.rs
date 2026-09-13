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
//!
//! Each entry point has a SINGLE definition whose body is cfg-split: the real
//! implementation under the feature, a no-op otherwise, so the C host always
//! links. One definition also means cbindgen emits exactly one declaration per
//! function (dual `#[cfg]`-branches produced duplicate header declarations).

/// C-ABI: register the millisecond clock for prove-phase timing. Call from C init
/// right after `shlosilo_timing_set_clock_fn` (same clock function address works).
///
/// # Safety
/// `clock_fptr` must be a valid `extern "C" fn() -> u32` address (ARM thumb ok).
#[no_mangle]
pub extern "C" fn shlosilo_bp_timing_set_clock(clock_fptr: u32) {
    #[cfg(feature = "prove-timing-ffi")]
    {
        monero_bulletproofs::register_prove_timing_clock(clock_fptr);
    }
    #[cfg(not(feature = "prove-timing-ffi"))]
    {
        let _ = clock_fptr;
    }
}

/// C-ABI: reset all prove-phase counters.
#[no_mangle]
pub extern "C" fn shlosilo_bp_timing_reset() {
    #[cfg(feature = "prove-timing-ffi")]
    {
        monero_bulletproofs::reset_prove_timing();
    }
}

/// C-ABI: read one phase's accumulated ms (0 for unknown phase).
#[no_mangle]
pub extern "C" fn shlosilo_bp_timing_phase(phase: u8) -> u32 {
    #[cfg(feature = "prove-timing-ffi")]
    {
        monero_bulletproofs::phase_ms(phase)
    }
    #[cfg(not(feature = "prove-timing-ffi"))]
    {
        let _ = phase;
        0
    }
}
