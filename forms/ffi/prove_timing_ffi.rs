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
//! links.
//!
//! Chain axis (batch 3): the real body needs BOTH the feature and `chain-xmr`,
//! because it forwards to `monero-bulletproofs` — an optional dependency carried
//! by that chain. A timing feature must never imply a chain (`build.rs` compares
//! the declared chain set with the resolved one, so a feature that quietly added
//! `chain-xmr` would be a declaration lie); the pair of conditions is the honest
//! way to say "diagnostics for a chain this build carries". One definition also means cbindgen emits exactly one declaration per
//! function (dual `#[cfg]`-branches produced duplicate header declarations).

/// C-ABI: register the millisecond clock for prove-phase timing. Call from C init
/// right after `shlosilo_timing_set_clock_fn` (same clock function works).
///
/// T-04 contract: typed nullable fn pointer, NULL unregisters.
///
/// # Safety
/// `clock_fptr`, when non-NULL, must be a valid `extern "C" fn() -> u32` on the target.
#[no_mangle]
pub unsafe extern "C" fn shlosilo_bp_timing_set_clock(clock_fptr: Option<extern "C" fn() -> u32>) {
    #[cfg(all(feature = "prove-timing-ffi", feature = "chain-xmr"))]
    {
        monero_bulletproofs::register_prove_timing_clock(clock_fptr);
    }
    #[cfg(not(all(feature = "prove-timing-ffi", feature = "chain-xmr")))]
    {
        let _ = clock_fptr;
    }
}

/// C-ABI: reset all prove-phase counters.
#[no_mangle]
pub extern "C" fn shlosilo_bp_timing_reset() {
    #[cfg(all(feature = "prove-timing-ffi", feature = "chain-xmr"))]
    {
        monero_bulletproofs::reset_prove_timing();
    }
}

/// C-ABI: read one phase's accumulated ms (0 for unknown phase).
#[no_mangle]
pub extern "C" fn shlosilo_bp_timing_phase(phase: u8) -> u32 {
    #[cfg(all(feature = "prove-timing-ffi", feature = "chain-xmr"))]
    {
        monero_bulletproofs::phase_ms(phase)
    }
    #[cfg(not(all(feature = "prove-timing-ffi", feature = "chain-xmr")))]
    {
        let _ = phase;
        0
    }
}
