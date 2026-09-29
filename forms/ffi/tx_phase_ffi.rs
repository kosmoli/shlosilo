//! Device-side tx-signing phase timing FFI (feature `tx-phase-timing-ffi`).
//!
//! C contract (T-04: typed nullable fn pointers, never integer addresses):
//! - `shlosilo_tx_phase_set_clock(uint32_t (*fptr)(void))` — register ms clock
//!   (NULL unregisters; last registration wins)
//! - `shlosilo_tx_phase_reset()` — zero accumulators
//! - `shlosilo_tx_phase_phase(u8) -> u32` — accumulated ms
//!
//! Each entry point has a SINGLE definition whose body is cfg-split: the real
//! implementation under the feature, a no-op otherwise, so the C host always
//! links. One definition also means cbindgen emits exactly one declaration per
//! function (dual `#[cfg]`-branches produced duplicate header declarations).

/// C-ABI: register the millisecond clock for tx-phase timing.
///
/// # Safety
/// `clock_fptr`, when non-NULL, must be a valid `extern "C" fn() -> u32` on the target.
#[cfg_attr(not(feature = "tx-phase-timing-ffi"), allow(unused_variables))]
#[no_mangle]
pub extern "C" fn shlosilo_tx_phase_set_clock(clock_fptr: Option<extern "C" fn() -> u32>) {
    #[cfg(feature = "tx-phase-timing-ffi")]
    {
        crate::tx_phase_hook::register_clock(clock_fptr);
    }
}

/// C-ABI: reset all tx-phase counters.
#[no_mangle]
pub extern "C" fn shlosilo_tx_phase_reset() {
    #[cfg(feature = "tx-phase-timing-ffi")]
    {
        crate::tx_phase_hook::reset_all();
    }
}

/// C-ABI: read one phase's accumulated ms (0 for unknown phase).
#[no_mangle]
pub extern "C" fn shlosilo_tx_phase_phase(phase: u8) -> u32 {
    #[cfg(feature = "tx-phase-timing-ffi")]
    {
        crate::tx_phase_hook::phase_ms(phase)
    }
    #[cfg(not(feature = "tx-phase-timing-ffi"))]
    {
        let _ = phase;
        0
    }
}
