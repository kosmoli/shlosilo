//! Device-side tx-signing phase timing FFI (feature `tx-phase-timing-ffi`).
//!
//! C contract:
//! - `shlosilo_tx_phase_set_clock(u32 fptr)` — register ms clock
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
/// `clock_fptr` must be a valid `extern "C" fn() -> u32` address (ARM thumb ok).
#[cfg_attr(not(feature = "tx-phase-timing-ffi"), allow(unused_variables))]
#[no_mangle]
pub extern "C" fn shlosilo_tx_phase_set_clock(clock_fptr: u32) {
    #[cfg(feature = "tx-phase-timing-ffi")]
    {
        // SAFETY: same fptr-as-u32 contract as shlosilo_bp_timing_set_clock.
        // `as usize` first: a u32->fn transmute fails to compile on 64-bit hosts
        // (E0512, pointer width differs). Device (thumbv7em) is 32-bit, host is
        // 64-bit; the widening is lossless and the C side only ever passes a valid
        // thumb function address on the device target.
        let f: fn() -> u32 = unsafe { core::mem::transmute(clock_fptr as usize) };
        crate::tx_phase_hook::register_clock(f);
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
