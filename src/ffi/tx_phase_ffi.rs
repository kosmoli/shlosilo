//! Device-side tx-signing phase timing FFI (feature `tx-phase-timing-ffi`).
//!
//! C contract:
//! - `shlosilo_tx_phase_set_clock(u32 fptr)` — register ms clock
//! - `shlosilo_tx_phase_reset()` — zero accumulators
//! - `shlosilo_tx_phase_phase(u8) -> u32` — accumulated ms (1..7)

#[cfg(feature = "tx-phase-timing-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_tx_phase_set_clock(clock_fptr: u32) {
    // SAFETY: same fptr-as-u32 contract as shlosilo_bp_timing_set_clock.
    let f: fn() -> u32 = unsafe { core::mem::transmute(clock_fptr) };
    crate::tx_phase_hook::register_clock(f);
}

#[cfg(feature = "tx-phase-timing-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_tx_phase_reset() {
    crate::tx_phase_hook::reset_all();
}

#[cfg(feature = "tx-phase-timing-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_tx_phase_phase(phase: u8) -> u32 {
    crate::tx_phase_hook::phase_ms(phase)
}

#[cfg(not(feature = "tx-phase-timing-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_tx_phase_set_clock(_clock_fptr: u32) {}
#[cfg(not(feature = "tx-phase-timing-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_tx_phase_reset() {}
#[cfg(not(feature = "tx-phase-timing-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_tx_phase_phase(_phase: u8) -> u32 {
    0
}
