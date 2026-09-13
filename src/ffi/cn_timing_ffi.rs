//! Device-side CN slow-hash phase timing FFI (feature `cn-timing-ffi`).
//!
//! Mirrors `prove_timing_ffi`: forwards the device-timing clock to the vendored
//! cryptonight `cn-timing` hook, exposes per-phase ms. Phases:
//! 1 = keccak init, 2 = scratchpad fill, 3 = main loop, 4 = final pass,
//! 5 = total (one `cryptonight_hash_v0` call).

#[cfg(feature = "cn-timing-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_cn_timing_set_clock(clock_fptr: u32) {
    // SAFETY: same fptr-as-u32 contract as shlosilo_bp_timing_set_clock.
    // `as usize` first: a u32->fn transmute fails to compile on 64-bit hosts
    // (E0512, pointer width differs). Device (thumbv7em) is 32-bit, host is
    // 64-bit; the widening is lossless and the C side only ever passes a valid
    // thumb function address on the device target.
    let f: fn() -> u32 = unsafe { core::mem::transmute(clock_fptr as usize) };
    cuprate_cryptonight::register_clock(f);
}

#[cfg(feature = "cn-timing-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_cn_timing_reset() {
    cuprate_cryptonight::reset_all();
}

#[cfg(feature = "cn-timing-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_cn_timing_phase(phase: u8) -> u32 {
    cuprate_cryptonight::phase_ms(phase)
}

// Production no-op stubs (feature off) so the C side always links.
#[cfg(not(feature = "cn-timing-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_cn_timing_set_clock(_clock_fptr: u32) {}
#[cfg(not(feature = "cn-timing-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_cn_timing_reset() {}
#[cfg(not(feature = "cn-timing-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_cn_timing_phase(_phase: u8) -> u32 {
    0
}
