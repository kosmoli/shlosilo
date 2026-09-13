//! Device-side CN slow-hash phase timing FFI (feature `cn-timing-ffi`).
//!
//! Mirrors `prove_timing_ffi`: forwards the device-timing clock to the vendored
//! cryptonight `cn-timing` hook, exposes per-phase ms. Phases:
//! 1 = keccak init, 2 = scratchpad fill, 3 = main loop, 4 = final pass,
//! 5 = total (one `cryptonight_hash_v0` call).
//!
//! Each entry point has a SINGLE definition whose body is cfg-split: the real
//! implementation under the feature, a no-op otherwise, so the C host always
//! links. One definition also means cbindgen emits exactly one declaration per
//! function (dual `#[cfg]`-branches produced duplicate header declarations).

/// C-ABI: register the millisecond clock for CN phase timing.
///
/// # Safety
/// `clock_fptr` must be a valid `extern "C" fn() -> u32` address (ARM thumb ok).
#[cfg_attr(not(feature = "cn-timing-ffi"), allow(unused_variables))]
#[no_mangle]
pub extern "C" fn shlosilo_cn_timing_set_clock(clock_fptr: u32) {
    #[cfg(feature = "cn-timing-ffi")]
    {
        // SAFETY: same fptr-as-u32 contract as shlosilo_bp_timing_set_clock.
        // `as usize` first: a u32->fn transmute fails to compile on 64-bit hosts
        // (E0512, pointer width differs). Device (thumbv7em) is 32-bit, host is
        // 64-bit; the widening is lossless and the C side only ever passes a valid
        // thumb function address on the device target.
        let f: fn() -> u32 = unsafe { core::mem::transmute(clock_fptr as usize) };
        cuprate_cryptonight::register_clock(f);
    }
}

/// C-ABI: reset all CN phase counters.
#[no_mangle]
pub extern "C" fn shlosilo_cn_timing_reset() {
    #[cfg(feature = "cn-timing-ffi")]
    cuprate_cryptonight::reset_all();
}

/// C-ABI: read one phase's accumulated ms (0 for unknown phase).
#[no_mangle]
pub extern "C" fn shlosilo_cn_timing_phase(phase: u8) -> u32 {
    #[cfg(feature = "cn-timing-ffi")]
    {
        cuprate_cryptonight::phase_ms(phase)
    }
    #[cfg(not(feature = "cn-timing-ffi"))]
    {
        let _ = phase;
        0
    }
}
