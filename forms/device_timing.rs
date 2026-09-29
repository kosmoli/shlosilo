//! Device-side stage timing (feature `device-timing`).
//!
//! When the feature is on, business/sign hot-path stages record elapsed
//! milliseconds and `shlosilo_timing_*` exposes the counters to the C smoke
//! task. When off, the entry points still exist but collapse to no-ops (see
//! the note on single definitions below).
//!
//! Timing source: a monotonically increasing millisecond counter supplied by
//! the C side (`shlosilo_timing_set_clock_fn`), so no platform-specific time
//! API is needed inside the Rust staticlib.

#![allow(dead_code)]
#![allow(unused_imports)]

/// Stage ids (u8): 1=ur_decode 2=pbkdf2_seed 3=bip32_derive 4=rlp_parse
/// 5=keccak_sighash 6=ecdsa_sign 7=y_parity 8=serialize.
///
/// Defined once at module level (not per feature branch): callers use these in
/// every configuration, and a single definition keeps cbindgen's C header free
/// of duplicates.
pub const STAGE_UR_DECODE: u8 = 1;
pub const STAGE_PBKDF2: u8 = 2;
pub const STAGE_BIP32: u8 = 3;
pub const STAGE_RLP: u8 = 4;
pub const STAGE_KECCAK: u8 = 5;
pub const STAGE_ECDSA: u8 = 6;
pub const STAGE_Y_PARITY: u8 = 7;
pub const STAGE_SERIALIZE: u8 = 8;
pub const STAGE_COUNT: usize = 8;

/// The C-side millisecond clock (T-04 contract): a typed nullable function
/// pointer, never an integer address. `None` means unregistered.
pub type ClockFn = extern "C" fn() -> u32;

#[cfg(feature = "device-timing")]
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

#[cfg(feature = "device-timing")]
mod imp {
    use super::*;

    #[allow(static_mut_refs)]
    pub static mut CLOCK_FN: Option<ClockFn> = None;
    pub static ENABLED: AtomicBool = AtomicBool::new(false);
    pub static LAST_MS: AtomicU32 = AtomicU32::new(0);

    static STAGE_MS: [AtomicU32; STAGE_COUNT] = [
        AtomicU32::new(0),
        AtomicU32::new(0),
        AtomicU32::new(0),
        AtomicU32::new(0),
        AtomicU32::new(0),
        AtomicU32::new(0),
        AtomicU32::new(0),
        AtomicU32::new(0),
    ];

    /// Register the C-side millisecond clock (typed nullable fn pointer).
    /// Idempotent; last registration wins, `None` unregisters.
    pub fn set_clock(fptr: Option<ClockFn>) {
        #[allow(static_mut_refs)]
        unsafe {
            CLOCK_FN = fptr;
        }
    }

    pub fn now_ms() -> u32 {
        #[allow(static_mut_refs)]
        match unsafe { CLOCK_FN } {
            Some(f) => f(),
            None => 0,
        }
    }

    pub struct Mark {
        start: u32,
        stage: u8,
    }

    impl Mark {
        pub fn start(stage: u8) -> Self {
            Mark {
                start: now_ms(),
                stage,
            }
        }

        pub fn end(self) {
            let dt = now_ms().wrapping_sub(self.start);
            // Guard before the index arithmetic: `stage == 0` would underflow
            // (wraps in release, panics in debug). Stage ids are 1-based.
            // See audit #15 P2-01.
            let idx = self.stage as usize;
            if idx > 0 && idx <= STAGE_COUNT {
                STAGE_MS[idx - 1].store(dt, Ordering::Relaxed);
            }
        }
    }

    pub fn total_ms() -> u32 {
        LAST_MS.load(Ordering::Relaxed)
    }

    pub fn set_total(ms: u32) {
        LAST_MS.store(ms, Ordering::Relaxed);
    }

    pub fn read_stage(stage: u8) -> u32 {
        // Same guard as `Mark::end`: stage 0 must not underflow (audit #15 P2-01).
        let idx = stage as usize;
        if idx > 0 && idx <= STAGE_COUNT {
            STAGE_MS[idx - 1].load(Ordering::Relaxed)
        } else {
            0
        }
    }

    pub fn reset_all() {
        for s in STAGE_MS.iter() {
            s.store(0, Ordering::Relaxed);
        }
        LAST_MS.store(0, Ordering::Relaxed);
    }
}

#[cfg(not(feature = "device-timing"))]
mod imp {
    pub struct Mark;
    impl Mark {
        pub fn start(_stage: u8) -> Self {
            Mark
        }
        pub fn end(self) {}
    }
    pub fn set_clock(_fptr: Option<super::ClockFn>) {}
    pub fn now_ms() -> u32 {
        0
    }
    pub fn read_stage(_stage: u8) -> u32 {
        0
    }
    pub fn total_ms() -> u32 {
        0
    }
    pub fn set_total(_ms: u32) {}
    pub fn reset_all() {}
}

pub use imp::*;

// C-ABI entry points. Each has a SINGLE definition whose body is cfg-split:
// the real implementation under the feature, a no-op otherwise. The C host
// links against both variants, and one definition keeps cbindgen's header free
// of duplicate declarations (audit #15 follow-up).

/// C-ABI: register the millisecond clock callback (no-op when the feature is off).
///
/// T-04 contract: the callback crosses the boundary as a typed nullable
/// function pointer — a mismatched signature is a compile error at the C call
/// site, and `NULL` means unregistered (last registration wins).
///
/// # Safety
/// `fptr`, when non-NULL, must be a valid `extern "C" fn() -> u32` on the target.
#[no_mangle]
pub extern "C" fn shlosilo_timing_set_clock_fn(fptr: Option<extern "C" fn() -> u32>) {
    #[cfg(feature = "device-timing")]
    {
        imp::set_clock(fptr);
    }
    #[cfg(not(feature = "device-timing"))]
    {
        let _ = fptr;
    }
}

/// C-ABI: read one stage's measured milliseconds (0 when the feature is off).
#[no_mangle]
pub extern "C" fn shlosilo_timing_get_stage(stage: u8) -> u32 {
    #[cfg(feature = "device-timing")]
    {
        imp::read_stage(stage)
    }
    #[cfg(not(feature = "device-timing"))]
    {
        let _ = stage;
        0
    }
}

/// C-ABI: total measured sign ms (0 when the feature is off).
#[no_mangle]
pub extern "C" fn shlosilo_timing_get_total() -> u32 {
    #[cfg(feature = "device-timing")]
    {
        imp::total_ms()
    }
    #[cfg(not(feature = "device-timing"))]
    {
        0
    }
}

/// C-ABI: reset all counters (no-op when the feature is off).
#[no_mangle]
pub extern "C" fn shlosilo_timing_reset() {
    #[cfg(feature = "device-timing")]
    {
        imp::reset_all();
    }
}

#[cfg(all(test, feature = "device-timing"))]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    /// Deterministic test clock: returns whatever the test last stored.
    static TICK: AtomicU32 = AtomicU32::new(0);

    extern "C" fn test_clock() -> u32 {
        TICK.load(Ordering::Relaxed)
    }

    /// T-04 pins (single test on purpose: the clock is a process-wide
    /// `static mut`, parallel tests would race on it).
    ///
    /// inv2: a real 64-bit function address survives the C-ABI round trip at
    /// full pointer width and is actually invoked (the u32 contract truncated
    /// it on every 64-bit host).
    /// inv3: NULL/None means unregistered — reads return 0, nothing else fires.
    #[test]
    fn inv2_inv3_clock_roundtrip_and_null_sentinel() {
        // inv2: register the real fn pointer through the C-ABI entry.
        shlosilo_timing_set_clock_fn(Some(test_clock));
        shlosilo_timing_reset();
        TICK.store(1_000, Ordering::Relaxed);
        let m = Mark::start(STAGE_UR_DECODE);
        TICK.store(1_050, Ordering::Relaxed);
        m.end();
        assert_eq!(
            shlosilo_timing_get_stage(STAGE_UR_DECODE),
            50,
            "inv2: the registered clock must be invoked through the full-width pointer"
        );

        // inv3: NULL unregisters (last registration wins) — reads are all zero.
        // TICK moves across the Mark so a stale registration (dt = 50) cannot
        // masquerade as the unregistered reading (dt = 0).
        shlosilo_timing_set_clock_fn(None);
        shlosilo_timing_reset();
        TICK.store(9_000, Ordering::Relaxed);
        let m = Mark::start(STAGE_UR_DECODE);
        TICK.store(9_500, Ordering::Relaxed);
        m.end();
        assert_eq!(
            shlosilo_timing_get_stage(STAGE_UR_DECODE),
            0,
            "inv3: unregistered clock must read as 0"
        );
        assert_eq!(
            shlosilo_timing_get_total(),
            0,
            "inv3: unregistered clock must read as 0"
        );
    }
}
