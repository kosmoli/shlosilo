//! Pairing-phase marker for crash forensics (device crash blackbox).
//!
//! The forgebox C host seals one record per pairing phase into its QSPI NOR
//! "blackbox" sector so a crash record (or a silently abandoned phase record)
//! pins where the pairing leg died. The C side drives phases 0/1/2/4 around
//! `pairing_run`; the point *inside* the FFI (3 = before the per-output key
//! image loop) is only visible here, so the core forwards it through a
//! registered host callback (same pattern as `generator_cache_ffi`).
//!
//! Host-agnostic: with no callback registered this is a plain atomic store
//! (the host tests exercise exactly that path).
//!
//! C side contract (`shlosilo.h`):
//! - `void hook(uint8_t phase)` — invoked on every `mark`;
//! - `void shlosilo_crash_phase_set_hook(void (*hook)(uint8_t))` — NULL
//!   unregisters;
//! - `uint8_t shlosilo_crash_phase_get(void)` — last marked phase (0xFF when
//!   none).

use core::sync::atomic::{AtomicU8, Ordering};

/// No phase marked yet (mirrors the C `CRASH_PHASE_NONE`).
pub const CRASH_PHASE_NONE: u8 = 0xFF;
/// 3 = immediately before the per-output key-image loop.
pub const CRASH_PHASE_PAIR_LOOP: u8 = 3;
/// Fine ladder (2026-10-15): the device wedges somewhere in the pairing
/// prologue; host runs it in 25 ms. These marks paint the death point.
pub const CRASH_PHASE_DECRYPT_IN: u8 = 5;
pub const CRASH_PHASE_SIG_VERIFY: u8 = 6;
pub const CRASH_PHASE_SIG_OK: u8 = 10;
pub const CRASH_PHASE_CN_DONE: u8 = 7;
pub const CRASH_PHASE_OWNERSHIP: u8 = 8;
pub const CRASH_PHASE_PARSED: u8 = 9;

/// C-side phase callback: `void hook(uint8_t phase)`.
pub type CrashPhaseHookC = extern "C" fn(u8);

static PHASE: AtomicU8 = AtomicU8::new(CRASH_PHASE_NONE);

#[allow(static_mut_refs)]
static mut HOOK: Option<CrashPhaseHookC> = None;

/// Mark a pairing phase. Updates the local atomic first (so `mark` stays
/// observable even if the host hook re-enters), then forwards to the host.
pub fn mark(phase: u8) {
    PHASE.store(phase, Ordering::SeqCst);
    #[allow(static_mut_refs)]
    let hook = unsafe { HOOK };
    if let Some(f) = hook {
        f(phase);
    }
}

/// Register the host phase callback (typed nullable fn pointer; `None`
/// unregisters). Last registration wins. The fn type is spelled out inline so
/// cbindgen maps it to a nullable C function pointer (same as
/// `shlosilo_gen_cache_set_hooks`; a type alias would surface as an opaque
/// `struct Option_...`).
#[no_mangle]
pub extern "C" fn shlosilo_crash_phase_set_hook(hook: Option<extern "C" fn(u8)>) {
    #[allow(static_mut_refs)]
    unsafe {
        HOOK = hook;
    }
}

/// Last marked phase (0xFF = none). C-side marks that bypass `mark` live in
/// the host blackbox only.
#[no_mangle]
pub extern "C" fn shlosilo_crash_phase_get() -> u8 {
    PHASE.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared sink for the single test below (the hook slot is `static mut`).
    static SEEN: AtomicU8 = AtomicU8::new(0xAA);

    extern "C" fn record(phase: u8) {
        SEEN.store(phase, Ordering::SeqCst);
    }

    /// Single test on purpose (mirrors T-04): the hook slot is `static mut`,
    /// so parallel tests would race the registration.
    #[test]
    fn phase_hook_marks_forwards_and_unregisters() {
        // fresh state
        shlosilo_crash_phase_set_hook(None);
        mark(CRASH_PHASE_PAIR_LOOP);
        assert_eq!(shlosilo_crash_phase_get(), CRASH_PHASE_PAIR_LOOP);
        assert_eq!(SEEN.load(Ordering::SeqCst), 0xAA, "no hook: not forwarded");

        // registered hook forwards and the getter tracks the atomic
        shlosilo_crash_phase_set_hook(Some(record));
        mark(CRASH_PHASE_PAIR_LOOP);
        assert_eq!(shlosilo_crash_phase_get(), CRASH_PHASE_PAIR_LOOP);
        assert_eq!(SEEN.load(Ordering::SeqCst), CRASH_PHASE_PAIR_LOOP);

        // unregister: mark still updates the getter, nothing forwarded
        shlosilo_crash_phase_set_hook(None);
        mark(0);
        assert_eq!(shlosilo_crash_phase_get(), 0);
        assert_eq!(SEEN.load(Ordering::SeqCst), CRASH_PHASE_PAIR_LOOP);
    }
}
