//! Crash-forensics phase ladder, **injected as a parameter**.
//!
//! External audit 2026-11-19 A3a-18: the chain layer called `ffi::crash_phase::mark`
//! directly in 7 places — a reverse dependency (chain sits below the ABI layer), which also
//! dragged a global mutable hook slot into protocol code. The ladder now travels as an
//! ordinary argument, exactly like the RNG: `forms/chain` names only this leaf module, and
//! the FFI layer decides what (if anything) observes the phases.
//!
//! Device values are frozen: the forgebox blackbox records these numbers in flash, and the
//! C side switches on them (`shlosilo.h`).

/// No phase marked yet (mirrors the C `CRASH_PHASE_NONE`).
pub const PHASE_NONE: u8 = 0xFF;
/// 3 = immediately before the per-output key-image loop.
pub const PHASE_PAIR_LOOP: u8 = 3;
/// Fine ladder (2026-10-15): the device wedges somewhere in the pairing prologue; the host
/// runs it in 25 ms. These marks paint the death point.
pub const PHASE_DECRYPT_IN: u8 = 5;
pub const PHASE_SIG_VERIFY: u8 = 6;
pub const PHASE_SIG_OK: u8 = 10;
pub const PHASE_CN_DONE: u8 = 7;
pub const PHASE_OWNERSHIP: u8 = 8;
pub const PHASE_PARSED: u8 = 9;

/// Phase observer. `None` = nobody is watching (host tests, integrations without a
/// blackbox). A plain `fn` pointer, so it stays `Copy`, allocation-free and free of any
/// trait-object machinery.
pub type PhaseTrace = Option<fn(u8)>;

/// Report one phase to the observer, if any.
#[inline]
pub fn mark(trace: PhaseTrace, phase: u8) {
    if let Some(f) = trace {
        f(phase);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static SEEN: AtomicUsize = AtomicUsize::new(0);
    fn observe(p: u8) {
        SEEN.store(p as usize, Ordering::SeqCst);
    }

    #[test]
    fn mark_forwards_to_the_observer_and_tolerates_none() {
        SEEN.store(0, Ordering::SeqCst);
        mark(None, PHASE_SIG_VERIFY);
        assert_eq!(
            SEEN.load(Ordering::SeqCst),
            0,
            "None must not invent a report"
        );
        mark(Some(observe), PHASE_SIG_VERIFY);
        assert_eq!(SEEN.load(Ordering::SeqCst), PHASE_SIG_VERIFY as usize);
        mark(Some(observe), PHASE_PARSED);
        assert_eq!(SEEN.load(Ordering::SeqCst), PHASE_PARSED as usize);
    }

    /// The device values are frozen (the blackbox and the C switch arms both encode them).
    #[test]
    fn phase_values_are_frozen() {
        assert_eq!(PHASE_NONE, 0xFF);
        assert_eq!(PHASE_PAIR_LOOP, 3);
        assert_eq!(PHASE_DECRYPT_IN, 5);
        assert_eq!(PHASE_SIG_VERIFY, 6);
        assert_eq!(PHASE_CN_DONE, 7);
        assert_eq!(PHASE_OWNERSHIP, 8);
        assert_eq!(PHASE_PARSED, 9);
        assert_eq!(PHASE_SIG_OK, 10);
    }
}
