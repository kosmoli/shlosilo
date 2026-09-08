//! shlosilo vendor patch (2026-09-08): prove-phase timing hooks (feature `prove-timing`).
//!
//! Phase probes inside the BP+ aggregate range proof, to decompose on-device
//! prove time (initial commit multiexp / A_hat / WIP rounds / point encode).
//! Mirrors the shlosilo `device-timing` pattern: the C side registers a
//! millisecond clock (function pointer as u32, ARM thumb addresses fit);
//! zero cost when the feature is off.
//!
//! Phase ids (u8):
//!   1 = bp_initial_multiexp  (A commit over 2n+1 terms)
//!   2 = bp_a_hat             (compute_A_hat incl. its multiexp)
//!   3 = bp_wip_rounds        (weighted inner product argument, all rounds)
//!   4 = bp_total             (whole prove call, incl. generators reduce)

use core::sync::atomic::{AtomicU32, Ordering};

pub(crate) const PHASE_INITIAL_MULTISEXP: u8 = 1;
pub(crate) const PHASE_A_HAT: u8 = 2;
pub(crate) const PHASE_WIP_ROUNDS: u8 = 3;
pub(crate) const PHASE_TOTAL: u8 = 4;
pub(crate) const PHASE_WIP_L_R: u8 = 5;
pub(crate) const PHASE_WIP_FOLD: u8 = 6;

static CLOCK_FN: AtomicU32 = AtomicU32::new(0);

/// Register the C-side millisecond clock (fptr as u32). Idempotent; last wins.
pub fn register_prove_timing_clock(fptr: u32) {
    CLOCK_FN.store(fptr, Ordering::Relaxed);
}

fn now_ms() -> u32 {
    let f = CLOCK_FN.load(Ordering::Relaxed);
    if f == 0 {
        return 0;
    }
    let fptr: extern "C" fn() -> u32 = unsafe { core::mem::transmute(f as usize) };
    fptr()
}

/// Marker for a phase start (stores the timestamp into the phase slot).
pub(crate) struct PhaseProbe(u8, u32);

impl PhaseProbe {
    pub(crate) fn start(phase: u8) -> Self {
        PhaseProbe(phase, now_ms())
    }

    pub(crate) fn end(self) {
        let elapsed = now_ms().wrapping_sub(self.1);
        record(self.0, elapsed);
    }
}

/// Accumulate elapsed ms per phase (wrapping add; smoke task reads and logs).
static PHASE_MS: [AtomicU32; 7] = [
    AtomicU32::new(0), // unused 0-index
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

pub(crate) fn record(phase: u8, ms: u32) {
    if (phase as usize) < PHASE_MS.len() {
        PHASE_MS[phase as usize].fetch_add(ms, Ordering::Relaxed);
    }
}

/// FFI: read one phase's accumulated ms (0 for unknown phase).
pub fn phase_ms(phase: u8) -> u32 {
    if (phase as usize) < PHASE_MS.len() {
        PHASE_MS[phase as usize].load(Ordering::Relaxed)
    } else {
        0
    }
}

/// FFI: reset all counters (call before a timed prove run).
pub fn reset() {
    for slot in PHASE_MS.iter() {
        slot.store(0, Ordering::Relaxed);
    }
}
