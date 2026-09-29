//! Device-side tx-signing phase timing (feature `tx-phase-timing`).
//!
//! Same atomic probe pattern as the vendor hooks, but lives in L1 (our code):
//! phases decompose the non-BP/non-CN remainder of an xmr sign.
//! Phases: 1 = decrypt+deserialize, 2 = per-output derivations,
//! 3 = prefix serialize + BP+ call wrapper, 4 = CLSAG loop,
//! 5 = wire serialization, 6 = key images, 7 = output encryption.
//! Sub-probes inside x3 (rct_base drill-down, bb3aa58 follow-up):
//! 8 = commitments build, 9 = prove_bulletproofs_plus total
//! (incl. statement/witness; bp4 is its inner prove-only total),
//! 10 = bp sig encode + pre-MLSAG keccaks.
//! 11 = sum masks + rct_base serialize + rct_base keccak.

use core::sync::atomic::{AtomicU32, Ordering};

pub const TX_PHASES: usize = 11;

type ClockFn = extern "C" fn() -> u32;

#[allow(static_mut_refs)]
static mut CLOCK_FN: Option<ClockFn> = None;
static ACC: [AtomicU32; TX_PHASES] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

pub fn register_clock(f: Option<ClockFn>) {
    #[allow(static_mut_refs)]
    unsafe {
        CLOCK_FN = f;
    }
}

pub fn reset_all() {
    for a in &ACC {
        a.store(0, Ordering::Relaxed);
    }
}

pub fn phase_ms(phase: u8) -> u32 {
    if phase == 0 || phase as usize > TX_PHASES {
        return 0;
    }
    ACC[phase as usize - 1].load(Ordering::Relaxed)
}

/// RAII probe; `end()` fires explicitly (bp4 lesson: Drop misses early-return
/// paths). Feature-off builds use the noop stub in `tx_phase_ffi` instead.
pub(crate) struct PhaseProbe {
    phase: u8,
    t0: u32,
    open: bool,
}

impl PhaseProbe {
    #[inline]
    pub(crate) fn start(phase: u8) -> Option<Self> {
        #[allow(static_mut_refs)]
        let t0 = unsafe { CLOCK_FN }?();
        Some(Self {
            phase,
            t0,
            open: true,
        })
    }

    #[inline]
    pub(crate) fn end(&mut self) {
        if !self.open {
            return;
        }
        self.open = false;
        #[allow(static_mut_refs)]
        let now = match unsafe { CLOCK_FN } {
            Some(f) => f(),
            None => return,
        };
        let dt = now.wrapping_sub(self.t0);
        // Guard before indexing: `phase == 0` would underflow the 1-based id
        // (wraps in release, panics in debug). See audit #15 P2-01.
        let idx = self.phase as usize;
        if idx > 0 && idx <= TX_PHASES {
            ACC[idx - 1].fetch_add(dt, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic test clock for this module's single test.
    static TICK: AtomicU32 = AtomicU32::new(0);

    extern "C" fn test_clock() -> u32 {
        TICK.load(Ordering::Relaxed)
    }

    /// T-04 inv2/inv3 + audit #15 P2-01. Single test function on purpose:
    /// these touch the `static mut` clock, parallel tests would race on it.
    ///
    /// inv2: a real 64-bit function address survives the C-ABI round trip
    /// (`shlosilo_tx_phase_set_clock`) and the probe actually times through it.
    /// inv3: `None` means unregistered — `PhaseProbe::start` refuses, reads are 0.
    /// P2-01: `end()` must not index out of bounds for an invalid phase id
    /// (pre-fix: `ACC[(phase - 1) as usize]` with phase 0 -> 255, panicking in
    /// every build, not just overflow-checked ones).
    #[test]
    fn inv23_tx_clock_contract_and_phase_guards() {
        // inv2: register through the C-ABI entry, drive a full probe cycle.
        crate::ffi::tx_phase_ffi::shlosilo_tx_phase_set_clock(Some(test_clock));
        reset_all();
        TICK.store(2_000, Ordering::Relaxed);
        let mut probe = PhaseProbe::start(1).expect("clock registered");
        TICK.store(2_012, Ordering::Relaxed);
        probe.end();
        assert_eq!(
            phase_ms(1),
            12,
            "inv2: probe must time through the registered pointer"
        );

        // P2-01: invalid ids must not underflow the 1-based index.
        for bad in [0u8, TX_PHASES as u8 + 1, 128, 255] {
            let mut probe = PhaseProbe::start(bad).expect("clock registered");
            probe.end(); // must not panic
        }

        // inv3: None unregisters (last registration wins).
        crate::ffi::tx_phase_ffi::shlosilo_tx_phase_set_clock(None);
        reset_all();
        assert!(
            PhaseProbe::start(1).is_none(),
            "inv3: unregistered clock must refuse probes"
        );
        assert_eq!(phase_ms(1), 0, "inv3: unregistered clock must read as 0");
    }
}
