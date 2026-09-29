//! CN slow-hash phase timing hook (feature `cn-timing`).
//!
//! Same pattern as monero-bulletproofs `prove_timing_hook`: atomic per-phase
//! ms accumulators driven by a registered device clock fn ptr, so the C smoke
//! task can decompose one `cryptonight_hash_v0` call on device.
//!
//! Phases (u8):
//! - 1 = keccak1600 initial
//! - 2 = scratchpad fill (2MB AES pseudo rounds)
//! - 3 = main loop (ITER/2 dependency-chain iterations)
//! - 4 = final scratchpad AES pass + keccak permutation + extra hash
//! - 5 = total (whole cn_slow_hash call)

use core::sync::atomic::{AtomicU32, Ordering};

pub const CN_PHASES: usize = 6;

type ClockFn = extern "C" fn() -> u32;

static ACC: [AtomicU32; CN_PHASES] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

#[allow(static_mut_refs)]
static mut CLOCK_FN: Option<ClockFn> = None;

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
    if phase == 0 || phase as usize > CN_PHASES {
        return 0;
    }
    ACC[phase as usize - 1].load(Ordering::Relaxed)
}

/// RAII accumulator for one phase; `end()` fires explicitly so direct-return
/// paths are covered (the bp4 lesson: Drop alone missed return paths).
pub(crate) struct PhaseProbe {
    phase: u8,
    t0: u32,
    open: bool,
}

impl PhaseProbe {
    #[inline]
    pub(crate) fn start(phase: u8) -> Option<Self> {
        if !enabled() {
            return None;
        }
        #[allow(static_mut_refs)]
        let t0 = match unsafe { CLOCK_FN } {
            Some(f) => f(),
            None => return None,
        };
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
        if idx > 0 && idx <= CN_PHASES {
            ACC[idx - 1].fetch_add(dt, Ordering::Relaxed);
        }
    }
}

#[inline]
fn enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn test_clock() -> u32 {
        1000
    }

    /// Audit #15 P2-01: `end()` must not index out of bounds for an invalid
    /// phase id (pre-fix: `ACC[(phase - 1) as usize]` with phase 0 -> 255).
    #[test]
    fn probe_end_rejects_invalid_phase_ids() {
        register_clock(Some(test_clock));
        for bad in [0u8, CN_PHASES as u8 + 1, 128, 255] {
            let mut probe = PhaseProbe::start(bad).expect("clock registered");
            probe.end(); // must not panic
        }
        let mut probe = PhaseProbe::start(1).expect("clock registered");
        probe.end();
        reset_all();
    }
}
