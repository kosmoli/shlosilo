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

type ClockFn = fn() -> u32;

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

pub fn register_clock(f: ClockFn) {
    #[allow(static_mut_refs)]
    unsafe {
        CLOCK_FN = Some(f);
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
        ACC[(self.phase - 1) as usize].fetch_add(dt, Ordering::Relaxed);
    }
}
