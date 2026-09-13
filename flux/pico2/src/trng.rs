//! Blocking RP2350 TRNG reader (checked path).
//!
//! Why not `embassy_rp::trng::blocking_fill_bytes`: its blocking wait path
//! panics whenever a generation run ends without a result for any reason
//! other than autocorrelation failure ("RNG not busy, but ehr is not valid").
//! Datasheet 12.12.3: a run stops on success OR on a failed internal entropy
//! check, and 12.12.2 says failed checks occur even at the recommended
//! settings ("do not eliminate ... entropy check failures"). With panic =
//! abort that path would eventually kill this firmware. This module is the
//! same policy as embassy's *async* path (reinitialize and restart on
//! failure) in blocking form, with counters and a `Result`.
//!
//! Design (datasheet 12.12):
//! - all three hardware entropy checks stay enabled (reset default); ROSC
//!   inverter chain 1 and sample count 25 (12.12.2 recommends 0-1 / 20-25);
//! - one accepted 192-bit EHR block (24 bytes) per `read_block` call;
//! - CRNGT / Von-Neumann failures clear the status bit and retry;
//!   autocorrelation failure is sticky ("Only RNG reset clears this bit") and
//!   takes a full software reset + reconfiguration before the retry;
//! - every wait is bounded and the retry budget is bounded: the reader can
//!   return `Err`, it can never hang or abort;
//! - each attempt explicitly restarts the block (RND_SRC_EN 0 -> 1) instead
//!   of relying on undocumented auto-restart behavior after a failed run.

use core::hint::spin_loop;

use embassy_rp::pac;
use embassy_rp::pac::trng::Trng as TrngRegs;

/// Bytes per accepted 192-bit entropy block (datasheet 12.12.1).
pub const BLOCK_LEN: usize = 24;

/// Datasheet 12.12.2 recommended operating point.
pub const DEFAULT_SAMPLE_COUNT: u32 = 25;
/// InverterChainLength::One (datasheet recommends 0 or 1).
const INVERTER_CHAIN_LEN: u8 = 1;

/// Poll bounds in loop iterations (~10-20 cycles each at 150 MHz). A wedged
/// block returns an Err instead of spinning forever; the fall bound is
/// generous because 12.12.4 notes generation can occasionally take >100x the
/// average.
const BUSY_SIGNAL_SPINS: u32 = 30_000_000;
const BUSY_FALL_SPINS: u32 = 60_000_000;
/// Status settle after BUSY falls (only guards a stale read).
const SETTLE_SPINS: u32 = 2_000;
/// Failed runs tolerated per block before giving up.
const MAX_FAILED_ATTEMPTS: u32 = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrngStats {
    /// Accepted 192-bit blocks.
    pub blocks: u32,
    /// CRNGT failures (two consecutive equal 16-bit blocks; result discarded).
    pub crngt_err: u32,
    /// Von-Neumann failures (32 consecutive equal bits; result discarded).
    pub vn_err: u32,
    /// Autocorrelation failures (sticky run; full reset applied).
    pub autocorr_err: u32,
    /// Runs that ended with no status at all (not a documented terminal state).
    pub odd_states: u32,
    /// Runs that never concluded within the poll bound.
    pub busy_timeouts: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrngError {
    /// A run never concluded within the poll bound.
    BusyTimeout,
    /// One block exceeded the failed-run retry budget.
    RetriesExhausted,
}

fn regs() -> TrngRegs {
    pac::TRNG
}

/// One-time bring-up: clean block reset, then the operating configuration.
/// Call once at boot, before any TRNG use.
pub fn init() {
    // The block's RESETS state at boot is not contractually defined for this
    // peripheral; give it a clean reset edge and wait for completion.
    pac::RESETS.reset().modify(|v| v.set_trng(true));
    let _ = pac::RESETS.reset().read();
    pac::RESETS.reset().modify(|v| v.set_trng(false));
    while !pac::RESETS.reset_done().read().trng() {}

    let regs = regs();
    write_config(&regs);
    regs.rnd_source_enable().write(|w| w.set_rnd_src_en(false));
}

fn write_config(regs: &TrngRegs) {
    // All three entropy checks enabled (explicit `false` = not bypassed).
    regs.trng_debug_control().write(|w| {
        w.set_auto_correlate_bypass(false);
        w.set_trng_crngt_bypass(false);
        w.set_vnc_bypass(false);
    });
    regs.trng_config()
        .write(|w| w.set_rnd_src_sel(INVERTER_CHAIN_LEN));
    regs.sample_cnt1().write(|w| *w = DEFAULT_SAMPLE_COUNT);
}

/// Sample-count override (bench stress testing: a low count makes entropy
/// checks fail more often, exercising the retry paths). The caller must have
/// stopped the source; restore with `set_sample_count(DEFAULT_SAMPLE_COUNT)`.
pub fn set_sample_count(n: u32) {
    regs().sample_cnt1().write(|w| *w = n);
}

/// Stop the entropy source (block idle, low power) and clear the bit counter.
pub fn stop() {
    let regs = regs();
    regs.rnd_source_enable().write(|w| w.set_rnd_src_en(false));
    regs.rst_bits_counter()
        .write(|w| w.set_rst_bits_counter(true));
}

/// Read one accepted 192-bit block; failed runs are retried (bounded).
pub fn read_block(stats: &mut TrngStats) -> Result<[u8; BLOCK_LEN], TrngError> {
    let regs = regs();
    let mut failures = 0u32;

    loop {
        if failures >= MAX_FAILED_ATTEMPTS {
            return Err(TrngError::RetriesExhausted);
        }

        restart(&regs);

        // Phase 1: wait for the run to become visible — BUSY rising, or
        // already-terminated status (a fast-failing run can conclude before
        // the first poll).
        let mut spins = 0u32;
        let mut running = false;
        loop {
            let isr = regs.rng_isr().read();
            if isr.ehr_valid() || isr.autocorr_err() || isr.crngt_err() || isr.vn_err() {
                break;
            }
            if regs.trng_busy().read().trng_busy() {
                running = true;
                break;
            }
            spins += 1;
            if spins > BUSY_SIGNAL_SPINS {
                stats.busy_timeouts += 1;
                return Err(TrngError::BusyTimeout);
            }
        }

        // Phase 2: a running generation must conclude.
        if running {
            spins = 0;
            while regs.trng_busy().read().trng_busy() {
                spins += 1;
                if spins > BUSY_FALL_SPINS {
                    stats.busy_timeouts += 1;
                    return Err(TrngError::BusyTimeout);
                }
            }
            for _ in 0..SETTLE_SPINS {
                spin_loop();
            }
        }

        // Phase 3: dispatch on the run's outcome.
        let isr = regs.rng_isr().read();
        if isr.ehr_valid() {
            let mut block = [0u8; BLOCK_LEN];
            read_ehr(&regs, &mut block);
            // Clear the status bit so the next attempt cannot mistake a
            // stale latch for a fresh result (the data registers are cleared
            // by reading EHR_DATA[5]; the flag needs the explicit clear).
            regs.rng_icr().write(|w| w.set_ehr_valid(true));
            stats.blocks += 1;
            return Ok(block);
        }
        if isr.autocorr_err() {
            stats.autocorr_err += 1;
            failures += 1;
            full_reset(&regs);
            continue;
        }
        if isr.crngt_err() || isr.vn_err() {
            if isr.crngt_err() {
                stats.crngt_err += 1;
            }
            if isr.vn_err() {
                stats.vn_err += 1;
            }
            failures += 1;
            regs.rng_icr().write(|w| {
                w.set_crngt_err(true);
                w.set_vn_err(true);
            });
            continue;
        }
        // No result, no error: not a documented terminal state; count it and
        // retry (the counter makes it visible if this ever happens).
        stats.odd_states += 1;
        failures += 1;
    }
}

/// Explicit restart: a 0 -> 1 edge on RND_SRC_EN with the bit counter
/// cleared, so each attempt starts from a defined state.
fn restart(regs: &TrngRegs) {
    regs.rnd_source_enable().write(|w| w.set_rnd_src_en(false));
    let _ = regs.rnd_source_enable().read(); // sync + settle
    regs.rst_bits_counter()
        .write(|w| w.set_rst_bits_counter(true));
    let _ = regs.rnd_source_enable().read();
    regs.rnd_source_enable().write(|w| w.set_rnd_src_en(true));
}

/// Full recovery for a sticky failure: internal soft reset (the only way to
/// clear AUTOCORR_ERR), reconfiguration, and a clear of the clearable flags.
fn full_reset(regs: &TrngRegs) {
    regs.trng_sw_reset().write(|w| w.set_trng_sw_reset(true));
    // A fixed delay is required after the soft reset; two reads of the
    // register are the documented-sufficient delay (driver comment).
    let _ = regs.trng_sw_reset().read();
    let _ = regs.trng_sw_reset().read();
    write_config(regs);
    regs.rng_icr().write(|w| {
        w.set_crngt_err(true);
        w.set_vn_err(true);
    });
}

/// Read the six EHR registers into `block`. Order matters: reading
/// EHR_DATA[5] clears all result registers and restarts sampling.
fn read_ehr(regs: &TrngRegs, block: &mut [u8; BLOCK_LEN]) {
    let ehr = [
        regs.ehr_data0(),
        regs.ehr_data1(),
        regs.ehr_data2(),
        regs.ehr_data3(),
        regs.ehr_data4(),
        regs.ehr_data5(),
    ];
    for (i, reg) in ehr.iter().enumerate() {
        block[i * 4..i * 4 + 4].copy_from_slice(&reg.read().to_ne_bytes());
    }
}
