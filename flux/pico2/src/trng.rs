//! Blocking RP2350 TRNG reader (checked path).
//!
//! Why not `embassy_rp::trng::blocking_fill_bytes`: its blocking wait path
//! panics whenever a run ends without a result for any reason other than
//! autocorrelation failure ("RNG not busy, but ehr is not valid"). Datasheet
//! 12.12.3: a run stops on success OR on a failed internal entropy check, and
//! 12.12.2 says failed checks occur even at recommended settings. With
//! panic = abort that path would eventually kill this firmware. This module
//! is the same policy as embassy's *async* path (reinitialize and restart on
//! failure) in blocking form, with counters and a `Result`.
//!
//! ## Measured behaviour on this silicon (RP2350, 2026-09-14 bring-up)
//!
//! - At the datasheet-recommended operating point (chain 1, sample 25) the
//!   hardware autocorrelation check fails **four times in a row within
//!   ~550 us** and latches: every subsequent attempt fails instantly until a
//!   software reset (`AUTOCORR_ERR`: "RNG ceases functioning until next
//!   reset"). The upstream embassy driver "works" only because it retries
//!   for seconds to minutes (measured: 101 s / 10.7 s / 7.5 s / 1.4 s / 25 s
//!   per accepted block across runs).
//! - With **ROSC chain 4 / sample 200** the same checks run clean: 256
//!   consecutive blocks, zero CRNGT / VN / autocorrelation failures, ~1.05 ms
//!   per accepted block (measured; the sweep knobs below found this point).
//!   These are the defaults; both stay runtime-tunable for other silicon.
//!
//! ## Design
//!
//! - all three hardware entropy checks stay enabled (reset default); ROSC
//!   inverter chain / sample count configurable (defaults above);
//! - **source lifecycle is job-scoped**: the source starts on the first
//!   `read_block` and keeps running across consecutive blocks. Restarting it
//!   per block (an earlier version's mistake) drives the block into the
//!   sticky-failure state;
//! - a fresh start flushes stale status (EHR_VALID / CRNGT / VN bits can
//!   survive from an earlier user of the block) and all-zero blocks are
//!   rejected and retried (datasheet: a failed check presents no results -
//!   the EHR registers read 0 - so a zero block is never a valid read);
//! - recovery on autocorrelation failure (the sticky one): stop the source,
//!   reset the autocorrelation statistics counters, pulse the software
//!   reset, re-apply the configuration, clear the clearable flags, re-enable;
//! - CRNGT / Von-Neumann failures are not terminal for the block: clear the
//!   flag and keep waiting;
//! - **patience is a time budget, not an attempt count**: the measured
//!   latch-recovery cycle is ~0.5-1 ms, so an attempt-count budget expires in
//!   tens of milliseconds while a stressed block can need seconds. The reader
//!   awaits between retry cycles (`yield_now`) so the executor keeps running
//!   (heartbeats, USB) during a long wait;
//! - `read_block` returns `Err` on timeout; it can never hang or abort.

use core::hint::spin_loop;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use embassy_futures::yield_now;
use embassy_rp::pac;
use embassy_rp::pac::trng::Trng as TrngRegs;
use embassy_time::{Duration, Instant};

/// Bytes per accepted 192-bit entropy block (datasheet 12.12.1).
pub const BLOCK_LEN: usize = 24;

/// Measured operating point (see module docs): chain 4 / sample 200.
pub const DEFAULT_SAMPLE_COUNT: u32 = 200;
pub const DEFAULT_CHAIN_LEN: u8 = 4;

/// Per-block patience budget (a stressed block can need seconds; the
/// measured latch-recovery cycle is sub-millisecond).
pub const DEFAULT_BLOCK_TIMEOUT_MS: u64 = 10_000;

/// Poll bounds in loop iterations (~10-30 cycles each at 150 MHz). A wedged
/// block returns an Err instead of spinning forever.
const BUSY_SIGNAL_SPINS: u32 = 30_000_000;
const BUSY_FALL_SPINS: u32 = 60_000_000;
/// Status settle after BUSY falls (only guards a stale read).
const SETTLE_SPINS: u32 = 2_000;
/// Absolute retry cap for one block (secondary to the time budget).
const MAX_FAILED_ATTEMPTS: u32 = 100_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrngStats {
    /// Accepted 192-bit blocks.
    pub blocks: u32,
    /// CRNGT failures (two consecutive equal 16-bit blocks; result discarded).
    pub crngt_err: u32,
    /// Von-Neumann failures (32 consecutive equal bits; result discarded).
    pub vn_err: u32,
    /// Autocorrelation failures (sticky run; full recovery applied).
    pub autocorr_err: u32,
    /// All-zero reads (no result presented - failed check or stale state).
    pub zero_blocks: u32,
    /// Runs that ended with no status at all.
    pub odd_states: u32,
    /// Runs that never concluded within the poll bound.
    pub busy_timeouts: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrngError {
    /// A run never concluded within the poll bound.
    BusyTimeout,
    /// One block exceeded the time or retry budget.
    Timeout,
}

// ── configuration (runtime-tunable for characterisation sweeps) ──

static CONFIG_SAMPLE: AtomicU32 = AtomicU32::new(DEFAULT_SAMPLE_COUNT);
static CONFIG_CHAIN: AtomicU8 = AtomicU8::new(DEFAULT_CHAIN_LEN);
/// True while the entropy source is enabled (job-scoped; see module docs).
static SOURCE_RUNNING: AtomicBool = AtomicBool::new(false);

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
    SOURCE_RUNNING.store(false, Ordering::Relaxed);
}

fn write_config(regs: &TrngRegs) {
    // All three entropy checks enabled (explicit `false` = not bypassed).
    regs.trng_debug_control().write(|w| {
        w.set_auto_correlate_bypass(false);
        w.set_trng_crngt_bypass(false);
        w.set_vnc_bypass(false);
    });
    regs.trng_config()
        .write(|w| w.set_rnd_src_sel(CONFIG_CHAIN.load(Ordering::Relaxed)));
    regs.sample_cnt1()
        .write(|w| *w = CONFIG_SAMPLE.load(Ordering::Relaxed));
}

/// Sample-count override (characterisation sweeps).
pub fn set_sample_count(n: u32) {
    CONFIG_SAMPLE.store(n, Ordering::Relaxed);
    regs().sample_cnt1().write(|w| *w = n);
}

/// ROSC inverter-chain-length override (0..=4).
pub fn set_chain_len(len: u8) {
    let len = len.min(4);
    CONFIG_CHAIN.store(len, Ordering::Relaxed);
    regs().trng_config().write(|w| w.set_rnd_src_sel(len));
}

/// Restore the measured operating point.
pub fn restore_default_config() {
    set_sample_count(DEFAULT_SAMPLE_COUNT);
    set_chain_len(DEFAULT_CHAIN_LEN);
}

/// RNG_VERSION register (IP revision).
pub fn version() -> u32 {
    regs().rng_version().read().0
}

/// AUTOCORR_STATISTIC register: (fails, trys) since the last write to it.
pub fn autocorr_statistic() -> (u8, u16) {
    let raw = regs().autocorr_statistic().read().0;
    (((raw >> 14) & 0xff) as u8, (raw & 0x3fff) as u16)
}

fn start_source(regs: &TrngRegs) {
    regs.rnd_source_enable().write(|w| w.set_rnd_src_en(false));
    let _ = regs.rnd_source_enable().read();
    regs.rst_bits_counter()
        .write(|w| w.set_rst_bits_counter(true));
    let _ = regs.rnd_source_enable().read();
    // Flush stale status from an earlier user of the block: a leftover
    // EHR_VALID with zeroed data registers used to produce a phantom
    // all-zero "block" as the first read of a job.
    regs.rng_icr().write(|w| {
        w.set_ehr_valid(true);
        w.set_crngt_err(true);
        w.set_vn_err(true);
    });
    regs.rnd_source_enable().write(|w| w.set_rnd_src_en(true));
    SOURCE_RUNNING.store(true, Ordering::Relaxed);
}

/// Stop the entropy source (block idle, low power). Called at job end.
pub fn stop() {
    let regs = regs();
    regs.rnd_source_enable().write(|w| w.set_rnd_src_en(false));
    regs.rst_bits_counter()
        .write(|w| w.set_rst_bits_counter(true));
    SOURCE_RUNNING.store(false, Ordering::Relaxed);
}

/// Full recovery for the sticky autocorrelation failure: stop the source,
/// clear the statistics counters, pulse the soft reset, re-apply the
/// configuration, clear the clearable flags, re-enable.
fn recover(regs: &TrngRegs) {
    regs.rnd_source_enable().write(|w| w.set_rnd_src_en(false));
    let _ = regs.rnd_source_enable().read();
    // "Any write to the register reset the counter" (AUTOCORR_STATISTIC).
    regs.autocorr_statistic()
        .write(|w| *w = pac::trng::regs::AutocorrStatistic(0));
    // Internal RNG reset (the only thing that clears AUTOCORR_ERR); a fixed
    // delay is required afterwards - the register reads are that delay.
    regs.trng_sw_reset().write(|w| w.set_trng_sw_reset(true));
    let _ = regs.trng_sw_reset().read();
    let _ = regs.trng_sw_reset().read();
    write_config(regs);
    regs.rng_icr().write(|w| {
        w.set_ehr_valid(true);
        w.set_crngt_err(true);
        w.set_vn_err(true);
    });
    start_source(regs);
}

/// Read one accepted 192-bit block, retrying failed runs within
/// `timeout_ms`. `Err` on timeout - never hangs, never aborts.
pub async fn read_block(
    stats: &mut TrngStats,
    timeout_ms: u64,
) -> Result<[u8; BLOCK_LEN], TrngError> {
    let regs = regs();
    if !SOURCE_RUNNING.load(Ordering::Relaxed) {
        start_source(&regs);
    }
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut failures = 0u32;

    loop {
        if Instant::now() >= deadline {
            return Err(TrngError::Timeout);
        }
        if failures >= MAX_FAILED_ATTEMPTS {
            return Err(TrngError::Timeout);
        }

        // Phase 1: wait for the run to become visible — BUSY rising, or
        // already-terminated status.
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
            // stale latch for a fresh result.
            regs.rng_icr().write(|w| w.set_ehr_valid(true));
            if block.iter().all(|&b| b == 0) {
                // A failed check presents no results (datasheet 12.12.3):
                // a zero block is never a valid read. Retry.
                stats.zero_blocks += 1;
                failures += 1;
                continue;
            }
            stats.blocks += 1;
            return Ok(block);
        }
        if isr.autocorr_err() {
            stats.autocorr_err += 1;
            failures += 1;
            recover(&regs);
            yield_now().await;
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
            // Not terminal for the block: clear and keep waiting.
            regs.rng_icr().write(|w| {
                w.set_crngt_err(true);
                w.set_vn_err(true);
            });
            yield_now().await;
            continue;
        }
        // No result, no error: not a documented terminal state; recover.
        stats.odd_states += 1;
        failures += 1;
        recover(&regs);
        yield_now().await;
    }
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

// ─────────────────────────────────────────────────────────────────────────
// Bring-up diagnostics (bench firmware only)
// ─────────────────────────────────────────────────────────────────────────

/// Raw register snapshot (all values as read from hardware).
#[derive(Clone, Copy, Debug, Default)]
pub struct RawSnapshot {
    pub isr: u32,
    pub imr: u32,
    pub busy: u32,
    pub valid: u32,
    pub config: u32,
    pub sample_cnt1: u32,
    pub debug_control: u32,
    pub source_enable: u32,
    pub autocorr_stat: u32,
    pub sw_reset: u32,
    pub version: u32,
}

pub fn snapshot() -> RawSnapshot {
    let regs = regs();
    RawSnapshot {
        isr: regs.rng_isr().read().0,
        imr: regs.rng_imr().read().0,
        busy: regs.trng_busy().read().0,
        valid: regs.trng_valid().read().0,
        config: regs.trng_config().read().0,
        sample_cnt1: regs.sample_cnt1().read(),
        debug_control: regs.trng_debug_control().read().0,
        source_enable: regs.rnd_source_enable().read().0,
        autocorr_stat: regs.autocorr_statistic().read().0,
        sw_reset: regs.trng_sw_reset().read().0,
        version: regs.rng_version().read().0,
    }
}

/// TRNG_BUSY flag alone (hot-path probe point).
pub fn busy_flag() -> bool {
    regs().trng_busy().read().trng_busy()
}

/// RNG_ISR raw value (hot-path probe point).
pub fn isr_raw() -> u32 {
    regs().rng_isr().read().0
}

/// The RESETS-block cycle from `init()`, on demand (A/B probe).
pub fn reset_cycle() {
    pac::RESETS.reset().modify(|v| v.set_trng(true));
    let _ = pac::RESETS.reset().read();
    pac::RESETS.reset().modify(|v| v.set_trng(false));
    while !pac::RESETS.reset_done().read().trng() {}
    SOURCE_RUNNING.store(false, Ordering::Relaxed);
}

/// Cold start: stop, re-apply the configuration, enable the source.
pub fn cold_start() {
    stop();
    let regs = regs();
    write_config(&regs);
    start_source(&regs);
}
