//! Blocking RP2350 TRNG reader (checked path) + SHA-256 conditioner.
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
//! ## Ownership
//!
//! All TRNG access goes through the single [`instance`] (an async mutex over
//! one [`Trng`] owner): the "two consecutive accepted blocks belong to one
//! conditioner invocation" guarantee is structural, not a caller
//! convention - a second consumer waits for the current operation instead of
//! interleaving MMIO accesses. (A dedicated entropy service task built on
//! this singleton is the natural production evolution; the singleton is the
//! substrate either way.)
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
//!   This operating point is characterised on THIS board only - validation
//!   across boards, temperature/voltage/load, and restart is an open item.
//! - The raw stream carries a **condition-dependent adjacent-bit
//!   correlation** (bit pairs equal ~50.0-52% instead of 50%): clean for the
//!   first ~8 blocks of an activation, degrading into clustering with longer
//!   uninterrupted reads (measured with position-resolved tests; reproducible
//!   across sessions, extraction independently validated against synthetic
//!   data). This matches the datasheet's own caveat that the TRNG's
//!   conditioning logic has pitfalls, "most notably the von Neumann
//!   decorrelator" - which the bootrom addresses by hashing raw samples with
//!   all internal checking and conditioning bypassed, a different
//!   instantiation from this one (see `conditioned32`).
//!
//! ## Entropy accounting (not yet established)
//!
//! `conditioned32` produces 32 output bytes; that is a **bit count, not a
//! min-entropy claim**. A vetted conditioner redistributes entropy and
//! cannot create it: the output's min-entropy depends on the raw source's
//! assessed min-entropy (NIST SP 800-90B's `n_in` / `h_in` model). What is
//! established here: the conditioner removes all structure the current test
//! suite can observe, on verified-clean input. A conservative min-entropy
//! lower bound requires an SP 800-90B non-IID assessment of the raw noise
//! source - an open item, alongside multi-board / environment / restart
//! coverage.
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
//!   survive from an earlier user of the block); all-zero reads are treated
//!   as a hardware-fault sentinel (datasheet: a failed check presents no
//!   result - the registers read 0) and retried. Excluding one value biases
//!   the output by ~2^-192, which is negligible;
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

#[cfg(feature = "bench")]
extern crate alloc;

use core::hint::spin_loop;

use embassy_futures::yield_now;
use embassy_rp::pac;
use embassy_rp::pac::trng::Trng as TrngRegs;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
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

/// Spins allowed while waiting for BUSY to rise when synchronising on a raw
/// capture block (`capture_raw`). The fill is a few hundred cycles; this is
/// a wedge guard only, and a missed rise fails the capture rather than
/// risking a partial block in the dataset.
#[cfg(feature = "bench")]
const RAW_RISE_SPINS: u32 = 2_000_000;
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
    /// The SHA-256 conditioner failed (unreachable for fixed-size input;
    /// present so the path never panics).
    Conditioner,
}

/// The single TRNG owner. All operations go through [`instance`].
pub struct Trng {
    source_running: bool,
    sample: u32,
    chain: u8,
}

impl Trng {
    const fn new() -> Self {
        Self {
            source_running: false,
            sample: DEFAULT_SAMPLE_COUNT,
            chain: DEFAULT_CHAIN_LEN,
        }
    }

    /// One-time bring-up: clean block reset, then the operating
    /// configuration. Call once at boot, before any TRNG use.
    pub fn init(&mut self) {
        // The block's RESETS state at boot is not contractually defined for
        // this peripheral; give it a clean reset edge and wait for
        // completion.
        pac::RESETS.reset().modify(|v| v.set_trng(true));
        let _ = pac::RESETS.reset().read();
        pac::RESETS.reset().modify(|v| v.set_trng(false));
        while !pac::RESETS.reset_done().read().trng() {}

        let regs = regs();
        self.write_config(&regs);
        regs.rnd_source_enable().write(|w| w.set_rnd_src_en(false));
        self.source_running = false;
    }

    fn write_config(&self, regs: &TrngRegs) {
        // All three entropy checks enabled (explicit `false` = not bypassed).
        regs.trng_debug_control().write(|w| {
            w.set_auto_correlate_bypass(false);
            w.set_trng_crngt_bypass(false);
            w.set_vnc_bypass(false);
        });
        regs.trng_config().write(|w| w.set_rnd_src_sel(self.chain));
        regs.sample_cnt1().write(|w| *w = self.sample);
    }

    /// Sample-count override (characterisation sweeps; bench builds only).
    #[cfg(feature = "bench")]
    pub fn set_sample_count(&mut self, n: u32) {
        self.sample = n;
        regs().sample_cnt1().write(|w| *w = n);
    }

    /// ROSC inverter-chain-length override (0..=4; bench builds only).
    #[cfg(feature = "bench")]
    pub fn set_chain_len(&mut self, len: u8) {
        let len = len.min(4);
        self.chain = len;
        regs().trng_config().write(|w| w.set_rnd_src_sel(len));
    }

    /// Restore the measured operating point (bench builds only).
    #[cfg(feature = "bench")]
    pub fn restore_default_config(&mut self) {
        self.set_sample_count(DEFAULT_SAMPLE_COUNT);
        self.set_chain_len(DEFAULT_CHAIN_LEN);
    }

    /// RNG_VERSION register (IP revision; bench builds only).
    #[cfg(feature = "bench")]
    pub fn version(&self) -> u32 {
        regs().rng_version().read().0
    }

    /// AUTOCORR_STATISTIC register: (fails, trys) since the last write to
    /// it (bench builds only).
    #[cfg(feature = "bench")]
    pub fn autocorr_statistic(&self) -> (u8, u16) {
        let raw = regs().autocorr_statistic().read().0;
        (((raw >> 14) & 0xff) as u8, (raw & 0x3fff) as u16)
    }

    fn start_source(&mut self, regs: &TrngRegs) {
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
        self.source_running = true;
    }

    /// Stop the entropy source (block idle, low power). Called at job end.
    pub fn stop(&mut self) {
        let regs = regs();
        regs.rnd_source_enable().write(|w| w.set_rnd_src_en(false));
        regs.rst_bits_counter()
            .write(|w| w.set_rst_bits_counter(true));
        self.source_running = false;
    }

    /// Full recovery for the sticky autocorrelation failure: stop the source,
    /// clear the statistics counters, pulse the soft reset, re-apply the
    /// configuration, clear the clearable flags, re-enable.
    fn recover(&mut self, regs: &TrngRegs) {
        regs.rnd_source_enable().write(|w| w.set_rnd_src_en(false));
        let _ = regs.rnd_source_enable().read();
        // "Any write to the register reset the counter" (AUTOCORR_STATISTIC).
        regs.autocorr_statistic()
            .write(|w| *w = pac::trng::regs::AutocorrStatistic(0));
        // Internal RNG reset (the only thing that clears AUTOCORR_ERR); a
        // fixed delay is required afterwards - the register reads are that
        // delay.
        regs.trng_sw_reset().write(|w| w.set_trng_sw_reset(true));
        let _ = regs.trng_sw_reset().read();
        let _ = regs.trng_sw_reset().read();
        self.write_config(regs);
        regs.rng_icr().write(|w| {
            w.set_ehr_valid(true);
            w.set_crngt_err(true);
            w.set_vn_err(true);
        });
        self.start_source(regs);
    }

    /// Read one accepted 192-bit block, retrying failed runs within
    /// `timeout_ms`. `Err` on timeout - never hangs, never aborts.
    pub async fn read_block(
        &mut self,
        stats: &mut TrngStats,
        timeout_ms: u64,
    ) -> Result<[u8; BLOCK_LEN], TrngError> {
        let regs = regs();
        if !self.source_running {
            self.start_source(&regs);
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
                    // Hardware-state fault sentinel: a failed check presents
                    // no result (datasheet 12.12.3), so zeroed registers mean
                    // the read is not evidence of a generated block. The
                    // excluded value biases the output by ~2^-192,
                    // negligible.
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
                self.recover(&regs);
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
            self.recover(&regs);
            yield_now().await;
        }
    }

    /// Read one 32-byte conditioned output: SHA-256 over two consecutive
    /// accepted raw blocks (2 x 192 = 384 raw bits in, 256 out).
    ///
    /// Why conditioning: the raw checked-path stream carries a measured,
    /// condition-dependent adjacent-bit correlation (see the module docs and
    /// the README bring-up notes) - an artifact of the hardware conditioning
    /// chain, which the datasheet names as a known pitfall of the Von Neumann
    /// decorrelator. Hashing is a conditioning design consistent with the
    /// datasheet's rationale; note the bootrom's variant hashes RAW samples
    /// with all internal checking and conditioning bypassed, whereas this
    /// reader keeps the three health checks enabled and conditions accepted
    /// blocks (a different instantiation of the same rationale). SHA-256 is
    /// a vetted conditioning component in the SP 800-90B taxonomy - and as
    /// with any conditioner, it redistributes entropy rather than creating
    /// it: no min-entropy claim is made for the output (see "Entropy
    /// accounting" in the module docs).
    ///
    /// Callers must hold the [`instance`] guard across the whole call so
    /// both blocks belong to one invocation (the API enforces this by taking
    /// `&mut self`).
    pub async fn conditioned32(
        &mut self,
        stats: &mut TrngStats,
        timeout_ms: u64,
    ) -> Result<[u8; 32], TrngError> {
        let a = self.read_block(stats, timeout_ms).await?;
        let b = self.read_block(stats, timeout_ms).await?;
        let mut buf = [0u8; BLOCK_LEN * 2];
        buf[..BLOCK_LEN].copy_from_slice(&a);
        buf[BLOCK_LEN..].copy_from_slice(&b);
        shlosilo::encoding::sha256::hash(&buf).map_err(|_| TrngError::Conditioner)
    }

    // ── bring-up diagnostics (bench firmware) ──

    /// Raw register snapshot (all values as read from hardware; bench
    /// builds only).
    #[cfg(feature = "bench")]
    pub fn snapshot(&self) -> RawSnapshot {
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

    /// TRNG_BUSY flag alone (hot-path probe point; bench builds only).
    #[cfg(feature = "bench")]
    pub fn busy_flag(&self) -> bool {
        regs().trng_busy().read().trng_busy()
    }

    /// RNG_ISR raw value (hot-path probe point; bench builds only).
    #[cfg(feature = "bench")]
    pub fn isr_raw(&self) -> u32 {
        regs().rng_isr().read().0
    }

    /// The RESETS-block cycle from `init()`, on demand (A/B probe; bench
    /// builds only).
    #[cfg(feature = "bench")]
    pub fn reset_cycle(&mut self) {
        pac::RESETS.reset().modify(|v| v.set_trng(true));
        let _ = pac::RESETS.reset().read();
        pac::RESETS.reset().modify(|v| v.set_trng(false));
        while !pac::RESETS.reset_done().read().trng() {}
        self.source_running = false;
    }

    /// Cold start: stop, re-apply the configuration, enable the source
    /// (bench builds only).
    #[cfg(feature = "bench")]
    pub fn cold_start(&mut self) {
        self.stop();
        let regs = regs();
        self.write_config(&regs);
        self.start_source(&regs);
    }
    /// Capture raw ROSC samples with all internal checking and conditioning
    /// bypassed (bench builds only; the SP 800-90B source-characterisation
    /// path).
    ///
    /// Mirrors the bootrom / pico-sdk raw recipe (datasheet 12.12.4.1):
    /// bypass the autocorrelation / CRNGT / von Neumann stages, sample once
    /// per cycle (`sample_cnt1 = 0`), then read EHR blocks back-to-back.
    /// Each block carries 192 consecutive raw samples (24 bytes); `out`
    /// receives them verbatim (cleared first).
    ///
    /// The checked-path configuration is restored before returning, so the
    /// other console commands and the signing path see the operating point
    /// they expect.
    #[cfg(feature = "bench")]
    pub fn capture_raw(
        &mut self,
        blocks: usize,
        chain: u8,
        sample: u32,
        out: &mut alloc::vec::Vec<u8>,
    ) -> Result<u32, TrngError> {
        let regs = regs();
        // Stop whatever ran before; raw configuration below wants a clean
        // start state.
        regs.rnd_source_enable().write(|w| w.set_rnd_src_en(false));
        let _ = regs.rnd_source_enable().read();

        // Raw mode: bypass all three checks and the Von Neumann balancer
        // (datasheet 12.12.4.1; the bootrom and pico_rand do the same).
        regs.trng_debug_control().write(|w| {
            w.set_auto_correlate_bypass(true);
            w.set_trng_crngt_bypass(true);
            w.set_vnc_bypass(true);
        });
        regs.trng_config()
            .write(|w| w.set_rnd_src_sel(chain.min(4)));
        regs.sample_cnt1().write(|w| *w = sample);
        // Drop stale status so nothing presents as a phantom first block.
        regs.rng_icr().write(|w| {
            w.set_ehr_valid(true);
            w.set_crngt_err(true);
            w.set_vn_err(true);
        });
        // Clean start: 0 -> 1 edge on the source enable (see start_source).
        regs.rnd_source_enable().write(|w| w.set_rnd_src_en(false));
        let _ = regs.rnd_source_enable().read();
        regs.rst_bits_counter()
            .write(|w| w.set_rst_bits_counter(true));
        let _ = regs.rnd_source_enable().read();
        regs.rnd_source_enable().write(|w| w.set_rnd_src_en(true));
        self.source_running = true;

        // Discard one block: the first read after a start can present a
        // partially-filled EHR.
        {
            let mut flush = [0u8; BLOCK_LEN];
            read_ehr(&regs, &mut flush);
        }

        out.clear();
        let mut n = 0u32;
        while (n as usize) < blocks {
            // Block sync (bootrom: "Wait for 192 ROSC samples to fill EHR,
            // this should take constant time"): the run becomes visible as
            // BUSY rising and concludes when BUSY falls. A read that does
            // not observe the rise would take a partial block, so a missed
            // rise is an error, not something to paper over.
            let mut spins = 0u32;
            while !regs.trng_busy().read().trng_busy() {
                core::hint::spin_loop();
                spins += 1;
                if spins > RAW_RISE_SPINS {
                    self.stop();
                    self.write_config(&regs);
                    return Err(TrngError::BusyTimeout);
                }
            }
            spins = 0;
            while regs.trng_busy().read().trng_busy() {
                core::hint::spin_loop();
                spins += 1;
                if spins > BUSY_FALL_SPINS {
                    self.stop();
                    self.write_config(&regs);
                    return Err(TrngError::BusyTimeout);
                }
            }
            let mut block = [0u8; BLOCK_LEN];
            read_ehr(&regs, &mut block);
            out.extend_from_slice(&block);
            n += 1;
        }

        self.stop();
        // Restore the checked-path operating point.
        self.write_config(&regs);
        Ok(n)
    }
}

/// Raw register snapshot (all values as read from hardware; bench builds
/// only).
#[cfg(feature = "bench")]
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

/// The single TRNG owner. Every consumer takes this guard; register access
/// from outside the module is not possible.
pub fn instance() -> &'static Mutex<CriticalSectionRawMutex, Trng> {
    static INSTANCE: Mutex<CriticalSectionRawMutex, Trng> = Mutex::new(Trng::new());
    &INSTANCE
}

fn regs() -> TrngRegs {
    pac::TRNG
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
