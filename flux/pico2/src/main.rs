//! shlosilo flux/pico2 - RP2350 + Embassy.
//!
//! This appearance consumes the `forms` core (the workspace root crate)
//! directly as a Rust library: no FFI, no C host. It owns its runtime -
//! embedded-alloc (global allocator), fault.rs (panic + hard-fault capture
//! with console reporting) - and uses embassy-rp's critical-section impl.
//!
//! Current scope: heartbeat LED + a bidirectional USB CDC-ACM console. The
//! console carries the version string, the on-device signing-smoke report,
//! and a bench command channel (test fixtures in over serial, results out -
//! see console.rs). defmt/RTT stays attached in parallel for probe
//! debugging.

#![no_std]
#![no_main]

mod console;
mod fault;
mod sign_smoke;
mod trng;

use core::alloc::{GlobalAlloc, Layout};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use defmt::info;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_rp::bind_interrupts;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::USB;
use embassy_rp::usb::{Driver, InterruptHandler};
use embassy_time::Timer;
use embassy_usb::Builder;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb_logger::ReceiverHandler as _;
use embedded_alloc::LlffHeap;
use static_cell::StaticCell;

/// Internal-SRAM heap: small working sets (BTC/ETH/console flows) and every
/// allocation below `PSRAM_THRESHOLD`. The XMR signing path was MEASURED to
/// demand more than the original 128 KiB: a crash recorder run showed 93088
/// bytes live plus a 49536-byte request routed here - 142624 total, which is
/// 11552 bytes over the old capacity (allocation failure -> panic). Grown to
/// 224 KiB: the measured demand plus ~81 KiB of slack, while leaving ~270 KiB
/// of the 512 KiB SRAM for stack (embassy tasks run on the main stack).
const SRAM_HEAP_SIZE: usize = 224 * 1024;
static mut SRAM_HEAP_MEM: [MaybeUninit<u8>; SRAM_HEAP_SIZE] =
    [MaybeUninit::uninit(); SRAM_HEAP_SIZE];

/// Allocations at or above this size route to PSRAM (QSPI, slower); smaller
/// ones stay in internal SRAM. Routing is by layout size ONLY, on both alloc
/// and dealloc - a fallback to the other region would make free-time routing
/// ambiguous.
///
/// Lowered 64 KiB -> 16 KiB (measured): the XMR path's mid-size working set
/// (tens of buffers in the 16-64 KiB class, 169 KiB live at last crash)
/// cannot live in the 512 KiB internal SRAM alongside the stack; the 8 MiB
/// PSRAM heap is its home. Only genuinely small allocations stay in SRAM.
const PSRAM_THRESHOLD: usize = 16 * 1024;

/// Global allocator: two embedded-alloc LLFF heaps plus live/peak counters.
///
/// - internal SRAM heap: SRAM_HEAP_SIZE, low-latency;
/// - PSRAM heap: the whole QMI CS1 memory-mapped region (8 MiB on this
///   board), initialised after the PSRAM driver brings the device up.
///
/// The peak counter answers the sizing question with measured numbers:
/// `used()` only shows the current level, so a flow that allocates and
/// frees within one call (every signing flow does) would otherwise look
/// like it needs nothing. PSRAM heap counters are separate so the `heap`
/// command can report both regions.
struct DualHeap {
    sram: LlffHeap,
    psram: LlffHeap,
    live: AtomicUsize,
    peak: AtomicUsize,
    psram_live: AtomicUsize,
    psram_peak: AtomicUsize,
}

/// Diagnostics for the crash recorder (set by the allocator itself, read by
/// the panic/hard-fault handlers): the layout of the last FAILED allocation
/// and the size of the last successful PSRAM-routed one. Without these a
/// "memory allocation failed" panic is anonymous - which allocation, which
/// region, how big.
static ALLOC_FAIL_SIZE: AtomicUsize = AtomicUsize::new(0);
static ALLOC_FAIL_ALIGN: AtomicUsize = AtomicUsize::new(0);
static ALLOC_FAIL_REGION: AtomicUsize = AtomicUsize::new(0);
static LAST_BIG_ALLOC: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn alloc_fail_size() -> usize {
    ALLOC_FAIL_SIZE.load(Ordering::Relaxed)
}
pub(crate) fn alloc_fail_align() -> usize {
    ALLOC_FAIL_ALIGN.load(Ordering::Relaxed)
}
/// 0 = SRAM heap, 1 = PSRAM heap.
pub(crate) fn alloc_fail_region() -> usize {
    ALLOC_FAIL_REGION.load(Ordering::Relaxed)
}
pub(crate) fn last_big_alloc() -> usize {
    LAST_BIG_ALLOC.load(Ordering::Relaxed)
}

/// Allocation trace ring: the last TRACE_N traced allocations (>= TRACE_MIN
/// bytes, plus every FAILED one), with size and region. Lives in .uninit so
/// it SURVIVES a crash reset - after a panic+reboot, `alloctrace` prints
/// exactly what the failing path requested, in order.
///
/// Diagnostics contract: this ring is read through `trace_len`/`trace_entry`
/// only.
const TRACE_N: usize = 24;
const TRACE_MIN: usize = 4096;
#[unsafe(link_section = ".uninit.trace")]
static TRACE_CURSOR: AtomicUsize = AtomicUsize::new(0);
#[unsafe(link_section = ".uninit.trace")]
static TRACE_SIZE: [core::sync::atomic::AtomicU32; TRACE_N] =
    [const { core::sync::atomic::AtomicU32::new(0) }; TRACE_N];
#[unsafe(link_section = ".uninit.trace")]
static TRACE_FLAGS: [core::sync::atomic::AtomicU32; TRACE_N] =
    [const { core::sync::atomic::AtomicU32::new(0) }; TRACE_N];

/// Record one traced allocation (bit 31 of flags = failed; bit 0 = region).
fn trace_alloc(size: usize, to_psram: bool, failed: bool) {
    if size < TRACE_MIN && !failed {
        return;
    }
    let n = TRACE_CURSOR.fetch_add(1, Ordering::Relaxed);
    let i = n % TRACE_N;
    let mut flags = to_psram as u32;
    if failed {
        flags |= 1 << 31;
    }
    TRACE_SIZE[i].store(size as u32, Ordering::Relaxed);
    TRACE_FLAGS[i].store(flags, Ordering::Relaxed);
}

/// Number of live ring entries (<= TRACE_N).
pub(crate) fn trace_len() -> usize {
    TRACE_CURSOR.load(Ordering::Relaxed).min(TRACE_N)
}

/// The k-th oldest live entry: (size, flags). flags bit31 = failed,
/// bit0 = region (0 sram, 1 psram).
pub(crate) fn trace_entry(k: usize) -> (u32, u32) {
    let total = TRACE_CURSOR.load(Ordering::Relaxed);
    let start = total - total.min(TRACE_N);
    let idx = (start + k) % TRACE_N;
    (
        TRACE_SIZE[idx].load(Ordering::Relaxed),
        TRACE_FLAGS[idx].load(Ordering::Relaxed),
    )
}

impl DualHeap {
    const fn empty() -> Self {
        Self {
            sram: LlffHeap::empty(),
            psram: LlffHeap::empty(),
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            psram_live: AtomicUsize::new(0),
            psram_peak: AtomicUsize::new(0),
        }
    }

    fn bump_peak(counter: &AtomicUsize, live: usize) {
        // CAS loop instead of load-then-store: an interrupt can allocate
        // between the load and the store, and a plain max-store could lose
        // that update.
        let mut peak = counter.load(Ordering::Relaxed);
        while live > peak {
            match counter.compare_exchange_weak(peak, live, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(seen) => peak = seen,
            }
        }
    }
}

unsafe impl GlobalAlloc for DualHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let to_psram = layout.size() >= PSRAM_THRESHOLD;
        let ptr = if to_psram {
            unsafe { self.psram.alloc(layout) }
        } else {
            unsafe { self.sram.alloc(layout) }
        };
        if ptr.is_null() {
            // Record the failed layout for the crash recorder: this is what
            // makes an "allocation failed" panic diagnosable.
            ALLOC_FAIL_SIZE.store(layout.size(), Ordering::Relaxed);
            ALLOC_FAIL_ALIGN.store(layout.align(), Ordering::Relaxed);
            ALLOC_FAIL_REGION.store(to_psram as usize, Ordering::Relaxed);
            trace_alloc(layout.size(), to_psram, true);
        } else {
            if to_psram {
                LAST_BIG_ALLOC.store(layout.size(), Ordering::Relaxed);
            }
            trace_alloc(layout.size(), to_psram, false);
            let (live_c, peak_c) = if to_psram {
                (&self.psram_live, &self.psram_peak)
            } else {
                (&self.live, &self.peak)
            };
            let live = live_c.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            Self::bump_peak(peak_c, live);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() >= PSRAM_THRESHOLD {
            self.psram_live.fetch_sub(layout.size(), Ordering::Relaxed);
            unsafe { self.psram.dealloc(ptr, layout) }
        } else {
            self.live.fetch_sub(layout.size(), Ordering::Relaxed);
            unsafe { self.sram.dealloc(ptr, layout) }
        }
    }
}

#[global_allocator]
static HEAP: DualHeap = DualHeap::empty();

/// (sram_used, sram_free, sram_peak) allocator snapshot.
pub(crate) fn heap_stats() -> (usize, usize, usize) {
    (
        HEAP.sram.used(),
        HEAP.sram.free(),
        HEAP.peak.load(Ordering::Relaxed),
    )
}

/// (psram_used, psram_free, psram_peak).
pub(crate) fn psram_stats() -> (usize, usize, usize) {
    (
        HEAP.psram.used(),
        HEAP.psram.free(),
        HEAP.psram_peak.load(Ordering::Relaxed),
    )
}

/// Re-arm the peak watermarks at the current live levels (one-op measurement).
pub(crate) fn heap_peak_reset() {
    HEAP.peak
        .store(HEAP.live.load(Ordering::Relaxed), Ordering::Relaxed);
    HEAP.psram_peak
        .store(HEAP.psram_live.load(Ordering::Relaxed), Ordering::Relaxed);
}

/// PSRAM status for the console report. The bring-up result used to be a
/// boot-time log line only - emitted before USB enumerates, i.e. invisible
/// to any host that attaches later. That made a psram bring-up failure
/// indistinguishable from a hang on the bench; the status now lives in
/// statics and is reported every cycle.
///
/// 0 = not tried; 1 = ready (heap not yet mapped, r/w untested);
/// 2 = r/w verified, heap mapped; 3 = bring-up failed (code in STATUS_LOW);
/// 4 = r/w test failed (first bad offset in PSRAM_RW_BAD_OFF).
static PSRAM_STATUS: AtomicUsize = AtomicUsize::new(0);
#[allow(dead_code)] // part of the status contract; read via render
static PSRAM_STATUS_LOW: AtomicUsize = AtomicUsize::new(0);
static PSRAM_RW_BAD_OFF: AtomicUsize = AtomicUsize::new(0);
static PSRAM_BASE: AtomicUsize = AtomicUsize::new(0);
static PSRAM_SIZE: AtomicUsize = AtomicUsize::new(0);
static PSRAM_HEAP_READY: AtomicBool = AtomicBool::new(false);

pub(crate) const PSRAM_STATUS_NOT_TRIED: usize = 0;
pub(crate) const PSRAM_STATUS_READY: usize = 1;
pub(crate) const PSRAM_STATUS_RW_OK: usize = 2;
pub(crate) const PSRAM_STATUS_FAILED: usize = 3;
pub(crate) const PSRAM_STATUS_RW_FAIL: usize = 4;

/// The mapped PSRAM region (base, size), if bring-up succeeded.
pub(crate) fn psram_region() -> Option<(usize, usize)> {
    let base = PSRAM_BASE.load(Ordering::Relaxed);
    if base == 0 {
        return None;
    }
    Some((base, PSRAM_SIZE.load(Ordering::Relaxed)))
}

/// Record a successful bring-up (region mapped; r/w still untested).
pub(crate) fn psram_mark_ready(base: usize, size: usize) {
    PSRAM_BASE.store(base, Ordering::Relaxed);
    PSRAM_SIZE.store(size, Ordering::Relaxed);
    PSRAM_STATUS.store(PSRAM_STATUS_READY, Ordering::Relaxed);
}

/// Record a bring-up failure (code: 0 DeviceNotFound, 1 InvalidConfig,
/// 2 SizeMismatch - see embassy_rp::psram::Error).
pub(crate) fn psram_mark_failed(code: usize) {
    PSRAM_STATUS_LOW.store(code, Ordering::Relaxed);
    PSRAM_STATUS.store(PSRAM_STATUS_FAILED, Ordering::Relaxed);
}

/// Record the r/w test outcome; on success also map the heap (only verified
/// memory is ever handed to the allocator). Idempotent: calling it again
/// after the heap is already mapped just re-affirms the status (the
/// underlying init() must run exactly once).
pub(crate) fn psram_mark_rw_ok() -> bool {
    let Some((base, size)) = psram_region() else {
        return false;
    };
    if !PSRAM_HEAP_READY.load(Ordering::Relaxed) {
        // SAFETY: the region is memory-mapped and the r/w test just wrote and
        // read it back; no allocator has handed out any of it.
        unsafe { HEAP.psram.init(base, size) };
        PSRAM_HEAP_READY.store(true, Ordering::Relaxed);
    }
    PSRAM_STATUS.store(PSRAM_STATUS_RW_OK, Ordering::Relaxed);
    true
}

/// Record an r/w test failure at the given offset.
pub(crate) fn psram_mark_rw_fail(off: usize) {
    PSRAM_RW_BAD_OFF.store(off, Ordering::Relaxed);
    PSRAM_STATUS.store(PSRAM_STATUS_RW_FAIL, Ordering::Relaxed);
}

/// Is the PSRAM heap mapped (r/w verified)?
pub(crate) fn psram_heap_ready() -> bool {
    PSRAM_HEAP_READY.load(Ordering::Relaxed)
}

/// Render the one-line PSRAM status for the console report.
pub(crate) fn psram_status_line(w: &mut impl core::fmt::Write) {
    match PSRAM_STATUS.load(Ordering::Relaxed) {
        PSRAM_STATUS_NOT_TRIED => {
            let _ = write!(w, "[psram] not initialised");
        }
        PSRAM_STATUS_READY | PSRAM_STATUS_RW_OK => {
            let base = PSRAM_BASE.load(Ordering::Relaxed);
            let size = PSRAM_SIZE.load(Ordering::Relaxed);
            let rw = if PSRAM_STATUS.load(Ordering::Relaxed) == PSRAM_STATUS_RW_OK {
                "rw=ok"
            } else {
                "rw=untested (psramtest)"
            };
            let _ = write!(w, "[psram] ready {} MiB at {:#x} {rw}", size >> 20, base);
        }
        PSRAM_STATUS_FAILED => {
            let code = PSRAM_STATUS_LOW.load(Ordering::Relaxed);
            let name = match code {
                0 => "DeviceNotFound",
                1 => "InvalidConfig",
                _ => "SizeMismatch",
            };
            let _ = write!(w, "[psram] bring-up failed: {name} (SRAM-only)");
        }
        _ => {
            let off = PSRAM_RW_BAD_OFF.load(Ordering::Relaxed);
            let _ = write!(w, "[psram] r/w test FAILED at offset {off:#x} (SRAM-only)");
        }
    }
}

/// Boot-time PSRAM r/w verification: write/read-back distinct word patterns
/// at five offsets; only a full pass maps the heap (see `psram_mark_rw_ok`).
fn boot_psram_check(base: usize, size: usize) {
    let offsets: [usize; 5] = [0, 2 << 20, 4 << 20, 6 << 20, size - 0x1000];
    for &off in &offsets {
        let p = (base + off) as *mut u32;
        let seed = 0xA5A5_0000u32 ^ (off as u32).wrapping_mul(0x9E37_79B9);
        unsafe {
            for i in 0..16u32 {
                core::ptr::write_volatile(p.add(i as usize), seed ^ i.wrapping_mul(0x0101_0101));
            }
            for i in 0..16u32 {
                let want = seed ^ i.wrapping_mul(0x0101_0101);
                if core::ptr::read_volatile(p.add(i as usize)) != want {
                    psram_mark_rw_fail(off);
                    info!(
                        "psram: boot r/w check FAILED at {=usize:#x} (SRAM-only)",
                        off
                    );
                    return;
                }
            }
        }
    }
    if psram_mark_rw_ok() {
        info!(
            "psram: boot r/w check ok; heap mapped ({=usize} bytes)",
            size
        );
    }
}

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
});

bind_interrupts!(struct TrngIrqs {
    TRNG_IRQ => embassy_rp::trng::InterruptHandler<embassy_rp::peripherals::TRNG>;
});

/// The upstream embassy TRNG driver, kept side by side with our own reader
/// for cross-checking on the bench: if the authoritative driver behaves
/// differently on the same silicon, the fault is in our reader (or in the
/// state our bring-up leaves the block in); if it behaves the same, the
/// fault is in the hardware/configuration understanding.
///
/// **Bench-only, and deliberately outside the trng::instance() discipline**:
/// it initialises and configures the same peripheral with its own writable
/// config, so it must not run concurrently with singleton consumers. The
/// bench serializes console commands, which is the only thing that uses
/// this; production firmware deletes it.
static EMB_TRNG: embassy_sync::blocking_mutex::Mutex<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    core::cell::RefCell<Option<embassy_rp::trng::Trng<'static, embassy_rp::peripherals::TRNG>>>,
> = embassy_sync::blocking_mutex::Mutex::new(core::cell::RefCell::new(None));

/// Read `dest.len()` bytes via the upstream embassy driver (blocking).
/// Panics inside embassy's wait path kill the firmware (panic = abort) -
/// which is itself a test result for the bench session.
pub(crate) fn emb_trng_fill(dest: &mut [u8]) {
    EMB_TRNG.lock(|cell| {
        if let Some(t) = cell.borrow_mut().as_mut() {
            t.blocking_fill_bytes(dest);
        }
    });
}

/// Is the upstream driver initialised (its `new` was called)?
pub(crate) fn emb_trng_ready() -> bool {
    EMB_TRNG.lock(|cell| cell.borrow().is_some())
}

/// USB console task: enumerates as a CDC-ACM serial port. `log!` records go
/// out over serial; `console::CommandHandler` processes incoming lines (the
/// bench command channel).
#[embassy_executor::task]
async fn usb_console_task(driver: Driver<'static, USB>) {
    // The version constant is NUL-terminated for C consumers; trim it for the
    // USB string descriptors.
    let version = shlosilo::ffi::version::SHLOSILO_VERSION_STRING.trim_end_matches('\0');

    let mut config = embassy_usb::Config::new(0x1209, 0x5353);
    config.manufacturer = Some("shlosilo");
    config.product = Some("shlosilo-pico2 console");
    config.serial_number = Some(version);
    config.max_power = 100;
    config.max_packet_size_0 = 64;

    // Descriptor and control buffers must outlive the device ('static).
    static CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
    static CDC_STATE: StaticCell<State<'static>> = StaticCell::new();

    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESCRIPTOR.init([0; 256]),
        BOS_DESCRIPTOR.init([0; 256]),
        &mut [], // no MS OS descriptors
        CONTROL_BUF.init([0; 64]),
    );
    let class = CdcAcmClass::new(&mut builder, CDC_STATE.init(State::new()), 64);
    let mut device = builder.build();

    // Install the global `log` sink (the USB serial port) and the receive
    // handler before the first record: `with_class!` also sets the crate's
    // global logger.
    let logs = embassy_usb_logger::with_class!(
        1024,
        log::LevelFilter::Info,
        class,
        crate::console::CommandHandler
    );

    log::info!("shlosilo-pico2 alive; {version}");

    // On-device signing smoke (fixture parity with flux/host-sim/sim_l3.c):
    // compute once, store the report; `console_report_task` serves it on a
    // cycle. Nothing is logged inline here - boot-time output is not
    // reliably delivered to a host that attaches later.
    let _ = sign_smoke::run(heap_stats);

    // Both futures are divergent; the task only ends if the device were to
    // stop for good.
    let _ = join(device.run(), logs).await;
}

/// Console cadence task: an `[hb]` line every 5 s (liveness + version string)
/// and the stored smoke report every 4th tick (20 s), so a reader attaching
/// at any time sees the full report within one cycle.
#[embassy_executor::task]
async fn console_report_task() {
    let version = shlosilo::ffi::version::SHLOSILO_VERSION_STRING.trim_end_matches('\0');
    // A running report task is the clean-boot milestone: re-arm the crash
    // reset budget (see fault.rs).
    fault::boot_ok();
    let mut tick: u32 = 0;
    loop {
        Timer::after_secs(5).await;
        tick = tick.wrapping_add(1);
        log::info!("[hb] shlosilo-pico2; {version}");
        {
            let mut buf = [0u8; 160];
            let mut w = sign_smoke::BufWriter::new(&mut buf);
            psram_status_line(&mut w);
            log::info!("{}", w.as_str());
        }
        if let Some(line) = fault::report() {
            log::info!("{line}");
        }
        if tick.is_multiple_of(4) {
            match sign_smoke::report() {
                Some(r) => log::info!("{r}"),
                None => log::info!("[smoke] report not ready yet"),
            }
        }
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // Crash record from the previous run (if the last boot died): render it
    // before anything else, so the console report can show it.
    fault::init();

    // SAFETY: runs once at startup, before any allocation happens.
    unsafe {
        HEAP.sram.init(
            core::ptr::addr_of_mut!(SRAM_HEAP_MEM) as usize,
            SRAM_HEAP_SIZE,
        )
    }

    let p = embassy_rp::init(Default::default());

    // PSRAM bring-up (QMI CS1, GPIO19 on this board - the pin the vendor's
    // Linux bootloader uses): 8 MiB memory-mapped at 0x11000000, used for
    // the large XMR allocations. A verification failure is logged and the
    // firmware continues SRAM-only (BTC/ETH/console do not need PSRAM).
    match embassy_rp::psram::Psram::new(
        embassy_rp::qmi_cs1::QmiCs1::new(p.QMI_CS1, p.PIN_19),
        // clock_hz drives the QSPI divisor computation; report the actual
        // system clock.
        embassy_rp::psram::Config::custom(
            embassy_rp::clocks::clk_sys_freq(),
            133_000_000,
            8,
            18,
            1,
            embassy_rp::psram::PageBreak::_1024,
            10,
            Some(0x35),
            0xEB,
            Some(0x38),
            24,
            embassy_rp::psram::FormatConfig {
                prefix_width: embassy_rp::psram::Width::Quad,
                addr_width: embassy_rp::psram::Width::Quad,
                suffix_width: embassy_rp::psram::Width::Quad,
                dummy_width: embassy_rp::psram::Width::Quad,
                data_width: embassy_rp::psram::Width::Quad,
                prefix_len: true,
                suffix_len: false,
            },
            Some(embassy_rp::psram::FormatConfig {
                prefix_width: embassy_rp::psram::Width::Quad,
                addr_width: embassy_rp::psram::Width::Quad,
                suffix_width: embassy_rp::psram::Width::Quad,
                dummy_width: embassy_rp::psram::Width::Quad,
                data_width: embassy_rp::psram::Width::Quad,
                prefix_len: true,
                suffix_len: false,
            }),
            8 * 1024 * 1024,
            embassy_rp::psram::VerificationType::Aps6404l,
            true,
        ),
    ) {
        Ok(psram) => {
            let base = psram.base_address() as usize;
            let size = psram.size();
            psram_mark_ready(base, size);
            // Boot r/w verification, immediately - before any task runs, so
            // no allocation can ever see an unverified heap. Silent on
            // success (the [psram] status line reports it); a failure marks
            // SRAM-only and the heartbeat line carries the reason.
            boot_psram_check(base, size);
            info!(
                "psram: {} MiB at {=usize:#x} (boot check done)",
                size >> 20,
                base
            );
        }
        Err(e) => {
            let code = match e {
                embassy_rp::psram::Error::DeviceNotFound => 0,
                embassy_rp::psram::Error::InvalidConfig => 1,
                _ => 2,
            };
            psram_mark_failed(code);
            info!("psram: bring-up failed ({:?}); continuing SRAM-only", e);
        }
    }

    // Bring up the hardware TRNG through its singleton owner (see trng.rs;
    // all register access is serialized through this instance).
    trng::instance().lock().await.init();

    // Side-by-side upstream driver for bench cross-checks (see EMB_TRNG).
    EMB_TRNG.lock(|cell| {
        *cell.borrow_mut() = Some(embassy_rp::trng::Trng::new(
            p.TRNG,
            TrngIrqs,
            embassy_rp::trng::Config::default(),
        ));
    });

    let driver = Driver::new(p.USB, Irqs);
    // Each task pool holds one slot, so these first spawns cannot fail.
    spawner.spawn(usb_console_task(driver).unwrap());
    spawner.spawn(console_report_task().unwrap());

    info!(
        "pico2 alive; shlosilo {}",
        shlosilo::ffi::version::SHLOSILO_VERSION_STRING.trim_end_matches('\0')
    );

    // Pico 2 (non-wireless): LED on GPIO25.
    let mut led = Output::new(p.PIN_25, Level::Low);
    loop {
        led.toggle();
        Timer::after_millis(500).await;
    }
}
