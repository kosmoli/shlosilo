//! shlosilo flux/pico2 - RP2350 + Embassy.
//!
//! This appearance consumes the `forms` core (the workspace root crate)
//! directly as a Rust library: no FFI, no C host. It owns its runtime -
//! embedded-alloc (global allocator), panic-probe (panic handler) - and uses
//! embassy-rp's critical-section impl.
//!
//! Current scope: heartbeat LED + a bidirectional USB CDC-ACM console. The
//! console carries the version string, the on-device signing-smoke report,
//! and a bench command channel (test fixtures in over serial, results out -
//! see console.rs). defmt/RTT stays attached in parallel for probe
//! debugging.

#![no_std]
#![no_main]

mod console;
mod sign_smoke;
mod trng;

use core::alloc::{GlobalAlloc, Layout};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

use defmt::info;
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
use {defmt_rtt as _, panic_probe as _};

/// Internal-SRAM heap sized for the small working sets: a 12.4 KiB PSBT
/// multipart decode plus signing peaks at ~103 KiB (measured), and the
/// BTC/ETH/console flows all live here. Large XMR allocations (CN's 2 MiB
/// scratchpad, BP+ generators) go to the PSRAM region instead.
const SRAM_HEAP_SIZE: usize = 128 * 1024;
static mut SRAM_HEAP_MEM: [MaybeUninit<u8>; SRAM_HEAP_SIZE] =
    [MaybeUninit::uninit(); SRAM_HEAP_SIZE];

/// Allocations at or above this size route to PSRAM (QSPI, slower); smaller
/// ones stay in internal SRAM. The CN scratchpad (2 MiB) and BP+ generator
/// tables (~256 KiB-class) are the consumers. Routing is by layout size
/// ONLY, on both alloc and dealloc - a fallback to the other region would
/// make free-time routing ambiguous.
const PSRAM_THRESHOLD: usize = 64 * 1024;

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
        if !ptr.is_null() {
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
    let mut tick: u32 = 0;
    loop {
        Timer::after_secs(5).await;
        tick = tick.wrapping_add(1);
        log::info!("[hb] shlosilo-pico2; {version}");
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
            // SAFETY: the region is now memory-mapped and writable, and no
            // allocator has handed out any of it yet.
            unsafe { HEAP.psram.init(base, size) };
            info!("psram: {} MiB ready at {=usize:#x}", size >> 20, base);
        }
        Err(e) => {
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
