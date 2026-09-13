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

/// Heap sized for the current largest flow: a 12.4 KiB PSBT multipart decode
/// plus signing. The `heap` console command prints used/free/peak so the
/// number is measured, not guessed (the XMR path's ~256 KiB-class
/// allocations are the next sizing item).
const HEAP_SIZE: usize = 128 * 1024;
static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];

/// Global allocator: embedded-alloc's LLFF heap plus live/peak counters.
///
/// The peak counter answers the sizing question with measured numbers:
/// `Heap::used()` only shows the current level, so a flow that allocates and
/// frees within one call (every signing flow does) would otherwise look like
/// it needs nothing.
struct TrackingHeap {
    inner: LlffHeap,
    live: AtomicUsize,
    peak: AtomicUsize,
}

impl TrackingHeap {
    const fn empty() -> Self {
        Self {
            inner: LlffHeap::empty(),
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }
}

unsafe impl GlobalAlloc for TrackingHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.inner.alloc(layout) };
        if !ptr.is_null() {
            let live = self.live.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            // CAS loop instead of load-then-store: an interrupt can allocate
            // between the load and the store, and a plain max-store could
            // lose that update.
            let mut peak = self.peak.load(Ordering::Relaxed);
            while live > peak {
                match self.peak.compare_exchange_weak(
                    peak,
                    live,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(seen) => peak = seen,
                }
            }
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.live.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { self.inner.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static HEAP: TrackingHeap = TrackingHeap::empty();

/// (used, free, peak) allocator snapshot.
pub(crate) fn heap_stats() -> (usize, usize, usize) {
    (
        HEAP.inner.used(),
        HEAP.inner.free(),
        HEAP.peak.load(Ordering::Relaxed),
    )
}

/// Re-arm the peak watermark at the current live level (for measuring one op).
pub(crate) fn heap_peak_reset() {
    HEAP.peak
        .store(HEAP.live.load(Ordering::Relaxed), Ordering::Relaxed);
}

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
});

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
        HEAP.inner
            .init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE)
    }

    let p = embassy_rp::init(Default::default());

    // Bring up the hardware TRNG (checked path; see trng.rs for the design).
    trng::init();

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
