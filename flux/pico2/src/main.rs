//! shlosilo flux/pico2 - RP2350 + Embassy.
//!
//! This appearance consumes the `forms` core (the workspace root crate)
//! directly as a Rust library: no FFI, no C host. It owns its runtime -
//! embedded-alloc (global allocator), panic-probe (panic handler) - and uses
//! embassy-rp's critical-section impl.
//!
//! Current scope: heartbeat LED + a USB CDC-ACM console. The console carries
//! the shlosilo version string (its git suffix identifies the exact build),
//! the periodic on-device signing smoke report, and is the I/O channel the
//! signing flow will use next. defmt/RTT stays attached in parallel for
//! probe-based debugging.
//!
//! Console delivery: output produced before a host opens the port is not
//! reliably delivered to a later reader (see sign_smoke.rs), so everything a
//! reader needs is served on a cadence instead of relying on boot-time
//! buffering.

#![no_std]
#![no_main]

mod sign_smoke;

use core::mem::MaybeUninit;

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
use embedded_alloc::LlffHeap as Heap;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

const HEAP_SIZE: usize = 16 * 1024;
static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];

#[global_allocator]
static HEAP: Heap = Heap::empty();

fn heap_used_free() -> (usize, usize) {
    (HEAP.used(), HEAP.free())
}

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
});

/// USB console task: enumerates as a CDC-ACM serial port and pumps `log!`
/// records to the host. Guest input is discarded for now; the signing flow
/// will take over the receive path.
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

    // Install the global `log` sink (the USB serial port) before the first
    // record: `with_class!` also sets the crate's global logger.
    let logs = embassy_usb_logger::with_class!(1024, log::LevelFilter::Info, class);

    log::info!("shlosilo-pico2 alive; {version}");

    // On-device signing smoke (fixture parity with flux/host-sim/sim_l3.c):
    // compute once, store the report; `console_report_task` serves it on a
    // cycle. Nothing is logged inline here - boot-time output is not
    // reliably delivered to a host that attaches later.
    let _ = sign_smoke::run(heap_used_free);

    // Both futures are divergent; the task only ends if the device were to
    // stop for good.
    let _ = join(device.run(), logs).await;
}

/// Console cadence task: an `[hb]` line every 5 s (liveness + version string)
/// and the stored smoke report every 4th tick (20 s), so a reader attaching
/// at any time sees the full report within one cycle. Revisit when the
/// signing flow takes over the channel.
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
    unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }

    let p = embassy_rp::init(Default::default());

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
