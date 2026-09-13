//! shlosilo flux/pico2 - RP2350 + Embassy skeleton.
//!
//! This appearance consumes the `forms` core (the workspace root crate)
//! directly as a Rust library: no FFI, no C host. It owns its runtime -
//! embedded-alloc (global allocator), panic-probe (panic handler) - and uses
//! embassy-rp's critical-section impl.
//!
//! Skeleton scope: heartbeat LED + proof that forms links into the image
//! (the version string is baked into the crate; its git-hash suffix
//! identifies the exact build).

#![no_std]
#![no_main]

use core::mem::MaybeUninit;

use defmt::info;
use embassy_executor::Spawner;
use embassy_rp::gpio::{Level, Output};
use embassy_time::Timer;
use embedded_alloc::LlffHeap as Heap;
use {defmt_rtt as _, panic_probe as _};

const HEAP_SIZE: usize = 16 * 1024;
static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];

#[global_allocator]
static HEAP: Heap = Heap::empty();

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    // SAFETY: runs once at startup, before any allocation happens.
    unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }

    let p = embassy_rp::init(Default::default());

    info!(
        "pico2 alive; shlosilo {}",
        shlosilo::ffi::version::SHLOSILO_VERSION_STRING
    );

    // Pico 2 (non-wireless): LED on GPIO25.
    let mut led = Output::new(p.PIN_25, Level::Low);
    loop {
        led.toggle();
        Timer::after_millis(500).await;
    }
}
