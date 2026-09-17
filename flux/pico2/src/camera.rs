//! OV5640 camera bring-up: XCLK (PWM), SCCB (I2C0), DVP capture (PIO0 + DMA).
//!
//! Bench-only for now (`bench` feature): this is the P3 bring-up surface.
//!
//! Hardware (docs/pico2-hardware-pinmap.md):
//!   D0..D7 = GP0..GP7, VSYNC = GP8, HREF = GP9, PCLK = GP10 (all PIO0,
//!   IN base GP0), XCLK = GP11 (PWM slice 5B, ~37.5 MHz), PWDN = GP24
//!   (low = powered), SCCB = GP28/SDA + GP29/SCL (I2C0, 100 kHz).
//!
//! This is a 1:1 port of the vendor's validated RP2350 demo
//! (~/codebases/spotpear-rp2350/C/02-CAM): the XCLK frequency formula, the
//! OV5640 register table and the `picampinos` DVP capture program. The
//! vendor demo runs its RP2350 at 150 MHz - the same clock this firmware
//! runs at - so the replicated formula lands on the same ~37.5 MHz XCLK
//! their hardware was validated with.
//!
//! Capture protocol (see the PIO program below): per group the state machine
//! pushes exactly FRAME_WORDS 16-bit samples - deliberately one short of
//! 240*320, so the frame counter expires inside the last line and the next
//! group re-arms on the following HREF rising edge (the next frame's first
//! line). Each sample = two 8-bit reads on consecutive PCLK edges (the DVP
//! word: YUV422 packs two bytes per pixel). A DMA of exactly FRAME_WORDS u16
//! words is therefore one frame minus its very last pixel - harmless for
//! both bring-up inspection and QR decoding.
//!
//! Bring-up diagnostics (added after the first hardware run wedged in the
//! DMA await): `capture` carries a 3 s timeout and reports how far the
//! transfer got; `rx_probe` drains the PIO RX FIFO without DMA (the ground
//! truth for "is anything being produced"); `init` reads back the key
//! configuration registers so a silently-dropped SCCB write is visible.

use core::cell::RefCell;

use embassy_rp::Peri;
use embassy_rp::bind_interrupts;
use embassy_rp::clocks;
use embassy_rp::dma::Channel;
use embassy_rp::gpio::Flex;
use embassy_rp::i2c::{Blocking as I2cBlocking, Config as I2cConfig, I2c};
use embassy_rp::peripherals::{
    DMA_CH0, I2C0, PIN_0, PIN_1, PIN_2, PIN_3, PIN_4, PIN_5, PIN_6, PIN_7, PIN_8, PIN_9, PIN_10,
    PIN_11, PIN_24, PIN_28, PIN_29, PIO0, PWM_SLICE5,
};
use embassy_rp::pio::{
    Config as PioConfig, Direction, Pin, Pio, ShiftConfig, ShiftDirection, StateMachine,
};
use embassy_rp::pwm::{Config as PwmConfig, Pwm};
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_time::{Duration, Instant, Timer, with_timeout};

bind_interrupts!(struct CamIrqs {
    PIO0_IRQ_0 => embassy_rp::pio::InterruptHandler<PIO0>;
    DMA_IRQ_0 => embassy_rp::dma::InterruptHandler<DMA_CH0>;
});

/// Frame geometry the sensor is configured for: QVGA, YUV422 (2 B/pixel).
pub const FRAME_W: usize = 240;
pub const FRAME_H: usize = 320;
/// 16-bit samples pushed per capture group (`240*320 - 1`; see the module
/// docs for why it is one short).
pub const FRAME_WORDS: usize = FRAME_W * FRAME_H - 1;

/// SCCB (I2C) slave address of the sensor (7-bit).
const SCCB_ADDR: u16 = 0x3C;
/// XCLK target the vendor's register table was tuned with. The PWM
/// formula below replicates the vendor code path exactly (integer divide
/// of clk_sys by this value), which at 150 MHz lands on 37.5 MHz.
const XCLK_TARGET_KHZ: u32 = 37_000;

/// Vendor OV5640 init table (`sensor_default_regs` from the Waveshare
/// RP2350 demo, transcribed 1:1). `0xFFFF` marks a millisecond delay: the
/// vendor's C loop writes the marker as if it were a register write
/// (almost certainly unintended); we honour the stated intent instead.
const INIT_TABLE: &[(u16, u16)] = &[
    (0x3008, 0x82),
    (0xFFFF, 10), // delay 10 ms
    (0x3008, 0x42),
    (0x3103, 0x13),
    (0x3017, 0xFF),
    (0x3018, 0xFF),
    (0x302C, 0xC3),
    (0x4740, 0x21),
    (0x4713, 0x02),
    (0x5001, 0x83),
    (0x3000, 0x20),
    (0xFFFF, 10), // delay 10 ms
    (0x3002, 0x1C),
    (0x3004, 0xFF),
    (0x3006, 0xC3),
    (0x5000, 0xA7),
    (0x5001, 0xA3),
    (0x5003, 0x08),
    (0x370C, 0x02),
    (0x3634, 0x40),
    (0x3A02, 0x03),
    (0x3A03, 0xD8),
    (0x3A08, 0x01),
    (0x3A09, 0x27),
    (0x3A0A, 0x00),
    (0x3A0B, 0xF6),
    (0x3A0D, 0x04),
    (0x3A0E, 0x03),
    (0x3A0F, 0x30),
    (0x3A10, 0x28),
    (0x3A11, 0x60),
    (0x3A13, 0x43),
    (0x3A14, 0x03),
    (0x3A15, 0xD8),
    (0x3A18, 0x00),
    (0x3A19, 0xF8),
    (0x3A1B, 0x30),
    (0x3A1E, 0x26),
    (0x3A1F, 0x14),
    (0x3600, 0x08),
    (0x3601, 0x33),
    (0x3C01, 0xA4),
    (0x3C04, 0x28),
    (0x3C05, 0x98),
    (0x3C06, 0x00),
    (0x3C07, 0x08),
    (0x3C08, 0x00),
    (0x3C09, 0x1C),
    (0x3C0A, 0x9C),
    (0x3C0B, 0x40),
    (0x460C, 0x22),
    (0x4001, 0x02),
    (0x4004, 0x02),
    (0x5180, 0xFF),
    (0x5181, 0xF2),
    (0x5182, 0x00),
    (0x5183, 0x14),
    (0x5184, 0x25),
    (0x5185, 0x24),
    (0x5186, 0x09),
    (0x5187, 0x09),
    (0x5188, 0x09),
    (0x5189, 0x75),
    (0x518A, 0x54),
    (0x518B, 0xE0),
    (0x518C, 0xB2),
    (0x518D, 0x42),
    (0x518E, 0x3D),
    (0x518F, 0x56),
    (0x5190, 0x46),
    (0x5191, 0xF8),
    (0x5192, 0x04),
    (0x5193, 0x70),
    (0x5194, 0xF0),
    (0x5195, 0xF0),
    (0x5196, 0x03),
    (0x5197, 0x01),
    (0x5198, 0x04),
    (0x5199, 0x12),
    (0x519A, 0x04),
    (0x519B, 0x00),
    (0x519C, 0x06),
    (0x519D, 0x82),
    (0x519E, 0x38),
    (0x5381, 0x1E),
    (0x5382, 0x5B),
    (0x5383, 0x08),
    (0x5384, 0x0A),
    (0x5385, 0x7E),
    (0x5386, 0x88),
    (0x5387, 0x7C),
    (0x5388, 0x6C),
    (0x5389, 0x10),
    (0x538A, 0x01),
    (0x538B, 0x98),
    (0x5300, 0x10),
    (0x5301, 0x10),
    (0x5302, 0x18),
    (0x5303, 0x19),
    (0x5304, 0x10),
    (0x5305, 0x10),
    (0x5306, 0x08),
    (0x5307, 0x16),
    (0x5308, 0x40),
    (0x5309, 0x10),
    (0x530A, 0x10),
    (0x530B, 0x04),
    (0x530C, 0x06),
    (0x5480, 0x01),
    (0x5481, 0x00),
    (0x5482, 0x1E),
    (0x5483, 0x3B),
    (0x5484, 0x58),
    (0x5485, 0x66),
    (0x5486, 0x71),
    (0x5487, 0x7D),
    (0x5488, 0x83),
    (0x5489, 0x8F),
    (0x548A, 0x98),
    (0x548B, 0xA6),
    (0x548C, 0xB8),
    (0x548D, 0xCA),
    (0x548E, 0xD7),
    (0x548F, 0xE3),
    (0x5490, 0x1D),
    (0x5580, 0x04),
    (0x5583, 0x40),
    (0x5584, 0x10),
    (0x5586, 0x20),
    (0x5587, 0x00),
    (0x5588, 0x01),
    (0x5589, 0x10),
    (0x558A, 0x00),
    (0x558B, 0xF8),
    (0x501D, 0x40),
    (0x3008, 0x02),
    (0x3C00, 0x04),
    (0xFFFF, 300), // delay 300 ms
    (0x0000, 0x00),
];

/// Peripherals the camera owns (grouped so `main` stays readable).
pub struct Pins {
    pub d0: Peri<'static, PIN_0>,
    pub d1: Peri<'static, PIN_1>,
    pub d2: Peri<'static, PIN_2>,
    pub d3: Peri<'static, PIN_3>,
    pub d4: Peri<'static, PIN_4>,
    pub d5: Peri<'static, PIN_5>,
    pub d6: Peri<'static, PIN_6>,
    pub d7: Peri<'static, PIN_7>,
    pub vsync: Peri<'static, PIN_8>,
    pub href: Peri<'static, PIN_9>,
    pub pclk: Peri<'static, PIN_10>,
    pub xclk: Peri<'static, PIN_11>,
    pub xclk_slice: Peri<'static, PWM_SLICE5>,
    pub pwdn: Peri<'static, PIN_24>,
    pub sda: Peri<'static, PIN_28>,
    pub scl: Peri<'static, PIN_29>,
    pub pio: Peri<'static, PIO0>,
    pub i2c: Peri<'static, I2C0>,
    pub dma: Peri<'static, DMA_CH0>,
}

pub struct Camera {
    i2c: I2c<'static, I2C0, I2cBlocking>,
    sm: StateMachine<'static, PIO0, 0>,
    /// SM1 carries the PIO plumbing self-test program (`cam selftest`):
    /// a free-running `push` loop. Words appearing there prove the SM /
    /// FIFO / drain path work, which separates "plumbing broken" from
    /// "the capture program's waits are never satisfied".
    sm1: StateMachine<'static, PIO0, 1>,
    dma: Channel<'static>,
    /// Kept so the PWM slice handle stays alive; XCLK keeps running regardless.
    _xclk: Pwm<'static>,
    /// PWDN (GP24). Held as a Flex so the boot state can be high-Z - the
    /// vendor demo never touches this pin, and this board's net semantics
    /// are not fully known (the schematic says PWDN; polarity unverified) -
    /// and so the console can sweep z / 0 / 1 at runtime (`cam pwdn`) while
    /// watching `cam rx`: a decisive experiment for the "sensor silent but
    /// SCCB alive" symptom.
    pwdn: Flex<'static>,
    /// Sensor id read over SCCB (0x5640 for the OV5640).
    pub sensor_id: u16,
    /// Completed capture transfers.
    pub frames: u32,
}

static CAMERA: Mutex<CriticalSectionRawMutex, RefCell<Option<Camera>>> =
    Mutex::new(RefCell::new(None));

pub fn install(cam: Camera) {
    CAMERA.lock(|c| *c.borrow_mut() = Some(cam));
}

/// Run `f` on the stored camera, or return None when not installed.
pub fn with_camera<R>(f: impl FnOnce(&mut Camera) -> R) -> Option<R> {
    let mut slot = CAMERA.lock(|c| c.borrow_mut().take());
    let r = slot.as_mut().map(f);
    CAMERA.lock(|c| *c.borrow_mut() = slot);
    r
}

/// Capture one frame into `buf` (must be at least FRAME_WORDS long). The
/// camera is taken out of its slot across the await; console jobs are
/// serialized, so there is exactly one consumer.
pub async fn capture_frame(buf: &mut [u16]) -> Option<CaptureResult> {
    assert!(buf.len() >= FRAME_WORDS, "frame buffer too small");
    let mut slot = CAMERA.lock(|c| c.borrow_mut().take());
    let r = match slot.as_mut() {
        Some(cam) => Some(cam.capture(buf).await),
        None => None,
    };
    CAMERA.lock(|c| *c.borrow_mut() = slot);
    r
}

/// RX-FIFO probe (see `Camera::rx_probe`).
pub async fn probe_rx(ms: u32) -> Option<(u32, u32)> {
    let mut slot = CAMERA.lock(|c| c.borrow_mut().take());
    let r = match slot.as_mut() {
        Some(cam) => Some(cam.rx_probe(ms).await),
        None => None,
    };
    CAMERA.lock(|c| *c.borrow_mut() = slot);
    r
}

/// Outcome of one capture attempt.
pub enum CaptureResult {
    /// The frame group completed: `buf` holds FRAME_WORDS valid words.
    Ok,
    /// Timed out; `words` words had been transferred when the transfer was
    /// aborted (0 = the PIO produced nothing at all - the sensor is not
    /// outputting, its signals are not reaching the pins, or the config
    /// writes did not land; see the readback line in `init`).
    Timeout {
        /// Words transferred before the abort.
        words: usize,
    },
}

impl Camera {
    /// Drive PWDN: 0 = low, 1 = high, anything else = high-Z (input).
    pub fn set_pwdn(&mut self, mode: u8) {
        match mode {
            0 => {
                self.pwdn.set_as_output();
                self.pwdn.set_low();
            }
            1 => {
                self.pwdn.set_as_output();
                self.pwdn.set_high();
            }
            _ => self.pwdn.set_as_input(),
        }
    }

    /// One DMA run = one capture group = one frame (see the module docs),
    /// with a hard timeout so a silent capture can never wedge the console
    /// (observed on the first hardware run: the DMA await blocked forever
    /// while the PIO sat in its VSYNC wait). The DMA write pointer tells us
    /// how far the transfer got before the abort, which separates "no data
    /// at all" (0 words) from "some data, then stall".
    pub async fn capture(&mut self, buf: &mut [u16]) -> CaptureResult {
        let base = buf.as_ptr() as usize;
        let rx = self.sm.rx();
        let transfer = rx.dma_pull(&mut self.dma, buf, false);
        match with_timeout(Duration::from_secs(3), transfer).await {
            Ok(()) => {
                self.frames = self.frames.wrapping_add(1);
                CaptureResult::Ok
            }
            Err(_) => {
                // The transfer was dropped (aborting the channel); the write
                // address register still holds the last written pointer.
                let end = self.dma.write_addr() as usize;
                CaptureResult::Timeout {
                    words: end.wrapping_sub(base).div_ceil(2).min(buf.len()),
                }
            }
        }
    }

    /// Drain the PIO RX FIFO for `ms` without DMA and report (words,
    /// non-zero words). This is the ground truth for "is the capture
    /// program producing anything": a live DVP stream fills the FIFO with
    /// varied pixel data; a program stuck on a `wait` leaves it empty.
    pub async fn rx_probe(&mut self, ms: u32) -> (u32, u32) {
        let mut words = 0u32;
        let mut nonzero = 0u32;
        for _ in 0..(ms / 10).max(1) {
            while let Some(w) = self.sm.rx().try_pull() {
                words += 1;
                if w != 0 {
                    nonzero += 1;
                }
            }
            Timer::after_millis(10).await;
        }
        (words, nonzero)
    }

    /// SCCB register write.
    pub fn wr(&mut self, reg: u16, val: u8) {
        let msg = [(reg >> 8) as u8, reg as u8, val];
        let _ = self.i2c.blocking_write(SCCB_ADDR, &msg);
    }

    /// SCCB register read.
    pub fn rd(&mut self, reg: u16) -> u8 {
        let mut v = [0u8; 1];
        let msg = [(reg >> 8) as u8, reg as u8];
        let _ = self.i2c.blocking_write_read(SCCB_ADDR, &msg, &mut v);
        v[0]
    }

    /// Read the 16-bit sensor id (regs 0x300A/0x300B).
    pub fn read_id(&mut self) -> u16 {
        let hi = self.rd(0x300A) as u16;
        let lo = self.rd(0x300B) as u16;
        (hi << 8) | lo
    }

    /// PIO plumbing self-test (see the `sm1` field): run SM1's push loop
    /// for `ms` and return the number of words drained. Nonzero proves the
    /// state machine, FIFOs and drain path all work.
    pub fn selftest(&mut self, ms: u32) -> u32 {
        self.sm1.clear_fifos();
        self.sm1.set_enable(true);
        let t0 = Instant::now();
        let mut n = 0u32;
        while t0.elapsed().as_millis() < ms as u64 {
            while self.sm1.rx().try_pull().is_some() {
                n = n.wrapping_add(1);
            }
        }
        self.sm1.set_enable(false);
        n
    }

    /// Re-run the SCCB configuration sequence (see `sccb_configure` for
    /// why this exists at runtime).
    pub async fn reinit(&mut self) -> u16 {
        let (id, _rb) = sccb_configure(&mut self.i2c).await;
        self.sensor_id = id;
        id
    }
}

/// Runtime `cam reinit`: take the camera out of its slot across the await
/// (console jobs are serialized, so there is exactly one consumer).
pub async fn reinit() -> Option<u16> {
    let mut slot = CAMERA.lock(|c| c.borrow_mut().take());
    let r = match slot.as_mut() {
        Some(cam) => Some(cam.reinit().await),
        None => None,
    };
    CAMERA.lock(|c| *c.borrow_mut() = slot);
    r
}

/// Dump the state of PIO0's first two state machines and the FIFO flags -
/// the decisive "where is the SM actually stuck" view. Register names mirror
/// the RP2350 PIO chapter (addr = program counter).
pub fn log_sm_state() {
    use embassy_rp::pac::PIO0;
    log::info!(
        "[cam] PIO0 gpiobase={} ctrl=0x{:08x} fdebug=0x{:08x} (rxstall/txstall/rxempty/txempty per SM)",
        PIO0.gpiobase().read().gpiobase() as u8,
        PIO0.ctrl().read().0,
        PIO0.fdebug().read().0,
    );
    for sm in 0..2usize {
        let s = PIO0.sm(sm);
        let addr = s.addr().read().0 & 0x1f;
        let cd = s.clkdiv().read();
        let ec = s.execctrl().read();
        let sc = s.shiftctrl().read();
        let pc = s.pinctrl().read();
        log::info!(
            "[cam] SM{sm}: pc={addr} clkdiv={}.{} execctrl=0x{:08x} shiftctrl=0x{:08x} \
             pinctrl=0x{:08x} (in_base={} out_base={} set_base={} sideset_base={})",
            cd.int(),
            cd.frac(),
            ec.0,
            sc.0,
            pc.0,
            pc.in_base(),
            pc.out_base(),
            pc.set_base(),
            pc.sideset_base(),
        );
    }
}

/// Count level transitions on GP8/GP9/GP10 over `ms` in one tight pass.
/// Returns (rising, falling) per line. The CPU sampling rate is a few MHz,
/// so frame-rate signals (VSYNC) are counted faithfully while line-rate
/// signals (HREF/PCLK) saturate - saturation itself is the finding ("the
/// line is running"). This measures over seconds what `cam pins` can only
/// see in its ~2 ms snapshot.
pub fn count_edges(ms: u32) -> [(u32, u32); 3] {
    let mut last = [0u8; 3];
    let mut rise = [0u32; 3];
    let mut fall = [0u32; 3];
    let v = embassy_rp::pac::SIO.gpio_in(0).read();
    for (i, pin) in [8usize, 9, 10].iter().enumerate() {
        last[i] = ((v >> pin) & 1) as u8;
    }
    let t0 = Instant::now();
    loop {
        for _ in 0..65536u32 {
            let v = embassy_rp::pac::SIO.gpio_in(0).read();
            for (i, pin) in [8usize, 9, 10].iter().enumerate() {
                let b = ((v >> pin) & 1) as u8;
                if b != last[i] {
                    if b == 1 {
                        rise[i] = rise[i].wrapping_add(1);
                    } else {
                        fall[i] = fall[i].wrapping_add(1);
                    }
                    last[i] = b;
                }
            }
        }
        if t0.elapsed().as_millis() >= ms as u64 {
            break;
        }
    }
    [(rise[0], fall[0]), (rise[1], fall[1]), (rise[2], fall[2])]
}

/// Sample the raw pad levels of the DVP lines (VSYNC GP8, HREF GP9,
/// PCLK GP10, XCLK GP11) `n` times back-to-back and report, per line, how
/// many samples read high: 0 = stuck low, n = stuck high, anything in
/// between = the line moved. `SIO.gpio_in` reflects the pad input
/// regardless of which peripheral owns the pin's function, so this works
/// while PIO drives the capture pins and PWM drives XCLK.
pub fn sample_pins(n: u32) -> [u32; 4] {
    let mut hits = [0u32; 4];
    for _ in 0..n {
        let v = embassy_rp::pac::SIO.gpio_in(0).read();
        for (i, pin) in [8usize, 9, 10, 11].iter().enumerate() {
            if (v >> pin) & 1 != 0 {
                hits[i] += 1;
            }
        }
    }
    hits
}

/// XCLK PWM config, replicating the vendor formula: top = clk_khz/f - 1 and
/// the vendor's `top * 0.5` compare (integer-truncated - at 150 MHz that is
/// a 25% duty; kept because it is what the validated hardware runs).
fn xclk_config() -> PwmConfig {
    let clk_khz = clocks::clk_sys_freq() / 1000;
    let top = (clk_khz / XCLK_TARGET_KHZ).saturating_sub(1).max(1) as u16;
    let mut cfg = PwmConfig::default();
    cfg.top = top;
    cfg.compare_b = (top as u32 * 50 / 100) as u16;
    cfg.enable = true;
    cfg
}

/// SCCB 4-byte write (reg..reg+3 = hi(d1), lo(d1), hi(d2), lo(d2)), mirroring
/// the vendor `OV5640_WR_Reg_2` used for the window/size registers.
fn wr4(i2c: &mut I2c<'static, I2C0, I2cBlocking>, reg: u16, d1: u16, d2: u16) {
    for (i, byte) in [d1 >> 8, d1 & 0xFF, d2 >> 8, d2 & 0xFF].iter().enumerate() {
        let r = reg + i as u16;
        let msg = [(r >> 8) as u8, r as u8, *byte as u8];
        let _ = i2c.blocking_write(SCCB_ADDR, &msg);
    }
}

/// Run the full SCCB configuration sequence (vendor init table + QVGA /
/// YUV422 setup) and return (sensor id, six-register readback). Used by
/// `init` and by the runtime `cam reinit` command - the latter exists
/// because a sensor that was configured while in a marginal power state can
/// need the sequence re-run after PWDN is driven properly.
async fn sccb_configure(i2c: &mut I2c<'static, I2C0, I2cBlocking>) -> (u16, [u8; 6]) {
    // Sensor id before anything else: proves XCLK + SCCB + the module.
    let hi = {
        let mut v = [0u8; 1];
        let _ = i2c.blocking_write_read(SCCB_ADDR, &[0x30, 0x0A], &mut v);
        v[0]
    };
    let lo = {
        let mut v = [0u8; 1];
        let _ = i2c.blocking_write_read(SCCB_ADDR, &[0x30, 0x0B], &mut v);
        v[0]
    };
    let sensor_id = ((hi as u16) << 8) | lo as u16;

    // Vendor init table, with its delays honoured (see INIT_TABLE docs).
    for &(reg, val) in INIT_TABLE {
        if reg == 0xFFFF {
            Timer::after_millis(val as u64).await;
        } else {
            let msg = [(reg >> 8) as u8, reg as u8, val as u8];
            let _ = i2c.blocking_write(SCCB_ADDR, &msg);
        }
    }
    Timer::after_millis(50).await;

    // set_size_and_colorspace: 240x320 window, 1:1 increments (vendor 1:1).
    wr4(i2c, 0x3800, 352, 26); // X/Y start
    wr4(i2c, 0x3804, 1792, 1946); // X/Y end
    wr4(i2c, 0x3808, 240, 320); // output size
    wr4(i2c, 0x380C, 2592, 1944); // total size
    wr4(i2c, 0x3810, 16, 14); // ISP offsets
    {
        // ISP control 01 |= 0x20 (vendor read-modify-write).
        let mut v = [0u8; 1];
        let _ = i2c.blocking_write_read(SCCB_ADDR, &[0x50, 0x01], &mut v);
        let msg = [0x50, 0x01, v[0] | 0x20];
        let _ = i2c.blocking_write(SCCB_ADDR, &msg);
    }
    Timer::after_millis(50).await;

    // set_image_options.
    let opts: [(u16, u8); 6] = [
        (0x3820, 0x01),
        (0x3821, 0x00),
        (0x4514, 0xAA),
        (0x4520, 0x0B),
        (0x3814, 0x31),
        (0x3815, 0x31),
    ];
    for (reg, val) in opts {
        let msg = [(reg >> 8) as u8, reg as u8, val];
        let _ = i2c.blocking_write(SCCB_ADDR, &msg);
    }
    Timer::after_millis(50).await;

    // set_pll.
    let pll: [(u16, u8); 9] = [
        (0x3039, 0x00),
        (0x3034, 0x1A),
        (0x3035, 0x11),
        (0x3036, 11),
        (0x3037, 0x01),
        (0x3108, 0x16),
        (0x3824, 0x04),
        (0x460C, 0x22),
        (0x3103, 0x13),
    ];
    for (reg, val) in pll {
        let msg = [(reg >> 8) as u8, reg as u8, val];
        let _ = i2c.blocking_write(SCCB_ADDR, &msg);
    }
    Timer::after_millis(50).await;

    // set_colorspace: YUV422 (FORMAT_CTRL=0x501F, FORMAT_CTRL00=0x4300).
    for (reg, val) in [(0x501F_u16, 0x01_u8), (0x4300, 0x61)] {
        let msg = [(reg >> 8) as u8, reg as u8, val];
        let _ = i2c.blocking_write(SCCB_ADDR, &msg);
    }
    Timer::after_millis(50).await;

    // Read back key configuration registers. A silently dropped SCCB write
    // would leave the sensor unconfigured and the DVP bus idle, which the
    // capture path cannot tell apart from a wiring fault - this line is the
    // discriminator. Expected: 0x3008=0x02 (powered, streaming), 0x3035=0x11
    // (PLL divider), 0x3808/0x3809 = 0x00 0xF0 (240 px), 0x4300=0x61
    // (YUV422), 0x4740=0x21 (clock polarities).
    let mut probe = [0u8; 6];
    for (i, reg) in [0x3008u16, 0x3035, 0x3808, 0x3809, 0x4300, 0x4740]
        .iter()
        .enumerate()
    {
        let mut v = [0u8; 1];
        let _ = i2c.blocking_write_read(SCCB_ADDR, &[(reg >> 8) as u8, *reg as u8], &mut v);
        probe[i] = v[0];
    }
    log::info!(
        "[cam] sensor id {sensor_id:#06x} (OV5640 = 0x5640); readback 0x3008={:#04x} \
         0x3035={:#04x} w=0x{:02x}{:02x} 0x4300={:#04x} 0x4740={:#04x}",
        probe[0],
        probe[1],
        probe[2],
        probe[3],
        probe[4],
        probe[5]
    );

    (sensor_id, probe)
}

/// Full bring-up: PWDN, XCLK, SCCB init (vendor tables + QVGA/YUV422
/// configuration), then the PIO capture program and its DMA channel.
/// Async because the vendor table carries millisecond delays.
pub async fn init(p: Pins) -> Camera {
    // PWDN (GP24). The vendor demo never touches this pin, but on this board
    // that is NOT good enough: measured behaviour is
    //   driven high  -> all four DVP lines dead (power-down/reset state),
    //   high-Z       -> PCLK runs but no frames (marginal, indeterminate),
    //   driven low   -> lines active (frames).
    // So power-up asserts it: brief high (force a known off state), then
    // low, then let the sensor settle before the SCCB init. The pin is kept
    // as a Flex so the console can still sweep z / 0 / 1 at runtime.
    let mut pwdn = Flex::new(p.pwdn);

    // XCLK first: the sensor must see a running clock when it powers up.
    let xclk = Pwm::new_output_b(p.xclk_slice, p.xclk, xclk_config());
    let clk_khz = clocks::clk_sys_freq() / 1000;
    let top = (clk_khz / XCLK_TARGET_KHZ).saturating_sub(1).max(1);
    log::info!(
        "[cam] XCLK: clk_sys {} kHz, top {} -> {} kHz (vendor formula)",
        clk_khz,
        top,
        clk_khz / (top + 1)
    );

    // GP11 is a PWM output; its pad input buffer is off by default, which
    // makes every XCLK reading in `cam pins` a bogus 0. Turn it on so the
    // pad sample is a real measurement.
    embassy_rp::pac::PADS_BANK0
        .gpio(11)
        .modify(|w| w.set_ie(true));

    pwdn.set_as_output();
    pwdn.set_high();
    Timer::after_millis(10).await; // force a known power-down state
    pwdn.set_low();
    Timer::after_millis(50).await; // power-up settle

    let mut i2c_cfg = I2cConfig::default();
    i2c_cfg.frequency = 100_000;
    // The board carries 1K external pullups (R44/R45).
    i2c_cfg.sda_pullup = false;
    i2c_cfg.scl_pullup = false;
    let mut i2c = I2c::new_blocking(p.i2c, p.scl, p.sda, i2c_cfg);
    Timer::after_millis(50).await; // XCLK settle (vendor: sleep_ms(50))

    let (sensor_id, _rb) = sccb_configure(&mut i2c).await;

    // ---- PIO capture program (vendor `picampinos`, 1:1) ----
    let mut pio = Pio::new(p.pio, CamIrqs);
    let prg = pio::pio_asm!(
        ".wrap_target",
        "out x, 32",
        "out y, 32",
        "wait 0 pin 8", // VSYNC
        "wait 1 pin 8",
        "frame:",
        "mov x, y",
        "line:",
        "wait 0 pin 9", // HREF
        "pixel:",
        "wait 1 pin 9",
        "wait 1 pin 10", // PCLK rising: first byte
        "in pins, 8",
        "wait 0 pin 10", // PCLK falling
        "wait 1 pin 10", // PCLK rising: second byte
        "in pins, 8",
        "wait 0 pin 10",
        "push block",
        "jmp x-- pixel",
        "wait 0 pin 9",
        "jmp frame",
        // Unreachable in this flow (nothing branches here, and the wrap
        // covers 0..=17): kept because the vendor listing has it, which
        // makes the loaded program byte-identical to theirs.
        "jmp 2",
        ".wrap",
    );
    let loaded = pio.common.load_program(&prg.program);

    let pins: [_; 11] = [
        pio.common.make_pio_pin(p.d0),
        pio.common.make_pio_pin(p.d1),
        pio.common.make_pio_pin(p.d2),
        pio.common.make_pio_pin(p.d3),
        pio.common.make_pio_pin(p.d4),
        pio.common.make_pio_pin(p.d5),
        pio.common.make_pio_pin(p.d6),
        pio.common.make_pio_pin(p.d7),
        pio.common.make_pio_pin(p.vsync),
        pio.common.make_pio_pin(p.href),
        pio.common.make_pio_pin(p.pclk),
    ];

    let in_pins: [&Pin<'static, PIO0>; 8] = core::array::from_fn(|i| &pins[i]);

    let mut cfg = PioConfig::default();
    cfg.use_program(&loaded, &[]);
    cfg.set_in_pins(&in_pins); // IN base = GP0 (D0..D7)
    // Vendor: sm_config_set_in_shift(shift_left, autopush=false, 32) and
    // sm_config_set_out_shift(shift_left, autopull=true, 32).
    cfg.shift_in = ShiftConfig {
        threshold: 32,
        direction: ShiftDirection::Left,
        auto_fill: false,
    };
    cfg.shift_out = ShiftConfig {
        threshold: 32,
        direction: ShiftDirection::Left,
        auto_fill: true,
    };
    cfg.clock_divider = 1u8.into(); // sample at clk_sys (150 MHz)

    let all_pins: [&Pin<'static, PIO0>; 11] = core::array::from_fn(|i| &pins[i]);
    let mut sm = pio.sm0;
    sm.set_config(&cfg);
    sm.set_pin_dirs(Direction::In, &all_pins);
    sm.clear_fifos();
    sm.set_enable(true);
    // X and Y are consumed by the program's first two OUT instructions.
    sm.tx().push(0); // X: reserved
    sm.tx().push((FRAME_WORDS - 1) as u32); // Y: samples per group

    log::info!(
        "[cam] capture armed: {}x{}, {} words/frame, PIO0 SM0 + DMA",
        FRAME_W,
        FRAME_H,
        FRAME_WORDS
    );

    // Self-test program for SM1: a tight push loop. Configured (but left
    // disabled) here; `cam selftest` enables it briefly and counts words.
    let test_prg = pio::pio_asm!(".wrap_target", "push block", ".wrap");
    let test_loaded = pio.common.load_program(&test_prg.program);
    let mut sm1 = pio.sm1;
    {
        let mut cfg1 = PioConfig::default();
        cfg1.use_program(&test_loaded, &[]);
        sm1.set_config(&cfg1);
    }

    let mut cam = Camera {
        i2c,
        sm,
        sm1,
        dma: Channel::new(p.dma, CamIrqs),
        _xclk: xclk,
        pwdn,
        sensor_id,
        frames: 0,
    };

    // Boot diagnostics: pad levels and a short RX-FIFO probe. Together with
    // the readback line these three separate the failure modes: writes not
    // landing / no DVP signals at the pads / signals present but the capture
    // program not consuming them.
    let hits = sample_pins(20_000);
    log::info!(
        "[cam] pad samples (20k): VSYNC(GP8) {}/20000 high, HREF(GP9) {}/20000, \
         PCLK(GP10) {}/20000, XCLK(GP11) {}/20000 (0 = stuck low, 20000 = stuck high)",
        hits[0],
        hits[1],
        hits[2],
        hits[3]
    );
    let (words, nonzero) = cam.rx_probe(200).await;
    log::info!("[cam] boot rx probe 200 ms: {words} words, {nonzero} non-zero");

    cam
}
