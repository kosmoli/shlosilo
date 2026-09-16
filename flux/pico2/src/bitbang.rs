//! Bit-banged I2C on the touch bus (GP26/GP27): bring-up forensics.
//!
//! History: this path found the fitted controller. Every CST816D-shaped
//! access (the vendor example's 0x15 recipe) NACKed - the panel had been
//! swapped for a larger one carrying an FT6236 at 0x38 - while the
//! driver-level error `Abort(NoAcknowledge)` could not separate "chip
//! not listening" from "controller-side problem". Bit-banging 0x08..0x77
//! with consecutive-ACK filtering surfaced 0x38 (5/5 ACKs, registers
//! readable), and the FT6236 driver path (touch.rs) now talks to it
//! directly. This module stays as the wire-level forensics instrument
//! and as the fallback for bus states the controller path cannot handle.
//!
//! This module talks to the bus with raw GPIO toggling: no I2C
//! peripheral, no driver, no interrupt logic - and it can *sample the
//! wire* bit by bit during a probe, which turns an uninterpretable NACK
//! into an observed waveform (which bit the slave acknowledged, or that
//! it never pulled SDA low at all).
//!
//! Wiring: open-drain emulation - drive low = output+low, release =
//! input with pull-up. `swap` flips the roles of GP26/GP27 to test a
//! swapped-wiring hypothesis without touching the hardware.
//!
//! After any `Bb` use the I2C1 function routing must be restored
//! (`panel` touch `rebuild()`): the Flex constructor re-routes the pins
//! to SIO and nothing puts them back automatically.

use cortex_m::asm::delay as spin_cycles;
use embassy_rp::Peripherals;
use embassy_rp::gpio::{Flex, Pull};

/// Default half-bit delay in CPU cycles. The core runs at 150 MHz
/// (embassy default), so 1500 cycles ~= 10 us ~= 50 kHz bus - slow
/// enough to tolerate weak pull-ups and contact resistance.
pub const DEFAULT_HALF_CYCLES: u32 = 1500;

/// Result of a traced single-byte probe.
pub struct ProbeTrace {
    /// The address byte the master drove (write shape, MSB first).
    pub sent: u8,
    /// The levels sampled back on SDA during the eight SCL-high phases.
    pub sampled: u8,
    /// True when SDA was low in the ACK slot (a real acknowledge).
    pub ack_low: bool,
}

pub struct Bb {
    sda: Flex<'static>,
    scl: Flex<'static>,
    half_cycles: u32,
}

impl Bb {
    /// `swap`: GP27 as SDA and GP26 as SCL (the opposite of the
    /// documented mapping) - a scan in this mode answers "is the pair
    /// merely swapped?".
    pub fn new(swap: bool, half_cycles: u32) -> Self {
        let p = unsafe { Peripherals::steal() };
        // Both wrap to the same Flex type, so the swap happens on the
        // constructed objects (PIN_26 and PIN_27 are distinct types).
        let flex_a = Flex::new(p.PIN_26);
        let flex_b = Flex::new(p.PIN_27);
        let (mut sda, mut scl) = if swap {
            (flex_b, flex_a)
        } else {
            (flex_a, flex_b)
        };
        sda.set_pull(Pull::Up);
        scl.set_pull(Pull::Up);
        sda.set_as_input();
        scl.set_as_input();
        Self {
            sda,
            scl,
            half_cycles,
        }
    }

    /// Half-bit delay in CPU cycles (the bus-speed knob).
    pub fn half_cycles(&self) -> u32 {
        self.half_cycles
    }

    /// Set the half-bit delay (takes effect on the next bit).
    pub fn set_half_cycles(&mut self, half: u32) {
        self.half_cycles = half;
    }

    /// Set the SDA/SCL pull mode (pull-down probing; restore with
    /// `Pull::Up` when done).
    pub fn set_pulls(&mut self, pull: embassy_rp::gpio::Pull) {
        self.sda.set_pull(pull);
        self.scl.set_pull(pull);
    }

    #[inline]
    fn half(&self) {
        spin_cycles(self.half_cycles);
    }

    #[inline]
    fn sda_low(&mut self) {
        self.sda.set_as_output();
        self.sda.set_low();
    }
    #[inline]
    fn sda_release(&mut self) {
        self.sda.set_as_input();
    }
    #[inline]
    fn scl_low(&mut self) {
        self.scl.set_as_output();
        self.scl.set_low();
    }
    #[inline]
    fn scl_release(&mut self) {
        self.scl.set_as_input();
    }

    /// Current level of SDA while released (for stuck-bus checks).
    pub fn sda_level(&mut self) -> bool {
        self.sda_release();
        self.sda.is_high()
    }

    /// SDA level as a plain input (releases the line first).
    pub fn sda_is_high(&mut self) -> bool {
        self.sda.set_as_input();
        self.sda.is_high()
    }

    /// SCL level as a plain input (releases the line first).
    pub fn scl_is_high(&mut self) -> bool {
        self.scl.set_as_input();
        self.scl.is_high()
    }

    fn start(&mut self) {
        self.sda_release();
        self.scl_release();
        self.half();
        self.sda_low();
        self.half();
        self.scl_low();
        self.half();
    }

    fn stop(&mut self) {
        self.sda_low();
        self.half();
        self.scl_release();
        self.half();
        self.sda_release();
        self.half();
    }

    /// Write one bit; returns the SDA level sampled while SCL was high.
    fn write_bit_sampled(&mut self, b: bool) -> bool {
        if b {
            self.sda_release();
        } else {
            self.sda_low();
        }
        self.half();
        self.scl_release();
        self.half();
        let sampled = self.sda.is_high();
        self.scl_low();
        self.half();
        sampled
    }

    fn write_bit(&mut self, b: bool) {
        let _ = self.write_bit_sampled(b);
    }

    /// Read one bit: release SDA, raise SCL, sample, lower SCL.
    fn read_bit(&mut self) -> bool {
        self.sda_release();
        self.half();
        self.scl_release();
        self.half();
        let v = self.sda.is_high();
        self.scl_low();
        self.half();
        v
    }

    /// Write a byte; true = acknowledged (SDA low in the ACK slot).
    fn write_byte(&mut self, byte: u8) -> bool {
        for i in (0..8).rev() {
            self.write_bit(byte & (1 << i) != 0);
        }
        !self.read_bit()
    }

    /// Read a byte; `ack` true = master ACKs (more bytes follow).
    fn read_byte(&mut self, ack: bool) -> u8 {
        let mut v = 0u8;
        for _ in 0..8 {
            v = (v << 1) | u8::from(self.read_bit());
        }
        self.write_bit(!ack);
        v
    }

    /// Address probe: START + address byte (write) + STOP.
    pub fn probe(&mut self, addr: u8) -> bool {
        self.start();
        let ack = self.write_byte(addr << 1);
        self.stop();
        ack
    }

    /// Probe with wire sampling: reports what the bus actually did.
    pub fn trace_probe(&mut self, addr: u8) -> ProbeTrace {
        self.start();
        let byte = addr << 1;
        let mut sampled = 0u8;
        for i in (0..8).rev() {
            let s = self.write_bit_sampled(byte & (1 << i) != 0);
            sampled = (sampled << 1) | u8::from(s);
        }
        let ack_low = !self.read_bit();
        self.stop();
        ProbeTrace {
            sent: byte,
            sampled,
            ack_low,
        }
    }

    /// Write the register pointer only (STOP separated).
    pub fn write_reg_only(&mut self, addr: u8, reg: u8) -> bool {
        self.start();
        let ok = self.write_byte(addr << 1) && self.write_byte(reg);
        self.stop();
        ok
    }

    /// I2C bus recovery: release both lines, clock SCL up to 9 times so a
    /// slave stuck mid-transaction (holding SDA low waiting for clocks)
    /// can finish its byte, then issue a STOP. Harmless on a healthy bus
    /// (both lines idle high; the pulses change nothing the slave cares
    /// about, and the STOP is a no-op boundary).
    pub fn bus_recover(&mut self) {
        self.sda_release();
        self.scl_release();
        self.half();
        for _ in 0..9 {
            self.scl_low();
            self.half();
            self.scl_release();
            self.half();
            // If SDA has been released by the slave, stop early.
            if self.sda.is_high() {
                break;
            }
        }
        // STOP: SDA low while SCL is high, then release SDA.
        self.sda_low();
        self.half();
        self.scl_release();
        self.half();
        self.sda_release();
        self.half();
    }

    /// Write register pointer + one value.
    pub fn write_reg(&mut self, addr: u8, reg: u8, val: u8) -> bool {
        self.write_regs(addr, reg, &[val])
    }

    /// Write register pointer + multiple values (auto-increment assumed).
    pub fn write_regs(&mut self, addr: u8, reg: u8, vals: &[u8]) -> bool {
        self.start();
        let mut ok = self.write_byte(addr << 1) && self.write_byte(reg);
        for v in vals {
            if !ok {
                break;
            }
            ok = self.write_byte(*v);
        }
        self.stop();
        ok
    }

    /// Repeated-start register read (the vendor driver's shape).
    pub fn read_reg(&mut self, addr: u8, reg: u8) -> Option<u8> {
        self.start();
        if !(self.write_byte(addr << 1) && self.write_byte(reg)) {
            self.stop();
            return None;
        }
        self.start(); // repeated start
        if !self.write_byte((addr << 1) | 1) {
            self.stop();
            return None;
        }
        let v = self.read_byte(false);
        self.stop();
        Some(v)
    }

    /// STOP-separated register read: pointer write with a STOP, then a
    /// fresh read transaction.
    pub fn read_reg_stop(&mut self, addr: u8, reg: u8) -> Option<u8> {
        if !self.write_reg_only(addr, reg) {
            return None;
        }
        self.start();
        if !self.write_byte((addr << 1) | 1) {
            self.stop();
            return None;
        }
        let v = self.read_byte(false);
        self.stop();
        Some(v)
    }

    /// Repeated-start multi-byte read from `reg` into `out`.
    pub fn read_regs(&mut self, addr: u8, reg: u8, out: &mut [u8]) -> bool {
        if out.is_empty() {
            return false;
        }
        self.start();
        if !(self.write_byte(addr << 1) && self.write_byte(reg)) {
            self.stop();
            return false;
        }
        self.start();
        if !self.write_byte((addr << 1) | 1) {
            self.stop();
            return false;
        }
        let last = out.len() - 1;
        for (i, b) in out.iter_mut().enumerate() {
            *b = self.read_byte(i != last);
        }
        self.stop();
        true
    }
}
