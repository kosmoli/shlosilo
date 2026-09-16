//! Touch driver (I2C1) for the pico2 bring-up rig.
//!
//! **The panel currently fitted carries a FocalTech FT6236** at 0x38
//! (chip id 0xA8 = 0x11): the vendor's example targets the *original* 2"
//! panel with a CST816D at 0x15, but this board has the swapped-in
//! larger panel (ST7796S display + FT6236 touch). The FT6236 was found
//! by bit-banged scanning after the controller path NACKed every
//! address and every CST816D-shaped access failed; the I2C controller
//! can now talk to it directly (5/5 probes ACK, registers readable).
//!
//! Both controllers are supported: `probe` identifies which one is
//! present (FT6236 first, then CST816D) and the rest dispatches on it.
//! - FT6236 registers per the FocalTech datasheet / Linux ft6236
//!   driver: 0x02 touch count, 0x03..0x06 point-1 (event in XH bits
//!   7..6, X/Y in 12-bit 4+8 form);
//! - CST816D registers per the vendor example (0xA7 id = 0xB6,
//!   0x01 gesture, 0x02 fingers, 0x03..0x06 X/Y).
//!
//! Pins: SDA=GP26, SCL=GP27, INT=GP17 (reads are polled over I2C),
//! RST=GP16 (shared with the LCD; the pulse is owned by `panel`).

use embassy_rp::i2c::{AbortReason, Blocking, Error as I2cError, I2c};
use embassy_rp::peripherals::I2C1;

/// FocalTech FT6236 (the fitted panel's controller).
pub const FT6236_ADDR: u8 = 0x38;
const FT6236_REG_DEV_MODE: u8 = 0x00;
const FT6236_REG_TD_STATUS: u8 = 0x02;
const FT6236_REG_P1_XH: u8 = 0x03;
const FT6236_REG_P1_XL: u8 = 0x04;
const FT6236_REG_P1_YH: u8 = 0x05;
const FT6236_REG_P1_YL: u8 = 0x06;
const FT6236_REG_CHIP_ID: u8 = 0xA8;
const FT6236_CHIP_ID: u8 = 0x11;

/// CST816D (the original 2" panel's controller; vendor example).
pub const CST816_ADDR: u8 = 0x15;
const CST816_REG_GESTURE: u8 = 0x01;
const CST816_REG_FINGERS: u8 = 0x02;
const CST816_REG_XPOS_H: u8 = 0x03;
const CST816_REG_XPOS_L: u8 = 0x04;
const CST816_REG_YPOS_H: u8 = 0x05;
const CST816_REG_YPOS_L: u8 = 0x06;
const CST816_REG_CHIP_ID: u8 = 0xA7;
const CST816_CHIP_ID: u8 = 0xB6;
const CST816_REG_IRQ_PULSE_WIDTH: u8 = 0xED;
const CST816_REG_NOR_SCAN_PER: u8 = 0xEE;
const CST816_REG_IRQ_CTL: u8 = 0xFA;
const CST816_REG_DIS_AUTO_SLEEP: u8 = 0xFE;

/// I2C configuration for the touch bus (400 kHz, the FT6236's rated
/// fast-mode speed; the bit-bang path runs slower).
pub fn i2c_config() -> embassy_rp::i2c::Config {
    let mut cfg = embassy_rp::i2c::Config::default();
    cfg.frequency = 400_000;
    cfg
}

type TouchI2c = I2c<'static, I2C1, Blocking>;

/// Which controller is fitted (detected by `probe`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Chip {
    Ft6236,
    Cst816,
}

impl Chip {
    pub fn name(self) -> &'static str {
        match self {
            Chip::Ft6236 => "FT6236",
            Chip::Cst816 => "CST816D",
        }
    }
}

/// One sampled point: raw values, no coordinate transform (the screen
/// mapping is settled on hardware during the bring-up).
pub struct Point {
    /// Contact count.
    pub fingers: u8,
    /// FT6236: point-1 event flag (0 down / 1 up / 2 contact / 3 none);
    /// CST816D: gesture id. Zero when idle.
    pub gesture: u8,
    pub x: u16,
    pub y: u16,
}

pub struct Touch {
    i2c: TouchI2c,
    freq: u32,
    chip: Option<Chip>,
}

fn nack() -> I2cError {
    I2cError::Abort(AbortReason::NoAcknowledge)
}

impl Touch {
    pub fn new(i2c: TouchI2c) -> Self {
        Self {
            i2c,
            freq: 400_000,
            chip: None,
        }
    }

    fn read_reg(&mut self, addr: u8, reg: u8) -> Result<u8, I2cError> {
        let mut b = [0u8; 1];
        self.i2c.blocking_write_read(addr, &[reg], &mut b)?;
        Ok(b[0])
    }

    fn write_reg(&mut self, addr: u8, reg: u8, val: u8) -> Result<(), I2cError> {
        self.i2c.blocking_write(addr, &[reg, val])
    }

    /// Identify the fitted controller: FT6236 (0x38, id 0xA8 = 0x11)
    /// first, then CST816D (0x15, id 0xA7 = 0xB6). Returns the chip and
    /// its chip-id byte.
    pub fn probe(&mut self) -> Result<(Chip, u8), I2cError> {
        if let Ok(id) = self.read_reg(FT6236_ADDR, FT6236_REG_CHIP_ID)
            && id == FT6236_CHIP_ID
        {
            self.chip = Some(Chip::Ft6236);
            return Ok((Chip::Ft6236, id));
        }
        if let Ok(id) = self.read_reg(CST816_ADDR, CST816_REG_CHIP_ID)
            && id == CST816_CHIP_ID
        {
            self.chip = Some(Chip::Cst816);
            return Ok((Chip::Cst816, id));
        }
        self.chip = None;
        Err(nack())
    }

    /// Post-reset configuration for the detected controller.
    pub fn configure(&mut self) -> Result<(), I2cError> {
        match self.chip {
            Some(Chip::Ft6236) => {
                // Device mode 0x00 = normal active (polling) operation.
                // The FT6236 wakes in this mode after reset; writing it
                // is an explicit anchor and matches the Linux driver's
                // power-on sequence.
                self.write_reg(FT6236_ADDR, FT6236_REG_DEV_MODE, 0x00)
            }
            Some(Chip::Cst816) => {
                // Vendor init: stay awake, point-event mode, scan
                // defaults.
                self.write_reg(CST816_ADDR, CST816_REG_DIS_AUTO_SLEEP, 0x01)?;
                self.write_reg(CST816_ADDR, CST816_REG_IRQ_PULSE_WIDTH, 0x01)?;
                self.write_reg(CST816_ADDR, CST816_REG_NOR_SCAN_PER, 0x01)?;
                self.write_reg(CST816_ADDR, CST816_REG_IRQ_CTL, 0x41)
            }
            None => Err(nack()),
        }
    }

    /// One point sample for the detected controller. `fingers == 0`
    /// means no contact.
    pub fn read_point(&mut self) -> Result<Point, I2cError> {
        match self.chip {
            Some(Chip::Ft6236) => {
                let status = self.read_reg(FT6236_ADDR, FT6236_REG_TD_STATUS)?;
                let fingers = status & 0x0F;
                let xh = self.read_reg(FT6236_ADDR, FT6236_REG_P1_XH)?;
                let xl = self.read_reg(FT6236_ADDR, FT6236_REG_P1_XL)?;
                let yh = self.read_reg(FT6236_ADDR, FT6236_REG_P1_YH)?;
                let yl = self.read_reg(FT6236_ADDR, FT6236_REG_P1_YL)?;
                Ok(Point {
                    fingers,
                    gesture: xh >> 6, // event flag
                    x: (u16::from(xh & 0x0F) << 8) | u16::from(xl),
                    y: (u16::from(yh & 0x0F) << 8) | u16::from(yl),
                })
            }
            Some(Chip::Cst816) => {
                let fingers = self.read_reg(CST816_ADDR, CST816_REG_FINGERS)?;
                let gesture = self.read_reg(CST816_ADDR, CST816_REG_GESTURE)?;
                let xh = self.read_reg(CST816_ADDR, CST816_REG_XPOS_H)?;
                let xl = self.read_reg(CST816_ADDR, CST816_REG_XPOS_L)?;
                let yh = self.read_reg(CST816_ADDR, CST816_REG_YPOS_H)?;
                let yl = self.read_reg(CST816_ADDR, CST816_REG_YPOS_L)?;
                Ok(Point {
                    fingers,
                    gesture,
                    x: (u16::from(xh & 0x0F) << 8) | u16::from(xl),
                    y: (u16::from(yh & 0x0F) << 8) | u16::from(yl),
                })
            }
            None => Err(nack()),
        }
    }

    // ---- diagnostics (bring-up; see the `i2c` console command) ----

    /// One electrical probe: write the register pointer 0 to `addr`; Ok
    /// means the device ACKed its address.
    pub fn probe_addr(&mut self, addr: u8) -> bool {
        self.i2c.blocking_write(addr, &[0x00]).is_ok()
    }

    /// Raw register read at an arbitrary address.
    pub fn read_reg_at(&mut self, addr: u8, reg: u8) -> Result<u8, I2cError> {
        self.read_reg(addr, reg)
    }

    /// Change the bus frequency (recreates the driver at the new speed).
    pub fn set_frequency(&mut self, freq: u32) {
        self.freq = freq;
        self.rebuild();
    }

    /// Current bus frequency (Hz).
    pub fn frequency(&self) -> u32 {
        self.freq
    }

    /// Recreate the I2C driver at the stored frequency. Used after a
    /// probe that repurposed the pins, and by `set_frequency`.
    ///
    /// SAFETY: the peripheral and both pins belong to this driver; a
    /// fresh `Peripherals::steal()` handle is legitimate as long as
    /// only one live driver exists, which the assignment below
    /// guarantees (the old driver has no hardware side effects on drop
    /// - the new construction simply re-applies the configuration).
    pub fn rebuild(&mut self) {
        let mut cfg = i2c_config();
        cfg.frequency = self.freq;
        let p = unsafe { embassy_rp::Peripherals::steal() };
        self.i2c = I2c::new_blocking(p.I2C1, p.PIN_27, p.PIN_26, cfg);
    }

    /// Read SDA/SCL as plain inputs (internal pull-ups on), then
    /// restore the bus. Both high = healthy idle; a stuck LOW line
    /// means a short, a device holding the bus, or missing pull-ups
    /// against a driven line. Returns (sda_high, scl_high).
    pub fn read_line_levels(&mut self) -> (bool, bool) {
        let p = unsafe { embassy_rp::Peripherals::steal() };
        let sda = embassy_rp::gpio::Input::new(p.PIN_26, embassy_rp::gpio::Pull::Up);
        let scl = embassy_rp::gpio::Input::new(p.PIN_27, embassy_rp::gpio::Pull::Up);
        let levels = (sda.is_high(), scl.is_high());
        drop(sda);
        drop(scl);
        self.rebuild(); // put the pins back on the I2C function
        levels
    }

    /// Read SDA/SCL with the internal PULL-DOWNs engaged: a connected
    /// module's pull-up network keeps the line high against the weaker
    /// internal pull-down, while a floating line is dragged low.
    /// Distinguishes "module side connected" from "floating line".
    pub fn read_line_pulldowns(&mut self) -> (bool, bool) {
        let p = unsafe { embassy_rp::Peripherals::steal() };
        let sda = embassy_rp::gpio::Input::new(p.PIN_26, embassy_rp::gpio::Pull::Down);
        let scl = embassy_rp::gpio::Input::new(p.PIN_27, embassy_rp::gpio::Pull::Down);
        let levels = (sda.is_high(), scl.is_high());
        drop(sda);
        drop(scl);
        self.rebuild();
        levels
    }

    /// Probe one address `n` times; returns the ACK count. A single ACK
    /// can be a bus artifact (observed on this bench); a real device
    /// answers every time.
    pub fn probe_addr_stats(&mut self, addr: u8, n: u32) -> u32 {
        let mut acks = 0u32;
        for _ in 0..n {
            if self.probe_addr(addr) {
                acks += 1;
            }
        }
        acks
    }

    /// STOP-separated register read: write the register pointer with a
    /// STOP, then read in a fresh transaction (compatibility shape for
    /// controllers that NACK a repeated start).
    pub fn read_reg_stop(&mut self, addr: u8, reg: u8) -> Result<u8, I2cError> {
        self.i2c.blocking_write(addr, &[reg])?;
        let mut b = [0u8; 1];
        self.i2c.blocking_read(addr, &mut b)?;
        Ok(b[0])
    }

    /// Multi-byte write (byte-level ACK behaviour probe).
    pub fn write_bytes(&mut self, addr: u8, bytes: &[u8]) -> Result<(), I2cError> {
        self.i2c.blocking_write(addr, bytes)
    }
}
