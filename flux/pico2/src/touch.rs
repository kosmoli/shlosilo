//! CST816D capacitive-touch driver (I2C1) for the pico2 bring-up rig.
//!
//! Pins: SDA=GP26, SCL=GP27, INT=GP17 (unused for now - reads are polled
//! over I2C), RST=GP16 (shared with the LCD; the pulse is owned by
//! `panel`). Register map and init recipe ported from the vendor's
//! `C/01-LCD/lib/Touch/CST816D.c`. I2C address 0x15, chip id (0xA7) = 0xB6.

use embassy_rp::i2c::{Blocking, Error as I2cError, I2c};
use embassy_rp::peripherals::I2C1;

pub const ADDR: u8 = 0x15;
pub const CHIP_ID: u8 = 0xB6;

const REG_GESTURE: u8 = 0x01;
const REG_FINGERS: u8 = 0x02;
const REG_XPOS_H: u8 = 0x03;
const REG_XPOS_L: u8 = 0x04;
const REG_YPOS_H: u8 = 0x05;
const REG_YPOS_L: u8 = 0x06;
const REG_CHIP_ID: u8 = 0xA7;
const REG_FW_VERSION: u8 = 0xA9;
const REG_IRQ_PULSE_WIDTH: u8 = 0xED;
const REG_NOR_SCAN_PER: u8 = 0xEE;
const REG_IRQ_CTL: u8 = 0xFA;
const REG_DIS_AUTO_SLEEP: u8 = 0xFE;

/// I2C configuration for the touch bus (vendor runs it at 400 kHz).
pub fn i2c_config() -> embassy_rp::i2c::Config {
    let mut cfg = embassy_rp::i2c::Config::default();
    cfg.frequency = 400_000;
    cfg
}

type TouchI2c = I2c<'static, I2C1, Blocking>;

/// One sampled point: raw registers, no coordinate transform. The screen
/// mapping (and the axis order for the portrait UI) is settled on hardware
/// during the P0/P1 bring-up.
pub struct Point {
    pub fingers: u8,
    pub gesture: u8,
    pub x: u16,
    pub y: u16,
}

pub struct Cst816 {
    i2c: TouchI2c,
}

impl Cst816 {
    pub fn new(i2c: TouchI2c) -> Self {
        Self { i2c }
    }

    fn read_reg(&mut self, reg: u8) -> Result<u8, I2cError> {
        let mut b = [0u8; 1];
        self.i2c.blocking_write_read(ADDR, &[reg], &mut b)?;
        Ok(b[0])
    }

    fn write_reg(&mut self, reg: u8, val: u8) -> Result<(), I2cError> {
        self.i2c.blocking_write(ADDR, &[reg, val])
    }

    /// Chip id + firmware revision; expect id 0xB6.
    pub fn probe(&mut self) -> Result<(u8, u8), I2cError> {
        let id = self.read_reg(REG_CHIP_ID)?;
        let fw = self.read_reg(REG_FW_VERSION)?;
        Ok((id, fw))
    }

    /// Vendor init (runs after the shared reset pulse): stay awake, point
    /// event mode, vendor scan defaults.
    pub fn configure(&mut self) -> Result<(), I2cError> {
        self.write_reg(REG_DIS_AUTO_SLEEP, 0x01)?;
        self.write_reg(REG_IRQ_PULSE_WIDTH, 0x01)?;
        self.write_reg(REG_NOR_SCAN_PER, 0x01)?;
        self.write_reg(REG_IRQ_CTL, 0x41)
    }

    /// One point sample, read register by register (vendor-path parity).
    /// `fingers == 0` means no contact.
    pub fn read_point(&mut self) -> Result<Point, I2cError> {
        let fingers = self.read_reg(REG_FINGERS)?;
        let gesture = self.read_reg(REG_GESTURE)?;
        let xh = self.read_reg(REG_XPOS_H)?;
        let xl = self.read_reg(REG_XPOS_L)?;
        let yh = self.read_reg(REG_YPOS_H)?;
        let yl = self.read_reg(REG_YPOS_L)?;
        let x = u16::from(xh & 0x0F) << 8 | u16::from(xl);
        let y = u16::from(yh & 0x0F) << 8 | u16::from(yl);
        Ok(Point {
            fingers,
            gesture,
            x,
            y,
        })
    }
}
