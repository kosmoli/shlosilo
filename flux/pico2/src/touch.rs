//! Touch driver for the pico2 bring-up rig.
//!
//! **Fitted panel: ST7796S display + FocalTech FT6236 touch at 0x38**
//! (chip id 0xA8 = 0x11) - the user swapped the kit's original 2" panel
//! (ST7789V2 + CST816D at 0x15) for a larger one. Both touch controllers
//! are supported; `probe` identifies which is present and the rest
//! dispatches on it.
//!
//! **Transport: bit-banged GPIO (see `bitbang.rs`), not the I2C
//! controller.** Two measured reasons:
//!
//! 1. the RP2350's DW I2C block, as driven by embassy-rp's blocking API,
//!    has no timeout on its status waits - a bus state it does not like
//!    (observed right after the shared reset pulse, and once during a
//!    full-address scan) hangs the whole firmware in a spin loop;
//! 2. the bit-bang path has fixed timing and cannot hang: the worst case
//!    is reading a wrong bit, and the caller retries.
//!
//! Touch polling needs a few hundred microseconds per sample, far below
//! what a fixed-timing bit-bang at ~100 kHz provides, so there is no
//! performance argument for the controller path here.
//!
//! Pins: SDA=GP26, SCL=GP27, INT=GP17 (reads are polled over I2C),
//! RST=GP16 (shared with the LCD; the pulse is owned by `panel`).
//!
//! FT6236 registers (FocalTech datasheet / Linux ft6236 driver):
//! 0x00 device mode, 0x02 touch count, 0x03..0x06 point 1 (XH carries
//! the event flag in bits 7..6 and x bits 11..8 in 3..0).
//! CST816D registers (vendor example): 0xA7 id = 0xB6, 0x01 gesture,
//! 0x02 fingers, 0x03..0x06 X/Y.

use crate::bitbang::Bb;
use embassy_rp::gpio::Pull;

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

/// Default bus speed: half-bit delay in CPU cycles. The core runs at
/// 150 MHz, so 500 cycles ~= 3.3 us per half-bit ~= 100 kHz equivalent
/// (comfortably inside the FT6236's rating, and ~4x faster than the
/// forensics default).
pub const DEFAULT_HALF_CYCLES: u32 = 500;

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

/// Raw-to-screen mapping for the fitted panel (FT6236, 320x480).
///
/// The digitizer's raw space is rotated 90 degrees relative to the
/// display: screen x follows raw y (increasing) and screen y follows raw
/// x (decreasing), with non-uniform scales. Coefficients were fitted by
/// least squares over five ground-truth touches (the four corner blocks
/// plus the screen centre, 2026-09-16 calibration run); max residual
/// ~14 px, i.e. inside finger-tip precision. Integer milli-units keep the
/// maths float-free (and cheap on the M33).
///
///   screen_x = (727 * raw_y - 13390) / 1000
///   screen_y = (-1829 * raw_x + 524182) / 1000
const CAL_SX_A: i32 = 727;
const CAL_SX_B: i32 = -13390;
const CAL_SY_A: i32 = -1829;
const CAL_SY_B: i32 = 524182;

/// Map a raw touch sample onto screen pixels (clamped to the panel).
pub fn to_screen(raw_x: u16, raw_y: u16) -> (u16, u16) {
    let sx = (CAL_SX_A * i32::from(raw_y) + CAL_SX_B) / 1000;
    let sy = (CAL_SY_A * i32::from(raw_x) + CAL_SY_B) / 1000;
    (
        sx.clamp(0, crate::lcd::WIDTH as i32 - 1) as u16,
        sy.clamp(0, crate::lcd::HEIGHT as i32 - 1) as u16,
    )
}

/// One sampled point: raw values, no coordinate transform.
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
    bb: Bb,
    chip: Option<Chip>,
}

impl Touch {
    pub fn new() -> Self {
        Self {
            bb: Bb::new(false, DEFAULT_HALF_CYCLES),
            chip: None,
        }
    }

    /// The bit-bang engine (shared with the forensics console commands).
    pub fn bb(&mut self) -> &mut Bb {
        &mut self.bb
    }

    /// Replace the bit-bang engine (swap/pacing changes from the console).
    pub fn rebuild_bb(&mut self, swap: bool, half_cycles: u32) {
        self.bb = Bb::new(swap, half_cycles);
    }

    /// Restore the default engine (documented pin roles, standard speed).
    pub fn restore_bb(&mut self) {
        self.rebuild_bb(false, DEFAULT_HALF_CYCLES);
    }

    /// Current half-bit delay in CPU cycles.
    pub fn half_cycles(&self) -> u32 {
        self.bb.half_cycles()
    }

    fn read_reg(&mut self, addr: u8, reg: u8) -> Result<u8, ()> {
        self.bb.read_reg(addr, reg).ok_or(())
    }

    fn write_reg(&mut self, addr: u8, reg: u8, val: u8) -> Result<(), ()> {
        if self.bb.write_reg(addr, reg, val) {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Identify the fitted controller: FT6236 (0x38, id 0xA8 = 0x11)
    /// first, then CST816D (0x15, id 0xA7 = 0xB6). Returns the chip and
    /// its chip-id byte.
    pub fn probe(&mut self) -> Result<(Chip, u8), ()> {
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
        Err(())
    }

    /// Post-reset configuration for the detected controller.
    pub fn configure(&mut self) -> Result<(), ()> {
        match self.chip {
            Some(Chip::Ft6236) => {
                // Device mode 0x00 = normal active (polling) mode, the
                // power-on default; wrote it as an explicit anchor.
                self.write_reg(FT6236_ADDR, FT6236_REG_DEV_MODE, 0x00)
            }
            Some(Chip::Cst816) => {
                // Vendor init: stay awake, point-event mode, scan defaults.
                self.write_reg(CST816_ADDR, CST816_REG_DIS_AUTO_SLEEP, 0x01)?;
                self.write_reg(CST816_ADDR, CST816_REG_IRQ_PULSE_WIDTH, 0x01)?;
                self.write_reg(CST816_ADDR, CST816_REG_NOR_SCAN_PER, 0x01)?;
                self.write_reg(CST816_ADDR, CST816_REG_IRQ_CTL, 0x41)
            }
            None => Err(()),
        }
    }

    /// One point sample for the detected controller. `fingers == 0`
    /// means no contact.
    pub fn read_point(&mut self) -> Result<Point, ()> {
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
            None => Err(()),
        }
    }

    // ---- diagnostics (bring-up; see the `i2c` console command) ----

    /// I2C bus recovery (9 clocks + STOP): releases a slave that is
    /// holding SDA low after a half-completed transaction.
    pub fn bus_recover(&mut self) {
        self.bb.bus_recover();
    }

    /// One electrical probe: send the address with no data; true means
    /// the device ACKed its address.
    pub fn probe_addr(&mut self, addr: u8) -> bool {
        self.bb.probe(addr)
    }

    /// Raw register read at an arbitrary address.
    pub fn read_reg_at(&mut self, addr: u8, reg: u8) -> Result<u8, ()> {
        self.read_reg(addr, reg)
    }

    /// Probe one address `n` times; returns the ACK count. A single ACK
    /// can be a bus artifact; a real device answers every time.
    pub fn probe_addr_stats(&mut self, addr: u8, n: u32) -> u32 {
        let mut acks = 0u32;
        for _ in 0..n {
            if self.probe_addr(addr) {
                acks += 1;
            }
        }
        acks
    }

    /// STOP-separated register read: pointer write with a STOP, then a
    /// fresh read transaction.
    pub fn read_reg_stop(&mut self, addr: u8, reg: u8) -> Result<u8, ()> {
        self.bb.read_reg_stop(addr, reg).ok_or(())
    }

    /// Multi-byte write.
    pub fn write_bytes(&mut self, addr: u8, bytes: &[u8]) -> Result<(), ()> {
        if bytes.is_empty() {
            return Err(());
        }
        let reg = bytes[0];
        if self.bb.write_regs(addr, reg, &bytes[1..]) {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Read SDA/SCL as plain inputs with the internal pull-ups on: both
    /// high = healthy idle; a stuck LOW line points at a short or a
    /// device holding the bus. Returns (sda_high, scl_high).
    pub fn read_line_levels(&mut self) -> (bool, bool) {
        self.bb.set_pulls(Pull::Up);
        (self.bb.sda_is_high(), self.bb.scl_is_high())
    }

    /// Read SDA/SCL against the internal pull-downs: a connected
    /// module's pull-up network keeps the lines high, a floating line
    /// is dragged low. Returns (sda_high, scl_high).
    pub fn read_line_pulldowns(&mut self) -> (bool, bool) {
        self.bb.set_pulls(Pull::Down);
        let levels = (self.bb.sda_is_high(), self.bb.scl_is_high());
        self.bb.set_pulls(Pull::Up);
        levels
    }
}
