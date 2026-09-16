//! ST7796S panel driver for the pico2 bring-up rig.
//!
//! **The fitted panel is an ST7796S (320x480)**: the user swapped the
//! kit's original 2" 240x320 panel for a larger one so QR codes render
//! legibly. The vendor's `C/01-LCD` sequence (which this driver ports)
//! is in fact the Sitronix-family unlock + gamma chain that the ST7796S
//! accepts - the same command set with a different resolution.
//!
//! Pins (verified against the vendor schematic; see
//! `docs/pico2-hardware-pinmap.md`): SPI1 SCK=GP14, MOSI=GP15 (MISO is
//! not connected on this board), D/C=GP12, CS=GP13, RST=GP16 (shared
//! with the touch controller), BL=GP18.
//!
//! Scope: bring-up - solid fills and the corner-marked test pattern.
//! The 1bpp canvas + text/QR rendering (P2 UI) builds on the same
//! window-write path.

use embassy_rp::gpio::Output;
use embassy_rp::peripherals::SPI1;
use embassy_rp::spi::{Blocking, Config as SpiConfig, Phase, Polarity, Spi};
use embassy_time::{Duration, block_for};

/// Panel resolution: ST7796S standard, landscape-off portrait.
pub const WIDTH: u16 = 320;
pub const HEIGHT: u16 = 480;

/// Portrait scan direction: MADCTL = BGR only (no MX/MY flips).
const MADCTL_PORTRAIT: u8 = 0x08;

type LcdSpi = Spi<'static, SPI1, Blocking>;

/// SPI configuration: mode 0, 50 MHz to start (the vendor drives the
/// same panel far faster; raise once the rig is confirmed).
pub fn spi_config() -> SpiConfig {
    let mut cfg = SpiConfig::default();
    cfg.frequency = 50_000_000;
    cfg.phase = Phase::CaptureOnFirstTransition;
    cfg.polarity = Polarity::IdleLow;
    cfg
}

pub struct St7796 {
    spi: LcdSpi,
    dc: Output<'static>,
    cs: Output<'static>,
    bl: Output<'static>,
}

impl St7796 {
    pub fn new(spi: LcdSpi, dc: Output<'static>, cs: Output<'static>, bl: Output<'static>) -> Self {
        Self { spi, dc, cs, bl }
    }

    /// Backlight (GP18). High = on is the working assumption; `lcd bl`
    /// on the console exists to confirm the polarity on hardware.
    pub fn backlight(&mut self, on: bool) {
        if on {
            self.bl.set_high();
        } else {
            self.bl.set_low();
        }
    }

    /// Command byte with D/C low; leaves CS as-is (the caller frames).
    fn cmd(&mut self, c: u8) {
        self.dc.set_low();
        let _ = self.spi.blocking_write(&[c]);
        self.dc.set_high();
    }

    fn data(&mut self, d: &[u8]) {
        let _ = self.spi.blocking_write(d);
    }

    /// One command with its data bytes, CS framed around the pair.
    fn cmd_data(&mut self, c: u8, d: &[u8]) {
        self.cs.set_low();
        self.cmd(c);
        if !d.is_empty() {
            self.data(d);
        }
        self.cs.set_high();
    }

    /// Full init: the vendor register list, delays included. The
    /// hardware reset pulse is owned by `panel` (the line is shared
    /// with the touch controller and must be pulsed once for both).
    pub fn init(&mut self) {
        for &(c, d, delay_ms) in INIT_SEQ {
            self.cmd_data(c, d);
            if delay_ms > 0 {
                block_for(Duration::from_millis(delay_ms));
            }
        }
    }

    /// Column/row address window, then RAMWR. CS stays low for the pixel
    /// stream; the caller closes the frame.
    fn begin_frame(&mut self, x0: u16, y0: u16, x1: u16, y1: u16) {
        let xs = [(x0 >> 8) as u8, x0 as u8, (x1 >> 8) as u8, x1 as u8];
        let ys = [(y0 >> 8) as u8, y0 as u8, (y1 >> 8) as u8, y1 as u8];
        self.cmd_data(0x2A, &xs);
        self.cmd_data(0x2B, &ys);
        self.cs.set_low();
        self.cmd(0x2C);
    }

    /// Fill a rectangle with one RGB565 colour (the window is inclusive
    /// on both ends; coordinates are clamped to the panel).
    pub fn fill_rect(&mut self, x: u16, y: u16, w: u16, h: u16, color: u16) {
        if w == 0 || h == 0 || x >= WIDTH || y >= HEIGHT {
            return;
        }
        let w = w.min(WIDTH - x);
        let h = h.min(HEIGHT - y);
        self.begin_frame(x, y, x + w - 1, y + h - 1);
        let hi = (color >> 8) as u8;
        let lo = color as u8;
        const CHUNK_PX: usize = 512;
        let mut buf = [0u8; CHUNK_PX * 2];
        for i in (0..buf.len()).step_by(2) {
            buf[i] = hi;
            buf[i + 1] = lo;
        }
        let mut left = u32::from(w) * u32::from(h);
        while left > 0 {
            let px = left.min(CHUNK_PX as u32) as usize;
            let _ = self.spi.blocking_write(&buf[..px * 2]);
            left -= px as u32;
        }
        self.cs.set_high();
    }

    pub fn fill(&mut self, color: u16) {
        self.fill_rect(0, 0, WIDTH, HEIGHT, color);
    }

    /// Blit a 1bpp framebuffer to the full panel: row-major, MSB = leftmost
    /// pixel, `stride` bytes per row, `rows` rows of `w` pixels. Set bits
    /// render as `on` (RGB565), clear bits as black. Rows are expanded to
    /// RGB565 in a stack buffer and streamed; a full 320x480 frame is
    /// ~307 KB of SPI traffic (~50 ms at 50 MHz).
    pub fn blit_1bpp(&mut self, fb: &[u8], stride: usize, rows: usize, w: usize, on: u16) {
        debug_assert!(stride * 8 >= w);
        self.begin_frame(0, 0, (w - 1) as u16, (rows - 1) as u16);
        let hi = (on >> 8) as u8;
        let lo = on as u8;
        const MAX_W: usize = 320;
        let mut row_buf = [0u8; MAX_W * 2];
        for y in 0..rows {
            let src = &fb[y * stride..y * stride + stride];
            for (i, &byte) in src.iter().enumerate() {
                for bit in 0..8usize {
                    let px_idx = i * 8 + bit;
                    if px_idx >= w {
                        break;
                    }
                    let o = px_idx * 2;
                    if byte & (0x80 >> bit) != 0 {
                        row_buf[o] = hi;
                        row_buf[o + 1] = lo;
                    } else {
                        row_buf[o] = 0;
                        row_buf[o + 1] = 0;
                    }
                }
            }
            let _ = self.spi.blocking_write(&row_buf[..w * 2]);
        }
        self.cs.set_high();
    }

    /// Bring-up pattern: four horizontal bands (red/green/blue/white,
    /// top to bottom) plus a black marker block in ALL FOUR corners.
    /// Band order verifies the scan direction, hue verifies RGB/BGR,
    /// and the four corner blocks prove the configured resolution
    /// actually covers the glass (a block outside the addressable area
    /// is silently dropped by the panel window logic).
    pub fn test_pattern(&mut self) {
        let colors = [0xF800u16, 0x07E0, 0x001F, 0xFFFF];
        let band = HEIGHT / 4;
        for (i, &c) in colors.iter().enumerate() {
            self.fill_rect(0, i as u16 * band, WIDTH, band, c);
        }
        let s = 16u16;
        self.fill_rect(2, 2, s, s, 0x0000); // top-left
        self.fill_rect(WIDTH - s - 2, 2, s, s, 0x0000); // top-right
        self.fill_rect(2, HEIGHT - s - 2, s, s, 0x0000); // bottom-left
        self.fill_rect(WIDTH - s - 2, HEIGHT - s - 2, s, s, 0x0000); // bottom-right
    }
}

/// Register sequence: (command, data, delay after). Ported 1:1 from the
/// vendor's LCD_2IN_SetAttributes + LCD_2IN_InitReg (the Sitronix-family
/// unlock + gamma chain the ST7796S accepts).
const INIT_SEQ: &[(u8, &[u8], u64)] = &[
    (0x11, &[], 120), // SLPOUT
    (0x36, &[MADCTL_PORTRAIT], 0),
    (0x3A, &[0x05], 0), // COLMOD: 16-bit (RGB565)
    (0xF0, &[0xC3], 0), // command set control (unlock)
    (0xF0, &[0x96], 0),
    (0xB4, &[0x01], 0),
    (0xB7, &[0xC6], 0),
    (0xC0, &[0x80, 0x45], 0),
    (0xC1, &[0x13], 0),
    (0xC2, &[0xA7], 0),
    (0xC5, &[0x0A], 0),
    (0xE8, &[0x40, 0x8A, 0x00, 0x00, 0x29, 0x19, 0xA5, 0x33], 0),
    (
        0xE0,
        &[
            0xD0, 0x08, 0x0F, 0x06, 0x06, 0x33, 0x30, 0x33, 0x47, 0x17, 0x13, 0x13, 0x2B, 0x31,
        ],
        0,
    ),
    (
        0xE1,
        &[
            0xD0, 0x0A, 0x11, 0x0B, 0x09, 0x07, 0x2F, 0x33, 0x47, 0x38, 0x15, 0x16, 0x2C, 0x32,
        ],
        0,
    ),
    (0xF0, &[0x3C], 0),
    (0xF0, &[0x69], 120),
    (0x21, &[], 0), // INVON
    (0x29, &[], 0), // DISPON
];
