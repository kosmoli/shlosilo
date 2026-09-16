//! SD card probe/read on the board's TF slot (SPI0) - the P0 tail item.
//!
//! Pins (verified pin map, `docs/pico2-hardware-pinmap.md`): MISO=GP20,
//! CS=GP21 (manual GPIO), CLK=GP22, MOSI=GP23. The schematic shows the
//! SD_CS net also continuing through R4 (0R) to the display connector's
//! pin 10 ("SD_CS-1") - so this module doubles as the empirical test of
//! whether anything on the display side interferes with the SD bus.
//!
//! Protocol: SPI mode, per the SD Physical Layer Simplified Spec -
//! power-up clocks, CMD0 (idle), CMD8 (voltage/echo), ACMD41 loop
//! (ready), CMD58 (OCR/CCS). Runs at 400 kHz (the init speed).
//! Read-only: single-block reads (CMD17); no writes or erases here.

use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::SPI0;
use embassy_rp::spi::{Blocking, Config as SpiConfig, Phase, Polarity, Spi};
use embassy_time::{Duration, block_for};

const CMD0: u8 = 0x40; // GO_IDLE_STATE
const CMD8: u8 = 0x48; // SEND_IF_COND
const CMD17: u8 = 0x51; // READ_SINGLE_BLOCK
const CMD55: u8 = 0x77; // APP_CMD
const CMD58: u8 = 0x7A; // READ_OCR
const ACMD41: u8 = 0x69; // SD_SEND_OP_COND

pub struct Sd {
    spi: Spi<'static, SPI0, Blocking>,
    cs: Output<'static>,
}

/// Handshake outcome, for the console report.
pub struct ProbeReport {
    /// R1 of CMD0: 0x01 = entered idle (card present), 0xFF = no response.
    pub cmd0: u8,
    /// CMD8 echo (v2 cards): expect 00 00 01 AA.
    pub cmd8: Option<[u8; 4]>,
    pub acmd41_tries: u32,
    /// Final ACMD41 R1: 0x00 = ready.
    pub acmd41_final: u8,
    pub ocr: Option<u32>,
}

impl ProbeReport {
    /// CCS bit of the OCR: true = SDHC/SDXC (block addressing).
    pub fn sdhc(&self) -> bool {
        self.ocr.map(|o| o & (1 << 30) != 0).unwrap_or(false)
    }
}

impl Sd {
    pub fn new() -> Self {
        let p = unsafe { embassy_rp::Peripherals::steal() };
        let mut cfg = SpiConfig::default();
        cfg.frequency = 400_000;
        cfg.phase = Phase::CaptureOnFirstTransition;
        cfg.polarity = Polarity::IdleLow;
        // CS as a manual GPIO, idle high; the SPI driver covers the
        // other three pins (GP22 CLK / GP23 MOSI / GP20 MISO).
        let cs = Output::new(p.PIN_21, Level::High);
        let spi = Spi::new_blocking(p.SPI0, p.PIN_22, p.PIN_23, p.PIN_20, cfg);
        Self { spi, cs }
    }

    fn xfer_byte(&mut self, out: u8) -> u8 {
        let mut r = [0u8; 1];
        let _ = self.spi.blocking_transfer(&mut r, &[out]);
        r[0]
    }

    /// Send a 6-byte command frame; collect R1 (up to 8 response bytes).
    fn send_cmd(&mut self, cmd: u8, arg: u32, crc: u8) -> u8 {
        let frame = [
            cmd,
            (arg >> 24) as u8,
            (arg >> 16) as u8,
            (arg >> 8) as u8,
            arg as u8,
            crc,
        ];
        for &b in &frame {
            let _ = self.xfer_byte(b);
        }
        for _ in 0..8 {
            let r = self.xfer_byte(0xFF);
            if r & 0x80 == 0 {
                return r;
            }
        }
        0xFF
    }

    /// Raise CS and give the card one trailing clock (per the spec).
    fn deselect(&mut self) {
        self.cs.set_high();
        let _ = self.xfer_byte(0xFF);
    }

    /// Full SPI-mode init handshake; returns the stage-by-stage report.
    pub fn probe(&mut self) -> ProbeReport {
        // Power-up: >= 74 clocks with CS high and MOSI high.
        self.cs.set_high();
        for _ in 0..10 {
            let _ = self.xfer_byte(0xFF);
        }
        block_for(Duration::from_millis(5));

        self.cs.set_low();
        let cmd0 = self.send_cmd(CMD0, 0, 0x95);
        self.deselect();

        let mut report = ProbeReport {
            cmd0,
            cmd8: None,
            acmd41_tries: 0,
            acmd41_final: 0xFF,
            ocr: None,
        };
        if cmd0 != 0x01 {
            return report;
        }

        // CMD8: interface condition (voltage + echo pattern), SD v2+.
        self.cs.set_low();
        let r1 = self.send_cmd(CMD8, 0x1AA, 0x87);
        if r1 == 0x01 {
            let mut echo = [0u8; 4];
            for b in &mut echo {
                *b = self.xfer_byte(0xFF);
            }
            report.cmd8 = Some(echo);
        }
        self.deselect();

        // ACMD41 loop: wait for the card to leave idle state.
        for i in 0..3000u32 {
            self.cs.set_low();
            let r55 = self.send_cmd(CMD55, 0, 0x01);
            self.deselect();
            if r55 > 0x01 {
                break;
            }
            self.cs.set_low();
            let r41 = self.send_cmd(ACMD41, 0x4000_0000, 0x01);
            self.deselect();
            report.acmd41_tries = i + 1;
            report.acmd41_final = r41;
            if r41 == 0x00 {
                break;
            }
            block_for(Duration::from_micros(200));
        }
        if report.acmd41_final != 0x00 {
            return report;
        }

        // CMD58: OCR - CCS bit distinguishes SDHC/SDXC from SDSC.
        self.cs.set_low();
        let r1 = self.send_cmd(CMD58, 0, 0x01);
        if r1 == 0x00 {
            let mut ocr = [0u8; 4];
            for b in &mut ocr {
                *b = self.xfer_byte(0xFF);
            }
            report.ocr = Some(u32::from_be_bytes(ocr));
        }
        self.deselect();
        report
    }

    /// Read one 512-byte block. LBA addressing; block 0 has the same
    /// address under LBA and byte modes, so this is valid for SDHC and
    /// SDSC alike at block 0 (higher blocks assume LBA/SDHC).
    pub fn read_block(&mut self, block: u32, buf: &mut [u8; 512]) -> Result<(), &'static str> {
        self.cs.set_low();
        let r1 = self.send_cmd(CMD17, block, 0x01);
        if r1 != 0x00 {
            self.deselect();
            return Err("CMD17 rejected");
        }
        // Data token 0xFE within a generous window; any other non-0xFF
        // byte is an error token (the card itself failed the read).
        for _ in 0..50_000u32 {
            let b = self.xfer_byte(0xFF);
            if b == 0xFE {
                let tx = [0xFFu8; 512];
                let mut rx = [0u8; 512];
                if self.spi.blocking_transfer(&mut rx, &tx).is_err() {
                    self.deselect();
                    return Err("transfer error");
                }
                buf.copy_from_slice(&rx);
                let _ = self.xfer_byte(0xFF); // CRC16 byte 1
                let _ = self.xfer_byte(0xFF); // CRC16 byte 2
                self.deselect();
                return Ok(());
            }
            if b != 0xFF {
                self.deselect();
                return Err("data error token");
            }
        }
        self.deselect();
        Err("no data token")
    }
}
