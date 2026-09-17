//! Bench command channel over the USB console (bidirectional serial).
//!
//! Development channel for the pico2 bring-up stage: the host feeds test
//! fixtures - a UR string, single frame or multipart fragments - over the
//! serial port and the board signs them with the session mnemonic, printing
//! the result. This is how a real-size fixture (e.g. the 12.4 KiB Sparrow
//! signet PSBT) reaches the board before a QR scanner exists.
//!
//! NOT a production input path: production appearances take inputs via QR /
//! dice with on-device confirmation.
//!
//! Bench-only surface (audit #17 P1-01): the commands that inject entropy or
//! load test key material, or poke the TRNG, are gated behind the `bench`
//! cargo feature and are NOT COMPILED into production images - `xmrseed`
//! (fixed XMR entropy), `entropy` (test-vector mnemonic) and the TRNG
//! diagnostic family (`trng`, `trngdump`, `trngrst`, `trngprobe`,
//! `trngemb`). Production keeps the UR input channel and the status
//! commands; its identity is visible as `build=production` on `version` and
//! on the heartbeat line.
//!
//! Protocol: ASCII lines (`\n` or `\r` terminates; `\r\n` yields one line).
//! Responses are `log` records on the same port.

use core::cell::RefCell;
#[cfg(feature = "bench")]
use core::fmt::Write as _;

extern crate alloc;

use embassy_futures::yield_now;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_time::{Duration, Instant, Timer, block_for};
use embassy_usb_logger::ReceiverHandler;

use shlosilo::business::sign::SignInput;
use shlosilo::encoding::sha256;
use shlosilo::entropy::mnemonic::{Mnemonic, WordCount};
use shlosilo::error::{ShlosiloError, ShlosiloErrorKind};
use shlosilo::ur::ur_decode;
use shlosilo::ur::ur_encode::UrTypeTag;
use shlosilo::ur::ur_multipart::{UrMultipartDecoder, UrMultipartEncoder};

use crate::sign_smoke;
#[cfg(feature = "bench")]
use crate::sign_smoke::BufWriter;
#[cfg(feature = "bench")]
use crate::trng::TrngError;
use crate::trng::{self, TrngStats};

/// Longest accepted input line: covers a single-frame UR (UR_URI_MAX_LEN =
/// 8192) and every multipart fragment (MULTIPART_FRAME_MAX_LEN is larger,
/// but practical fragments - a few hundred bytes of bytewords - fit here).
const LINE_CAP: usize = 8192;

/// Signing output buffer: the FFI ceiling (multipart payload + overhead).
const SIGN_OUT_CAP: usize = 16384 + 512;

/// XMR signed-blob storage: the smoke fixture's signed txset is 3458 B
/// (measured on the host); 8 KiB leaves room for larger single-tx fixtures.
const XMR_OUT_CAP: usize = 8 * 1024;

/// Entropy handed to the XMR signing path: two conditioned 32-byte outputs
/// (the §B.5 contract requires >=16 B; the signer hashes this into its
/// purpose-separated RNG stream, so conditioning plus hashing absorbs any
/// source bias).
const XMR_ENTROPY_LEN: usize = 64;

/// Build flavor (audit #17): `bench` when the bench-only console surface is
/// compiled in, `production` otherwise; the probe features (`perf-timing` /
/// `perf-bench`) append `+perf` (`bench+perf`, or `perf` without bench) so a
/// perf-experiment image is distinguishable at a glance. Carried by
/// `version` and every heartbeat line.
pub(crate) const BUILD_FLAVOR: &str = if cfg!(feature = "bench") {
    if cfg!(any(feature = "perf-timing", feature = "perf-bench")) {
        "bench+perf"
    } else {
        "bench"
    }
} else if cfg!(any(feature = "perf-timing", feature = "perf-bench")) {
    "perf"
} else {
    "production"
};

/// Session state for the command channel.
struct ConsoleState {
    line: [u8; LINE_CAP],
    line_len: usize,
    /// Timestamp (ms, monotonic) of the last received byte. A partial line
    /// older than STALE_LINE_MS is discarded before new data is appended:
    /// on the bench, a host-side tty echo can send the device's own boot
    /// banner back into its RX during the enumeration window (echo is on
    /// until a host program sets the port to raw); the banner has no
    /// terminator of its own, so without this the *first* command after
    /// every boot merged with the leftover banner text and was rejected.
    last_byte_ms: u64,
    /// A line arrived that did not fit; drop it and report once.
    line_overflow: bool,
    /// Session mnemonic override (indices + word count) set by `entropy`.
    /// `None` = the built-in dice fixture (the same wallet as the boot smoke).
    session: Option<([u16; 24], u8)>,
    /// In-flight multipart UR session.
    decoder: Option<UrMultipartDecoder>,
    /// Pending XMR signing request: the decoded UR payload, owned on the
    /// heap (16 KiB-class; above the PSRAM threshold it lands there).
    xmr_pending: Option<alloc::vec::Vec<u8>>,
    /// Fixed-entropy override for XMR (`xmrseed <hex>`): when set, the next
    /// XMR job uses this instead of the TRNG, enabling a byte-exact A/B
    /// against a host recomputation. Bench-build only (audit #17): the
    /// field does not exist in production images.
    #[cfg(feature = "bench")]
    xmr_seed: Option<([u8; 64], usize)>,
    /// Last signed XMR blob, retrievable via `xmrout <hex_off> <hex_len>`.
    xmr_out: [u8; XMR_OUT_CAP],
    xmr_out_len: usize,
    /// Raw-ROSC capture (`trngraw`; bench builds): 192-bit raw blocks from
    /// the fully-bypassed TRNG, held for `trngrawout` to stream. The
    /// SP 800-90B source-characterisation buffer.
    #[cfg(feature = "bench")]
    raw_buf: Option<alloc::vec::Vec<u8>>,
}

/// A partial line with no terminator for this long is stale (see
/// `last_byte_ms`); any command is delivered in one USB transfer, so this
/// threshold cannot cut a legitimate command apart.
const STALE_LINE_MS: u64 = 1_000;

impl ConsoleState {
    const fn new() -> Self {
        Self {
            line: [0u8; LINE_CAP],
            line_len: 0,
            last_byte_ms: 0,
            line_overflow: false,
            session: None,
            decoder: None,
            xmr_pending: None,
            #[cfg(feature = "bench")]
            xmr_seed: None,
            xmr_out: [0u8; XMR_OUT_CAP],
            xmr_out_len: 0,
            #[cfg(feature = "bench")]
            raw_buf: None,
        }
    }

    /// Append incoming bytes; process each completed line. Returns a
    /// deferred job when the line requests one (TRNG streaming must run
    /// with awaits — see `handle_data`).
    fn feed(&mut self, data: &[u8]) -> Option<TrngJob> {
        if !data.is_empty() {
            let now = Instant::now().as_millis();
            if self.line_len > 0 && now.saturating_sub(self.last_byte_ms) > STALE_LINE_MS {
                // Discard the stale partial (see `last_byte_ms`).
                self.line_len = 0;
                self.line_overflow = false;
            }
            self.last_byte_ms = now;
        }
        let mut job = None;
        for &b in data {
            match b {
                b'\n' | b'\r' => {
                    if self.line_overflow {
                        self.line_overflow = false;
                        self.line_len = 0;
                        log::info!("[err] input line too long (>{LINE_CAP} bytes); dropped");
                    } else if self.line_len > 0 {
                        // Copy out of `self` so `process` can take &mut self.
                        let mut buf = [0u8; LINE_CAP];
                        let n = self.line_len;
                        buf[..n].copy_from_slice(&self.line[..n]);
                        self.line_len = 0;
                        if let Some(j) = self.process(&buf[..n]) {
                            job = Some(j);
                        }
                    }
                }
                _ => {
                    if self.line_len < LINE_CAP {
                        self.line[self.line_len] = b;
                        self.line_len += 1;
                    } else {
                        self.line_overflow = true;
                    }
                }
            }
        }
        job
    }

    fn process(&mut self, raw: &[u8]) -> Option<TrngJob> {
        let line = trim_ascii(raw);
        if line.is_empty() {
            return None;
        }

        // Bench instrumentation: echo what reached the command parser, so a
        // silently-dropped input is attributable (never arrived vs. arrived
        // but produced nothing).
        {
            let n = line.len().min(56);
            let s = core::str::from_utf8(&line[..n]).unwrap_or("<bin>");
            log::info!("[rx] {}B {:?}", line.len(), s);
        }

        if line.starts_with(b"ur:") {
            return self.handle_ur(line);
        }

        let (cmd, args) = split_first_word(line);
        match cmd {
            b"help" => self.cmd_help(),
            b"version" => self.cmd_version(),
            b"smoke" => self.cmd_smoke(),
            b"panel" => self.cmd_panel(),
            b"lcd" => self.cmd_lcd(args),
            b"touch" => self.cmd_touch(args),
            b"touchint" => return Some(parse_touchint(args)),
            b"touchdraw" => return Some(parse_touchdraw(args)),
            b"sd" => self.cmd_sd(args),
            b"ui" => return self.cmd_ui(args),
            b"i2c" => self.cmd_i2c(args),
            b"bbscan" => self.cmd_bbscan(args),
            b"bbid" => self.cmd_bbid(args),
            b"bbrd" => self.cmd_bbrd(args),
            b"bbwr" => self.cmd_bbwr(args),
            b"bbinit" => self.cmd_bbinit(args),
            b"bbtrace" => self.cmd_bbtrace(args),
            b"heap" => self.cmd_heap(args),
            #[cfg(feature = "bench")]
            b"entropy" => self.cmd_entropy(args),
            #[cfg(feature = "bench")]
            b"trng" => return Some(parse_trng_job(args)),
            #[cfg(feature = "bench")]
            b"trngdump" => return Some(TrngJob::simple(JobMode::Dump)),
            #[cfg(feature = "bench")]
            b"trngrst" => return Some(TrngJob::simple(JobMode::Rst)),
            #[cfg(feature = "bench")]
            b"trngprobe" => return Some(parse_trng_probe(args)),
            #[cfg(feature = "bench")]
            b"trngemb" => return Some(parse_trng_emb(args)),
            #[cfg(feature = "bench")]
            b"trngraw" => return Some(parse_trngraw(args)),
            #[cfg(feature = "bench")]
            b"trngrawout" => return Some(parse_trngrawout(args)),
            #[cfg(feature = "bench")]
            b"trngtrace" => return Some(parse_trngtrace(args)),
            #[cfg(feature = "bench")]
            b"trngcheck" => return Some(parse_trngcheck(args)),
            #[cfg(feature = "bench")]
            b"temp" => match crate::read_die_temp_c() {
                Some(v) => log::info!("[temp] {v:.1} C"),
                None => log::info!("[temp] unavailable"),
            },
            b"xmrout" => self.cmd_xmrout(args),
            #[cfg(feature = "perf-timing")]
            b"xtiming" => crate::perf_timing::log_phases(),
            #[cfg(feature = "perf-timing")]
            b"xmrchunk" => self.cmd_xmrchunk(args),
            #[cfg(feature = "perf-bench")]
            b"perfbench" => self.cmd_perfbench(args),
            #[cfg(feature = "bench")]
            b"xmrseed" => self.cmd_xmrseed(args),
            b"alloctest" => self.cmd_alloctest(args),
            b"alloctrace" => self.cmd_alloctrace(),
            b"psramtest" => return Some(TrngJob::simple(JobMode::PsramTest)),
            #[cfg(feature = "bench")]
            b"cam" => return self.cmd_cam(args),
            b"faultclr" => crate::fault::clear(),
            _ => {
                let echo = core::str::from_utf8(cmd).unwrap_or("<non-utf8>");
                log::info!("[err] unknown command: {echo} (try: help)");
            }
        }
        None
    }

    fn cmd_help(&self) {
        log::info!("[help] console commands (build: {}):", BUILD_FLAVOR);
        log::info!("[help]   help            this text");
        log::info!("[help]   version         version + C-ABI version");
        log::info!("[help]   smoke           boot signing-smoke report (also replayed every 20 s)");
        log::info!(
            "[help]   panel           panel bring-up: reset + touch + LCD init + test pattern"
        );
        log::info!("[help]   lcd pattern|fill <hex565>|bl <0|1>   ST7796S panel ops");
        log::info!("[help]   touch [n]       touch samples (raw x/y; n<=8, 100 ms apart)");
        log::info!("[help]   i2c freq <khz> | scan | scan0 | id <a> | rd <a> <r> | wr <a> <b..>");
        log::info!("[help]        | lines | pulldown | recover | rstprobe <a>  (bus diagnostics)");
        log::info!(
            "[help]   touchint [ms]   monitor TP_INT (GP17) for edge activity (touch the panel)"
        );
        log::info!(
            "[help]   touchdraw [secs]  paint a trail at the mapped touch position (drag finger)"
        );
        log::info!("[help]   sd probe | sd read <blk>  TF-slot SD card (SPI0, read-only probe)");
        log::info!("[help]   ui orient | draw <welcome|detail|qr> | run [secs] | qr <text>");
        log::info!("[help]   ui ur <hex>   UR carousel: cycle fountain frames as QR (X exits)");
        log::info!("[help]   bbscan|bbid|bbrd|bbwr|bbinit|bbtrace  bit-banged I2C on GP26/27");
        log::info!("[help]                   (swap, d=<cycles>, numbers hex; bring-up forensics)");
        log::info!("[help]   heap [reset]    allocator used/free/peak (reset re-arms peak)");
        #[cfg(feature = "bench")]
        log::info!("[help]   entropy <hex>   set session mnemonic from test-vector entropy");
        #[cfg(feature = "bench")]
        log::info!(
            "[help]                   (16/20/24/28/32 bytes; default = built-in dice fixture)"
        );
        log::info!(
            "[help]   ur:<type>/...   feed a UR (single frame, or multipart fragments in any"
        );
        log::info!(
            "[help]                   order); signs on completion with the session mnemonic"
        );
        #[cfg(feature = "bench")]
        log::info!("[help]   trng [stress] [cond] [sample=<n>] [chain=<0-4>] [timeout=<ms>] [n]");
        #[cfg(feature = "bench")]
        log::info!(
            "[help]                   n raw blocks (24 B) as hex; cond = n conditioned 32-byte"
        );
        #[cfg(feature = "bench")]
        log::info!(
            "[help]                   outputs (SHA-256 over two blocks - the consumer path);"
        );
        #[cfg(feature = "bench")]
        log::info!(
            "[help]                   stress = sample 2; overrides are restored on job exit"
        );
        #[cfg(feature = "bench")]
        log::info!("[help]   trngdump        raw TRNG register dump (bring-up diagnostic)");
        #[cfg(feature = "bench")]
        log::info!("[help]   trngrst         RESETS-block cycle for the TRNG, then a dump");
        #[cfg(feature = "bench")]
        log::info!("[help]   trngprobe [ms]  cold-start + trace every BUSY/ISR transition");
        #[cfg(feature = "bench")]
        log::info!("[help]   trngemb [n]     read n blocks via the upstream embassy driver");
        #[cfg(feature = "bench")]
        log::info!(
            "[help]   trngraw <n> [chain] [sample]  raw-ROSC capture (all checks bypassed; SP 800-90B data)"
        );
        #[cfg(feature = "bench")]
        log::info!("[help]   trngrawout [start] [pace_ms]  stream the last raw capture as hex");
        #[cfg(feature = "bench")]
        log::info!(
            "[help]   trngtrace [blocks] [chain] [sample] [window]  trace BUSY/VALID around raw blocks"
        );
        #[cfg(feature = "bench")]
        log::info!(
            "[help]   trngcheck [nblocks] [timeout_ms]  capture checked-path blocks (production reader; dump via trngrawout)"
        );
        #[cfg(feature = "bench")]
        log::info!("[help]   temp            read the on-die temperature sensor");
        #[cfg(feature = "bench")]
        log::info!(
            "[help]   cam id | rx [ms] | pins [n] | pwdn <z|0|1> | grab [n] | dump [stride] [byte]"
        );
        #[cfg(feature = "bench")]
        log::info!(
            "[help]        | reg <hexreg> [hexval]   OV5640 bring-up: SCCB, FIFO and pad probes"
        );
        #[cfg(feature = "bench")]
        log::info!("[help]                   OV5640 bring-up: SCCB id, frame stats, hex PGM dump");
        log::info!("[help]   xmrout <off> <n> fetch a hex segment of the last signed XMR blob");
        #[cfg(feature = "perf-timing")]
        log::info!("[help]   xtiming         dump the XMR phase-timing table (probe builds)");
        #[cfg(feature = "perf-timing")]
        log::info!(
            "[help]   xmrchunk <n>    BP+ multiexp chunk size (table placement; probe builds)"
        );
        #[cfg(feature = "perf-bench")]
        log::info!(
            "[help]   perfbench [name] ...  probes; ctm <n> <chunk> <iters>, xchain <n> <iters> <tail> <gen>, vt2f <iters>"
        );
        log::info!("[help]   ur:xmr-txunsigned/...  signs with TRNG entropy (deferred job;");
        log::info!("[help]                   fetch the result with xmrout)");
        log::info!("[help]   psramtest       verify PSRAM r/w with patterns at 5 offsets;");
        log::info!("[help]                   maps the psram heap on success");
        log::info!("[help]   alloctest <sz>  probe a single allocation (64k/256k/1m/2m...);");
        log::info!("[help]                   'sweep' = standard ladder, 'free' = heap stats");
        log::info!("[help]   alloctrace      print the allocation trace ring (survives resets)");
        log::info!("[help]   faultclr        clear the pending [crash] record");
        log::info!("[help] lines end with \\n or \\r");
    }

    fn cmd_version(&self) {
        let v = shlosilo::ffi::version::SHLOSILO_VERSION_STRING.trim_end_matches('\0');
        let cabi = shlosilo::ffi::version::SHLOSILO_CABI_VERSION_STRING.trim_end_matches('\0');
        log::info!("[ver] {v} (cabi {cabi}) build={}", BUILD_FLAVOR);
    }

    fn cmd_smoke(&self) {
        match sign_smoke::report() {
            Some(r) => log::info!("{r}"),
            None => log::info!("[smoke] report not ready yet"),
        }
    }

    /// `panel`: re-run the full panel bring-up (shared reset pulse, touch
    /// probe + configure, LCD init, test pattern).
    fn cmd_panel(&self) {
        if !crate::panel::reinit() {
            log::info!("[err] panel: not installed");
        }
    }

    /// `lcd pattern` | `lcd fill <rgb565 hex>` | `lcd bl <0|1>` - bring-up
    /// operations for the ST7796S panel (see flux/pico2/src/lcd.rs).
    fn cmd_lcd(&self, args: &[u8]) {
        let (sub, rest) = split_first_word(args);
        if sub.is_empty() || sub == b"pattern" {
            match crate::panel::with_panel(|p| p.lcd.test_pattern()) {
                Some(()) => log::info!("[lcd] test pattern drawn (bands r/g/b/w + origin chip)"),
                None => log::info!("[err] lcd: panel not installed"),
            }
            return;
        }
        match sub {
            b"fill" => {
                let Some(color) = parse_hex_u16(rest) else {
                    log::info!("[err] lcd: usage: lcd fill <rgb565 hex, e.g. f800>");
                    return;
                };
                match crate::panel::with_panel(|p| p.lcd.fill(color)) {
                    Some(()) => log::info!("[lcd] filled 240x320 with 0x{color:04x}"),
                    None => log::info!("[err] lcd: panel not installed"),
                }
            }
            b"bl" => {
                let on = match trim_ascii(rest) {
                    b"1" | b"on" => Some(true),
                    b"0" | b"off" => Some(false),
                    _ => None,
                };
                match on {
                    Some(on) => match crate::panel::with_panel(|p| p.lcd.backlight(on)) {
                        Some(()) => log::info!("[lcd] backlight {}", if on { "on" } else { "off" }),
                        None => log::info!("[err] lcd: panel not installed"),
                    },
                    None => log::info!("[err] lcd: usage: lcd bl <0|1>"),
                }
            }
            _ => log::info!("[err] lcd: usage: lcd pattern | lcd fill <hex565> | lcd bl <0|1>"),
        }
    }

    /// `i2c ...`: bus diagnostics for the panel bring-up.
    ///   `i2c freq <khz>`           set the touch bus frequency
    ///   `i2c scan`                 scan I2C1 (GP26/27) 0x08..0x77
    ///   `i2c scan0`                scan I2C0 (GP28/29, the camera SCCB pins)
    ///   `i2c rd <addr> <reg>`      raw register read on I2C1
    ///   `i2c lines`                read SDA/SCL idle levels as GPIO
    fn cmd_i2c(&self, args: &[u8]) {
        let (sub, rest) = split_first_word(args);
        match sub {
            b"freq" => {
                let khz = core::str::from_utf8(trim_ascii(rest))
                    .ok()
                    .and_then(|s| s.parse::<u32>().ok());
                match khz {
                    Some(k) if (10..=1000).contains(&k) => {
                        // Bit-bang pacing: half = 50e6 / f_hz CPU cycles
                        // (150 MHz core / (3 halves per bit)).
                        let half = (50_000_000u32 / (k * 1000)).clamp(40, 200_000);
                        match crate::panel::with_panel(|p| p.touch.bb().set_half_cycles(half)) {
                            Some(()) => {
                                log::info!("[i2c] bit-bang pace = {k} kHz (half {half} cycles)")
                            }
                            None => log::info!("[err] i2c: panel not installed"),
                        }
                    }
                    _ => log::info!("[err] i2c: usage: i2c freq <khz> (10..=1000)"),
                }
            }
            b"scan" => match crate::panel::with_panel(|p| {
                let mut n = 0u32;
                for addr in 0x08u8..=0x77 {
                    if p.touch.probe_addr(addr) {
                        n += 1;
                        log::info!("[i2c] bus1 ACK 0x{addr:02x}");
                    }
                }
                // Explicit verdicts for the known touch-controller candidates.
                for (addr, name) in [(0x15u8, "CST816D"), (0x2E, "CST816S"), (0x38, "FT6236")] {
                    let ok = p.touch.probe_addr(addr);
                    log::info!(
                        "[i2c] candidate {name} 0x{addr:02x}: {}",
                        if ok { "ACK" } else { "NACK" }
                    );
                }
                n
            }) {
                Some(n) => log::info!(
                    "[i2c] bus1 scan done: {n} device(s), {} kHz",
                    crate::panel::with_panel(|p| 50_000_000u32 / p.touch.half_cycles())
                        .unwrap_or(0)
                        / 1000
                ),
                None => log::info!("[err] i2c: panel not installed"),
            },
            b"scan0" => {
                // The camera SCCB pins (GP28/29) are unowned at runtime, so a
                // fresh handled set is legitimate; the bus is built for this
                // scan only and dropped afterwards.
                let p = unsafe { embassy_rp::Peripherals::steal() };
                let mut cfg = embassy_rp::i2c::Config::default();
                cfg.frequency = 100_000;
                let mut bus = embassy_rp::i2c::I2c::new_blocking(p.I2C0, p.PIN_29, p.PIN_28, cfg);
                let mut n = 0u32;
                for addr in 0x08u8..=0x77 {
                    if bus.blocking_write(addr, &[0x00]).is_ok() {
                        n += 1;
                        log::info!("[i2c] bus0 ACK 0x{addr:02x}");
                    }
                }
                log::info!("[i2c] bus0 scan done: {n} device(s), 100 kHz");
            }
            b"rd" => {
                let mut w = rest
                    .split(|b: &u8| b.is_ascii_whitespace())
                    .filter(|w| !w.is_empty());
                let addr = w.next().and_then(parse_hex_u8);
                let reg = w.next().and_then(parse_hex_u8);
                match (addr, reg) {
                    (Some(addr), Some(reg)) => {
                        match crate::panel::with_panel(|p| p.touch.read_reg_at(addr, reg)) {
                            Some(Ok(v)) => {
                                log::info!("[i2c] rd 0x{addr:02x}[0x{reg:02x}] = 0x{v:02x}")
                            }
                            Some(Err(e)) => {
                                log::info!("[i2c] rd 0x{addr:02x}[0x{reg:02x}] failed: {e:?}")
                            }
                            None => log::info!("[err] i2c: panel not installed"),
                        }
                    }
                    _ => log::info!("[err] i2c: usage: i2c rd <addr_hex> <reg_hex>"),
                }
            }
            b"lines" => match crate::panel::with_panel(|p| p.touch.read_line_levels()) {
                Some((sda, scl)) => log::info!(
                    "[i2c] bus1 idle levels (pull-up): SDA={} SCL={}",
                    if sda { "high" } else { "LOW" },
                    if scl { "high" } else { "LOW" }
                ),
                None => log::info!("[err] i2c: panel not installed"),
            },
            b"id" => {
                let addr = trim_ascii(rest)
                    .split(|b: &u8| b.is_ascii_whitespace())
                    .next()
                    .and_then(parse_hex_u8);
                match addr {
                    Some(addr) => {
                        let r = crate::panel::with_panel(|p| {
                            let acks = p.touch.probe_addr_stats(addr, 5);
                            log::info!("[i2c] id {addr:#04x}: write probes 5 -> {acks} ACK");
                            for reg in [0x00u8, 0xa7u8] {
                                match p.touch.read_reg_stop(addr, reg) {
                                    Ok(v) => log::info!(
                                        "[i2c] id {addr:#04x}: rd1 {reg:#04x} (stop-sep) = {v:#04x}"
                                    ),
                                    Err(e) => log::info!(
                                        "[i2c] id {addr:#04x}: rd1 {reg:#04x} (stop-sep) failed: {e:?}"
                                    ),
                                }
                                match p.touch.read_reg_at(addr, reg) {
                                    Ok(v) => log::info!(
                                        "[i2c] id {addr:#04x}: rd {reg:#04x} (restart) = {v:#04x}"
                                    ),
                                    Err(e) => log::info!(
                                        "[i2c] id {addr:#04x}: rd {reg:#04x} (restart) failed: {e:?}"
                                    ),
                                }
                            }
                        });
                        if r.is_none() {
                            log::info!("[err] i2c: panel not installed");
                        }
                    }
                    None => log::info!("[err] i2c: usage: i2c id <addr_hex>"),
                }
            }
            b"wr" => {
                let mut w = rest
                    .split(|b: &u8| b.is_ascii_whitespace())
                    .filter(|w| !w.is_empty());
                let addr = w.next().and_then(parse_hex_u8);
                let mut buf = [0u8; 4];
                let mut n = 0usize;
                while n < buf.len() {
                    match w.next().and_then(parse_hex_u8) {
                        Some(v) => {
                            buf[n] = v;
                            n += 1;
                        }
                        None => break,
                    }
                }
                match addr {
                    Some(addr) if n > 0 => {
                        let bytes = &buf[..n];
                        match crate::panel::with_panel(|p| p.touch.write_bytes(addr, bytes)) {
                            Some(Ok(())) => {
                                log::info!("[i2c] wr {addr:#04x}: {n} byte(s) all ACKed")
                            }
                            Some(Err(e)) => {
                                log::info!("[i2c] wr {addr:#04x}: failed at byte: {e:?}")
                            }
                            None => log::info!("[err] i2c: panel not installed"),
                        }
                    }
                    _ => log::info!("[err] i2c: usage: i2c wr <addr_hex> <b0> [b1] [b2] [b3]"),
                }
            }
            b"rstprobe" => {
                let addr = trim_ascii(rest)
                    .split(|b: &u8| b.is_ascii_whitespace())
                    .next()
                    .and_then(parse_hex_u8);
                match addr {
                    Some(addr) => {
                        let r = crate::panel::with_panel(|p| {
                            log::info!(
                                "[i2c] rstprobe {addr:#04x}: pulsed shared reset (GP16); the LCD blanks - run `panel` afterwards"
                            );
                            p.rst.set_low();
                            block_for(Duration::from_millis(10));
                            p.rst.set_high();
                            let mut waited: u64 = 0;
                            for target in [0u64, 50, 100, 200, 500] {
                                if target > waited {
                                    block_for(Duration::from_millis(target - waited));
                                    waited = target;
                                }
                                let ok = p.touch.probe_addr(addr);
                                log::info!(
                                    "[i2c] rstprobe +{target} ms: {}",
                                    if ok { "ACK" } else { "NACK" }
                                );
                            }
                        });
                        if r.is_none() {
                            log::info!("[err] i2c: panel not installed");
                        }
                    }
                    None => log::info!("[err] i2c: usage: i2c rstprobe <addr_hex>"),
                }
            }
            b"recover" => match crate::panel::with_panel(|p| {
                p.touch.bus_recover();
                let after = p.touch.read_line_levels();
                (after.0, after.1)
            }) {
                Some((sda, scl)) => log::info!(
                    "[i2c] bus recovery (9 clocks + STOP); after: SDA={} SCL={}",
                    if sda { "high" } else { "LOW (still stuck!)" },
                    if scl { "high" } else { "LOW" }
                ),
                None => log::info!("[err] i2c: panel not installed"),
            },
            b"pulldown" => match crate::panel::with_panel(|p| p.touch.read_line_pulldowns()) {
                Some((sda, scl)) => log::info!(
                    "[i2c] bus1 with pull-downs: SDA={} SCL={} (high = external pull-ups present)",
                    if sda { "high" } else { "LOW" },
                    if scl { "high" } else { "LOW" }
                ),
                None => log::info!("[err] i2c: panel not installed"),
            },
            _ => log::info!(
                "[err] i2c: usage: freq <khz> | scan | scan0 | id <a> | rd <a> <r> | wr <a> <b..> | lines | pulldown | recover | rstprobe <a>"
            ),
        }
    }

    /// Run `f` with a temporary bit-bang engine installed on the touch
    /// bus (pin roles and pacing per the command arguments). The default
    /// engine is restored afterwards. The engine is borrowed from the
    /// touch driver - it owns GP26/27, so all bus users share one owner.
    fn with_bb<R>(
        &self,
        swap: bool,
        half: u32,
        f: impl FnOnce(&mut crate::bitbang::Bb) -> R,
    ) -> Option<R> {
        crate::panel::with_panel(|p| {
            p.touch.rebuild_bb(swap, half);
            let r = f(p.touch.bb());
            p.touch.restore_bb();
            r
        })
    }

    /// `bbscan [swap] [consec] [d=<cycles>]`: bit-banged scan of
    /// 0x08..0x77 (numbers hex; `consec` = required consecutive ACKs,
    /// default 2; `d=` = half-bit delay in CPU cycles). Reports every
    /// address that ACKs, its consecutive run, and for addresses that
    /// reach the bar a register-0 read. Immune to the controller-level
    /// spurious ACKs: consecutive probes filter them out.
    fn cmd_bbscan(&self, args: &[u8]) {
        let a = parse_bb_args(args);
        let consec = a.nums[0].map(|v| v.clamp(1, 5)).unwrap_or(2);
        let half = a.half.unwrap_or(crate::bitbang::DEFAULT_HALF_CYCLES);
        let r = self.with_bb(a.swap, half, |bb| {
            log::info!(
                "[bb] scan 0x08..0x77 (swap={}, half={half} cyc, {consec} consecutive ACKs required)",
                a.swap
            );
            let mut found = 0u32;
            let mut flakes = 0u32;
            for addr in 0x08u8..=0x77 {
                let mut acks = 0u32;
                for _ in 0..consec {
                    if bb.probe(addr) {
                        acks += 1;
                    } else {
                        break;
                    }
                }
                if acks == consec {
                    found += 1;
                    match bb.read_reg(addr, 0x00) {
                        Some(v) => {
                            log::info!("[bb]  0x{addr:02x}: {acks}/{consec} ACKs, reg00=0x{v:02x}")
                        }
                        None => {
                            log::info!("[bb]  0x{addr:02x}: {acks}/{consec} ACKs, reg00 read FAILED")
                        }
                    }
                } else if acks > 0 {
                    flakes += 1;
                    log::info!("[bb]  0x{addr:02x}: flake ({acks}/{consec})");
                }
            }
            log::info!("[bb] scan done: {found} candidate(s), {flakes} flake(s)");
        });
        if r.is_none() {
            log::info!("[err] bb: panel not installed");
        }
    }

    /// `bbid [swap] [addr] [d=<cycles>]`: assess one address over
    /// bit-bang - five probes, a wire trace of the address byte (which
    /// bits were seen on SDA, and whether the ACK slot was pulled low),
    /// then register reads (0xA7 chip id + 0x00..0x06 status) in both
    /// transaction shapes.
    fn cmd_bbid(&self, args: &[u8]) {
        let a = parse_bb_args(args);
        let addr = a.nums[0].map(|v| v as u8).unwrap_or(0x15);
        let half = a.half.unwrap_or(crate::bitbang::DEFAULT_HALF_CYCLES);
        let r = self.with_bb(a.swap, half, |bb| {
            let mut acks = 0u32;
            for _ in 0..5 {
                if bb.probe(addr) {
                    acks += 1;
                }
            }
            log::info!("[bb] id 0x{addr:02x}: probes 5 -> {acks} ACK");
            let t = bb.trace_probe(addr);
            log::info!(
                "[bb] id 0x{addr:02x}: trace sent=0b{:08b} sampled=0b{:08b} ack_slot={}",
                t.sent,
                t.sampled,
                if t.ack_low {
                    "LOW (ACK)"
                } else {
                    "high (NACK)"
                }
            );
            for reg in [0xA7u8, 0x00, 0x01, 0x02, 0x03, 0x06] {
                match bb.read_reg(addr, reg) {
                    Some(v) => log::info!("[bb] id 0x{addr:02x}: rd {reg:#04x} = {v:#04x}"),
                    None => log::info!("[bb] id 0x{addr:02x}: rd {reg:#04x} NACK"),
                }
            }
            match bb.read_reg_stop(addr, 0xA7) {
                Some(v) => log::info!("[bb] id 0x{addr:02x}: rd 0xa7 (stop-sep) = {v:#04x}"),
                None => log::info!("[bb] id 0x{addr:02x}: rd 0xa7 (stop-sep) NACK"),
            }
        });
        if r.is_none() {
            log::info!("[err] bb: panel not installed");
        }
    }

    /// `bbrd [swap] <addr> <reg> [n] [d=<cycles>]`: bit-banged multi-byte
    /// register read (repeated start), n capped at 32.
    fn cmd_bbrd(&self, args: &[u8]) {
        let a = parse_bb_args(args);
        let (Some(addr), Some(reg)) = (a.nums[0], a.nums[1]) else {
            log::info!("[err] bb: usage: bbrd [swap] <addr> <reg> [n] [d=<cycles>]  (numbers hex)");
            return;
        };
        let n = a.nums[2].map(|v| v.clamp(1, 32)).unwrap_or(1) as usize;
        let half = a.half.unwrap_or(crate::bitbang::DEFAULT_HALF_CYCLES);
        let r = self.with_bb(a.swap, half, |bb| {
            let mut buf = [0u8; 32];
            if bb.read_regs(addr as u8, reg as u8, &mut buf[..n]) {
                let mut hex = [0u8; 64];
                let s = sign_smoke::to_hex(&buf[..n], &mut hex);
                log::info!("[bb] rd 0x{addr:02x}[0x{reg:02x}..{n}]: {s}");
            } else {
                log::info!("[bb] rd 0x{addr:02x}[0x{reg:02x}]: NACK");
            }
        });
        if r.is_none() {
            log::info!("[err] bb: panel not installed");
        }
    }

    /// `bbwr [swap] <addr> <reg> <val> [val2] [d=<cycles>]`: bit-banged
    /// write of one or two register values.
    fn cmd_bbwr(&self, args: &[u8]) {
        let a = parse_bb_args(args);
        let (Some(addr), Some(reg), Some(val)) = (a.nums[0], a.nums[1], a.nums[2]) else {
            log::info!(
                "[err] bb: usage: bbwr [swap] <addr> <reg> <val> [val2] [d=]  (numbers hex)"
            );
            return;
        };
        let half = a.half.unwrap_or(crate::bitbang::DEFAULT_HALF_CYCLES);
        let r = self.with_bb(a.swap, half, |bb| {
            let ok = match a.nums[3] {
                Some(val2) => bb.write_regs(addr as u8, reg as u8, &[val as u8, val2 as u8]),
                None => bb.write_reg(addr as u8, reg as u8, val as u8),
            };
            log::info!(
                "[bb] wr 0x{addr:02x} {reg:#04x}=0x{val:02x}: {}",
                if ok { "ACK" } else { "NACK" }
            );
        });
        if r.is_none() {
            log::info!("[err] bb: panel not installed");
        }
    }

    /// `bbinit [swap] [addr] [d=<cycles>]`: reset pulse (GP16), then the
    /// vendor init writes over bit-bang (DisAutoSleep + scan/IRQ
    /// defaults), then a chip-id read; redraws the display at the end
    /// (the shared reset blanks it).
    fn cmd_bbinit(&self, args: &[u8]) {
        let a = parse_bb_args(args);
        let addr = a.nums[0].map(|v| v as u8).unwrap_or(0x15);
        let half = a.half.unwrap_or(crate::bitbang::DEFAULT_HALF_CYCLES);
        crate::panel::with_panel(|p| {
            p.rst.set_low();
            block_for(Duration::from_millis(10));
            p.rst.set_high();
        });
        block_for(Duration::from_millis(300));
        let r = self.with_bb(a.swap, half, |bb| {
            log::info!(
                "[bb] init 0x{addr:02x}: post-reset probe = {}",
                if bb.probe(addr) { "ACK" } else { "NACK" }
            );
            for (reg, val, name) in [
                (0xFEu8, 0x01u8, "DisAutoSleep"),
                (0xED, 0x01, "IrqPulseWidth"),
                (0xEE, 0x01, "NorScanPer"),
                (0xFA, 0x41, "IrqCtl(point)"),
            ] {
                let ok = bb.write_reg(addr, reg, val);
                log::info!(
                    "[bb] init: {name} <- 0x{val:02x}: {}",
                    if ok { "ACK" } else { "NACK" }
                );
            }
            match bb.read_reg(addr, 0xA7) {
                Some(v) => log::info!("[bb] init: chip id 0xa7 = 0x{v:02x} (CST816D = 0xb6)"),
                None => log::info!("[bb] init: chip id read NACK"),
            }
        });
        if r.is_none() {
            log::info!("[err] bb: panel not installed");
        }
        crate::panel::with_panel(|p| {
            p.lcd.init();
            p.lcd.test_pattern();
        });
        log::info!("[bb] init done; display redrawn");
    }

    /// `bbtrace [swap] [addr] [d=<cycles>]`: three traced address probes
    /// - the raw wire view (sent vs sampled SDA bits, ACK slot level).
    fn cmd_bbtrace(&self, args: &[u8]) {
        let a = parse_bb_args(args);
        let addr = a.nums[0].map(|v| v as u8).unwrap_or(0x15);
        let half = a.half.unwrap_or(crate::bitbang::DEFAULT_HALF_CYCLES);
        let r = self.with_bb(a.swap, half, |bb| {
            log::info!("[bb] trace 0x{addr:02x} (swap={}, half={half} cyc)", a.swap);
            for i in 0..3 {
                let t = bb.trace_probe(addr);
                log::info!(
                    "[bb] #{i} sent=0b{:08b} sampled=0b{:08b} ack_slot={}",
                    t.sent,
                    t.sampled,
                    if t.ack_low {
                        "LOW (ACK)"
                    } else {
                        "high (NACK)"
                    }
                );
            }
            log::info!(
                "[bb] SDA idle after traces: {}",
                if bb.sda_level() {
                    "high"
                } else {
                    "LOW (stuck)"
                }
            );
        });
        if r.is_none() {
            log::info!("[err] bb: panel not installed");
        }
    }

    /// `ui draw <welcome|detail|qr>` | `ui run [secs]` | `ui qr <text>`:
    /// the mono UI (1bpp canvas + 8x16 ASCII text + QR + O/X zones).
    /// `draw` renders one page statically, `run` starts the interactive
    /// demo (touch-driven page switching, bounded window), `qr` renders
    /// an arbitrary string as a QR page.
    fn cmd_ui(&self, args: &[u8]) -> Option<TrngJob> {
        let (sub, rest) = split_first_word(args);
        match sub {
            b"orient" => {
                crate::ui::orientation_pattern();
                log::info!(
                    "[ui] orientation pattern drawn (edge labels UP/DOWN/LEFT/RIGHT + L marker)"
                );
            }
            b"draw" => {
                let name = trim_ascii(rest);
                let page = match name {
                    b"" | b"welcome" => crate::ui::Page::Welcome,
                    b"detail" => crate::ui::Page::Detail,
                    b"qr" => crate::ui::Page::Qr,
                    _ => {
                        log::info!("[err] ui: usage: ui draw <welcome|detail|qr>");
                        return None;
                    }
                };
                match crate::ui::show(page, None) {
                    Ok(()) => log::info!("[ui] page drawn"),
                    Err(()) => log::info!("[err] ui: QR encode failed"),
                }
            }
            b"run" => return Some(parse_ui_run(rest)),
            b"ur" => {
                let hex = trim_ascii(rest);
                let mut buf = [0u8; UR_PAYLOAD_MAX];
                match parse_hex(hex, &mut buf) {
                    Some(n) if n > 0 => {
                        let slot = unsafe { &mut *core::ptr::addr_of_mut!(UR_PAYLOAD) };
                        slot[..n].copy_from_slice(&buf[..n]);
                        UR_PAYLOAD_LEN.store(n, core::sync::atomic::Ordering::Relaxed);
                        log::info!("[ui] UR carousel payload staged ({n} B)");
                        return Some(parse_ui_ur());
                    }
                    _ => log::info!(
                        "[err] ui: usage: ui ur <hex payload, <= {UR_PAYLOAD_MAX} bytes>"
                    ),
                }
            }
            b"qr" => {
                let s = match core::str::from_utf8(trim_ascii(rest)) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        log::info!("[err] ui: usage: ui qr <text>");
                        return None;
                    }
                };
                // The text lives in the console line buffer; copy to a
                // static so the job can use it after this call returns.
                let n = s.len().min(QR_TEXT_MAX);
                let slot = unsafe { &mut *core::ptr::addr_of_mut!(QR_TEXT) };
                slot[..n].copy_from_slice(&s.as_bytes()[..n]);
                QR_TEXT_LEN.store(n, core::sync::atomic::Ordering::Relaxed);
                return Some(TrngJob::simple(JobMode::UiQr));
            }
            _ => log::info!(
                "[err] ui: usage: ui orient | ui draw <welcome|detail|qr> | ui run [secs] | ui qr <text>"
            ),
        }
        None
    }

    /// `sd probe` | `sd read <block_hex>`: the board's TF slot on SPI0
    /// (MISO=GP20, CS=GP21, CLK=GP22, MOSI=GP23). `probe` runs the SPI
    /// init handshake (CMD0 -> CMD8 -> ACMD41 -> CMD58) and reports each
    /// stage; `read` initialises and reads one 512-byte block. Read-only:
    /// this module performs no writes or erases.
    ///
    /// This is also the empirical half of the SD_CS question: the net
    /// runs to the display connector's pin 10 via R4 (0R), so a clean
    /// card handshake proves nothing there interferes.
    /// `cam id | grab [n] | dump [stride] [byte] | reg <hexreg> [hexval]`:
    /// the OV5640 bring-up surface (bench-only - the camera is the P3 scan
    /// input). `id` re-reads the sensor id over SCCB; `grab`/`dump` queue
    /// deferred capture jobs (frames stream over the console).
    #[cfg(feature = "bench")]
    fn cmd_cam(&self, args: &[u8]) -> Option<TrngJob> {
        fn dec(s: &[u8]) -> Option<u32> {
            core::str::from_utf8(s)
                .ok()
                .and_then(|s| s.trim().parse().ok())
        }
        let (sub, rest) = split_first_word(args);
        match sub {
            b"id" => {
                match crate::camera::with_camera(|c| {
                    let id = c.read_id();
                    c.sensor_id = id;
                    id
                }) {
                    Some(id) => log::info!("[cam] sensor id {id:#06x} (OV5640 = 0x5640)"),
                    None => log::info!("[err] cam: not initialised"),
                }
                None
            }
            b"grab" => {
                let mut job = TrngJob::simple(JobMode::CamGrab);
                job.arg = dec(split_first_word(rest).0).unwrap_or(1);
                Some(job)
            }
            b"rx" => {
                let mut job = TrngJob::simple(JobMode::CamRx);
                job.arg = dec(split_first_word(rest).0).unwrap_or(1000);
                Some(job)
            }
            b"pwdn" => {
                let mode = match split_first_word(rest).0 {
                    b"0" => 0u8,
                    b"1" => 1u8,
                    _ => 2u8, // anything else = high-Z
                };
                match crate::camera::with_camera(|c| c.set_pwdn(mode)) {
                    Some(()) => log::info!(
                        "[cam] PWDN <- {}",
                        if mode == 0 {
                            "low (driven)"
                        } else if mode == 1 {
                            "high (driven)"
                        } else {
                            "high-Z (input, vendor default)"
                        }
                    ),
                    None => log::info!("[err] cam: not initialised"),
                }
                None
            }
            b"pins" => {
                let n = dec(split_first_word(rest).0)
                    .unwrap_or(20_000)
                    .clamp(1, 200_000);
                let h = crate::camera::sample_pins(n);
                log::info!(
                    "[cam] pad samples ({n}): VSYNC(GP8) {}/{} high, HREF(GP9) {}/{}, \
                     PCLK(GP10) {}/{}, XCLK(GP11) {}/{} (0 = stuck low, n = stuck high)",
                    h[0],
                    n,
                    h[1],
                    n,
                    h[2],
                    n,
                    h[3],
                    n
                );
                None
            }
            b"dump" => {
                let (a, rest2) = split_first_word(rest);
                let mut job = TrngJob::simple(JobMode::CamDump);
                job.arg = dec(a).unwrap_or(2); // stride
                job.off = dec(split_first_word(rest2).0).unwrap_or(0) as usize;
                Some(job)
            }
            b"reg" => {
                let (a, rest2) = split_first_word(rest);
                match (parse_hex_u16(a), rest2.is_empty()) {
                    (Some(r), true) => match crate::camera::with_camera(|c| c.rd(r)) {
                        Some(v) => log::info!("[cam] reg {r:#06x} = {v:#04x}"),
                        None => log::info!("[err] cam: not initialised"),
                    },
                    (Some(r), false) => match parse_hex_u8(split_first_word(rest2).0) {
                        Some(v) => match crate::camera::with_camera(|c| c.wr(r, v)) {
                            Some(()) => log::info!("[cam] reg {r:#06x} <- {v:#04x}"),
                            None => log::info!("[err] cam: not initialised"),
                        },
                        None => log::info!("[err] cam reg: bad value"),
                    },
                    _ => log::info!("[err] cam reg <hexreg> [hexval]"),
                }
                None
            }
            _ => {
                log::info!(
                    "[err] cam: id | grab [n] | dump [stride] [byte] | reg <hexreg> [hexval]"
                );
                None
            }
        }
    }

    fn cmd_sd(&self, args: &[u8]) {
        let (sub, rest) = split_first_word(args);
        match sub {
            b"probe" | b"" => {
                let mut sd = crate::sd::Sd::new();
                let r = sd.probe();
                log::info!(
                    "[sd] CMD0 -> 0x{:02x} (0x01 = card idle, 0xff = no response)",
                    r.cmd0
                );
                if let Some(e) = r.cmd8 {
                    log::info!(
                        "[sd] CMD8 echo = {:02x} {:02x} {:02x} {:02x} (expect 00 00 01 aa)",
                        e[0],
                        e[1],
                        e[2],
                        e[3]
                    );
                }
                log::info!(
                    "[sd] ACMD41: {} tries, final R1 0x{:02x}",
                    r.acmd41_tries,
                    r.acmd41_final
                );
                if let Some(ocr) = r.ocr {
                    log::info!(
                        "[sd] OCR = 0x{ocr:08x} CCS={} ({})",
                        r.sdhc() as u8,
                        if r.sdhc() { "SDHC/SDXC" } else { "SDSC" }
                    );
                }
                if r.acmd41_final == 0x00 {
                    log::info!("[sd] card ready; try `sd read 0`");
                } else if r.cmd0 == 0x01 {
                    log::info!("[err] sd: card responded but never left idle (ACMD41)");
                } else {
                    log::info!("[err] sd: no card in the TF slot (or the bus is open)");
                }
            }
            b"read" => {
                let Some(block) = parse_hex_u32(rest) else {
                    log::info!("[err] sd: usage: sd read <block_hex, e.g. 0>");
                    return;
                };
                let mut sd = crate::sd::Sd::new();
                let r = sd.probe();
                if r.acmd41_final != 0x00 {
                    log::info!("[err] sd: card not ready (run `sd probe`; is the card inserted?)");
                    return;
                }
                let mut buf = [0u8; 512];
                match sd.read_block(block, &mut buf) {
                    Ok(()) => {
                        let mut hex = [0u8; 40];
                        let s = sign_smoke::to_hex(&buf[..16], &mut hex);
                        log::info!("[sd] block {block} read ok; bytes 0..16: {s}");
                        let mbr = buf[510] == 0x55 && buf[511] == 0xAA;
                        log::info!(
                            "[sd] bytes 510..512 = {:02x} {:02x} ({})",
                            buf[510],
                            buf[511],
                            if block == 0 && mbr {
                                "MBR signature ok"
                            } else if block == 0 {
                                "no 0x55aa (not an MBR?)"
                            } else {
                                "block read"
                            }
                        );
                    }
                    Err(e) => log::info!("[err] sd read block {block}: {e}"),
                }
            }
            _ => log::info!("[err] sd: usage: sd probe | sd read <block_hex>"),
        }
    }

    /// `touch [n]`: sample the fitted touch controller, n max 8,
    /// 100 ms apart; prints raw register values and the calibrated
    /// screen coordinates.
    fn cmd_touch(&self, args: &[u8]) {
        let a = trim_ascii(args);
        let n = if a.is_empty() {
            1
        } else {
            match core::str::from_utf8(a)
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
            {
                Some(v) => v.clamp(1, 8),
                None => {
                    log::info!("[err] touch: usage: touch [n] (n <= 8)");
                    return;
                }
            }
        };
        let r = crate::panel::with_panel(|p| {
            for i in 0..n {
                match p.touch.read_point() {
                    Ok(pt) => {
                        let (sx, sy) = crate::touch::to_screen(pt.x, pt.y);
                        log::info!(
                            "[touch] #{i} fingers={} gesture=0x{:02x} raw=({}, {}) screen=({}, {})",
                            pt.fingers,
                            pt.gesture,
                            pt.x,
                            pt.y,
                            sx,
                            sy
                        )
                    }
                    Err(e) => {
                        log::info!("[touch] #{i} i2c error: {e:?}");
                        break;
                    }
                }
                if i + 1 < n {
                    block_for(Duration::from_millis(100));
                }
            }
        });
        if r.is_none() {
            log::info!("[err] touch: panel not installed");
        }
    }

    fn cmd_heap(&self, args: &[u8]) {
        let args = trim_ascii(args);
        if args == b"reset" {
            crate::heap_peak_reset();
            let (used, free, peak) = crate::heap_stats();
            let (pu, pf, pp) = crate::psram_stats();
            log::info!(
                "[heap] peak reset; sram {used}/{free} peak {peak}; psram {pu}/{pf} peak {pp}"
            );
        } else {
            let (used, free, peak) = crate::heap_stats();
            let (pu, pf, pp) = crate::psram_stats();
            log::info!(
                "[heap] sram used {used} free {free} peak {peak}; psram used {pu} free {pf} peak {pp}"
            );
        }
    }

    /// Fetch a segment of the last signed XMR blob as hex:
    /// `xmrout <hex_off> <hex_len>` (both in hex characters; len capped at
    /// 512 to stay within the log pipe). The summary line reports the total.
    fn cmd_xmrout(&self, args: &[u8]) {
        if self.xmr_out_len == 0 {
            log::info!("[err] xmrout: no signed XMR blob stored yet");
            return;
        }
        let mut off: Option<usize> = None;
        let mut len: Option<usize> = None;
        for w in args
            .split(|b| b.is_ascii_whitespace())
            .filter(|w| !w.is_empty())
        {
            let v = core::str::from_utf8(w)
                .ok()
                .and_then(|s| s.parse::<usize>().ok());
            if off.is_none() {
                off = v;
            } else if len.is_none() {
                len = v;
            }
        }
        let (Some(mut off), len) = (off, len.unwrap_or(512)) else {
            log::info!("[err] xmrout: usage: xmrout <hex_off> <hex_len>");
            return;
        };
        let total = self.xmr_out_len * 2;
        // align down to byte boundaries and clamp
        off &= !1;
        if off >= total {
            log::info!("[err] xmrout: offset {off} past end ({total})");
            return;
        }
        let len = len.min(512).min(total - off) & !1;
        let mut hex = [0u8; 512];
        let s = sign_smoke::to_hex(&self.xmr_out[off / 2..(off + len) / 2], &mut hex);
        log::info!("[xmrout] {off}+{len}/{total} {s}");
    }

    /// `xmrseed <hex>`: set fixed entropy for the next XMR job (A/B mode).
    /// Bench builds only (audit #17).
    #[cfg(feature = "bench")]
    fn cmd_xmrseed(&mut self, args: &[u8]) {
        let mut buf = [0u8; 64];
        match parse_hex(args, &mut buf) {
            Some(n) => {
                log::info!(
                    "[xmr] fixed entropy set ({n} B; next XMR job uses this instead of the TRNG - A/B mode)"
                );
                self.xmr_seed = Some((buf, n));
            }
            None => log::info!("[err] xmrseed: expected hex, 1..=64 bytes"),
        }
    }

    /// `alloctest <size>[k|m] [align]` | `alloctest sweep` | `alloctest free`:
    /// probe the global allocator directly via `alloc::alloc::alloc`, which
    /// returns null instead of panicking on failure - the safe way to find
    /// which sizes a heap can serve without crashing the session.
    fn cmd_alloctest(&self, args: &[u8]) {
        let args = trim_ascii(args);
        if args == b"free" {
            let (su, sf, sp) = crate::heap_stats();
            let (pu, pf, pp) = crate::psram_stats();
            log::info!(
                "[alloctest] sram used={su} free={sf} peak={sp}; psram used={pu} free={pf} peak={pp}"
            );
            return;
        }
        if args == b"sweep" {
            if !crate::psram_heap_ready() {
                log::info!("[alloctest] psram heap not mapped (run psramtest first)");
            }
            for size in [
                64 * 1024usize,
                256 * 1024,
                1024 * 1024,
                2 * 1024 * 1024,
                4 * 1024 * 1024,
            ] {
                probe_alloc(size, 8);
            }
            let (pu, pf, _) = crate::psram_stats();
            let (su, sf, _) = crate::heap_stats();
            log::info!(
                "[alloctest] sweep done; sram free={sf} used={su}; psram free={pf} used={pu}"
            );
            return;
        }
        let mut size: Option<usize> = None;
        let mut align: Option<usize> = None;
        for w in args
            .split(|b| b.is_ascii_whitespace())
            .filter(|w| !w.is_empty())
        {
            let Ok(s) = core::str::from_utf8(w) else {
                continue;
            };
            let v = if let Some(num) = s.strip_suffix(['k', 'K']) {
                num.parse::<usize>().ok().map(|n| n * 1024)
            } else if let Some(num) = s.strip_suffix(['m', 'M']) {
                num.parse::<usize>().ok().map(|n| n * 1024 * 1024)
            } else {
                s.parse::<usize>().ok()
            };
            if size.is_none() {
                size = v;
            } else if align.is_none() {
                align = v;
            }
        }
        match size {
            Some(size) => probe_alloc(size, align.unwrap_or(8)),
            None => {
                log::info!("[err] alloctest: usage: alloctest <size>[k|m] [align] | sweep | free")
            }
        }
    }

    /// `alloctrace`: print the allocation trace ring (>= 4 KiB allocations
    /// plus every failed one). The ring lives in .uninit and SURVIVES a
    /// crash reset: run this after a reboot to see what the failing path
    /// requested, in order, newest last.
    fn cmd_alloctrace(&self) {
        let n = crate::trace_len();
        log::info!("[trace] ring: {n} entries, newest last (>= 4 KiB and failures)");
        for k in 0..n {
            let (size, flags) = crate::trace_entry(k);
            let region = if flags & 1 == 1 { "psram" } else { "sram" };
            if flags & (1 << 31) != 0 {
                log::info!("[trace] {k}: size={size} region={region} FAILED");
            } else {
                log::info!("[trace] {k}: size={size} region={region}");
            }
        }
    }

    /// `entropy <hex>`: test-vector mnemonic loader. Bench builds only
    /// (audit #17).
    #[cfg(feature = "bench")]
    /// `xmrchunk <n>`: set the BP+ multiexp chunk size (terms per CT table).
    /// Larger chunks = fewer doubling chains but bigger tables; the table
    /// routes to PSRAM once `n * 1280B` exceeds the 16 KiB threshold
    /// (n >= 13). Probe builds only.
    #[cfg(feature = "perf-timing")]
    fn cmd_xmrchunk(&self, args: &[u8]) {
        let n = core::str::from_utf8(trim_ascii(args))
            .unwrap_or("")
            .parse::<usize>()
            .map(|v| v.clamp(1, 256));
        match n {
            Ok(v) => {
                shlosilo::chain::xmr::set_bp_multiexp_chunk_terms(v);
                let table = v * 1280;
                log::info!(
                    "[chunk] bp+ multiexp chunk = {v} terms (table {table} B -> {})",
                    if table > 16 * 1024 { "PSRAM" } else { "SRAM" }
                );
            }
            Err(_) => log::info!("[err] xmrchunk: usage: xmrchunk <terms>"),
        }
    }

    /// `perfbench [name] [iters]`: run the dalek device-primitive benchmarks
    /// (fmul / fsq / select / selaff / madd / maddaff / quad / ct <n> / vt2).
    /// With no name (or `all`) runs the standard suite with defaults.
    /// Diagnostic builds only (feature `perf-bench`).
    #[cfg(feature = "perf-bench")]
    fn cmd_perfbench(&self, args: &[u8]) {
        use shlosilo::ffi::perf_bench_ffi as pb;

        fn timed(label: &str, iters: u32, f: extern "C" fn(u32) -> u64) {
            let t0 = Instant::now();
            let dig = f(iters);
            let us = t0.elapsed().as_micros();
            let per = if iters > 0 { us / u64::from(iters) } else { 0 };
            log::info!("[pf] {label} iters={iters}: {us}us total, {per}us/op, dig={dig}");
        }

        let args = trim_ascii(args);
        let mut words = args
            .split(|b| b.is_ascii_whitespace())
            .filter(|w| !w.is_empty());
        let name = words.next().unwrap_or(b"all");
        let parse = |w: Option<&[u8]>, d: u32| -> u32 {
            w.and_then(|w| core::str::from_utf8(w).ok())
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(d)
        };
        let iters = parse(words.next(), 0);
        let n = parse(words.next(), 36);

        match name {
            b"all" => {
                timed(
                    "fmul",
                    if iters > 0 { iters } else { 2000 },
                    pb::shlosilo_perf_fmul,
                );
                timed(
                    "fsq",
                    if iters > 0 { iters } else { 2000 },
                    pb::shlosilo_perf_fsq,
                );
                timed(
                    "select",
                    if iters > 0 { iters } else { 200 },
                    pb::shlosilo_perf_select,
                );
                timed(
                    "selaff",
                    if iters > 0 { iters } else { 200 },
                    pb::shlosilo_perf_select_affine,
                );
                timed(
                    "madd",
                    if iters > 0 { iters } else { 100 },
                    pb::shlosilo_perf_madd,
                );
                timed(
                    "maddaff",
                    if iters > 0 { iters } else { 100 },
                    pb::shlosilo_perf_madd_affine,
                );
                timed(
                    "quad",
                    if iters > 0 { iters } else { 100 },
                    pb::shlosilo_perf_quadruple,
                );
                timed(
                    "vt2",
                    if iters > 0 { iters } else { 200 },
                    pb::shlosilo_perf_vartime_2term,
                );
                // ct_chunk takes (n, iters): one 36-term chunk per iteration.
                let t0 = Instant::now();
                let dig = pb::shlosilo_perf_ct_chunk(36, if iters > 0 { iters } else { 2 });
                let us = t0.elapsed().as_micros();
                log::info!(
                    "[pf] ct36 iters={}: {us}us total, {per}us/chunk, dig={dig}",
                    if iters > 0 { iters } else { 2 },
                    per = us / u64::from(if iters > 0 { iters } else { 2 })
                );
            }
            b"fmul" => timed("fmul", warm(iters), pb::shlosilo_perf_fmul),
            b"fsq" => timed("fsq", warm(iters), pb::shlosilo_perf_fsq),
            b"select" => timed("select", warm(iters), pb::shlosilo_perf_select),
            b"selaff" => timed("selaff", warm(iters), pb::shlosilo_perf_select_affine),
            b"madd" => timed("madd", warm(iters), pb::shlosilo_perf_madd),
            b"maddaff" => timed("maddaff", warm(iters), pb::shlosilo_perf_madd_affine),
            b"quad" => timed("quad", warm(iters), pb::shlosilo_perf_quadruple),
            b"vt2" => timed("vt2", warm(iters), pb::shlosilo_perf_vartime_2term),
            b"ct" => {
                let t0 = Instant::now();
                let dig = pb::shlosilo_perf_ct_chunk(n.min(512), warm(iters));
                let us = t0.elapsed().as_micros();
                let it = warm(iters);
                log::info!(
                    "[pf] ct{n} iters={it}: {us}us total, {per}us/chunk, dig={dig}",
                    per = us / u64::from(it)
                );
            }
            b"ctm" => {
                // ctm <n> <chunk> <iters>: chunked CT multiexp with
                // full-width scalars (the in-situ shape; see ct_chunked).
                let mut w = args
                    .split(|b: &u8| b.is_ascii_whitespace())
                    .filter(|w| !w.is_empty());
                let _ = w.next(); // "ctm"
                let n = parse(w.next(), 130).clamp(1, 512);
                let c = parse(w.next(), 12).clamp(1, 512);
                let it = parse(w.next(), 1).clamp(1, 512);
                let t0 = Instant::now();
                let dig = pb::shlosilo_perf_ct_chunked(n, c, it);
                let us = t0.elapsed().as_micros();
                let chunks = n.div_ceil(c);
                log::info!(
                    "[pf] ctm n={n} chunk={c} iters={it}: {us}us total, {per_chunk}us/chunk, {per_term}us/term, dig={dig}",
                    per_chunk = us / u64::from(chunks * it),
                    per_term = us / u64::from(n * it)
                );
            }
            b"xchain" => {
                // xchain <n> <iters> <tail> <gen>: the in-situ WIP L/R
                // call chain (tuple Vec + chunked wrapper + optional
                // INV_EIGHT/compress tail), gen=1 for generator-table
                // points. Compare against `ctm` for the same n.
                let mut w = args
                    .split(|b: &u8| b.is_ascii_whitespace())
                    .filter(|w| !w.is_empty());
                let _ = w.next(); // "xchain"
                let n = parse(w.next(), 130).clamp(1, 1024);
                let it = parse(w.next(), 1).clamp(1, 512);
                let tail = parse(w.next(), 1) != 0;
                let gend = parse(w.next(), 1) != 0;
                let t0 = Instant::now();
                let dig = pb::shlosilo_perf_xchain(n, it, tail as u32, gend as u32);
                let us = t0.elapsed().as_micros();
                log::info!(
                    "[pf] xchain n={n} iters={it} tail={} gen={}: {us}us total, {per}us/call, dig={dig}",
                    tail as u32,
                    gend as u32,
                    per = us / u64::from(it)
                );
            }
            b"vt2f" => {
                let it = if iters > 0 { iters } else { 20 };
                let t0 = Instant::now();
                let dig = pb::shlosilo_perf_vartime_2term_fw(it);
                let us = t0.elapsed().as_micros();
                log::info!(
                    "[pf] vt2f iters={it}: {us}us total, {per}us/op, dig={dig}",
                    per = us / u64::from(it)
                );
            }
            _ => log::info!("[err] perfbench: unknown name"),
        }

        fn warm(iters: u32) -> u32 {
            if iters == 0 { 200 } else { iters }
        }
    }

    #[cfg(feature = "bench")]
    fn cmd_entropy(&mut self, args: &[u8]) {
        let mut bytes = [0u8; 32];
        let n = match parse_hex(args, &mut bytes) {
            Some(n) => n,
            None => {
                log::info!("[err] entropy: expected 16/20/24/28/32 bytes as hex");
                return;
            }
        };
        let result = Mnemonic::from_entropy(&bytes[..n]);
        bytes.fill(0);
        match result {
            Ok(m) => {
                let idx = m.indices();
                let mut store = [0u16; 24];
                store[..idx.len()].copy_from_slice(idx);
                self.session = Some((store, idx.len() as u8));

                let mut buf = [0u8; 160];
                let mut w = BufWriter::new(&mut buf);
                let _ = write!(w, "[entropy] session key set (bench channel); idx =");
                for i in idx {
                    let _ = write!(w, " {i}");
                }
                log::info!("{}", w.as_str());
            }
            Err(e) => log::info!("[err] entropy: {:?}", e.kind),
        }
    }

    fn handle_ur(&mut self, line: &[u8]) -> Option<TrngJob> {
        let s = match core::str::from_utf8(line) {
            Ok(s) => s,
            Err(_) => {
                log::info!("[err] ur: line is not utf8");
                return None;
            }
        };

        // Single frame (no seq-count segment) first.
        if let Ok(decoded) = ur_decode::decode(s) {
            let tag = decoded.type_tag();
            log::info!(
                "[ur] single frame: type={} len={}",
                tag.type_name(),
                decoded.as_ref().len()
            );
            return self.sign_and_report(tag, decoded.as_ref());
        }
        // Not a single frame (or over its budget): try multipart below.

        let (seq, count) = match parse_seq(s) {
            Some(v) => v,
            None => {
                log::info!("[err] ur: neither a valid single frame nor a multipart frame");
                return None;
            }
        };

        // Start a fresh session when the frame opens one (seq 1) or when the
        // previous session is finished/absent. Fragments may arrive in any
        // order (fountain), so seq > 1 with no session still starts one.
        let fresh = seq == 1
            || self
                .decoder
                .as_ref()
                .is_none_or(UrMultipartDecoder::complete);
        if fresh {
            self.decoder = Some(UrMultipartDecoder::new());
        }
        let mut dec = self.decoder.take().expect("decoder was just created");

        match dec.receive_frame(s) {
            Ok(is_new) => {
                log::info!(
                    "[ur] frag {seq}/{count} ({}) {}%",
                    if is_new { "new" } else { "dup" },
                    dec.progress()
                );
                if dec.complete() {
                    let tag = UrTypeTag::from_name(dec.ur_type().unwrap_or(""));
                    match dec.payload() {
                        Ok(Some(payload)) => {
                            log::info!(
                                "[ur] complete: type={} len={}",
                                tag.type_name(),
                                payload.len()
                            );
                            // Decoder consumed; the session ends here.
                            return self.sign_and_report(tag, &payload);
                        }
                        Ok(None) => log::info!("[err] ur: complete but payload missing"),
                        Err(e) => log::info!("[err] ur payload: {:?}", e.kind),
                    }
                } else {
                    self.decoder = Some(dec); // keep the session for the next fragment
                }
            }
            Err(e) => {
                log::info!("[err] ur frame: {:?}", e.kind);
                // Session dropped (decoder not put back).
            }
        }
        None
    }

    /// Dispatch a decoded payload. BTC/ETH sign synchronously (RFC-6979,
    /// fast); XMR returns a deferred job - its signing path takes TRNG
    /// entropy and runs the CN scratchpad + BP+ prove chain, which is a
    /// seconds-scale synchronous operation.
    fn sign_and_report(&mut self, tag: UrTypeTag, payload: &[u8]) -> Option<TrngJob> {
        match tag {
            UrTypeTag::XmrTxUnsigned => {
                self.xmr_pending = Some(alloc::vec::Vec::from(payload));
                return Some(TrngJob::simple(JobMode::SignXmr));
            }
            UrTypeTag::XmrTxSigned | UrTypeTag::CryptoMoneroTx => {
                log::info!("[err] sign: unsupported XMR type ({})", tag.type_name());
                return None;
            }
            _ => {}
        }

        let mnemonic = match self.session_mnemonic() {
            Ok(m) => m,
            Err(e) => {
                log::info!("[err] session mnemonic: {:?}", e.kind);
                return None;
            }
        };
        let input = SignInput::Mnemonic {
            mnemonic,
            passphrase: b"",
        };

        // BTC/ETH do not consume injected entropy (RFC-6979); empty slice per
        // the §B.5 contract. (XMR takes TRNG entropy in its deferred job.)
        let mut out = [0u8; SIGN_OUT_CAP];
        let tname = tag.type_name();
        match shlosilo::business::sign::sign_with_entropy(input, tag, payload, &[], &mut out) {
            Ok(n) => {
                match sha256::hash(&out[..n]) {
                    Ok(digest) => log::info!(
                        "[sign] {tname} ok: {n} bytes sha256={}",
                        sign_smoke::to_hex(&digest, &mut [0u8; 64])
                    ),
                    Err(e) => log::info!("[err] sha256: {:?}", e.kind),
                }
                if n <= 128 {
                    // Full output for small results (covers the ETH fixture,
                    // 111 bytes); large results are compared by digest.
                    let mut hex = [0u8; 256];
                    log::info!(
                        "[sign] {tname} hex: {}",
                        sign_smoke::to_hex(&out[..n], &mut hex)
                    );
                }
            }
            Err(e) => log::info!("[err] sign {tname}: {:?}", e.kind),
        }
        None
    }

    fn session_mnemonic(&self) -> Result<Mnemonic, ShlosiloError> {
        match &self.session {
            Some((indices, count)) => {
                let count = *count as usize;
                let wc = WordCount::try_from_count(count).ok_or_else(|| {
                    ShlosiloError::new(ShlosiloErrorKind::MnemonicInvalidWordCount)
                })?;
                Mnemonic::from_indices(&indices[..count], wc)
            }
            None => sign_smoke::fixture_mnemonic(),
        }
    }
}

static CONSOLE: Mutex<CriticalSectionRawMutex, RefCell<ConsoleState>> =
    Mutex::new(RefCell::new(ConsoleState::new()));

/// Maximum length of the `ui qr` payload (QR version-40 byte capacity is
/// 2953 at ECC-L; leave headroom).
const QR_TEXT_MAX: usize = 2048;

/// `ui qr <text>` staging: the console line buffer is transient, so the
/// payload is copied here for the deferred job. Single consumer (console
/// jobs are serialized).
static mut QR_TEXT: [u8; QR_TEXT_MAX] = [0u8; QR_TEXT_MAX];
static QR_TEXT_LEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// `ui ur <hex>` staging: the UR carousel payload. One console line caps
/// the hex at LINE_CAP characters, hence 4096 bytes (a 3458-byte XMR
/// signature fits; larger payloads need a fragment-feeding extension).
const UR_PAYLOAD_MAX: usize = 4096;
static mut UR_PAYLOAD: [u8; UR_PAYLOAD_MAX] = [0u8; UR_PAYLOAD_MAX];
static UR_PAYLOAD_LEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// UR carousel cadence: milliseconds per frame. A ~450-char frame encodes
/// in tens of milliseconds on this core and the flush is ~50 ms, so this
/// leaves comfortable scanning dwell time per frame.
const UR_FRAME_MS: u64 = 450;

/// The USB receive handler: assembles lines and drives the command channel.
pub struct CommandHandler;

impl ReceiverHandler for CommandHandler {
    fn handle_data(&self, data: &[u8]) -> impl core::future::Future<Output = ()> + Send {
        // Synchronous commands run at call time; a TRNG job is returned as a
        // deferred job because it streams over seconds: the job yields
        // between blocks so the logger's sender half (polled via the join in
        // the logger task) keeps draining the log pipe. A synchronous
        // multi-second burst would overflow the 1 KiB pipe and drop output.
        let job = CONSOLE.lock(|cell| cell.borrow_mut().feed(data));
        async move {
            if let Some(job) = job {
                run_trng_job(job).await;
            }
        }
    }

    fn new() -> Self {
        Self
    }
}

/// A deferred console job (see `handle_data`).
#[derive(Clone, Copy)]
struct TrngJob {
    mode: JobMode,
    /// Generic numeric parameter for base-surface deferred jobs (TouchInt:
    /// the monitoring window in ms). Not gated: these jobs run in
    /// production builds.
    arg: u32,
    /// Parameters of the bench-only TRNG diagnostic jobs (`bench` feature).
    #[cfg(feature = "bench")]
    stress: bool,
    /// Stream conditioned 32-byte outputs (SHA-256) instead of raw blocks.
    #[cfg(feature = "bench")]
    cond: bool,
    #[cfg(feature = "bench")]
    sample: Option<u32>,
    #[cfg(feature = "bench")]
    chain: Option<u8>,
    /// Per-block patience budget in milliseconds.
    #[cfg(feature = "bench")]
    timeout_ms: u64,
    /// Stream: block/output count. Probe: duration in ms. Emb: block count.
    /// RawCapture: block count.
    #[cfg(feature = "bench")]
    count: u32,
    /// RawDump: first block to stream. CamDump: which byte of each DVP
    /// word to stream (0 = the first sample of the pair). Unused elsewhere.
    #[cfg(feature = "bench")]
    off: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JobMode {
    /// Our reader, streaming accepted blocks as hex.
    #[cfg(feature = "bench")]
    Stream,
    /// Raw busy/ISR transition trace after a cold start.
    #[cfg(feature = "bench")]
    Probe,
    /// The upstream embassy driver (cross-check).
    #[cfg(feature = "bench")]
    Emb,
    /// Raw register dump.
    #[cfg(feature = "bench")]
    Dump,
    /// RESETS-block cycle, then a dump.
    #[cfg(feature = "bench")]
    Rst,
    /// Raw-ROSC capture into the console buffer (SP 800-90B data collection).
    #[cfg(feature = "bench")]
    RawCapture,
    /// Stream the stored raw capture out as paced hex lines.
    #[cfg(feature = "bench")]
    RawDump,
    /// Trace the BUSY/VALID waveform around raw blocks (mechanism forensics).
    #[cfg(feature = "bench")]
    RawTrace,
    /// Capture checked-path blocks through the production reader into the
    /// dump buffer (dataset collection without the lossy per-line log stream).
    #[cfg(feature = "bench")]
    CheckCapture,
    /// Monitor the touch INT line (GP17) for edge activity during a
    /// bring-up window - independent liveness proof for the controller.
    TouchInt,
    /// Visual touch-mapping check: paint a trail at the calibrated touch
    /// position while the finger moves.
    TouchDraw,
    /// Interactive mono-UI demo (pages + O/X zones) for `secs`.
    UiRun,
    /// Render the staged `ui qr <text>` payload as a QR page.
    UiQr,
    /// UR multipart carousel: cycle fountain frames of the staged payload.
    UiUr,
    /// Sign the pending XMR request (TRNG entropy + the full signing path).
    SignXmr,
    /// Verify the PSRAM memory-mapped data path; map the heap on success.
    PsramTest,
    /// Capture N camera frames; log per-frame byte statistics.
    #[cfg(feature = "bench")]
    CamGrab,
    /// Capture one camera frame; stream one byte plane as paced hex lines.
    #[cfg(feature = "bench")]
    CamDump,
    /// Drain the camera PIO RX FIFO for `arg` ms (no DMA) and report.
    #[cfg(feature = "bench")]
    CamRx,
}

impl TrngJob {
    /// A job with no parameters.
    const fn simple(mode: JobMode) -> Self {
        Self {
            mode,
            arg: 0,
            #[cfg(feature = "bench")]
            stress: false,
            #[cfg(feature = "bench")]
            cond: false,
            #[cfg(feature = "bench")]
            sample: None,
            #[cfg(feature = "bench")]
            chain: None,
            #[cfg(feature = "bench")]
            timeout_ms: 0,
            #[cfg(feature = "bench")]
            count: 0,
            #[cfg(feature = "bench")]
            off: 0,
        }
    }
}

/// Parse `trng [stress] [cond] [sample=<n>] [chain=<0-4>] [timeout=<ms>]
/// [nblocks]`; default 64 blocks, capped at 4096.
#[cfg(feature = "bench")]
fn parse_trng_job(args: &[u8]) -> TrngJob {
    let mut stress = false;
    let mut cond = false;
    let mut sample: Option<u32> = None;
    let mut chain: Option<u8> = None;
    let mut timeout_ms: u64 = trng::DEFAULT_BLOCK_TIMEOUT_MS;
    let mut count: u32 = 64;
    for word in args
        .split(|b| b.is_ascii_whitespace())
        .filter(|w| !w.is_empty())
    {
        let s = core::str::from_utf8(word).unwrap_or("");
        if word == b"stress" {
            stress = true;
        } else if word == b"cond" {
            cond = true;
        } else if let Some(v) = s.strip_prefix("sample=") {
            sample = v.parse::<u32>().ok().map(|n| n.min(0xffff));
        } else if let Some(v) = s.strip_prefix("chain=") {
            chain = v.parse::<u8>().ok().map(|n| n.min(4));
        } else if let Some(v) = s.strip_prefix("timeout=") {
            timeout_ms = v.parse::<u64>().unwrap_or(timeout_ms).clamp(100, 120_000);
        } else if let Ok(n) = s.parse::<u32>() {
            count = n.clamp(1, 16384);
        }
    }
    TrngJob {
        mode: JobMode::Stream,
        arg: 0,
        stress,
        cond,
        sample,
        chain,
        timeout_ms,
        count,
        off: 0,
    }
}

/// `touchint [ms]`: monitor GP17 (touch INT) for edge activity during a
/// window (default 15 s, cap 120 s). An independent liveness proof for the
/// controller: a scanning chip pulses INT on touch even when its I2C is
/// broken or misaddressed.
fn parse_touchint(args: &[u8]) -> TrngJob {
    let ms = core::str::from_utf8(trim_ascii(args))
        .unwrap_or("")
        .parse::<u32>()
        .unwrap_or(15_000)
        .clamp(500, 120_000);
    let mut job = TrngJob::simple(JobMode::TouchInt);
    job.arg = ms;
    job
}

/// `ui run [secs]`: interactive mono-UI demo (deferred job).
fn parse_ui_run(args: &[u8]) -> TrngJob {
    let secs = core::str::from_utf8(trim_ascii(args))
        .unwrap_or("")
        .parse::<u32>()
        .unwrap_or(120)
        .clamp(5, 600);
    let mut job = TrngJob::simple(JobMode::UiRun);
    job.arg = secs;
    job
}

/// Interactive UI job wrapper (see `ui::run`).
async fn run_ui(secs: u32) {
    crate::ui::run(secs).await;
}

/// `ui ur <hex>` job parameters: fixed window (X stops it early).
fn parse_ui_ur() -> TrngJob {
    let mut job = TrngJob::simple(JobMode::UiUr);
    job.arg = 120;
    job
}

/// UR carousel: split the staged payload into fountain frames (200-byte
/// fragments, `ur:xmr-txunsigned/...`) and cycle them as QR codes. This
/// is the delivery path for signed outputs that exceed a single QR: a
/// 3458-byte XMR signature is ~18 frames here, ~8 s per cycle at the
/// default cadence. X on the left zone stops it; O is inert.
async fn run_ui_ur(secs: u32) {
    let len = UR_PAYLOAD_LEN.load(core::sync::atomic::Ordering::Relaxed);
    if len == 0 {
        log::info!("[err] ui ur: no payload staged");
        return;
    }
    let payload: &[u8] = unsafe { &(&*core::ptr::addr_of!(UR_PAYLOAD))[..len] };
    let mut enc = match UrMultipartEncoder::new("xmr-txunsigned", payload, 200) {
        Ok(e) => e,
        Err(e) => {
            log::info!("[err] ui ur: encoder: {:?}", e.kind);
            return;
        }
    };
    let total = enc.fragment_count();
    let cycle_ms = total as u64 * UR_FRAME_MS;
    log::info!(
        "[ui] UR carousel: {len} B payload, {total} frames ({UR_FRAME_MS} ms/frame, ~{} s/cycle)",
        cycle_ms / 1000
    );
    let t0 = Instant::now();
    let mut shown: u32 = 0;
    let mut seq: usize;
    while (Instant::now() - t0).as_secs() < u64::from(secs) {
        let frame = match enc.next_cyclic_frame() {
            Ok(f) => f,
            Err(e) => {
                log::info!("[err] ui ur: frame: {:?}", e.kind);
                break;
            }
        };
        // The frame string carries the real sequence id; the display
        // counter is 1-based for humans.
        seq = (shown as usize % total) + 1;
        if crate::ui::qr_carousel_frame(&frame, seq, total).is_err() {
            log::info!("[err] ui ur: frame too large to render");
            break;
        }
        shown += 1;
        if shown.is_multiple_of(8) {
            log::info!("[ui] ur frames shown: {shown}");
        }
        Timer::after_millis(UR_FRAME_MS).await;
        // X (left half of the button band) stops the carousel.
        let pt = crate::panel::with_panel(|p| p.touch.read_point());
        if let Some(Ok(pt)) = pt
            && pt.fingers > 0
        {
            let (sx, sy) = crate::touch::to_screen(pt.x, pt.y);
            if sy as i32 >= crate::ui::ZONE_Y && (sx as i32) < crate::ui::ZONE_SPLIT_X {
                log::info!("[ui] carousel stopped by tap at ({sx},{sy})");
                break;
            }
        }
    }
    log::info!("[ui] UR carousel done: {shown} frames shown");
    let _ = crate::ui::show(crate::ui::Page::Welcome, None);
}

/// `touchdraw [secs]`: visual touch-mapping check. Fills the screen dark,
/// draws the four corner reference blocks, then paints a green trail at
/// the calibrated screen position of the touch point for the duration
/// (default 60 s, cap 120 s). The trail should track the finger; a
/// rotated or mirrored trail means the calibration in touch.rs is wrong.
fn parse_touchdraw(args: &[u8]) -> TrngJob {
    let secs = core::str::from_utf8(trim_ascii(args))
        .unwrap_or("")
        .parse::<u32>()
        .unwrap_or(60)
        .clamp(5, 120);
    let mut job = TrngJob::simple(JobMode::TouchDraw);
    job.arg = secs;
    job
}

/// Parse `trngprobe [ms]` (default 60 ms): cold-start the block and trace
/// every BUSY/ISR transition.
#[cfg(feature = "bench")]
fn parse_trng_probe(args: &[u8]) -> TrngJob {
    let ms = core::str::from_utf8(trim_ascii(args))
        .unwrap_or("")
        .parse::<u32>()
        .unwrap_or(60)
        .clamp(1, 5000);
    TrngJob {
        mode: JobMode::Probe,
        arg: 0,
        stress: false,
        cond: false,
        sample: None,
        chain: None,
        timeout_ms: 0,
        count: ms,
        off: 0,
    }
}

/// Parse `trngemb [n]` (default 4): read n blocks through the upstream
/// embassy driver, with per-block timing.
#[cfg(feature = "bench")]
fn parse_trng_emb(args: &[u8]) -> TrngJob {
    let n = core::str::from_utf8(trim_ascii(args))
        .unwrap_or("")
        .parse::<u32>()
        .unwrap_or(4)
        .clamp(1, 256);
    TrngJob {
        mode: JobMode::Emb,
        arg: 0,
        stress: false,
        cond: false,
        sample: None,
        chain: None,
        timeout_ms: 0,
        count: n,
        off: 0,
    }
}

/// Dispatch a deferred TRNG job. All register access happens under the
/// single trng::instance() lock (see trng.rs "Ownership").
/// Per-frame byte statistics: min/max/mean over one byte of each DVP word.
/// Reporting both bytes is how the bring-up establishes which one carries
/// luma (the other is chroma and hovers near 128).
#[cfg(feature = "bench")]
fn cam_byte_stats(buf: &[u16], high: bool) -> (u8, u8, u32) {
    let mut min = 0xFFu8;
    let mut max = 0u8;
    let mut sum = 0u64;
    for &w in buf {
        let v = if high { (w >> 8) as u8 } else { w as u8 };
        min = min.min(v);
        max = max.max(v);
        sum += v as u64;
    }
    (min, max, (sum / buf.len() as u64) as u32)
}

/// \`cam grab [n]\`: capture n frames, log per-frame statistics and timing.
#[cfg(feature = "bench")]
async fn run_cam_grab(n: u32) {
    use crate::camera::CaptureResult;
    let n = n.clamp(1, 64);
    let mut buf = alloc::vec![0u16; crate::camera::FRAME_WORDS];
    for i in 0..n {
        let t0 = Instant::now();
        let res = match crate::camera::capture_frame(&mut buf).await {
            Some(r) => r,
            None => {
                log::info!("[err] cam: not initialised");
                return;
            }
        };
        match res {
            CaptureResult::Ok => {
                let (mn0, mx0, av0) = cam_byte_stats(&buf, true);
                let (mn1, mx1, av1) = cam_byte_stats(&buf, false);
                log::info!(
                    "[cam] frame {i} ({} ms): b0 {mn0}..{mx0} avg {av0} | b1 {mn1}..{mx1} avg {av1}",
                    t0.elapsed().as_millis()
                );
            }
            CaptureResult::Timeout { words } => {
                log::info!(
                    "[cam] frame {i}: TIMEOUT after {} ms; {words}/{} words transferred \
                     (0 = PIO produced nothing - check the readback line and wiring)",
                    t0.elapsed().as_millis(),
                    crate::camera::FRAME_WORDS
                );
                return;
            }
        }
    }
    log::info!("[cam] {n} frame(s) captured");
}

/// \`cam rx [ms]\`: drain the PIO RX FIFO for `ms` (no DMA) and report the
/// word count. This is the ground truth for "is the capture program
/// producing anything at all" - it needs no DMA, no interrupts and no
/// alignment.
#[cfg(feature = "bench")]
async fn run_cam_rx(ms: u32) {
    let ms = ms.clamp(10, 10_000);
    match crate::camera::probe_rx(ms).await {
        Some((words, nonzero)) => log::info!(
            "[cam] rx probe {ms} ms: {words} words drained, {nonzero} non-zero \
             (a silent FIFO = the PIO is sitting in a wait: no DVP data)"
        ),
        None => log::info!("[err] cam: not initialised"),
    }
}

/// `cam dump [stride] [byte]`: capture a frame and stream one byte plane as
/// paced hex lines, one PGM row per line - the host script reassembles the
/// image. `stride` decimates x and y (default 2 -> 120x160; 1 -> 240x320);
/// `byte` picks the DVP word byte (0 = the first sample of each pair).
#[cfg(feature = "bench")]
async fn run_cam_dump(stride: u32, byte: u32) {
    use crate::camera::{FRAME_H, FRAME_W, FRAME_WORDS};
    let stride = match stride {
        1 => 1,
        4 => 4,
        _ => 2,
    };
    let high = byte == 0;
    let mut buf = alloc::vec![0u16; FRAME_WORDS];
    // Two captures: between jobs the state machine stalls on a full FIFO,
    // so the first transfer can start mid-group; the second is continuous
    // (see the camera module docs).
    for round in 0..2 {
        match crate::camera::capture_frame(&mut buf).await {
            None => {
                log::info!("[err] cam: not initialised");
                return;
            }
            Some(crate::camera::CaptureResult::Ok) => {}
            Some(crate::camera::CaptureResult::Timeout { words }) => {
                log::info!(
                    "[cam] dump: capture {round} timed out ({words}/{} words) - aborting",
                    FRAME_WORDS
                );
                return;
            }
        }
    }
    let cols = FRAME_W / stride;
    log::info!(
        "[cam] PGM {cols} {} stride {stride} byte {byte}",
        FRAME_H / stride
    );
    let mut row = alloc::vec![0u8; cols];
    let mut hex = alloc::vec![0u8; cols * 2];
    for y in (0..FRAME_H).step_by(stride) {
        for (n, x) in (0..FRAME_W).step_by(stride).enumerate() {
            let w = buf[y * FRAME_W + x];
            row[n] = if high { (w >> 8) as u8 } else { w as u8 };
        }
        let s = sign_smoke::to_hex(&row, &mut hex);
        log::info!("[cam] {y} {s}");
        Timer::after_millis(2).await;
    }
    log::info!("[cam] end");
}

async fn run_trng_job(job: TrngJob) {
    match job.mode {
        #[cfg(feature = "bench")]
        JobMode::Stream => run_trng_stream(job).await,
        #[cfg(feature = "bench")]
        JobMode::Probe => run_trng_probe(job).await,
        #[cfg(feature = "bench")]
        JobMode::Emb => run_trng_emb(job).await,
        #[cfg(feature = "bench")]
        JobMode::Dump => {
            let t = trng::instance().lock().await;
            log_snapshot(&t.snapshot());
        }
        #[cfg(feature = "bench")]
        JobMode::Rst => {
            let mut t = trng::instance().lock().await;
            t.reset_cycle();
            t.stop();
            log_snapshot(&t.snapshot());
        }
        #[cfg(feature = "bench")]
        JobMode::RawCapture => run_trngraw(job).await,
        #[cfg(feature = "bench")]
        JobMode::RawDump => run_trngrawout(job).await,
        #[cfg(feature = "bench")]
        JobMode::RawTrace => run_trngtrace(job).await,
        #[cfg(feature = "bench")]
        JobMode::CheckCapture => run_trngcheck(job).await,
        JobMode::TouchInt => run_touchint(job.arg).await,
        JobMode::TouchDraw => run_touchdraw(job.arg).await,
        JobMode::UiRun => run_ui(job.arg).await,
        JobMode::UiUr => run_ui_ur(job.arg).await,
        JobMode::UiQr => {
            let n = QR_TEXT_LEN.load(core::sync::atomic::Ordering::Relaxed);
            let slot = unsafe { &*core::ptr::addr_of!(QR_TEXT) };
            let text = core::str::from_utf8(&slot[..n]).unwrap_or("");
            match crate::ui::show(crate::ui::Page::Qr, Some(text)) {
                Ok(()) => log::info!("[ui] qr drawn ({n} bytes)"),
                Err(()) => log::info!("[err] ui: QR encode failed (payload too long?)"),
            }
        }
        JobMode::SignXmr => run_sign_xmr().await,
        JobMode::PsramTest => run_psram_test().await,
        #[cfg(feature = "bench")]
        JobMode::CamGrab => run_cam_grab(job.arg).await,
        #[cfg(feature = "bench")]
        JobMode::CamDump => run_cam_dump(job.arg, job.off as u32).await,
        #[cfg(feature = "bench")]
        JobMode::CamRx => run_cam_rx(job.arg).await,
    }
}

#[cfg(feature = "bench")]
fn log_snapshot(s: &trng::RawSnapshot) {
    log::info!(
        "[tdump] isr=0x{:08x} imr=0x{:08x} busy=0x{:08x} valid=0x{:08x} cfg=0x{:08x} \
         sample={} dbg=0x{:08x} srcen=0x{:08x} acstat=0x{:08x} swrst=0x{:08x} ver=0x{:08x}",
        s.isr,
        s.imr,
        s.busy,
        s.valid,
        s.config,
        s.sample_cnt1,
        s.debug_control,
        s.source_enable,
        s.autocorr_stat,
        s.sw_reset,
        s.version
    );
}

/// Verify the PSRAM memory-mapped data path: write distinct word patterns at
/// several offsets and read them back. Each step is logged BEFORE the access
/// (with a drain delay), because the failure this exists to catch - the QMI
/// bus stalling on a broken memory-mapped path - freezes the core inside the
/// load/store: the last emitted line then names the exact op that hung.
///
/// On success the PSRAM heap is mapped: this is the first moment any
/// allocator may touch the region (see main.rs).
async fn run_psram_test() {
    let Some((base, size)) = crate::psram_region() else {
        log::info!("[psramtest] no mapped region (bring-up failed); nothing to test");
        return;
    };
    log::info!("[psramtest] region {base:#x}+{size:#x}");
    let offsets: [usize; 5] = [0, 2 << 20, 4 << 20, 6 << 20, size - 0x1000];
    for &off in &offsets {
        let seed = 0xA5A5_0000u32 ^ (off as u32).wrapping_mul(0x9E37_79B9);
        log::info!("[psramtest] off={off:#x} write");
        Timer::after_millis(120).await; // drain before a possibly-hanging op
        unsafe {
            let p = (base + off) as *mut u32;
            for i in 0..16u32 {
                core::ptr::write_volatile(p.add(i as usize), seed ^ i.wrapping_mul(0x0101_0101));
            }
        }
        log::info!("[psramtest] off={off:#x} read");
        Timer::after_millis(120).await;
        let mut bad: Option<(u32, u32, u32)> = None;
        unsafe {
            let p = (base + off) as *mut u32;
            for i in 0..16u32 {
                let want = seed ^ i.wrapping_mul(0x0101_0101);
                let got = core::ptr::read_volatile(p.add(i as usize));
                if got != want && bad.is_none() {
                    bad = Some((i, want, got));
                }
            }
        }
        match bad {
            None => log::info!("[psramtest] off={off:#x} ok"),
            Some((i, want, got)) => {
                crate::psram_mark_rw_fail(off);
                log::info!(
                    "[psramtest] off={off:#x} MISMATCH word {i}: want {want:#010x} got {got:#010x}"
                );
                log::info!("[psramtest] FAILED; the psram heap stays unmapped (SRAM-only)");
                return;
            }
        }
    }
    if crate::psram_mark_rw_ok() {
        log::info!("[psramtest] ALL OK; psram heap ready ({size:#x} bytes usable)");
    } else {
        log::info!("[err] psramtest: region vanished mid-test?");
    }
}

/// Sign the pending XMR request: fetch TRNG entropy, run the full signing
/// path, store the encrypted signed blob for `xmrout` retrieval.
///
/// This runs inside the USB receiver future. The signing stretch itself is
/// synchronous (CN scratchpad + BP+ prove; the host fixture takes ~100 ms
/// on a desktop, seconds-to-minutes on this board with the scratchpad in
/// PSRAM), so during it the executor makes no progress: no heartbeats, no
/// USB servicing. The host-side runner must allow minutes and treat
/// mid-sign silence as expected (bench/xmr_sign.py does). Moving the signer
/// onto core1 would remove the stall; the first bring-up values simplicity,
/// and the stall is bounded and observable.
async fn run_sign_xmr() {
    // Take the pending payload and the session mnemonic out of the console
    // state under a short lock (the signing stretch must not hold it).
    let (payload, mnemonic) = CONSOLE.lock(|cell| {
        let mut s = cell.borrow_mut();
        let payload = s.xmr_pending.take();
        let mnemonic = s.session_mnemonic();
        (payload, mnemonic)
    });
    let Some(payload) = payload else {
        log::info!("[err] xmr: no pending request");
        return;
    };
    let mnemonic = match mnemonic {
        Ok(m) => m,
        Err(e) => {
            log::info!("[err] xmr session mnemonic: {:?}", e.kind);
            return;
        }
    };

    // The XMR path's CN scratchpad is 2 MiB: it can only come from PSRAM,
    // and only r/w-verified PSRAM may be handed to the allocator. Refuse
    // early instead of tripping an allocation failure mid-flow.
    if !crate::psram_heap_ready() {
        log::info!("[err] xmr: psram heap not ready (run psramtest first); request dropped");
        return;
    }

    #[cfg(feature = "bench")]
    let source = if CONSOLE.lock(|c| c.borrow().xmr_seed.is_some()) {
        "fixed A/B"
    } else {
        "TRNG"
    };
    #[cfg(not(feature = "bench"))]
    let source = "TRNG";
    log::info!(
        "[xmr] request: enc_len={} (entropy: {source})",
        payload.len()
    );
    yield_now().await; // let the log pipe drain before the long stretch

    // §B.5 entropy injection. Production path: conditioned TRNG outputs (the
    // signer hashes them into its purpose-separated RNG stream). The bench
    // feature adds the `xmrseed` fixed-entropy override (byte-exact A/B
    // against a host recomputation), which takes the place of the TRNG read.
    let mut stats = TrngStats::default();
    let mut entropy_buf = [0u8; XMR_ENTROPY_LEN];
    #[cfg(feature = "bench")]
    let entropy_len = match CONSOLE.lock(|c| c.borrow_mut().xmr_seed.take()) {
        Some((buf, n)) => {
            entropy_buf[..n].copy_from_slice(&buf[..n]);
            n
        }
        None => match fill_entropy_from_trng(&mut stats, &mut entropy_buf).await {
            Some(n) => n,
            None => return,
        },
    };
    #[cfg(not(feature = "bench"))]
    let entropy_len = match fill_entropy_from_trng(&mut stats, &mut entropy_buf).await {
        Some(n) => n,
        None => return,
    };
    let entropy = &entropy_buf[..entropy_len];
    log::info!(
        "[xmr] entropy ready ({entropy_len} B); signing... (executor stalls for the duration)"
    );
    yield_now().await;

    // Timing probes: zero the accumulators before the timed stretch.
    #[cfg(feature = "perf-timing")]
    crate::perf_timing::reset();

    let input = SignInput::Mnemonic {
        mnemonic,
        passphrase: b"",
    };
    let mut out = [0u8; XMR_OUT_CAP];
    let t0 = Instant::now();
    match shlosilo::business::sign::sign_with_entropy(
        input,
        UrTypeTag::XmrTxUnsigned,
        &payload,
        entropy,
        &mut out,
    ) {
        Ok(n) => {
            let ms = t0.elapsed().as_millis();
            CONSOLE.lock(|cell| {
                let mut s = cell.borrow_mut();
                s.xmr_out[..n].copy_from_slice(&out[..n]);
                s.xmr_out_len = n;
            });
            match sha256::hash(&out[..n]) {
                Ok(digest) => log::info!(
                    "[xmr] signed ok: {n} bytes in {ms} ms sha256={} (fetch: xmrout <off> 512; total {} hex chars)",
                    sign_smoke::to_hex(&digest, &mut [0u8; 64]),
                    n * 2
                ),
                Err(e) => log::info!("[err] xmr sha256: {:?}", e.kind),
            }
        }
        Err(e) => log::info!("[err] xmr sign: {:?}", e.kind),
    }

    // Phase breakdown after the timed stretch (perf-timing builds only;
    // emitted here because the executor stall made mid-sign output
    // impossible).
    #[cfg(feature = "perf-timing")]
    crate::perf_timing::log_phases();
}

/// Fetch conditioned TRNG entropy into `buf` - the production entropy path
/// (and the fallback when no bench fixed-entropy override is set). Returns
/// the byte count, or None on TRNG failure (already logged). Runs under the
/// singleton TRNG guard and stops the source before returning.
async fn fill_entropy_from_trng(stats: &mut TrngStats, buf: &mut [u8]) -> Option<usize> {
    let mut ok = true;
    {
        let mut t = trng::instance().lock().await;
        for chunk in buf.chunks_mut(32) {
            match t.conditioned32(stats, trng::DEFAULT_BLOCK_TIMEOUT_MS).await {
                Ok(out) => chunk.copy_from_slice(&out),
                Err(e) => {
                    log::info!("[err] xmr entropy: {:?}", e);
                    ok = false;
                    break;
                }
            }
        }
        t.stop();
    }
    if ok { Some(buf.len()) } else { None }
}

/// Single-allocation probe via the raw allocator API (null on failure, no
/// panic): writes a pattern at both ends, reads it back, reports region.
fn probe_alloc(size: usize, align: usize) {
    if size == 0 {
        log::info!("[alloctest] size=0 skipped");
        return;
    }
    let Ok(layout) = core::alloc::Layout::from_size_align(size, align.max(1)) else {
        log::info!("[alloctest] size={size} align={align}: invalid layout");
        return;
    };
    let p = unsafe { alloc::alloc::alloc(layout) };
    if p.is_null() {
        log::info!("[alloctest] size={size} align={align} -> FAILED (null returned)");
        return;
    }
    let addr = p as usize;
    let region = if (0x1100_0000..0x1100_0000 + 0x800000).contains(&addr) {
        "psram"
    } else {
        "sram"
    };
    // touch both ends: catches an unmapped/aliased region and read-back faults
    unsafe {
        core::ptr::write_volatile(p, 0xA5);
        core::ptr::write_volatile(p.add(size - 1), 0x5A);
    }
    let ok = unsafe {
        core::ptr::read_volatile(p) == 0xA5 && core::ptr::read_volatile(p.add(size - 1)) == 0x5A
    };
    log::info!(
        "[alloctest] size={size} align={align} -> ok ptr={addr:#010x} region={region} rw={}",
        if ok { "ok" } else { "MISMATCH" }
    );
    unsafe { alloc::alloc::dealloc(p, layout) };
}

/// Touch-trail painter: every 40 ms, read the touch controller, convert to
/// screen coordinates, and (when a finger is down) paint a 3x3 dot at that
/// position. Old dots are left in place - the accumulating trail makes the
/// mapping visually checkable at a glance. Runs as a deferred job; the
/// periodic Timer await keeps the USB console and heartbeats responsive.
async fn run_touchdraw(secs: u32) {
    // Prep: dark background + the four corner blocks for reference.
    crate::panel::with_panel(|p| {
        p.lcd.fill(0x1082); // near-black
        let s = 16u16;
        let w = crate::lcd::WIDTH;
        let h = crate::lcd::HEIGHT;
        for (x, y) in [
            (2, 2),
            (w - s - 2, 2),
            (2, h - s - 2),
            (w - s - 2, h - s - 2),
        ] {
            p.lcd.fill_rect(x, y, s, s, 0xFFFF);
        }
    });
    log::info!("[tdraw] {secs}s: drag a finger on the screen; dots should track it exactly");
    let t0 = Instant::now();
    let mut dots: u32 = 0;
    let mut last: Option<(u16, u16)> = None;
    while (Instant::now() - t0).as_secs() < u64::from(secs) {
        let pt = crate::panel::with_panel(|p| p.touch.read_point());
        if let Some(Ok(pt)) = pt
            && pt.fingers > 0
        {
            let (sx, sy) = crate::touch::to_screen(pt.x, pt.y);
            // Skip duplicate positions (finger resting).
            if last != Some((sx, sy)) {
                crate::panel::with_panel(|p| {
                    p.lcd
                        .fill_rect(sx.saturating_sub(1), sy.saturating_sub(1), 3, 3, 0x07E0);
                });
                last = Some((sx, sy));
                dots += 1;
            }
        }
        Timer::after_millis(40).await;
    }
    log::info!("[tdraw] done: {dots} dot(s) painted");
}

/// Monitor the touch INT line (GP17) for edge activity. Tight polling with
/// periodic yields keeps the executor (USB, heartbeats) alive for the whole
/// window.
async fn run_touchint(ms: u32) {
    let p = unsafe { embassy_rp::Peripherals::steal() };
    let pin = embassy_rp::gpio::Input::new(p.PIN_17, embassy_rp::gpio::Pull::Up);
    log::info!("[tint] monitoring TP_INT (GP17) for {ms} ms - touch the panel now");
    let t0 = Instant::now();
    let mut last = pin.is_high();
    let mut edges: u32 = 0;
    let mut low: u32 = 0;
    let mut samples: u32 = 0;
    while (Instant::now() - t0).as_millis() < u64::from(ms) {
        let cur = pin.is_high();
        if cur != last {
            edges += 1;
            last = cur;
        }
        if !cur {
            low += 1;
        }
        samples += 1;
        if samples.is_multiple_of(512) {
            yield_now().await;
        }
    }
    log::info!(
        "[tint] done: samples={samples} edges={edges} low_samples={low} final_level={}",
        if last { "high" } else { "low" }
    );
}

/// Trace BUSY/ISR transitions after a cold start (bring-up diagnostic: shows
/// exactly when the state machine latches, and whether it ever generates).
#[cfg(feature = "bench")]
async fn run_trng_probe(job: TrngJob) {
    let mut t = trng::instance().lock().await;
    t.cold_start();
    let t0 = Instant::now();
    let mut last = (t.busy_flag(), t.isr_raw());
    log::info!("[tprobe] begin busy={} isr=0x{:08x}", last.0, last.1);
    let mut transitions: u32 = 0;
    loop {
        let now = Instant::now();
        if now - t0 >= embassy_time::Duration::from_millis(job.count as u64) {
            break;
        }
        let cur = (t.busy_flag(), t.isr_raw());
        if cur != last {
            transitions += 1;
            log::info!(
                "[tprobe] +{}us busy={} isr=0x{:08x}",
                (now - t0).as_micros(),
                cur.0,
                cur.1
            );
            last = cur;
        }
        yield_now().await;
    }
    let now = Instant::now();
    let cur = (t.busy_flag(), t.isr_raw());
    log::info!(
        "[tprobe] end +{}us busy={} isr=0x{:08x} transitions={}",
        (now - t0).as_micros(),
        cur.0,
        cur.1,
        transitions
    );
    t.stop();
}

/// Cross-check through the upstream embassy driver (see EMB_TRNG in main).
#[cfg(feature = "bench")]
async fn run_trng_emb(job: TrngJob) {
    if !crate::emb_trng_ready() {
        log::info!("[temb] upstream driver not initialised");
        return;
    }
    log::info!("[temb] upstream embassy driver, {} blocks", job.count);
    let mut buf = [0u8; trng::BLOCK_LEN];
    let mut hex = [0u8; trng::BLOCK_LEN * 2];
    for i in 0..job.count {
        let t0 = Instant::now();
        crate::emb_trng_fill(&mut buf);
        let us = (Instant::now() - t0).as_micros();
        log::info!(
            "[temb] #{} {} {}us",
            i,
            sign_smoke::to_hex(&buf, &mut hex),
            us
        );
        yield_now().await;
    }
    log::info!("[temb] done");
}

/// Stream through our reader as hex lines, then a stats summary:
/// raw 24-byte blocks (`trng <n>`) or conditioned 32-byte outputs
/// (`trng cond <n>`, each consuming two raw blocks).
///
/// Config precedence: `stress` (sample 2, failure-prone) > explicit
/// `sample=`/`chain=` overrides > the measured operating point. The
/// overrides exist for characterisation sweeps on the bench; the job
/// restores the defaults on exit either way.
#[cfg(feature = "bench")]
async fn run_trng_stream(job: TrngJob) {
    let mut t = trng::instance().lock().await;
    let sample = if job.stress {
        2
    } else {
        job.sample.unwrap_or(trng::DEFAULT_SAMPLE_COUNT)
    };
    let chain = job.chain.unwrap_or(trng::DEFAULT_CHAIN_LEN);
    t.set_sample_count(sample);
    t.set_chain_len(chain);
    let (ver, ac_fails, ac_trys) = (
        t.version(),
        t.autocorr_statistic().0,
        t.autocorr_statistic().1,
    );
    log::info!(
        "[trng] start: n={} cond={} sample={} chain={} timeout={}ms ver=0x{:08x} acstat={}/{}",
        job.count,
        job.cond,
        sample,
        chain,
        job.timeout_ms,
        ver,
        ac_fails,
        ac_trys
    );

    let t0 = Instant::now();
    let mut stats = TrngStats::default();
    let mut error: Option<TrngError> = None;
    let mut hex = [0u8; 64];

    for _ in 0..job.count {
        let read = if job.cond {
            match t.conditioned32(&mut stats, job.timeout_ms).await {
                Ok(out) => {
                    log::info!("[trng] {}", sign_smoke::to_hex(&out, &mut hex));
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else {
            match t.read_block(&mut stats, job.timeout_ms).await {
                Ok(block) => {
                    log::info!(
                        "[trng] {}",
                        sign_smoke::to_hex(&block, &mut hex[..trng::BLOCK_LEN * 2])
                    );
                    Ok(())
                }
                Err(e) => Err(e),
            }
        };
        if let Err(e) = read {
            error = Some(e);
            break;
        }
        // `read_block` awaits between retry cycles itself; one more yield
        // here keeps the logger's sender draining between delivered outputs.
        yield_now().await;
    }
    t.stop();
    t.restore_default_config();

    let ms = t0.elapsed().as_millis();
    let per_block_us = if stats.blocks > 0 {
        ms * 1000 / stats.blocks as u64
    } else {
        0
    };
    let (ac_fails, ac_trys) = t.autocorr_statistic();
    let mode = if job.cond { "cond outputs" } else { "blocks" };
    match error {
        None => log::info!(
            "[trng] done: {} raw blocks -> {} {mode} in {} ms (~{} us/block); crngt={} vn={} autocorr={} zero={} odd={} timeout={}; acstat={}/{}",
            stats.blocks,
            if job.cond {
                stats.blocks / 2
            } else {
                stats.blocks
            },
            ms,
            per_block_us,
            stats.crngt_err,
            stats.vn_err,
            stats.autocorr_err,
            stats.zero_blocks,
            stats.odd_states,
            stats.busy_timeouts,
            ac_fails,
            ac_trys
        ),
        Some(e) => log::info!(
            "[trng] FAILED after {} raw blocks in {} ms: {:?}; crngt={} vn={} autocorr={} zero={} odd={} timeout={}; acstat={}/{}",
            stats.blocks,
            ms,
            e,
            stats.crngt_err,
            stats.vn_err,
            stats.autocorr_err,
            stats.zero_blocks,
            stats.odd_states,
            stats.busy_timeouts,
            ac_fails,
            ac_trys
        ),
    }
}

/// Largest raw capture accepted: 262,144 blocks x 24 B = 6 MiB (the PSRAM
/// heap has 8 MiB; the generator vectors take ~320 KiB).
#[cfg(feature = "bench")]
const RAW_MAX_BLOCKS: u32 = 262_144;

/// Blocks per dump line (4 x 192 bits = 96 B -> 192 hex chars + index).
#[cfg(feature = "bench")]
const RAW_DUMP_BLOCKS_PER_LINE: usize = 4;

/// `trngcheck [nblocks] [timeout_ms]`: capture n blocks through the
/// production reader (`read_block`: checked path, health checks + Von
/// Neumann active, chain 4 / sample 200 defaults) into the dump buffer.
/// Stream back with `trngrawout` (paced + indexed). Defaults: 16384 blocks.
#[cfg(feature = "bench")]
fn parse_trngcheck(args: &[u8]) -> TrngJob {
    let mut n: u32 = 16384;
    let mut timeout: u64 = 0;
    for (k, word) in args
        .split(|b| b.is_ascii_whitespace())
        .filter(|w| !w.is_empty())
        .enumerate()
    {
        let s = core::str::from_utf8(word).unwrap_or("");
        match k {
            0 => n = s.parse::<u32>().unwrap_or(16384).clamp(1, RAW_MAX_BLOCKS),
            1 => timeout = s.parse::<u64>().unwrap_or(0),
            _ => {}
        }
    }
    TrngJob {
        mode: JobMode::CheckCapture,
        arg: 0,
        stress: false,
        cond: false,
        sample: None,
        chain: None,
        timeout_ms: timeout,
        count: n,
        off: 0,
    }
}

/// Checked-path capture handler: fills the dump buffer via the production
/// reader so the host can retrieve the dataset with the paced, indexed
/// `trngrawout` dump (the per-line log stream cannot carry thousands of
/// blocks without USB pipe drops).
#[cfg(feature = "bench")]
async fn run_trngcheck(job: TrngJob) {
    let blocks = job.count as usize;
    let timeout_ms = if job.timeout_ms == 0 {
        trng::DEFAULT_BLOCK_TIMEOUT_MS
    } else {
        job.timeout_ms
    };
    let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(blocks * trng::BLOCK_LEN);
    let mut stats = TrngStats::default();
    let t0 = Instant::now();
    let mut result: Result<(), trng::TrngError> = Ok(());
    {
        let mut t = trng::instance().lock().await;
        for _ in 0..blocks {
            match t.read_block(&mut stats, timeout_ms).await {
                Ok(block) => buf.extend_from_slice(&block),
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        t.stop();
    }
    match result {
        Ok(()) => {
            let ms = t0.elapsed().as_millis().max(1);
            let n = buf.len() / trng::BLOCK_LEN;
            let bits = (n * 192) as u64;
            let tstr = match crate::read_die_temp_c() {
                Some(v) => alloc::format!("{v:.1}C"),
                None => alloc::string::String::from("n/a"),
            };
            log::info!(
                "[tchk] captured {n} checked-path blocks = {bits} bits in {ms} ms ({} us/block; crngt={} vn={} autocorr={} zero={} odd={} timeout={} temp={tstr})",
                ms * 1000 / (n as u64).max(1),
                stats.crngt_err,
                stats.vn_err,
                stats.autocorr_err,
                stats.zero_blocks,
                stats.odd_states,
                stats.busy_timeouts,
            );
            CONSOLE.lock(|c| c.borrow_mut().raw_buf = Some(buf));
        }
        Err(e) => log::info!("[tchk] capture failed after {blocks} requested: {e:?}"),
    }
}

/// `trngtrace [blocks] [chain] [sample] [window]`: trace the
/// (TRNG_BUSY, TRNG_VALID) waveform around raw blocks. Defaults: 3 blocks,
/// chain 4, sample 0, window 4096 core cycles (raise the window to cover a
/// slow fill, e.g. 60000 for sample=200).
#[cfg(feature = "bench")]
fn parse_trngtrace(args: &[u8]) -> TrngJob {
    let mut blocks: u32 = 3;
    let mut chain: Option<u8> = None;
    let mut sample: Option<u32> = None;
    let mut window: u64 = 4096;
    for (k, word) in args
        .split(|b| b.is_ascii_whitespace())
        .filter(|w| !w.is_empty())
        .enumerate()
    {
        let s = core::str::from_utf8(word).unwrap_or("");
        match k {
            0 => blocks = s.parse::<u32>().unwrap_or(3).clamp(1, 16),
            1 => chain = s.parse::<u8>().ok().map(|v| v.min(4)),
            2 => sample = s.parse::<u32>().ok().map(|v| v.min(0xffff)),
            3 => window = s.parse::<u64>().unwrap_or(4096).clamp(256, 600_000),
            _ => {}
        }
    }
    TrngJob {
        mode: JobMode::RawTrace,
        arg: 0,
        stress: false,
        cond: false,
        sample,
        chain,
        // `timeout_ms` carries the trace window here.
        timeout_ms: window,
        count: blocks,
        off: 0,
    }
}

/// `trngraw <nblocks> [chain] [sample]`: capture n 192-bit blocks of raw
/// ROSC samples (all internal checking and conditioning bypassed — the
/// SP 800-90B source-characterisation path). Defaults: chain 4 (the
/// checked-path operating point), sample 0 (one sample per cycle, the
/// bootrom / pico-sdk raw value).
#[cfg(feature = "bench")]
fn parse_trngraw(args: &[u8]) -> TrngJob {
    let mut n: u32 = 4096;
    let mut chain: Option<u8> = None;
    let mut sample: Option<u32> = None;
    for (k, word) in args
        .split(|b| b.is_ascii_whitespace())
        .filter(|w| !w.is_empty())
        .enumerate()
    {
        let s = core::str::from_utf8(word).unwrap_or("");
        match k {
            0 => n = s.parse::<u32>().unwrap_or(4096).clamp(1, RAW_MAX_BLOCKS),
            1 => {
                chain = match s {
                    "rand" => Some(trng::CHAIN_RANDOM),
                    _ => s.parse::<u8>().ok().map(|v| v.min(4)),
                }
            }
            2 => sample = s.parse::<u32>().ok().map(|v| v.min(0xffff)),
            _ => {}
        }
    }
    TrngJob {
        mode: JobMode::RawCapture,
        arg: 0,
        stress: false,
        cond: false,
        sample,
        chain,
        timeout_ms: 0,
        count: n,
        off: 0,
    }
}

/// `trngrawout [start_block] [pace_ms]`: stream the buffered raw capture as
/// `[traw] <block> <hex>` lines (4 blocks per line), paced (default 1 ms per
/// line) so the USB log pipe cannot overflow. A dropped line would leave a
/// gap in the hex; the host detects gaps by block number and re-dumps the
/// affected range.
#[cfg(feature = "bench")]
fn parse_trngrawout(args: &[u8]) -> TrngJob {
    let mut start: usize = 0;
    let mut pace: u64 = 1;
    for (k, word) in args
        .split(|b| b.is_ascii_whitespace())
        .filter(|w| !w.is_empty())
        .enumerate()
    {
        let s = core::str::from_utf8(word).unwrap_or("");
        match k {
            0 => start = s.parse::<usize>().unwrap_or(0),
            1 => pace = s.parse::<u64>().unwrap_or(1).clamp(1, 1000),
            _ => {}
        }
    }
    TrngJob {
        mode: JobMode::RawDump,
        arg: 0,
        stress: false,
        cond: false,
        sample: None,
        chain: None,
        timeout_ms: pace,
        count: 0,
        off: start,
    }
}

/// Capture handler: fills the console's raw buffer (PSRAM-routed for any
/// realistic size) and reports rate + rough sanity figures.
#[cfg(feature = "bench")]
async fn run_trngraw(job: TrngJob) {
    let blocks = job.count as usize;
    let chain = job.chain.unwrap_or(trng::DEFAULT_CHAIN_LEN);
    let sample = job.sample.unwrap_or(0);
    let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(blocks * trng::BLOCK_LEN);
    let t0 = Instant::now();
    let result = {
        let mut t = trng::instance().lock().await;
        t.capture_raw(blocks, chain, sample, &mut buf)
    };
    match result {
        Ok(n) => {
            let ms = t0.elapsed().as_millis().max(1);
            let bits = u64::from(n) * 192;
            let zero_blocks = buf
                .chunks(trng::BLOCK_LEN)
                .filter(|c| c.iter().all(|&b| b == 0))
                .count();
            let ones: u32 = buf.iter().map(|b| b.count_ones()).sum();
            let ones_pm = (u64::from(ones) * 1000 / bits.max(1)) as u32;
            let tstr = match crate::read_die_temp_c() {
                Some(v) => alloc::format!("{v:.1}C"),
                None => alloc::string::String::from("n/a"),
            };
            log::info!(
                "[traw] captured {n} blocks = {bits} raw bits in {ms} ms ({} kbit/s; ones~{ones_pm}e-3; zero-blocks={zero_blocks} temp={tstr})",
                bits / ms
            );
            CONSOLE.lock(|c| c.borrow_mut().raw_buf = Some(buf));
        }
        Err(e) => log::info!("[traw] capture failed: {e:?}"),
    }
}

/// Dump handler: streams the stored capture as paced hex lines. The buffer
/// is copied out chunk-wise under the console lock so nothing is borrowed
/// across the awaits.
#[cfg(feature = "bench")]
async fn run_trngrawout(job: TrngJob) {
    let total = CONSOLE.lock(|c| {
        c.borrow()
            .raw_buf
            .as_ref()
            .map(|b| b.len() / trng::BLOCK_LEN)
            .unwrap_or(0)
    });
    if total == 0 {
        log::info!("[err] trngrawout: no capture buffered (run `trngraw <n>` first)");
        return;
    }
    let start = job.off.min(total);
    let pace_ms = if job.timeout_ms == 0 {
        1
    } else {
        job.timeout_ms.min(1000)
    };
    log::info!(
        "[traw] dump {start}..{total} ({} blocks, pace {pace_ms} ms/line)",
        total - start
    );
    let mut i = start;
    while i < total {
        let take = RAW_DUMP_BLOCKS_PER_LINE.min(total - i);
        let mut raw = [0u8; trng::BLOCK_LEN * RAW_DUMP_BLOCKS_PER_LINE];
        let nbytes = CONSOLE.lock(|c| {
            let s = c.borrow();
            let buf = s.raw_buf.as_ref().expect("buffer checked above");
            let a = i * trng::BLOCK_LEN;
            let n = take * trng::BLOCK_LEN;
            raw[..n].copy_from_slice(&buf[a..a + n]);
            n
        });
        let mut hex = [0u8; trng::BLOCK_LEN * RAW_DUMP_BLOCKS_PER_LINE * 2];
        let s = sign_smoke::to_hex(&raw[..nbytes], &mut hex);
        log::info!("[traw] {i} {s}");
        i += take;
        Timer::after_millis(pace_ms).await;
    }
    log::info!("[traw] done (buffer holds {total} blocks)");
}

/// Trace handler: runs the trace and dumps the recorded waveform as paced
/// lines (`[ttr] b<blk> e<idx> cyc=<cycles> polls=<n> busy=<0|1> valid=<0|1>`).
#[cfg(feature = "bench")]
async fn run_trngtrace(job: TrngJob) {
    let blocks = job.count as usize;
    let chain = job.chain.unwrap_or(trng::DEFAULT_CHAIN_LEN);
    let sample = job.sample.unwrap_or(0);
    let window = if job.timeout_ms == 0 {
        4096
    } else {
        job.timeout_ms
    };
    let mut out: alloc::vec::Vec<trng::TraceBlock> = alloc::vec::Vec::new();
    let result = {
        let mut t = trng::instance().lock().await;
        t.trace_raw(blocks, chain, sample, window as u32, &mut out)
    };
    match result {
        Ok(n) => {
            let tstr = match crate::read_die_temp_c() {
                Some(v) => alloc::format!("{v:.1}C"),
                None => alloc::string::String::from("n/a"),
            };
            log::info!("[ttr] {n} blocks traced; temp={tstr}");
            for (bi, tb) in out.iter().enumerate() {
                log::info!(
                    "[ttr] b{bi} read_spins={} valid_at_read={} window={} events={}{}",
                    tb.read_spins,
                    tb.ehr_valid as u8,
                    tb.window,
                    tb.events.len(),
                    if tb.truncated { " TRUNCATED" } else { "" }
                );
                for (ei, ev) in tb.events.iter().enumerate() {
                    log::info!(
                        "[ttr] b{bi} e{ei} cyc={} polls={} busy={} valid={}",
                        ev.cycles,
                        ev.polls,
                        ev.busy as u8,
                        ev.valid as u8
                    );
                    Timer::after_millis(2).await;
                }
            }
            log::info!("[ttr] done");
        }
        Err(e) => log::info!("[ttr] trace failed: {e:?}"),
    }
}

/// Trim ASCII whitespace from both ends.
fn trim_ascii(s: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = s.len();
    while start < end && s[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && s[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &s[start..end]
}

/// Split at the first space: (command word, trimmed rest).
fn split_first_word(line: &[u8]) -> (&[u8], &[u8]) {
    match line.iter().position(|&b| b == b' ') {
        Some(i) => (&line[..i], trim_ascii(&line[i + 1..])),
        None => (line, &[]),
    }
}

/// Parse 1..=4 hex chars into a u16 (`lcd fill` colour entry). Not
/// bench-gated: the panel commands are part of the base surface.
fn parse_hex_u16(s: &[u8]) -> Option<u16> {
    let s = strip_0x(trim_ascii(s));
    if s.is_empty() || s.len() > 4 {
        return None;
    }
    let mut v: u16 = 0;
    for &b in s {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        v = (v << 4) | u16::from(d);
    }
    Some(v)
}

/// Parse 1..=2 hex chars into a u8, with an optional 0x prefix (`i2c rd`).
fn parse_hex_u8(s: &[u8]) -> Option<u8> {
    let s = strip_0x(trim_ascii(s));
    if s.is_empty() || s.len() > 2 {
        return None;
    }
    let mut v: u8 = 0;
    for &b in s {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        v = (v << 4) | d;
    }
    Some(v)
}

/// Parsed bb-command arguments: `swap`, `d=<half-cycles>` and up to four
/// bare numbers (interpreted as hex, `0x` prefix optional).
struct BbArgs {
    swap: bool,
    half: Option<u32>,
    nums: [Option<u32>; 4],
}

fn parse_bb_args(args: &[u8]) -> BbArgs {
    let mut out = BbArgs {
        swap: false,
        half: None,
        nums: [None; 4],
    };
    let mut n = 0usize;
    for w in args
        .split(|b: &u8| b.is_ascii_whitespace())
        .filter(|w| !w.is_empty())
    {
        if w == b"swap" {
            out.swap = true;
            continue;
        }
        let Ok(s) = core::str::from_utf8(w) else {
            continue;
        };
        if let Some(v) = s.strip_prefix("d=") {
            if let Ok(v) = v.parse::<u32>() {
                out.half = Some(v.clamp(100, 100_000));
            }
            continue;
        }
        let t = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        if let Ok(v) = u32::from_str_radix(t, 16)
            && n < out.nums.len()
        {
            out.nums[n] = Some(v);
            n += 1;
        }
    }
    out
}

/// Parse 1..=8 hex chars into a u32, with an optional 0x prefix
/// (`sd read`). Not bench-gated: the SD commands are base surface.
fn parse_hex_u32(s: &[u8]) -> Option<u32> {
    let s = strip_0x(trim_ascii(s));
    if s.is_empty() || s.len() > 8 {
        return None;
    }
    let mut v: u32 = 0;
    for &b in s {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        v = (v << 4) | u32::from(d);
    }
    Some(v)
}

/// Drop a leading `0x`/`0X` from a trimmed byte string.
fn strip_0x(s: &[u8]) -> &[u8] {
    if s.len() >= 2 && s[0] == b'0' && (s[1] == b'x' || s[1] == b'X') {
        &s[2..]
    } else {
        s
    }
}

/// Parse the `seq-count` segment of a multipart frame URI
/// (`ur:<type>/<seq>-<count>/<body>`), or None if the shape does not match.
fn parse_seq(s: &str) -> Option<(usize, usize)> {
    let rest = s.strip_prefix("ur:")?;
    let (_type_name, rest) = rest.split_once('/')?;
    let (seq_seg, _body) = rest.split_once('/')?;
    let (seq, count) = seq_seg.split_once('-')?;
    Some((seq.parse().ok()?, count.parse().ok()?))
}

/// Parse a hex string into `out`; returns the byte count on success.
/// Base surface: used by `ui ur` (payload staging) and by the bench-only
/// commands (`xmrseed` / `entropy`).
fn parse_hex(s: &[u8], out: &mut [u8]) -> Option<usize> {
    let s = trim_ascii(s);
    if s.is_empty() || !s.len().is_multiple_of(2) || s.len() > out.len() * 2 {
        return None;
    }
    for (i, pair) in s.chunks(2).enumerate() {
        out[i] = (hex_val(pair[0])? << 4) | hex_val(pair[1])?;
    }
    Some(s.len() / 2)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
