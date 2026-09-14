//! Bench command channel over the USB console (bidirectional serial).
//!
//! Development channel for the pico2 bring-up stage: the host feeds test
//! fixtures - a UR string, single frame or multipart fragments - over the
//! serial port and the board signs them with the session mnemonic, printing
//! the result. This is how a real-size fixture (e.g. the 12.4 KiB Sparrow
//! signet PSBT) reaches the board before a QR scanner exists.
//!
//! NOT a production input path: production appearances take inputs via QR /
//! dice with on-device confirmation. This channel exists on the bench
//! firmware so the host can drive exact test vectors; the same reasoning
//! applies to `entropy`, which loads test key material.
//!
//! Protocol: ASCII lines (`\n` or `\r` terminates; `\r\n` yields one line).
//! Responses are `log` records on the same port.

use core::cell::RefCell;
use core::fmt::Write as _;

extern crate alloc;

use embassy_futures::yield_now;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_time::Instant;
use embassy_usb_logger::ReceiverHandler;

use shlosilo::business::sign::SignInput;
use shlosilo::encoding::sha256;
use shlosilo::entropy::mnemonic::{Mnemonic, WordCount};
use shlosilo::error::{ShlosiloError, ShlosiloErrorKind};
use shlosilo::ur::ur_decode;
use shlosilo::ur::ur_encode::UrTypeTag;
use shlosilo::ur::ur_multipart::UrMultipartDecoder;

use crate::sign_smoke::{self, BufWriter};
use crate::trng::{self, TrngError, TrngStats};

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
    /// against a host recomputation. Bench-only; the production path is
    /// the TRNG.
    xmr_seed: Option<([u8; 64], usize)>,
    /// Last signed XMR blob, retrievable via `xmrout <hex_off> <hex_len>`.
    xmr_out: [u8; XMR_OUT_CAP],
    xmr_out_len: usize,
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
            xmr_seed: None,
            xmr_out: [0u8; XMR_OUT_CAP],
            xmr_out_len: 0,
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
            b"heap" => self.cmd_heap(args),
            b"entropy" => self.cmd_entropy(args),
            b"trng" => return Some(parse_trng_job(args)),
            b"trngdump" => return Some(TrngJob::simple(JobMode::Dump)),
            b"trngrst" => return Some(TrngJob::simple(JobMode::Rst)),
            b"trngprobe" => return Some(parse_trng_probe(args)),
            b"trngemb" => return Some(parse_trng_emb(args)),
            b"xmrout" => self.cmd_xmrout(args),
            b"xmrseed" => self.cmd_xmrseed(args),
            _ => {
                let echo = core::str::from_utf8(cmd).unwrap_or("<non-utf8>");
                log::info!("[err] unknown command: {echo} (try: help)");
            }
        }
        None
    }

    fn cmd_help(&self) {
        log::info!("[help] bench channel commands:");
        log::info!("[help]   help            this text");
        log::info!("[help]   version         version + C-ABI version");
        log::info!("[help]   smoke           boot signing-smoke report (also replayed every 20 s)");
        log::info!("[help]   heap [reset]    allocator used/free/peak (reset re-arms peak)");
        log::info!("[help]   entropy <hex>   set session mnemonic from test-vector entropy");
        log::info!(
            "[help]                   (16/20/24/28/32 bytes; default = built-in dice fixture)"
        );
        log::info!(
            "[help]   ur:<type>/...   feed a UR (single frame, or multipart fragments in any"
        );
        log::info!(
            "[help]                   order); signs on completion with the session mnemonic"
        );
        log::info!("[help]   trng [stress] [cond] [sample=<n>] [chain=<0-4>] [timeout=<ms>] [n]");
        log::info!(
            "[help]                   n raw blocks (24 B) as hex; cond = n conditioned 32-byte"
        );
        log::info!(
            "[help]                   outputs (SHA-256 over two blocks - the consumer path);"
        );
        log::info!(
            "[help]                   stress = sample 2; overrides are restored on job exit"
        );
        log::info!("[help]   trngdump        raw TRNG register dump (bring-up diagnostic)");
        log::info!("[help]   trngrst         RESETS-block cycle for the TRNG, then a dump");
        log::info!("[help]   trngprobe [ms]  cold-start + trace every BUSY/ISR transition");
        log::info!("[help]   trngemb [n]     read n blocks via the upstream embassy driver");
        log::info!("[help]   xmrout <off> <n> fetch a hex segment of the last signed XMR blob");
        log::info!("[help]   ur:xmr-txunsigned/...  signs with TRNG entropy (deferred job;");
        log::info!("[help]                   fetch the result with xmrout)");
        log::info!("[help] lines end with \\n or \\r");
    }

    fn cmd_version(&self) {
        let v = shlosilo::ffi::version::SHLOSILO_VERSION_STRING.trim_end_matches('\0');
        let cabi = shlosilo::ffi::version::SHLOSILO_CABI_VERSION_STRING.trim_end_matches('\0');
        log::info!("[ver] {v} (cabi {cabi})");
    }

    fn cmd_smoke(&self) {
        match sign_smoke::report() {
            Some(r) => log::info!("{r}"),
            None => log::info!("[smoke] report not ready yet"),
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
    stress: bool,
    /// Stream conditioned 32-byte outputs (SHA-256) instead of raw blocks.
    cond: bool,
    sample: Option<u32>,
    chain: Option<u8>,
    /// Per-block patience budget in milliseconds.
    timeout_ms: u64,
    /// Stream: block/output count. Probe: duration in ms. Emb: block count.
    count: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JobMode {
    /// Our reader, streaming accepted blocks as hex.
    Stream,
    /// Raw busy/ISR transition trace after a cold start.
    Probe,
    /// The upstream embassy driver (cross-check).
    Emb,
    /// Raw register dump.
    Dump,
    /// RESETS-block cycle, then a dump.
    Rst,
    /// Sign the pending XMR request (TRNG entropy + the full signing path).
    SignXmr,
}

impl TrngJob {
    /// A job with no parameters (dump / reset).
    const fn simple(mode: JobMode) -> Self {
        Self {
            mode,
            stress: false,
            cond: false,
            sample: None,
            chain: None,
            timeout_ms: 0,
            count: 0,
        }
    }
}

/// Parse `trng [stress] [cond] [sample=<n>] [chain=<0-4>] [timeout=<ms>]
/// [nblocks]`; default 64 blocks, capped at 4096.
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
            count = n.clamp(1, 4096);
        }
    }
    TrngJob {
        mode: JobMode::Stream,
        stress,
        cond,
        sample,
        chain,
        timeout_ms,
        count,
    }
}

/// Parse `trngprobe [ms]` (default 60 ms): cold-start the block and trace
/// every BUSY/ISR transition.
fn parse_trng_probe(args: &[u8]) -> TrngJob {
    let ms = core::str::from_utf8(trim_ascii(args))
        .unwrap_or("")
        .parse::<u32>()
        .unwrap_or(60)
        .clamp(1, 5000);
    TrngJob {
        mode: JobMode::Probe,
        stress: false,
        cond: false,
        sample: None,
        chain: None,
        timeout_ms: 0,
        count: ms,
    }
}

/// Parse `trngemb [n]` (default 4): read n blocks through the upstream
/// embassy driver, with per-block timing.
fn parse_trng_emb(args: &[u8]) -> TrngJob {
    let n = core::str::from_utf8(trim_ascii(args))
        .unwrap_or("")
        .parse::<u32>()
        .unwrap_or(4)
        .clamp(1, 256);
    TrngJob {
        mode: JobMode::Emb,
        stress: false,
        cond: false,
        sample: None,
        chain: None,
        timeout_ms: 0,
        count: n,
    }
}

/// Dispatch a deferred TRNG job. All register access happens under the
/// single trng::instance() lock (see trng.rs "Ownership").
async fn run_trng_job(job: TrngJob) {
    match job.mode {
        JobMode::Stream => run_trng_stream(job).await,
        JobMode::Probe => run_trng_probe(job).await,
        JobMode::Emb => run_trng_emb(job).await,
        JobMode::Dump => {
            let t = trng::instance().lock().await;
            log_snapshot(&t.snapshot());
        }
        JobMode::Rst => {
            let mut t = trng::instance().lock().await;
            t.reset_cycle();
            t.stop();
            log_snapshot(&t.snapshot());
        }
        JobMode::SignXmr => run_sign_xmr().await,
    }
}

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

    log::info!(
        "[xmr] request: enc_len={} (entropy: {})",
        payload.len(),
        if CONSOLE.lock(|c| c.borrow().xmr_seed.is_some()) {
            "fixed A/B"
        } else {
            "TRNG"
        }
    );
    yield_now().await; // let the log pipe drain before the long stretch

    // §B.5 entropy injection. Production path: conditioned TRNG outputs (the
    // signer hashes them into its purpose-separated RNG stream). A/B path:
    // `xmrseed` set a fixed byte string, so the output can be compared
    // byte-for-byte against a host recomputation.
    let fixed = CONSOLE.lock(|c| c.borrow_mut().xmr_seed.take());
    let mut stats = TrngStats::default();
    let mut entropy_buf = [0u8; XMR_ENTROPY_LEN];
    let entropy_len;
    if let Some((buf, n)) = fixed {
        entropy_buf[..n].copy_from_slice(&buf[..n]);
        entropy_len = n;
    } else {
        let mut ok = true;
        {
            let mut t = trng::instance().lock().await;
            for chunk in entropy_buf.chunks_mut(32) {
                match t
                    .conditioned32(&mut stats, trng::DEFAULT_BLOCK_TIMEOUT_MS)
                    .await
                {
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
        if !ok {
            return;
        }
        entropy_len = XMR_ENTROPY_LEN;
    }
    let entropy = &entropy_buf[..entropy_len];
    log::info!(
        "[xmr] entropy ready ({entropy_len} B); signing... (executor stalls for the duration)"
    );
    yield_now().await;

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
}

/// Trace BUSY/ISR transitions after a cold start (bring-up diagnostic: shows
/// exactly when the state machine latches, and whether it ever generates).
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

/// Parse the `seq-count` segment of a multipart frame URI
/// (`ur:<type>/<seq>-<count>/<body>`), or None if the shape does not match.
fn parse_seq(s: &str) -> Option<(usize, usize)> {
    let rest = s.strip_prefix("ur:")?;
    let (_type_name, rest) = rest.split_once('/')?;
    let (seq_seg, _body) = rest.split_once('/')?;
    let (seq, count) = seq_seg.split_once('-')?;
    Some((seq.parse().ok()?, count.parse().ok()?))
}

/// Parse hex into `out`; returns the byte count on success.
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
