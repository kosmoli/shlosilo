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

/// Session state for the command channel.
struct ConsoleState {
    line: [u8; LINE_CAP],
    line_len: usize,
    /// A line arrived that did not fit; drop it and report once.
    line_overflow: bool,
    /// Session mnemonic override (indices + word count) set by `entropy`.
    /// `None` = the built-in dice fixture (the same wallet as the boot smoke).
    session: Option<([u16; 24], u8)>,
    /// In-flight multipart UR session.
    decoder: Option<UrMultipartDecoder>,
}

impl ConsoleState {
    const fn new() -> Self {
        Self {
            line: [0u8; LINE_CAP],
            line_len: 0,
            line_overflow: false,
            session: None,
            decoder: None,
        }
    }

    /// Append incoming bytes; process each completed line. Returns a
    /// deferred job when the line requests one (TRNG streaming must run
    /// with awaits — see `handle_data`).
    fn feed(&mut self, data: &[u8]) -> Option<TrngJob> {
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
            self.handle_ur(line);
            return None;
        }

        let (cmd, args) = split_first_word(line);
        match cmd {
            b"help" => self.cmd_help(),
            b"version" => self.cmd_version(),
            b"smoke" => self.cmd_smoke(),
            b"heap" => self.cmd_heap(args),
            b"entropy" => self.cmd_entropy(args),
            b"trng" => return Some(parse_trng_job(args)),
            b"trngdump" => self.cmd_trngdump(),
            b"trngrst" => self.cmd_trngrst(),
            b"trngprobe" => return Some(parse_trng_probe(args)),
            b"trngemb" => return Some(parse_trng_emb(args)),
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
        log::info!("[help]   trng [stress] [sample=<n>] [chain=<0-4>] [nblocks]");
        log::info!(
            "[help]                   read nblocks TRNG blocks (24 B each, default 64) as hex;"
        );
        log::info!("[help]                   stress = sample 2; sample/chain override the config;");
        log::info!("[help]                   ends with a stats line");
        log::info!("[help]   trngdump        raw TRNG register dump (bring-up diagnostic)");
        log::info!("[help]   trngrst         RESETS-block cycle for the TRNG, then a dump");
        log::info!("[help]   trngprobe [ms]  cold-start + trace every BUSY/ISR transition");
        log::info!("[help]   trngemb [n]     read n blocks via the upstream embassy driver");
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
            log::info!("[heap] peak reset; used {used} free {free} peak {peak}");
        } else {
            let (used, free, peak) = crate::heap_stats();
            log::info!("[heap] used {used} free {free} peak {peak}");
        }
    }

    /// Raw TRNG register dump (bring-up diagnostics; see trng.rs).
    fn cmd_trngdump(&self) {
        let s = trng::snapshot();
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

    /// RESETS-block cycle on demand (A/B: is the peripheral reset cycle the
    /// thing that leaves the block in a weird state?).
    fn cmd_trngrst(&self) {
        trng::reset_cycle();
        trng::stop();
        self.cmd_trngdump();
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

    fn handle_ur(&mut self, line: &[u8]) {
        let s = match core::str::from_utf8(line) {
            Ok(s) => s,
            Err(_) => {
                log::info!("[err] ur: line is not utf8");
                return;
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
            self.sign_and_report(tag, decoded.as_ref());
            return;
        }
        // Not a single frame (or over its budget): try multipart below.

        let (seq, count) = match parse_seq(s) {
            Some(v) => v,
            None => {
                log::info!("[err] ur: neither a valid single frame nor a multipart frame");
                return;
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
                            self.sign_and_report(tag, &payload);
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
    }

    fn sign_and_report(&mut self, tag: UrTypeTag, payload: &[u8]) {
        match tag {
            UrTypeTag::XmrTxUnsigned | UrTypeTag::XmrTxSigned | UrTypeTag::CryptoMoneroTx => {
                log::info!(
                    "[err] sign: XMR paths need an entropy source (RP2350 TRNG) - not wired yet"
                );
                return;
            }
            _ => {}
        }

        let mnemonic = match self.session_mnemonic() {
            Ok(m) => m,
            Err(e) => {
                log::info!("[err] session mnemonic: {:?}", e.kind);
                return;
            }
        };
        let input = SignInput::Mnemonic {
            mnemonic,
            passphrase: b"",
        };

        // BTC/ETH do not consume injected entropy (RFC-6979); empty slice per
        // the §B.5 contract. XMR would take TRNG bytes here.
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
    sample: Option<u32>,
    chain: Option<u8>,
    /// Stream: block count. Probe: duration in ms. Emb: block count.
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
}

/// Parse `trng [stress] [sample=<n>] [chain=<0-4>] [nblocks]`;
/// default 64 blocks, capped at 4096.
fn parse_trng_job(args: &[u8]) -> TrngJob {
    let mut stress = false;
    let mut sample: Option<u32> = None;
    let mut chain: Option<u8> = None;
    let mut count: u32 = 64;
    for word in args
        .split(|b| b.is_ascii_whitespace())
        .filter(|w| !w.is_empty())
    {
        let s = core::str::from_utf8(word).unwrap_or("");
        if word == b"stress" {
            stress = true;
        } else if let Some(v) = s.strip_prefix("sample=") {
            sample = v.parse::<u32>().ok().map(|n| n.min(0xffff));
        } else if let Some(v) = s.strip_prefix("chain=") {
            chain = v.parse::<u8>().ok().map(|n| n.min(4));
        } else if let Ok(n) = s.parse::<u32>() {
            count = n.clamp(1, 4096);
        }
    }
    TrngJob {
        mode: JobMode::Stream,
        stress,
        sample,
        chain,
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
        sample: None,
        chain: None,
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
        sample: None,
        chain: None,
        count: n,
    }
}

/// Dispatch a deferred TRNG job.
async fn run_trng_job(job: TrngJob) {
    match job.mode {
        JobMode::Stream => run_trng_stream(job).await,
        JobMode::Probe => run_trng_probe(job).await,
        JobMode::Emb => run_trng_emb(job).await,
    }
}

/// Trace BUSY/ISR transitions after a cold start (bring-up diagnostic: shows
/// exactly when the state machine latches, and whether it ever generates).
async fn run_trng_probe(job: TrngJob) {
    trng::cold_start();
    let t0 = Instant::now();
    let mut last = (trng::busy_flag(), trng::isr_raw());
    log::info!("[tprobe] begin busy={} isr=0x{:08x}", last.0, last.1);
    let mut transitions: u32 = 0;
    loop {
        let now = Instant::now();
        if now - t0 >= embassy_time::Duration::from_millis(job.count as u64) {
            break;
        }
        let cur = (trng::busy_flag(), trng::isr_raw());
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
    let cur = (trng::busy_flag(), trng::isr_raw());
    log::info!(
        "[tprobe] end +{}us busy={} isr=0x{:08x} transitions={}",
        (now - t0).as_micros(),
        cur.0,
        cur.1,
        transitions
    );
    trng::stop();
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

/// Stream `count` blocks through our reader as hex lines, then a stats
/// summary.
///
/// Config precedence: `stress` (sample 2, failure-prone) > explicit
/// `sample=`/`chain=` overrides > the datasheet-recommended defaults.
/// The overrides exist for characterisation sweeps on the bench (find the
/// config where the hardware entropy checks behave); the job restores the
/// defaults on exit either way.
async fn run_trng_stream(job: TrngJob) {
    let sample = if job.stress {
        2
    } else {
        job.sample.unwrap_or(trng::DEFAULT_SAMPLE_COUNT)
    };
    let chain = job.chain.unwrap_or(trng::DEFAULT_CHAIN_LEN);
    trng::set_sample_count(sample);
    trng::set_chain_len(chain);
    let (ver, ac_fails, ac_trys) = (
        trng::version(),
        trng::autocorr_statistic().0,
        trng::autocorr_statistic().1,
    );
    log::info!(
        "[trng] start: n={} sample={} chain={} ver=0x{:08x} acstat={}/{}",
        job.count,
        sample,
        chain,
        ver,
        ac_fails,
        ac_trys
    );

    let t0 = Instant::now();
    let mut stats = TrngStats::default();
    let mut error: Option<TrngError> = None;
    let mut hex = [0u8; trng::BLOCK_LEN * 2];

    for _ in 0..job.count {
        match trng::read_block(&mut stats) {
            Ok(block) => log::info!("[trng] {}", sign_smoke::to_hex(&block, &mut hex)),
            Err(e) => {
                error = Some(e);
                break;
            }
        }
        // Let the executor run the logger's sender (and the rest) between
        // blocks; each block is a few hundred microseconds to milliseconds
        // of CPU work.
        yield_now().await;
    }
    trng::stop();
    trng::restore_default_config();

    let ms = t0.elapsed().as_millis();
    let per_block_us = if stats.blocks > 0 {
        ms * 1000 / stats.blocks as u64
    } else {
        0
    };
    let (ac_fails, ac_trys) = trng::autocorr_statistic();
    match error {
        None => log::info!(
            "[trng] done: {} blocks in {} ms (~{} us/block); crngt={} vn={} autocorr={} odd={} timeout={}; acstat={}/{}",
            stats.blocks,
            ms,
            per_block_us,
            stats.crngt_err,
            stats.vn_err,
            stats.autocorr_err,
            stats.odd_states,
            stats.busy_timeouts,
            ac_fails,
            ac_trys
        ),
        Some(e) => log::info!(
            "[trng] FAILED after {} blocks in {} ms: {:?}; crngt={} vn={} autocorr={} odd={} timeout={}; acstat={}/{}",
            stats.blocks,
            ms,
            e,
            stats.crngt_err,
            stats.vn_err,
            stats.autocorr_err,
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
fn parse_hex(s: &[u8], out: &mut [u8; 32]) -> Option<usize> {
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
