//! Desktop carrier — the shell's first no-hardware implementation.
//!
//! Files, a terminal and nothing else (design 2026-11-26 §5): a `ur:` request comes in
//! from `--in`, review pages go to stdout with page numbers, one keystroke per semantic
//! action comes from stdin, the reply UR goes to `--out`. No camera, no panel, no touch.
//!
//! What lives here is exactly what the design calls platform adaptation: read the
//! transport, frame the artifact, draw text, map keys. Everything about *what* the
//! request means and *what* the operator must be shown is the shell's and forms'.
//!
//! # Multi-frame UR (design §10 gap 9)
//!
//! A request above a single QR's capacity arrives as a stream of
//! `ur:<type>/<seq>-<total>/<bytewords>` frames, one per line in `--in`; an artifact
//! above it leaves as one frame per line in `--out`. Both halves go through forms'
//! multipart codec, and both use the **device path**, not the leaking convenience
//! constructor:
//!
//! - decode: [`ur_multipart::UrDecodeWsLayout::compute`] +
//!   [`ur_multipart::ur_decode_ws_place`] — forms' zero-heap placement, where the decoder
//!   handle and its pools are carved out of a buffer *this carrier owns*. `frames` are fed
//!   one at a time through `receive_frame`, whose internal scratch is the workspace's own
//!   `scratch` segment (an effect of `ws_base` being set by the placement).
//! - encode: [`ur_multipart::UrMultipartEncoder`] + `next_frame_into`, i.e. caller-provided
//!   scratch and frame buffers.
//!
//! Why this path and not `UrMultipartDecoder::new()`: that constructor exists for FFI
//! staging and tests and its documented contract is "pools allocated + leaked on purpose".
//! The desktop carrier is the chain-axis acceptance executor (design §6) — if *it* used the
//! leaking host-only constructor, the path the pico2 carrier will actually take would be
//! exercised nowhere, and the leak would hide the real question this carrier is supposed to
//! answer ("does the workspace sizing work?"). The cost is the three-line `unsafe` in
//! [`assemble_frames`], where the stability the placement contract demands is locally
//! obvious: the `Vec` is allocated once and never moved, reallocated or mutated again.
//!
//! # Usage
//!
//! ```text
//! shlosilo-flux-desktop --in <request.ur> --out <reply.ur> --seed-hex <128 hex digits>
//!                       [--rows 12] [--network testnet|mainnet|regtest] [--mfp <8 hex>]
//!                       [--frag <bytes>]
//! ```
//!
//! - `--in`: a file holding the request. Every line starting with `ur:` is a frame, so a
//!   copy-pasted QR dump works; comment lines and blanks are ignored. Either one
//!   single-frame URI (`ur:<type>/<body>`) or the whole multi-frame set
//!   (`ur:<type>/<seq>-<total>/<body>`, any order — the fountain decoder is order-free and
//!   tolerates duplicates) is accepted.
//! - `--out`: where the reply UR text is written after a successful sign — one line for a
//!   single frame, one line per fragment for a multi-frame artifact.
//! - `--seed-hex`: the BIP-39 seed to sign with, 64 bytes as hex. Required, with no
//!   default: a carrier that ships a built-in seed is a carrier that signs with it.
//! - `--rows`: review rows this "screen" holds per page (the platform's layout number;
//!   the shell paginates with it).
//! - `--network`: wallet network for the review renderer (forms prefers the request's
//!   own derivation when it carries one).
//! - `--mfp`: wallet master fingerprint, 4 bytes as hex; enables change-output marking.
//! - `--frag`: payload bytes per outbound UR frame (1..=4096). Default is the platform
//!   profile's own number (`limits::UR_ENCODE_FRAGMENT_LEN`, 200 on the host profile), so
//!   a plain run fragments exactly like the device will.
//!
//! # Action keys (one character, then Enter; read from stdin)
//!
//! | key | action  |
//! |-----|---------|
//! | `y` | confirm |
//! | `n` | next page |
//! | `p` | previous page |
//! | `q` | cancel |
//!
//! EOF is treated as `q`: with no operator left there is nobody to confirm, and the
//! carrier seam requires the action source to make progress.
//!
//! # Exit codes
//!
//! | code | meaning |
//! |------|---------|
//! | 0 | signed, artifact written |
//! | 1 | bad arguments / unreadable or undecodable request |
//! | 2 | no request to hand over |
//! | 3 | cancelled by the operator |
//! | 4 | forms refused (the fixed failure words were printed as the page) |
//! | 5 | flow finished but the artifact could not be written or framed |
//!
//! A transport-level failure (a frame that does not decode, a set that never completes,
//! an artifact over the framing ceiling) prints forms' fixed words — the same table the
//! review pages use — and never a code or a payload byte.

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use shlosilo::error::{ShlosiloError, ShlosiloErrorCode, ShlosiloErrorKind};
use shlosilo::failure_text;
use shlosilo::network::Network;
use shlosilo::ur::ur_decode;
use shlosilo::ur::ur_encode::{self, UrTypeTag};
use shlosilo::ur::ur_multipart;
use shlosilo_flux_shell::{
    run_once, workspace_bytes, Action, Carrier, OutPiece, Page, Request, ShellConfig, ShellError,
    Workspaces,
};

const USAGE: &str =
    "usage: shlosilo-flux-desktop --in <request.ur> --out <reply.ur> --seed-hex <128 hex digits>
                              [--rows 12] [--network testnet|mainnet|regtest] [--mfp <8 hex>]
                              [--frag <bytes>]";

/// Largest `--frag` this carrier accepts.
///
/// Not a protocol number: a fragment above a few KiB makes a frame whose bytewords no
/// screen can show, and the frame buffer forms writes into is
/// `MULTIPART_FRAME_MAX_LEN`. The ceiling is here to refuse a nonsensical flag by name
/// instead of letting a frame overflow later.
const FRAG_MAX: usize = 4096;

/// Slack added to the `--frag`-sized scratch handed to `next_frame_into`, for the part
/// CBOR wrapper (array header, four small ints, bytes header). Generous on purpose: the
/// scratch is a `Vec` on the host, and a too-small one raises a capacity error deep in the
/// codec instead of here.
const PART_CBOR_SLACK: usize = 512;

/// Parsed command line.
struct Args {
    input: PathBuf,
    out: PathBuf,
    seed: Option<[u8; 64]>,
    print_layout: bool,
    decode_only: bool,
    rows: usize,
    network: Network,
    master_fingerprint: Option<[u8; 4]>,
    frag: usize,
}

impl Args {
    fn parse<I: Iterator<Item = String>>(mut argv: I) -> Result<Self, String> {
        let mut input: Option<PathBuf> = None;
        let mut out: Option<PathBuf> = None;
        let mut seed: Option<[u8; 64]> = None;
        let mut rows = 12usize;
        let mut network = Network::BitcoinTestnet;
        let mut master_fingerprint: Option<[u8; 4]> = None;
        let mut print_layout = false;
        let mut decode_only = false;
        // The profile's own number, not a literal: an outbound fragment length that
        // disagrees with the platform profile is a memory budget nobody measured.
        let mut frag = ur_multipart::DEFAULT_FRAGMENT_LEN;

        while let Some(flag) = argv.next() {
            match flag.as_str() {
                "--in" => input = Some(PathBuf::from(value(&mut argv, "--in")?)),
                "--out" => out = Some(PathBuf::from(value(&mut argv, "--out")?)),
                "--seed-hex" => {
                    seed = Some(parse_fixed_hex::<64>(&value(&mut argv, "--seed-hex")?)?)
                }
                "--rows" => {
                    let raw = value(&mut argv, "--rows")?;
                    rows = raw
                        .parse::<usize>()
                        .map_err(|_| format!("--rows: {raw:?} is not a row count"))?;
                }
                "--frag" => {
                    let raw = value(&mut argv, "--frag")?;
                    let n = raw
                        .parse::<usize>()
                        .map_err(|_| format!("--frag: {raw:?} is not a byte count"))?;
                    if n == 0 || n > FRAG_MAX {
                        return Err(format!("--frag: {n} is outside 1..={FRAG_MAX}"));
                    }
                    frag = n;
                }
                "--network" => {
                    let raw = value(&mut argv, "--network")?;
                    network = match raw.as_str() {
                        "mainnet" => Network::BitcoinMainnet,
                        "testnet" => Network::BitcoinTestnet,
                        "regtest" => Network::BitcoinRegtest,
                        other => {
                            return Err(format!("--network: {other:?} (testnet|mainnet|regtest)"))
                        }
                    };
                }
                "--mfp" => {
                    master_fingerprint = Some(parse_fixed_hex::<4>(&value(&mut argv, "--mfp")?)?)
                }
                // Carrier bring-up: print the workspace breakdown and exit. A carrier has to
                // size its memory from these six numbers, and "the total" hides which term
                // moved when a build changes (or when the target's pointer width does).
                "--print-layout" => print_layout = true,
                // Decode a UR file and report the payload digest, without signing: this is
                // how an artifact gets checked against a golden measured elsewhere (a device
                // that only printed a digest, another architecture, another carrier).
                "--decode-only" => decode_only = true,
                "-h" | "--help" => return Err(String::from("help requested")),
                other => return Err(format!("unknown argument {other:?}")),
            }
        }

        Ok(Args {
            input: match input {
                Some(path) => path,
                None if print_layout || decode_only => PathBuf::new(),
                None => return Err(String::from("--in is required")),
            },
            out: match out {
                Some(path) => path,
                None if print_layout || decode_only => PathBuf::new(),
                None => return Err(String::from("--out is required")),
            },
            seed,
            print_layout,
            decode_only,
            rows,
            network,
            master_fingerprint,
            frag,
        })
    }
}

/// Take the value that follows a flag.
fn value<I: Iterator<Item = String>>(argv: &mut I, name: &str) -> Result<String, String> {
    argv.next().ok_or_else(|| format!("{name} needs a value"))
}

/// Fixed-width hex (the only hex shapes this carrier takes: a 64-byte seed, a 4-byte
/// fingerprint). Rejects wrong lengths instead of padding or truncating a secret.
fn parse_fixed_hex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    let bytes = text.as_bytes();
    if bytes.len() != N * 2 {
        return Err(format!(
            "expected {} hex digits, got {}",
            N * 2,
            bytes.len()
        ));
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let pair = text.get(i * 2..i * 2 + 2).ok_or("short hex")?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| format!("{pair:?} is not hex"))?;
    }
    Ok(out)
}

/// forms' fixed words for a failure class — the only vocabulary this carrier may print.
///
/// The number in an error (a code, a required length, a frame index) never reaches the
/// screen: `failure_text` collapses a class to one ambiguous phrase on purpose, and a
/// carrier that bypasses it is the split-code leak that table exists to prevent.
fn words(kind: ShlosiloErrorKind) -> String {
    let code = ShlosiloErrorCode::from_shlosilo_error(ShlosiloError::new(kind));
    failure_text::sign_failure_text(code)
        .to_str()
        // Fallback keeps fail-closed if forms' CStr ever stops being UTF-8.
        .unwrap_or("sign failed")
        .to_owned()
}

/// `ur:<type>/<seq>-<total>/<body>` — the shape the fountain decoder takes.
///
/// The single-frame shape (`ur:<type>/<body>`) has no second `/`; that is forms' own rule
/// (`ur_decode::decode` refuses a body containing `/`), restated here only to route the
/// line to the right decoder.
fn is_multipart(uri: &str) -> bool {
    let rest = match uri.get(..3) {
        Some(prefix) if prefix.eq_ignore_ascii_case("ur:") => &uri[3..],
        _ => return false,
    };
    rest.split_once('/')
        .is_some_and(|(_, body)| body.contains('/'))
}

/// Assemble one request from a multi-frame set.
///
/// Any order, duplicates allowed (that is what a fountain codec is for); what is *not*
/// allowed is a set that never completes, a frame whose body does not decode, or frames
/// whose sequence metadata disagree with their own part — forms answers all three with an
/// error, and each becomes fixed words here.
fn assemble_frames(frames: &[&str]) -> Result<(String, Vec<u8>), String> {
    let layout = ur_multipart::UrDecodeWsLayout::compute();
    // Owned by this carrier, and by nothing else: `ur_decode_ws_place` carves the decoder
    // handle *and* its pools (decoded/buffer/queue/received slots, the fountain arenas,
    // the per-frame CBOR scratch) out of this one span.
    let mut ws = vec![0u8; layout.total];
    let handle = ur_multipart::ur_decode_ws_place(&mut ws)
        .ok_or_else(|| words(ShlosiloErrorKind::BufferTooSmall))?;
    // SAFETY: `ws` is exactly `layout.total` bytes (the placement checked it) and stays at
    // that address, unmoved and unreallocated, for the whole function — which is precisely
    // the placement contract ("the workspace must stay at a stable address until free").
    // The fabricated `'static` lifetime on the handle is that contract, not a claim that the
    // pools outlive this function: everything derived from them is either used here or
    // copied out (the payload is), so no borrow of `ws` escapes. `ws` is never accessed
    // through any other path while `decoder` is alive, so there is no aliasing.
    let decoder = unsafe { &mut *handle };

    for frame in frames {
        decoder.receive_frame(frame).map_err(|e| words(e.kind))?;
        // `receive_frame` (not `receive_frame_with`) is correct here precisely because the
        // handle came from the placement: `ws_base` is set, so the frame CBOR scratch is
        // the workspace's own segment instead of a per-call allocation.
    }
    if !decoder.complete() {
        // Frames missing (or too few distinct ones): the session never assembled. forms'
        // word for a torn container is the "re-scan the request" one, which is the
        // operator's actual next move.
        return Err(words(ShlosiloErrorKind::UrPayloadInvalidCbor));
    }
    let type_name = decoder
        .ur_type()
        .ok_or_else(|| words(ShlosiloErrorKind::UrPayloadUnknownType))?
        .to_owned();
    // `payload_len` is the assembled *message* length (content plus the CBOR byte-string
    // shell, if the sender shelled it); `payload_into` strips the shell and reports the
    // content length. Both come from forms so this carrier never guesses a size.
    let needed = decoder
        .payload_len()
        .map_err(|e| words(e.kind))?
        .ok_or_else(|| words(ShlosiloErrorKind::UrPayloadInvalidCbor))?;
    let mut payload = vec![0u8; needed];
    let n = decoder
        .payload_into(&mut payload)
        .map_err(|e| words(e.kind))?
        .ok_or_else(|| words(ShlosiloErrorKind::UrPayloadInvalidCbor))?;
    payload.truncate(n);
    Ok((type_name, payload))
}

/// Read the request file and decode it into (type name, payload).
///
/// One single-frame line, or the whole multi-frame set — anything else is refused by name.
fn load_request(path: &Path) -> Result<(String, Vec<u8>), String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    // Every `ur:` line is a frame. Trimming and case-insensitivity are the carrier's job:
    // QR alphanumeric mode carries no lowercase, so a photographed dump may be upper-cased.
    let frames: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| line.len() > 3 && line[..3].eq_ignore_ascii_case("ur:"))
        .collect();
    if frames.is_empty() {
        return Err(format!("no ur: line in {}", path.display()));
    }

    if frames.iter().any(|frame| is_multipart(frame)) {
        if let Some(odd) = frames.iter().find(|frame| !is_multipart(frame)) {
            return Err(format!(
                "{}: mixed shapes — a single-frame line {odd:?} next to multi-frame frames",
                path.display()
            ));
        }
        return assemble_frames(&frames);
    }

    if frames.len() > 1 {
        return Err(format!(
            "{}: {} single-frame ur: lines; one request is one line (or a multi-frame set)",
            path.display(),
            frames.len()
        ));
    }
    let line = frames[0];
    let rest = &line[3..];
    let (type_name, body) = rest
        .split_once('/')
        .ok_or_else(|| format!("{}: not a ur:<type>/<body> string", path.display()))?;
    if body.contains('/') {
        // Unreachable: that is the multi-frame shape handled above. Kept as a refusal so a
        // future shape change fails loudly instead of being decoded as a single frame.
        return Err(format!("ur:{type_name}: not a single-frame request"));
    }
    let decoded = ur_decode::decode(line).map_err(|e| words(e.kind))?;
    Ok((type_name.to_owned(), decoded.as_ref().to_vec()))
}

/// The request the shell will be handed, as this carrier holds it.
///
/// Staged once at start-up: this carrier serves one request per run, so the second
/// `next_request` answers `None`.
struct DesktopCarrier {
    staged: Option<(String, Vec<u8>)>,
    taken: bool,
    out_path: PathBuf,
    /// Outbound payload bytes per UR frame (`--frag`, default the profile's number).
    frag: usize,
    /// `Some((type name, payload length))` once the artifact reached disk.
    wrote: Option<(String, usize)>,
    stdin: io::StdinLock<'static>,
}

impl DesktopCarrier {
    fn new(request: (String, Vec<u8>), out_path: PathBuf, frag: usize) -> Self {
        DesktopCarrier {
            staged: Some(request),
            taken: false,
            out_path,
            frag,
            wrote: None,
            stdin: io::stdin().lock(),
        }
    }

    /// Frame the artifact: one UR line, or one line per fragment when it overflows a
    /// single frame.
    ///
    /// The single-frame ceiling is forms' (`ur_encode::UR_PAYLOAD_MAX_LEN`); above it the
    /// multipart encoder takes over, whose own payload ceiling is the platform profile's
    /// inbound number — an artifact over *that* is refused with forms' capacity words.
    fn frame(&self, out: &OutPiece<'_>) -> Result<String, String> {
        let tag = UrTypeTag::from_name(out.type_name);
        if out.bytes.len() <= ur_encode::UR_PAYLOAD_MAX_LEN {
            let uri = ur_encode::encode(tag, out.bytes).map_err(|e| words(e.kind))?;
            return Ok(format!("{}\n", uri.as_str()));
        }

        let mut enc = ur_multipart::UrMultipartEncoder::new(out.type_name, out.bytes, self.frag)
            .map_err(|e| words(e.kind))?;
        let count = enc.fragment_count();
        let mut scratch = vec![0u8; self.frag + PART_CBOR_SLACK];
        let mut buf = vec![0u8; ur_multipart::MULTIPART_FRAME_MAX_LEN];
        // Roughly: `ur:<type>/<seq>-<total>/` + 2 chars of bytewords per payload byte.
        let mut text = String::with_capacity(count * (self.frag * 2 + 24));
        for _ in 0..count {
            let n = enc
                .next_frame_into(&mut scratch, &mut buf)
                .map_err(|e| words(e.kind))?;
            let frame = std::str::from_utf8(&buf[..n])
                .map_err(|_| words(ShlosiloErrorKind::EncodingInvalidFormat))?;
            text.push_str(frame);
            // One frame per line: every downstream tool (diff, cat, a wallet that reads a
            // whole file) sees the frames in the order they must be shown.
            text.push('\n');
        }
        Ok(text)
    }
}

impl Carrier for DesktopCarrier {
    fn next_request(&mut self) -> Option<Request<'_>> {
        if self.taken {
            return None;
        }
        self.taken = true;
        self.staged
            .as_ref()
            .map(|(type_name, payload)| Request { type_name, payload })
    }

    fn draw(&mut self, page: &Page<'_>) {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        // The page number is part of the line a human (or a future UI golden) reads: a
        // review without "1/3" hides that there is more to see.
        let _ = writeln!(out, "[page {}/{}]", page.page, page.pages);
        for line in page.lines {
            let _ = writeln!(out, "{line}");
        }
        if let Some(status) = page.status {
            let _ = writeln!(out, "status: {status}");
        }
        let _ = out.flush();
    }

    fn action(&mut self) -> Action {
        loop {
            // Prompts go to stderr so stdout stays a clean page dump.
            eprint!("action [y=confirm n=next p=prev q=cancel] > ");
            let _ = io::stderr().flush();
            let mut line = String::new();
            match self.stdin.read_line(&mut line) {
                // EOF: nobody is left to confirm.
                Ok(0) => return Action::Cancel,
                Ok(_) => match line.chars().next() {
                    Some('y') | Some('Y') => return Action::Confirm,
                    Some('n') | Some('N') => return Action::Next,
                    Some('p') | Some('P') => return Action::Prev,
                    Some('q') | Some('Q') => return Action::Cancel,
                    // A blank line or an unknown key is not an answer; ask again. EOF on
                    // the next read ends the loop, so this cannot spin.
                    _ => continue,
                },
                Err(_) => return Action::Cancel,
            }
        }
    }

    fn emit(&mut self, out: &OutPiece<'_>) {
        // Framing the artifact is the carrier's job (the shell only says what type and
        // which bytes).
        let text = match self.frame(out) {
            Ok(text) => text,
            Err(message) => {
                eprintln!("{message}");
                return;
            }
        };
        match fs::write(&self.out_path, text.as_bytes()) {
            Ok(()) => {
                let frames = text.lines().count();
                println!(
                    "wrote {} (ur:{}, {} bytes, {} frame{})",
                    self.out_path.display(),
                    out.type_name,
                    out.bytes.len(),
                    frames,
                    if frames == 1 { "" } else { "s" }
                );
                self.wrote = Some((out.type_name.to_owned(), out.bytes.len()));
            }
            Err(e) => eprintln!("cannot write {}: {e}", self.out_path.display()),
        }
    }
}

fn main() -> ExitCode {
    let args = match Args::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}\n\n{USAGE}");
            return ExitCode::from(1);
        }
    };
    if args.print_layout {
        // Pure probe: no request, no seed, no signing - just the six numbers a carrier must
        // size its memory from, so a 32-bit and a 64-bit build can be compared term by term.
        let ws = workspace_bytes();
        let kv = ws.kv_rec_bytes();
        println!(
            "layout request={} review_arena={} review_recs={}x{}={} review_typed={} sign_ws={} out={} total={}",
            ws.request,
            ws.review_arena,
            ws.review_recs,
            kv,
            ws.review_recs * kv,
            ws.review_typed,
            ws.sign_ws,
            ws.out,
            ws.total_bytes()
        );
        println!("layout pointer_width={}", core::mem::size_of::<usize>() * 8);
        // Identity probe: a carrier must be able to say which build it is, and this is the same
        // string the firmware prints at boot. (It also keeps the constant from being lifted out
        // of the image, which is what makes a purity check able to prove the artifact is ours.)
        println!(
            "build shlosilo_version={} cabi={}",
            shlosilo::ffi::version::SHLOSILO_VERSION_STRING.trim_end_matches('\0'),
            shlosilo::ffi::version::SHLOSILO_CABI_VERSION_STRING.trim_end_matches('\0')
        );
        return ExitCode::SUCCESS;
    }
    if args.decode_only {
        let request = match load_request(&args.input) {
            Ok(request) => request,
            Err(message) => {
                eprintln!("{message}");
                return ExitCode::from(1);
            }
        };
        let digest = match shlosilo::encoding::sha256::hash(&request.1) {
            Ok(digest) => digest,
            Err(e) => {
                eprintln!("sha256: {:?}", e.kind);
                return ExitCode::from(1);
            }
        };
        let mut hex = String::new();
        for byte in digest {
            use core::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        println!(
            "payload ur:{} {} bytes sha256={hex}",
            request.0,
            request.1.len()
        );
        return ExitCode::SUCCESS;
    }
    let seed = match args.seed {
        Some(seed) => seed,
        None => {
            eprintln!("--seed-hex is required (except with --print-layout)");
            return ExitCode::from(1);
        }
    };
    let request = match load_request(&args.input) {
        Ok(request) => request,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(1);
        }
    };
    eprintln!(
        "request ur:{} ({} bytes); workspace {} bytes",
        request.0,
        request.1.len(),
        workspace_bytes().total_bytes()
    );

    let mut carrier = DesktopCarrier::new(request, args.out, args.frag);
    let config = ShellConfig {
        seed: &seed,
        network: args.network,
        master_fingerprint: args.master_fingerprint,
        rows_per_page: args.rows,
    };
    // The workspace is the carrier's (this carrier's) memory, not the shell's: this is the
    // seam design §10 gap 5 was about. The owner is dropped when the run ends.
    let mut ws = Workspaces::owned();
    match run_once(&mut carrier, &config, &mut ws.borrow()) {
        Ok(()) => {
            if carrier.wrote.is_some() {
                ExitCode::SUCCESS
            } else {
                eprintln!("the flow finished without an artifact on disk");
                ExitCode::from(5)
            }
        }
        Err(ShellError::NoRequest) => {
            eprintln!("no request");
            ExitCode::from(2)
        }
        Err(ShellError::Cancelled) => {
            eprintln!("cancelled");
            ExitCode::from(3)
        }
        Err(ShellError::Refused) => {
            // The page above already carries forms' fixed words; printing a code here
            // would be the split-code leak the word table exists to prevent.
            eprintln!("refused");
            ExitCode::from(4)
        }
        Err(ShellError::Misconfigured) => {
            eprintln!("misconfigured: --rows must be at least 1");
            ExitCode::from(1)
        }
    }
}
