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
//! # Usage
//!
//! ```text
//! shlosilo-flux-desktop --in <request.ur> --out <reply.ur> --seed-hex <128 hex digits>
//!                       [--rows 12] [--network testnet|mainnet|regtest] [--mfp <8 hex>]
//! ```
//!
//! - `--in`: a file holding the request. The first line starting with `ur:` wins, so a
//!   copy-pasted QR dump works. Single-frame UR only in this slice (a multi-part
//!   `ur:<type>/<seq>-<total>/…` request is refused by name, not silently).
//! - `--out`: where the reply UR text is written after a successful sign.
//! - `--seed-hex`: the BIP-39 seed to sign with, 64 bytes as hex. Required, with no
//!   default: a carrier that ships a built-in seed is a carrier that signs with it.
//! - `--rows`: review rows this "screen" holds per page (the platform's layout number;
//!   the shell paginates with it).
//! - `--network`: wallet network for the review renderer (forms prefers the request's
//!   own derivation when it carries one).
//! - `--mfp`: wallet master fingerprint, 4 bytes as hex; enables change-output marking.
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
//! | 5 | flow finished but the artifact could not be written |

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use shlosilo::network::Network;
use shlosilo::ur::ur_decode;
use shlosilo::ur::ur_encode::{self, UrTypeTag};
use shlosilo_flux_shell::{
    run_once, workspace_bytes, Action, Carrier, OutPiece, Page, Request, ShellConfig, ShellError,
};

const USAGE: &str =
    "usage: shlosilo-flux-desktop --in <request.ur> --out <reply.ur> --seed-hex <128 hex digits>
                              [--rows 12] [--network testnet|mainnet|regtest] [--mfp <8 hex>]";

/// Parsed command line.
struct Args {
    input: PathBuf,
    out: PathBuf,
    seed: [u8; 64],
    rows: usize,
    network: Network,
    master_fingerprint: Option<[u8; 4]>,
}

impl Args {
    fn parse<I: Iterator<Item = String>>(mut argv: I) -> Result<Self, String> {
        let mut input: Option<PathBuf> = None;
        let mut out: Option<PathBuf> = None;
        let mut seed: Option<[u8; 64]> = None;
        let mut rows = 12usize;
        let mut network = Network::BitcoinTestnet;
        let mut master_fingerprint: Option<[u8; 4]> = None;

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
                "-h" | "--help" => return Err(String::from("help requested")),
                other => return Err(format!("unknown argument {other:?}")),
            }
        }

        Ok(Args {
            input: input.ok_or("--in is required")?,
            out: out.ok_or("--out is required")?,
            seed: seed.ok_or("--seed-hex is required")?,
            rows,
            network,
            master_fingerprint,
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

/// The request the shell will be handed, as this carrier holds it.
///
/// Staged once at start-up: this carrier serves one request per run, so the second
/// `next_request` answers `None`.
struct DesktopCarrier {
    staged: Option<(String, Vec<u8>)>,
    taken: bool,
    out_path: PathBuf,
    /// `Some((type name, payload length))` once the artifact reached disk.
    wrote: Option<(String, usize)>,
    stdin: io::StdinLock<'static>,
}

impl DesktopCarrier {
    fn new(request: (String, Vec<u8>), out_path: PathBuf) -> Self {
        DesktopCarrier {
            staged: Some(request),
            taken: false,
            out_path,
            wrote: None,
            stdin: io::stdin().lock(),
        }
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
        // which bytes): single-frame UR text here, which is what a wallet scans.
        let tag = UrTypeTag::from_name(out.type_name);
        let uri = match ur_encode::encode(tag, out.bytes) {
            Ok(uri) => uri,
            Err(_) => {
                eprintln!(
                    "cannot frame the artifact: {} bytes exceeds the single-frame ur:{} budget",
                    out.bytes.len(),
                    out.type_name
                );
                return;
            }
        };
        // The trailing newline is for every text tool downstream (diff, cat, wallets
        // that read a whole file).
        let mut text = String::from(uri.as_str());
        text.push('\n');
        match fs::write(&self.out_path, text.as_bytes()) {
            Ok(()) => {
                println!(
                    "wrote {} (ur:{}, {} bytes)",
                    self.out_path.display(),
                    out.type_name,
                    out.bytes.len()
                );
                self.wrote = Some((out.type_name.to_owned(), out.bytes.len()));
            }
            Err(e) => eprintln!("cannot write {}: {e}", self.out_path.display()),
        }
    }
}

/// Read the request file and decode its `ur:` line into (type name, payload).
fn load_request(path: &Path) -> Result<(String, Vec<u8>), String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| line.len() > 3 && line[..3].eq_ignore_ascii_case("ur:"))
        .ok_or_else(|| format!("no ur: line in {}", path.display()))?;
    let rest = &line[3..];
    let (type_name, body) = rest
        .split_once('/')
        .ok_or_else(|| format!("{}: not a ur:<type>/<body> string", path.display()))?;
    if body.contains('/') {
        // Multi-part (`ur:<type>/<seq>-<total>/…`): forms has the fountain decoder, but
        // this slice of the carrier does not provision its workspace, so refuse by name
        // instead of guessing. See the slice report.
        return Err(format!(
            "ur:{type_name}: multi-part requests are not carried by this slice (single-frame ur: only)"
        ));
    }
    let decoded = ur_decode::decode(line)
        .map_err(|_| format!("ur:{type_name}: the request did not decode"))?;
    Ok((type_name.to_owned(), decoded.as_ref().to_vec()))
}

fn main() -> ExitCode {
    let args = match Args::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}\n\n{USAGE}");
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
        workspace_bytes()
    );

    let mut carrier = DesktopCarrier::new(request, args.out);
    let config = ShellConfig {
        seed: &args.seed,
        network: args.network,
        master_fingerprint: args.master_fingerprint,
        rows_per_page: args.rows,
    };
    match run_once(&mut carrier, &config) {
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
