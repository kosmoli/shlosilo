//! On-device signing smoke: exercises the business layer (create_account /
//! export_readonly / sign) with the same fixed fixtures the host-sim uses
//! (flux/host-sim/sim_l3.c), so the board's output can be diffed against the
//! host oracle.
//!
//! Rust-native: calls the `forms` core directly (no FFI). The whole run is
//! synchronous - the fixtures are pure functions of their inputs (dice rolls
//! go through exact rejection sampling, no RNG; BTC/ETH signing is RFC-6979
//! deterministic) - so it can execute on the embassy executor without
//! borrowing an async context.
//!
//! Delivery: the report is computed once at boot and stored here; it is then
//! served by `console_report_task` on a 20 s cycle. Output that is produced
//! before a host opens the USB port is not reliably delivered to a reader
//! that attaches later (observed on Linux cdc_acm - even a reader that opens
//! within half a second of the node appearing, with ModemManager stopped,
//! sees none of it). Serving the report periodically puts it on the live
//! path, which is trustworthy, and makes the console dependable for a reader
//! that attaches at any time.

use core::cell::UnsafeCell;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicUsize, Ordering};

use shlosilo::business;
use shlosilo::derivation::path::DerivationPath;
use shlosilo::entropy::mnemonic::{Mnemonic, WordCount};
use shlosilo::error::ShlosiloError;
use shlosilo::network::Network;
use shlosilo::ur::ur_decode;

/// Fixed dice-roll fixture (matches flux/host-sim/sim_l3.c): 64 x d6,
/// [1..6] cycling. 64 rolls exceed the 128-bit floor for a 12-word mnemonic.
fn fixture_rolls() -> [u8; 64] {
    let mut rolls = [0u8; 64];
    for (i, r) in rolls.iter_mut().enumerate() {
        *r = (i % 6 + 1) as u8;
    }
    rolls
}

/// ETH sign-request fixture UR (matches flux/host-sim/sim_l3.c).
const ETH_SIGN_REQUEST_URI: &str = "ur:eth-sign-request/otaohddmaowpadlalrfrnysgaelrktecmwaelfgmaymwcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcplfaxvdlartlalalaaxadaaadrpceaadt";

const REPORT_CAP: usize = 1024;

/// The stored report: written exactly once at boot, then read by the
/// reporting task on every cycle.
struct Report {
    len: AtomicUsize,
    buf: UnsafeCell<[u8; REPORT_CAP]>,
}

// SAFETY: single writer (the console task, at boot) publishes `len` with
// Release only after the bytes are in place; readers load `len` with Acquire
// and then read exactly that many bytes. No reader exists before boot
// completes, and the content is immutable afterwards.
unsafe impl Sync for Report {}

static REPORT: Report = Report {
    len: AtomicUsize::new(0),
    buf: UnsafeCell::new([0u8; REPORT_CAP]),
};

fn store(s: &str) {
    let n = core::cmp::min(s.len(), REPORT_CAP);
    // SAFETY: the single writer runs at boot; no concurrent readers exist
    // until `len` is published below.
    let buf = unsafe { &mut *REPORT.buf.get() };
    buf[..n].copy_from_slice(&s.as_bytes()[..n]);
    REPORT.len.store(n, Ordering::Release);
}

/// The stored report, or `None` if the smoke has not finished (never happens
/// after the boot second; the reporting task handles it anyway).
pub fn report() -> Option<&'static str> {
    let n = REPORT.len.load(Ordering::Acquire);
    if n == 0 {
        return None;
    }
    // SAFETY: `len` was published after these bytes were written; the range
    // is within the buffer by construction.
    let buf = unsafe { &*REPORT.buf.get() };
    core::str::from_utf8(&buf[..n]).ok()
}

/// Minimal fixed-buffer writer: truncates silently at capacity (the report
/// fits with a wide margin; truncation would be a code-size bug, not a
/// runtime condition worth an error path here).
struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl core::fmt::Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = core::cmp::min(s.len(), self.buf.len().saturating_sub(self.pos));
        self.buf[self.pos..self.pos + n].copy_from_slice(&s.as_bytes()[..n]);
        self.pos += n;
        Ok(())
    }
}

impl BufWriter<'_> {
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.pos]).unwrap_or("<non-utf8>")
    }
}

/// Render bytes as lowercase hex into `out`; returns the hex &str.
fn to_hex<'a>(bytes: &[u8], out: &'a mut [u8]) -> &'a str {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    assert!(out.len() >= bytes.len() * 2, "hex buffer too small");
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    core::str::from_utf8(&out[..bytes.len() * 2]).unwrap_or("<hex>")
}

/// Run the three-step fixture flow once and store the report. `heap_probe`
/// reports (used, free) from the caller's allocator so the report can carry
/// heap before/after figures without this module knowing the allocator.
pub fn run(heap_probe: fn() -> (usize, usize)) -> Result<(), ShlosiloError> {
    let mut scratch = [0u8; REPORT_CAP];
    let mut w = BufWriter {
        buf: &mut scratch,
        pos: 0,
    };
    let result = run_inner(&mut w, heap_probe);
    if let Err(e) = &result {
        let _ = writeln!(w, "[smoke] FAILED: {:?}", e.kind);
    }
    store(w.as_str());
    result
}

fn run_inner(
    w: &mut BufWriter<'_>,
    heap_probe: fn() -> (usize, usize),
) -> Result<(), ShlosiloError> {
    let (heap_used_before, heap_free_before) = heap_probe();

    // ── Step 1: create_account — dice rolls → mnemonic indices ──
    let rolls = fixture_rolls();
    let mut mnemonic_buf = [0u8; 24];
    business::create_account::create_account(
        WordCount::Words12,
        6,
        &rolls,
        b"",
        &mut mnemonic_buf,
    )?;

    let mut indices = [0u16; 12];
    for (i, idx) in indices.iter_mut().enumerate() {
        *idx = u16::from_le_bytes([mnemonic_buf[i * 2], mnemonic_buf[i * 2 + 1]]);
    }
    let _ = writeln!(
        w,
        "[smoke] create_account ok: idx = {} {} {} {} {} {} {} {} {} {} {} {}",
        indices[0],
        indices[1],
        indices[2],
        indices[3],
        indices[4],
        indices[5],
        indices[6],
        indices[7],
        indices[8],
        indices[9],
        indices[10],
        indices[11]
    );

    // ── Step 2: export_readonly — mnemonic → crypto-hdkey UR ──
    let mnemonic = Mnemonic::from_indices(&indices, WordCount::Words12)?;
    let mut seed = [0u8; 64];
    business::restore_seed::restore_seed(&mnemonic, b"", &mut seed)?;
    let path = DerivationPath::from_flat([44u32 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 0])?;
    let mut export_out = [0u8; 2048];
    let export_len = business::export_readonly::export_readonly(
        business::export_readonly::ExportProtocol::CryptoHdKey,
        &seed,
        Network::BitcoinMainnet,
        core::slice::from_ref(&path),
        &mut export_out,
    )?;
    let uri = core::str::from_utf8(&export_out[..export_len]).unwrap_or("<non-utf8>");
    let _ = writeln!(w, "[smoke] export_readonly ok: {uri}");

    // ── Step 3: sign — eth-sign-request UR fixture → signed tx ──
    let decoded = ur_decode::decode(ETH_SIGN_REQUEST_URI)?;
    // Note: the C-side FFI entry additionally runs its network check
    // (check_network) before signing - that check lives at the host boundary
    // (the FFI layer owns the network parameter) and is a no-op for this ETH
    // fixture under the host-sim's network argument; the direct Rust path
    // goes straight to the business layer the same way.
    let signing_mnemonic = Mnemonic::from_indices(&indices, WordCount::Words12)?;
    let input = business::sign::SignInput::Mnemonic {
        mnemonic: signing_mnemonic,
        passphrase: b"",
    };
    let mut sign_out = [0u8; 512];
    // BTC/ETH do not consume injected entropy (RFC-6979); empty slice per the
    // §B.5 contract.
    let sign_len = business::sign::sign_with_entropy(
        input,
        decoded.type_tag(),
        decoded.as_ref(),
        &[],
        &mut sign_out,
    )?;
    let mut hex_buf = [0u8; 1024];
    let hex = to_hex(&sign_out[..sign_len], &mut hex_buf);
    let _ = writeln!(w, "[smoke] sign ok: {sign_len} bytes");
    let _ = writeln!(w, "[smoke] signed: {hex}");

    // Zero the sensitive stack material (parity with the C host's cleanup).
    seed.fill(0);
    mnemonic_buf.fill(0);

    let (heap_used_after, heap_free_after) = heap_probe();
    let _ = writeln!(
        w,
        "[smoke] heap used/free: {heap_used_before} {heap_free_before} -> {heap_used_after} {heap_free_after}"
    );

    Ok(())
}
