# pico2 appearance (RP2350 · Embassy · no_std)

A Rust-native **flux** appearance. Unlike forgebox (a C host that consumes
shlosilo through the C ABI), pico2 consumes the `forms` core — the workspace
root crate — directly as a Rust library. No FFI. It owns its runtime:
embedded-alloc (global allocator), panic-probe (panic handler), and
embassy-rp's critical-section impl.

Target: `thumbv8m.main-none-eabihf` (RP2350A, e.g. Raspberry Pi Pico 2).

## Build

```sh
cargo build --release     # from this directory; target comes from .cargo/config.toml,
                          # linker scripts (link.x/memory.x/defmt.x) from build.rs
python3 pack_uf2.py       # ELF -> RP2350-correct UF2 (see below)
```

(Or `make pico2` / `make pico2-uf2` from the repository root.)

Two build flavors (audit #17): **production** (default; `make pico2` /
`make pico2-uf2`) and **bench** (`make pico2-bench` / `make pico2-bench-uf2`,
i.e. `cargo build --release --features bench`). The `bench` feature adds the
console's bench-only surface (below: `xmrseed`, `entropy`, the TRNG
diagnostic commands); production images must not contain it, and
`scripts/check_pico2_flavors.sh` (CI-gated; also `make pico2-check-flavors`)
asserts the split. The flavor of a flashed board is visible as
`build=production` / `build=bench` on the `version` line and every heartbeat.

`pack_uf2.py` post-processes the elf2uf2-rs output: it retags every block to
the rp2350-arm-s family (0xe48bff59 — the tool emits the RP2040 ID, which the
RP2350 bootrom rejects) and prepends the RP2350-E10 errata workaround block
(Absolute family, targeting the end of flash — the same shape picotool and
official RP2350 UF2s use; A3+ bootroms recognise its extension tag and ignore
it, A2 needs it for drag-and-drop when a partition table is present).

## Flash

Hold BOOTSEL while plugging the board in, then copy the .uf2 onto the
`RP2350` drive that appears. Aliveness signals: LED heartbeat on GPIO25, and
the USB console (below) — the version string is readable over the serial
port without any debug probe; defmt/RTT also carries it for probe users.

## USB console

The board enumerates as a USB CDC-ACM serial device — `1209:5353` (the
pid.codes shared VID; the PID is a dev-only placeholder), product
"shlosilo-pico2 console". The serial-number string is the shlosilo version
string, so `/dev/serial/by-id/` and `udevadm info -n /dev/ttyACM0` identify
the exact build.

Open `/dev/ttyACM0` at any time. Two cadences serve the console:

- `[hb] shlosilo-pico2; v0.5.0-poc4+<git>` every 5 s — liveness + version;
- the stored signing-smoke report (below) every 20 s.

Cadence, not buffering, is the delivery mechanism: output written before a
host opens the port is not reliably delivered to a reader that attaches
later (measured on Linux cdc_acm across four boots — even a reader opening
within 0.5 s of the node appearing, with ModemManager stopped, saw none of
it; live-cadence output always arrived). The boot banner is kept as a
best-effort first record but nothing depends on it.

### Console commands

The console is bidirectional: send ASCII lines (`\n` or `\r` terminates).
Commands marked *(bench)* exist only in bench builds (`bench` feature,
audit #17) - production builds compile them out:

- `help` — command list
- `version` — version + C-ABI version
- `smoke` — print the boot signing-smoke report (same as the 20 s replay)
- `panel` — re-run the full panel bring-up (shared reset, touch probe,
  LCD init, test pattern; the reset pulse blanks the display, which is
  redrawn before the command returns)
- `lcd pattern` | `lcd fill <hex565>` | `lcd bl <0|1>` — ST7789V2 ops:
  redraw the pattern, fill a colour, switch the backlight
- `touch [n]` — sample the fitted touch controller (n ≤ 8, 100 ms
  apart): finger count, gesture, raw register values AND the calibrated
  screen coordinates
- `i2c freq <khz>` | `i2c scan` | `i2c scan0` | `i2c rd <addr> <reg>` |
  `i2c lines` | `i2c pulldown` | `i2c id <addr>` | `i2c wr <addr> <b0>…` |
  `i2c rstprobe <addr>` — bus bring-up diagnostics: change the touch bus
  speed, scan I2C1 (GP26/27) or I2C0 (GP28/29, the camera SCCB pins) for
  ACKing addresses, read a register at any address (both repeated-start
  and STOP-separated shapes), read the idle line levels as GPIO
  (pull-up), read them against internal pull-downs (external pull-ups
  present?), identify one address (repeat probes + chip-id register
  attempts), write 1-4 bytes, and pulse the shared reset then probe at
  increasing delays
- `touchint [ms]` — monitor the touch controller's INT line (GP17) for
  edge activity during a window (default 15 s): an independent liveness
  proof that does not depend on the I2C path
- `ui orient` | `ui draw <welcome|detail|qr>` | `ui run [secs]` |
  `ui qr <text>` | `ui ur <hex>` — the mono UI surface: the orientation
  reference pattern (edge labels + asymmetric marker), static pages, the
  interactive demo, an arbitrary QR page, and the **UR carousel** (a
  multipart UR split into 200-byte fountain frames and cycled as QR
  codes — the delivery path for signed outputs past the ~2953-byte
  single-frame ceiling; X exits). Host-verified end to end: a real
  3986-byte device-signed txset encodes to 20 frames (v14, 73×73), one
  cycle reassembles byte-exact through the core decoder, and every frame
  scans back byte-identical through an independent QR reader
  (`tests/pico2_ur_carousel_host.rs` + `bench/ur_frames_check.py`)
- `touchdraw [secs]` — visual mapping check: dark screen + four corner
  reference blocks, then a green trail painted at the calibrated
  position of the touch point (default 60 s). The trail must track the
  finger; a rotated or mirrored trail means the calibration constants
  in `touch.rs` are wrong
- `sd probe` | `sd read <block_hex>` — the board's TF slot on SPI0
  (MISO=GP20, CS=GP21, CLK=GP22, MOSI=GP23): full SPI-mode init
  handshake (CMD0/CMD8/ACMD41/CMD58) with a stage-by-stage report, and
  a single-block read (block 0 carries the MBR signature check).
  Read-only; also the empirical half of the SD_CS question (the CS net
  also runs to the display connector via R4, so a clean handshake
  proves the display side does not interfere)
- `bbscan` | `bbid` | `bbrd` | `bbwr` | `bbinit` | `bbtrace` — the
  bit-banged I2C fallback/forensics path on the same GP26/27 pins: raw
  GPIO toggling with no I2C peripheral and no driver in the loop, plus
  wire-level sampling (`bbtrace` reports the SDA levels seen during the
  address byte and whether the ACK slot was pulled low — turning a
  driver-level NACK into an observed waveform). `swap` flips the pin
  roles; `d=<cycles>` sets the half-bit delay; numbers are hex
- `heap [reset]` — allocator used/free/peak; `reset` re-arms the peak
  watermark for measuring one operation
- `entropy <hex>` *(bench)* — set the session mnemonic from test-vector
  entropy (16/20/24/28/32 bytes → 12/15/18/21/24 words); default = the
  built-in dice fixture (the smoke wallet)
- `ur:<type>/<body>` — a single-frame UR is decoded and signed immediately
- `ur:<type>/<n>-<m>/<body>` — multipart fragments, fed in any order; the
  payload is signed once the session completes
- `trng [stress] [sample=<n>] [chain=<0-4>] [timeout=<ms>] [nblocks]` *(bench)* —
  read `nblocks` TRNG blocks (24 B each, default 64, max 4096) and stream
  them as hex; ends with a stats line (retry counters, autocorr statistic,
  per-block timing); `stress` = sample count 2, `sample=`/`chain=`/`timeout=`
  override the characterisation settings (all restored on job exit)
- `trngraw <nblocks> [chain] [sample]` *(bench)* — capture raw ROSC samples
  with all internal checks and conditioning bypassed (the bootrom / SP
  800-90B source-characterisation path; one sample per cycle by default);
  holds up to 262,144 blocks (6 MiB ring in PSRAM, fixed chain length), then
  reports the capture line + a wait statistic line (`[traw] waits=...`) so
  the BUSY handshake can be audited
- `trngrawout [start_block] [pace_ms]` *(bench)* — stream the buffered raw
  capture back as paced `[traw] <index> <hex>` lines (4 blocks per line,
  1 ms/line default); the host detects a dropped line by block index
- `trngcheck <nblocks> [timeout_ms]` *(bench)* — capture checked-path blocks
  through the production reader (health checks + Von Neumann active,
  chain 4 / sample 200) into the same buffer; retrieve with `trngrawout`
  (the per-line log stream cannot carry dataset-sized captures - measured
  ~95 % line loss at 2048 blocks)
- `trngtrace [blocks] [chain] [sample] [window]` *(bench)* — DWT
  cycle-stamped (BUSY, VALID) waveform around raw blocks (acquisition
  mechanism forensics; default window 4096 cycles, raise to ~60000 for
  sample=200)
- `temp` *(bench)* — on-die temperature readout (RP2350 TS); also appended
  to the `trngraw`/`trngcheck` capture lines

Signing prints `[sign] <type> ok: <n> bytes sha256=<hex>`, plus
`[sign] <type> hex: <hex>` when the output is ≤128 bytes (covers the ETH
fixture). The channel is a bring-up surface, not a production input path:
production appearances take inputs via QR/dice with on-device confirmation.
`xmrseed` (fixed XMR entropy) and `entropy` (test key material) inject
entropy for the bench and are compiled out of production images entirely
(audit #17).

Host-side notes (Linux):
- `99-shlosilo-pico2.rules` (this directory; installed to
  /etc/udev/rules.d/ on the dev machine) marks the device
  `ID_MM_DEVICE_IGNORE` — ModemManager would otherwise auto-probe and drain
  the port — and grants the plugdev group access;
- **first-command quirk**: until a host program sets the port to raw, the
  tty has ECHO enabled — the device's boot banner is echoed back into its
  own RX and, lacking a terminator, merges with the first command sent
  later. The firmware now discards partial lines idle for >1 s, and the
  bench scripts additionally flush the port before their first command;
- defmt/RTT stays attached for probe-based debugging.

## Panel (LCD + touch) bring-up

**The fitted panel is an ST7796S (320x480) + FocalTech FT6236 touch** -
the user swapped the kit's original 2" 240x320 ST7789V2 + CST816D panel
for a larger one so QR codes render legibly. Both controllers are
supported: `touch.rs` auto-detects (FT6236 at 0x38, chip id 0xA8=0x11,
first; then CST816D at 0x15) and dispatches all operations on what it
found.

Pins, per the verified pin map (`docs/pico2-hardware-pinmap.md`):
SCK=GP14, MOSI=GP15 (MISO not connected), D/C=GP12, CS=GP13, RST=GP16
(shared with the touch controller), BL=GP18; touch SDA=GP26, SCL=GP27,
INT=GP17 (not used yet - reads go over I2C). The display init sequence is
a port of the vendor C reference (`C/01-LCD/lib/LCD/LCD_2in.c`); it turns
out to be the Sitronix-family unlock + gamma chain the ST7796S accepts
(the same sequence the vendor ships, at a different resolution). The SPI
clock starts conservative (50 MHz) and can be raised once the rig is
confirmed.

**Touch calibration (2026-09-16, on hardware)**: the digitizer is
axis-aligned with the display, but the x axis is MIRRORED (raw x grows
to the screen's left) and y is direct (raw y grows downward); scales
near 1:1. Coefficients in `touch.rs` (`to_screen`) come from a
controlled drag test (vertical drags sweep raw y 0→~475 top-to-bottom,
horizontal drags sweep raw x ~315→1 left-to-right) anchored at the
centre touch; corner presses confirm the orientation (residuals ≤24 px,
dominated by the bezel preventing presses exactly at the glass edge).
`touchdraw` is the visual check. Calibration history: a first five-point
run looked like a 90° rotation and produced a swapped-axis trail —
corner presses alone cannot separate a rotation from a mirror, only the
drag directions can.

**How the chip identity was established** (the vendor example's CST816D
recipe NACKed on every access): bit-banged I2C scanning (`bbscan`, see
the console commands) found the FT6236 at 0x38 with consecutive-ACK
filtering, and register 0xA8 reads 0x11.

**The touch transport is the bit-bang engine, not the I2C controller.**
Measured on this bench: the RP2350's DW I2C block, as driven by
embassy-rp's blocking API, has no timeout on its status waits, and a bus
state it does not like - seen right after the shared reset pulse, and
once during a full-address scan - hangs the firmware in a spin loop
(recovery: unplug/replug). The bit-bang path has fixed timing and cannot
hang: the worst case is reading a wrong bit, which the caller retries.
Touch polling needs a few hundred microseconds per sample, well within
what a ~100 kHz fixed-timing bit-bang provides. The `i2c` console
commands therefore also drive the bit-bang engine (`i2c freq` maps to
its pacing); the `bb*` commands remain the forensics surface (swap /
`d=` pacing / wire traces).

**The kit ships unassembled.** The display module, the white FPC ribbon
and the camera are separate parts: the ribbon must be inserted into the
board's `Disp 1P` FPC connector (18-pin FPC-SMD_F0503-ZV-18-20T-R;
camera on `Cam 1P`) AND into the display module's own socket. Because the
LCD bus is write-only (MISO is not connected on this board), a successful
`lcd init` in firmware proves nothing electrically - the connectivity
signals are the backlight glowing and the touch controller ACKing on
I2C1. If the screen is dark and `i2c scan` finds zero devices, the panel
is not connected (seating, latch, or ribbon orientation), not a firmware
fault. `i2c freq/scan/scan0/rd/lines` are the console diagnostics for
this.

Boot runs the full bring-up (shared reset pulse, touch probe + configure,
LCD init, test pattern). The touch probe is retried (50 ms steps, up to
~400 ms) because the FT6236 needs time after the reset release before it
answers; each retry is a cheap bit-bang probe. A fresh flash shows the
pattern with no console interaction: four horizontal bands (red/green/blue/white, top to
bottom) plus a black marker block in **all four corners** - band order
verifies the scan direction, hue verifies RGB/BGR, and the corner blocks
prove the configured resolution (320x480) covers the glass (a block
outside the addressable window is silently dropped). `lcd bl <0|1>`
exists to confirm the backlight polarity on hardware.

## On-device signing smoke

At boot the firmware runs the three-step fixture flow once and stores the
report; `console_report_task` re-serves it on the 20 s cycle:

1. `create_account` — 64 x d6 dice fixture → mnemonic indices (word0 = 1565);
2. `export_readonly` — m/44'/0'/0'/0/0 crypto-hdkey UR;
3. `sign` — the eth-sign-request fixture UR → 111-byte signed tx.

The fixtures and expected outputs are shared with `flux/host-sim/sim_l3.c`
(the C-ABI oracle) and pinned on the host by `tests/pico2_smoke_parity.rs`
through the same direct Rust path. Verified on hardware: indices, UR and
signed hex match the host oracle byte for byte.

The flow is deterministic (dice → exact rejection sampling, no RNG;
BTC/ETH → RFC-6979), so no entropy source is needed for the fixture path; a
real-device flow will use the RP2350 TRNG.

Heap: dual-region global allocator. Allocations < 16 KiB go to a 224 KiB
internal-SRAM heap; the rest go to the PSRAM region (8 MiB). The PSRAM r/w
path is verified at boot (five offsets, write/read-back) before the heap is
mapped; `psramtest` re-runs the check on demand. Both heaps have live/peak
counters (the `heap` console command; `heap reset` re-arms the peaks).
`alloctest <size>|sweep` probes single allocations (null-on-failure, no
panic); `alloctrace` prints the allocation trace ring (>= 4 KiB allocations
plus failures), which lives in `.uninit` and survives a crash reset.

Measured on hardware (2026-09-14): boot smoke peak 649 B; ETH fixture sign
peak 388 B; the 12.4 KiB Sparrow PSBT multipart decode + sign peaks at
**102,746 B**. The XMR path's working set outgrew the SRAM heap in two
recorded steps (93088 live + 49536 request, then 169264 live + 57344
request - allocation failures at 128 KiB and 224 KiB), which is why the
threshold dropped 64 KiB -> 16 KiB: only genuinely small allocations stay
in SRAM now.

### Bench runner

`bench/run_bench.py` drives the channel end to end and checks the board's
output against the host-pinned values (ETH full hex + sha256; Sparrow
length + sha256). It requires the bench build (`make pico2-bench-uf2`): the
Sparrow session uses the bench-only `entropy` command.

```sh
cargo test --release --test pico2_smoke_parity -- --ignored --nocapture   # fixtures -> /tmp
python3 flux/pico2/bench/run_bench.py                                    # board must be plugged in
```

## Hardware TRNG

`src/trng.rs` is a blocking reader for the RP2350 TRNG on the **checked
path**: all three hardware entropy checks (autocorrelation, CRNGT, Von
Neumann) stay enabled; one accepted 192-bit block (24 B) per read.

Why not `embassy_rp::trng::blocking_fill_bytes`: that blocking path panics
whenever a run ends without a result for any reason other than
autocorrelation failure (datasheet 12.12.3: a run stops on success *or* on a
failed entropy check). With panic = abort that would eventually kill the
firmware. This module applies embassy's *async* policy (reinitialize +
restart on failure) in blocking form: ordered recovery (stop source, reset
the autocorrelation statistics counters, pulse the software reset, re-apply
the configuration, re-enable), bounded time budget, `Result` with counters.

**Measured behaviour on this silicon (2026-09-14 bring-up):**

- At the datasheet-recommended point (chain 1, sample 25) the hardware
  autocorrelation check fails **four times in a row within ~550 µs** and
  latches — every later attempt fails instantly until a software reset.
  The upstream embassy driver produces blocks at that point only by
  retrying for a long time (measured per-block latencies: 101 s, 25 s,
  10.7 s, 7.5 s, 1.4 s across runs — plus occasional millisecond passes).
- At **chain 4 / sample 200** the same checks run clean: 256 consecutive
  blocks, zero failures, **~1.05 ms/block**. These are now the firmware
  defaults (`DEFAULT_CHAIN_LEN` / `DEFAULT_SAMPLE_COUNT`); both remain
  runtime-tunable for other silicon via `sample=`/`chain=`.
- The **raw stream carries a condition-dependent adjacent-bit correlation**
  (bit pairs equal 50.0–52.0% instead of 50%; runs-test |z| up to ~14 on
  24 KiB samples, while monobit / byte chi-square / serial correlation stay
  clean). Position-resolved tests locate it: activations producing ≤8
  blocks are fully clean, 12–16-block activations degrade in the tail,
  longer uninterrupted reads carry it throughout. The effect size grows
  with read length (segment z ≈ +3 at 17–20 blocks, ≈ +5 at 64) and is
  bounded (p ≤ ~0.52). Extraction was independently validated against
  synthetic drop/merge replays and the statistics calibrated on synthetic
  samples. This matches the datasheet's own caveat that the TRNG's
  conditioning logic has pitfalls, "most notably the von Neumann
  decorrelator" — which the RP2350 bootrom avoids by hashing raw samples.

**Conditioning** (`read_conditioned32`, the consumer path): SHA-256 over
two consecutive accepted raw blocks (2 × 192 = 384 health-checked raw bits
→ 256 output bits). The hardware health checks stay enabled as the source
monitor; conditioning removes the residual structure from what consumers
see — a conditioning design consistent with the datasheet's rationale.
SHA-256 is a vetted conditioning component in the SP 800-90B taxonomy;
note the bootrom's variant hashes **raw** samples with all internal
checking and conditioning bypassed, whereas this reader keeps the three
health checks enabled and conditions accepted blocks (a different
instantiation of the same rationale).

**No entropy-accounting claim**: 256 output bits is a bit count, not a
min-entropy statement — a vetted conditioner redistributes entropy and
cannot create it. A conservative min-entropy bound for the output requires
an SP 800-90B non-IID assessment of the raw noise source; that (together
with multi-board / temperature / voltage / restart coverage and the
current operating point being characterised on this board only) is an open
item for the entropy-assurance milestone.

Verified on hardware (2026-09-14, same session A/B, 512 units each):
conditioned outputs pass the full quality suite (runs z **+1.30**, chi2
270.7, monobit 0.55, min-entropy 7.508, no duplicates/zeros), while the
raw stream on the same silicon still shows the clustering (runs z −11.35,
chi2 400.6).

Design consequences baked in: the source lifecycle is job-scoped (a
per-block restart drives the block into the sticky state); a fresh start
flushes stale status bits (a leftover EHR_VALID with zeroed data once
produced a phantom all-zero first block); all-zero reads are rejected and
retried as a **hardware-fault sentinel** (a failed check presents no
result — the registers read 0; the excluded value biases the output by
~2^-192, negligible); patience is a **time budget**
(10 s/block default), not an attempt count — the measured latch-recovery
cycle is sub-millisecond, so attempt counts expire in tens of milliseconds
while a stressed block may need seconds; the reader awaits between retry
cycles so the executor (heartbeats, USB) keeps running.

On the bench channel (bench builds only):

- `trng <n>` — raw blocks (source diagnostics);
- `trng cond <n>` — conditioned 32-byte outputs (consumer path).

`bench/trng_test.py` runs the quality checks (duplicate units, all-zero
units, monobit, byte chi-square, serial correlation, runs test, crude
min-entropy) in chunks and prints the device-side counters:

```sh
python3 flux/pico2/bench/trng_test.py            # raw blocks (diagnostics)
python3 flux/pico2/bench/trng_test.py --cond     # conditioned consumer path
python3 flux/pico2/bench/trng_test.py --stress   # failure-prone config, expect retries
```

These are single-run sanity checks, not a certification — the hardware
checks are the primary defense. The signing-path consumer (XMR randomness
injection, §B.5 entropy parameter) will use `read_conditioned32`; wiring
that path (and the entropy-assurance work above) is the next milestone —
it is not connected yet.

All TRNG access is serialized through a single owner (`trng::instance()`,
an async mutex over one `Trng`): the "two consecutive accepted blocks
belong to one conditioner invocation" guarantee is structural, not a
caller convention.

## Status

Flashed and verified on hardware (2026-09-13/14, RP2350 board): BOOTSEL
drag-and-drop works, the LED heartbeat runs, the USB console is live, the
three-step signing flow runs on-device with byte-identical output to the
host oracle, and the serial bench channel signs host-fed fixtures — the
ETH fixture (full hex match) and the 12.4 KiB Sparrow signet PSBT as 32
multipart fragments (12447-byte signed output, sha256 match).

The hardware TRNG is characterised: checked operating point chain 4 /
sample 200, conditioned consumer path verified, single-owner access (see
above). Entropy accounting (SP 800-90B assessment of the raw source) and
multi-board/environment validation are open items.

XMR signing runs end-to-end on-device: the console accepts an
`xmr-txunsigned` UR, fetches conditioned TRNG entropy (the §B.5
parameter) and produces the signed, encrypted txset, fetched via `xmrout`
segments. Verified against a host recomputation byte-for-byte in the
fixed-entropy A/B mode: 3458-byte blob, digest `5b57cb65...`.

**XMR signing time (single-input fixture)**: **~17 s** (16,920 ms in the
latest 4+4 batch protocol; 18.6 s at the chunk-placement milestone, 26.2 s
at first bring-up — cross-build drift of ±5-8% applies between firmware
builds, so compare within one build). Two wins compose: BP+ table placement
— the CT Straus multiexp tables are `n × 1280 B` and cost ~2× per term once
they cross the 16 KiB PSRAM routing threshold (measured: SRAM tables
~11.7 ms + n×4.0 ms per chunk vs PSRAM ~7.6 ms + n×9.34 ms; see `bench/`
and the `perfbench` console command); the chunk size is a per-host runtime
knob (`set_bp_multiexp_chunk_terms`): forgebox keeps 36 (46 KB tables in
its 48 K SRAM pool), pico2 sets 12 (15,360 B -> SRAM heap, boot-time
default) — and the `codegen-compact` out-of-line CT-Straus codegen
(−197 ms net / −540 ms mechanism accounting on the batch protocol; part of
the perf target's default features). Remaining time (batch readings):
BP+ prove (bp1 1.3 / bp5 3.1 / bp6 3.0 s), CN ~5.1 s and CLSAG ~2.3 s.

Probe builds (`make pico2-perf-uf2`, features `perf-timing` + `perf-bench`
+ `codegen-compact`; flavor shows as `build=bench+perf`): `xtiming` dumps
the per-phase tables (tx / bp / cn) accumulated during the last sign;
`perfbench [name] [iters]` times raw device primitives (fmul / select /
madd / quad / chunked CT multiexp / vartime 2-term); `xmrchunk <n>` flips
the chunk size at runtime for single-variable A/B runs.

LCD + touch bring-up has landed (2026-09-16): ST7789V2 over SPI1 and
CST816D over I2C1 with the boot test pattern; on-board verification of
this code is the immediate next step.

Next steps: QR (camera) input in place of the bench channel (the RP2350
board now carries a touchscreen + camera), and further XMR tuning from the
phase tables (bp6 folding and CN are at their measured floors; bp5's
remaining gap is the open one). Entropy assurance is complete — see
`docs/entropy-assurance.md`.