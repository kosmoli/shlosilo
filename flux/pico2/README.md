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

### Console commands (bench channel)

The console is bidirectional: send ASCII lines (`\n` or `\r` terminates):

- `help` — command list
- `version` — version + C-ABI version
- `smoke` — print the boot signing-smoke report (same as the 20 s replay)
- `heap [reset]` — allocator used/free/peak; `reset` re-arms the peak
  watermark for measuring one operation
- `entropy <hex>` — set the session mnemonic from test-vector entropy
  (16/20/24/28/32 bytes → 12/15/18/21/24 words); default = the built-in
  dice fixture (the smoke wallet)
- `ur:<type>/<body>` — a single-frame UR is decoded and signed immediately
- `ur:<type>/<n>-<m>/<body>` — multipart fragments, fed in any order; the
  payload is signed once the session completes
- `trng [stress] [sample=<n>] [chain=<0-4>] [timeout=<ms>] [nblocks]` —
  read `nblocks` TRNG blocks (24 B each, default 64, max 4096) and stream
  them as hex; ends with a stats line (retry counters, autocorr statistic,
  per-block timing); `stress` = sample count 2, `sample=`/`chain=`/`timeout=`
  override the characterisation settings (all restored on job exit)

Signing prints `[sign] <type> ok: <n> bytes sha256=<hex>`, plus
`[sign] <type> hex: <hex>` when the output is ≤128 bytes (covers the ETH
fixture). This is a bench channel on the bring-up firmware, not a
production input path: production appearances take inputs via QR/dice with
on-device confirmation; `entropy` loads test key material by the same
reasoning.

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
length + sha256):

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

On the bench channel:

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

Next steps: XMR randomness injection from the TRNG (the §B.5 entropy
parameter), heap sizing for the XMR path, then QR (camera) input in place
of the bench channel.