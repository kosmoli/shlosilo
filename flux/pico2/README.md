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
- `trng [stress] [n]` — read `n` hardware-TRNG blocks (24 B each, default
  64, max 4096) and stream them as hex; ends with a stats line (retry
  counters + per-block timing); `stress` switches to a failure-prone
  sample count for the job, to exercise the retry paths on real silicon

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

Heap: 128 KiB embedded-alloc heap with live/peak counters (the `heap`
console command; `heap reset` re-arms the peak for one operation). Measured
on hardware (2026-09-14): boot smoke peak 649 B; ETH fixture sign peak
388 B; the 12.4 KiB Sparrow PSBT multipart decode + sign peaks at
**102,746 B** — over three quarters of the heap, so the XMR path's BP+
generator allocations (~256 KiB-class) will need a larger budget or a
different placement strategy (the next sizing item).

### Bench runner

`bench/run_bench.py` drives the channel end to end and checks the board's
output against the host-pinned values (ETH full hex + sha256; Sparrow
length + sha256):

```sh
cargo test --release --test pico2_smoke_parity -- --ignored --nocapture   # fixtures -> /tmp
python3 flux/pico2/bench/run_bench.py                                    # board must be plugged in
```

## Hardware TRNG

`src/trng.rs` is a blocking reader for the RP2350 TRNG, on the **checked
path**: all three hardware entropy checks (autocorrelation, CRNGT, Von
Neumann) stay enabled, ROSC inverter chain 1 / sample count 25 (datasheet
12.12.2 recommended range), one accepted 192-bit block (24 B) per read.

Why not `embassy_rp::trng::blocking_fill_bytes`: that blocking path panics
whenever a run ends without a result for any reason other than
autocorrelation failure (datasheet 12.12.3: a run stops on success *or* on a
failed entropy check; 12.12.2: failed checks occur even at recommended
settings). With panic = abort that would eventually kill the firmware. This
module applies embassy's *async* policy (reinitialize + restart on failure)
in blocking form: CRNGT/VN failures clear-and-retry, autocorrelation
(sticky) takes a full software reset, every wait and the retry budget are
bounded, and the outcome is a `Result` with counters.

On the bench channel, `trng <n>` streams raw accepted blocks for host-side
analysis; `bench/trng_test.py` runs the quality checks (duplicate blocks,
monobit, byte chi-square, serial correlation, runs test, crude min-entropy)
and prints the device-side retry counters:

```sh
python3 flux/pico2/bench/trng_test.py            # 1024 blocks, normal config
python3 flux/pico2/bench/trng_test.py --stress   # failure-prone config, expect retries
```

These are single-run sanity checks, not a certification — the hardware
checks are the primary defense. The signing-path consumer (XMR randomness
injection, §B.5 entropy parameter) lands with the next milestone.

## Status

Flashed and verified on hardware (2026-09-13/14, RP2350 board): BOOTSEL
drag-and-drop works, the LED heartbeat runs, the USB console is live, the
three-step signing flow runs on-device with byte-identical output to the
host oracle, and the serial bench channel signs host-fed fixtures — the
ETH fixture (full hex match) and the 12.4 KiB Sparrow signet PSBT as 32
multipart fragments (12447-byte signed output, sha256 match).

Next steps: XMR randomness injection from the TRNG (the §B.5 entropy
parameter), heap sizing for the XMR path, then QR (camera) input in place
of the bench channel.
