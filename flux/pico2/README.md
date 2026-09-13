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
real-device flow will use the RP2350 TRNG. Heap: the 16 KiB embedded-alloc
heap is untouched by this flow (0 used before and after — no leak); the XMR
path's BP+ generator allocations (~256 KiB-class) are the next sizing item.

## Status

Flashed and verified on hardware (2026-09-13/14, RP2350 board): BOOTSEL
drag-and-drop works, the LED heartbeat runs, the USB console is live, and
the three-step signing flow runs on-device with byte-identical output to
the host oracle.

Next steps: the USB data channel for real inputs (fixtures in / results
out, replacing the hard-coded fixture), then the RP2350 TRNG for the real
entropy path, then heap sizing for the XMR path.
