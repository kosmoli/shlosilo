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

Open `/dev/ttyACM0` at any time: a heartbeat line
`[hb] shlosilo-pico2; v0.5.0-poc4+<git>` repeats every 5 s, and the buffered
tail of recent output is delivered immediately on open.

The one-shot boot banner (`shlosilo-pico2 alive; ...`) is best-effort only:
it is logged while the device is still enumerating — before the host-side
port exists — and can be lost to an endpoint-activation race or to a
transient prober draining the port. The heartbeat carries the same version
string, so the console never looks dead.

Host-side notes (Linux):
- `99-shlosilo-pico2.rules` (this directory; installed to
  /etc/udev/rules.d/ on the dev machine) marks the device
  `ID_MM_DEVICE_IGNORE` — ModemManager would otherwise auto-probe and drain
  the port — and grants the plugdev group access;
- defmt/RTT stays attached for probe-based debugging.

## Status

Flashed and verified on hardware (2026-09-13/14, RP2350 board): BOOTSEL
drag-and-drop works, the LED heartbeat runs, and the USB console is live
(heartbeat lines with the version string read over /dev/ttyACM0). Details of
the flash path: pack_uf2.py below.

Next steps: bring the signing flow over (create_account / export_readonly /
sign) and validate it against the same oracle vectors used on forgebox, with
the console as the data channel.
