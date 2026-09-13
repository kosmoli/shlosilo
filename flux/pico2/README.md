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
`RP2350` drive that appears. Aliveness signal: LED heartbeat on GPIO25. The
boot log (shlosilo version line) goes over defmt/RTT, which needs a debug
probe — until one is wired up, the LED is the smoke test.

## Status

Skeleton: heartbeat LED (GPIO25) + boot log over defmt/RTT printing the
shlosilo version string (the git suffix identifies the build).

Next steps: boot2/flash configuration, USB/QR I/O plan, then bring the
signing flow over and validate it against the same oracle vectors used on
forgebox.
