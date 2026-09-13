# pico2 appearance (RP2350 · Embassy · no_std)

A Rust-native **flux** appearance. Unlike forgebox (a C host that consumes
shlosilo through the C ABI), pico2 consumes the `forms` core — the workspace
root crate — directly as a Rust library. No FFI. It owns its runtime:
embedded-alloc (global allocator), panic-probe (panic handler), and
embassy-rp's critical-section impl.

Target: `thumbv8m.main-none-eabihf` (RP2350A, e.g. Raspberry Pi Pico 2).

## Build

```sh
cargo build --release     # from this directory; target + rustflags come from .cargo/config.toml
```

## Status

Skeleton: heartbeat LED (GPIO25) + boot log over defmt/RTT printing the
shlosilo version string (the git suffix identifies the build).

Next steps: boot2/flash configuration, USB/QR I/O plan, then bring the
signing flow over and validate it against the same oracle vectors used on
forgebox.
