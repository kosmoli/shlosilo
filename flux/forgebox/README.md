# forgebox appearance (MH1903 · FreeRTOS · LVGL)

This directory is a **flux** appearance of shlosilo: the hardware-facing side
(drivers, RTOS tasks, UI, flash/SD, power) for the ForgeBox board
(MH1903, Cortex-M4, 1 MB SRAM + 8 MB QSPI PSRAM, 16 MB QSPI NOR flash).

Naming: `forms` is the pure-function core (the cargo crate at the repository
root); `flux` is where side effects, time, and hardware live — the layer that
runs, races, and fails in ways no test vector can capture. This host is flux.

## What this host provides (the L3 contract)

| Service | Implementation |
|---|---|
| allocator | `shlosilo/embedded_alloc_glue.c` — SRAM first-fit pool (`0x20099000..0x200FC000`, 396 KB) with PSRAM `heap_4` fallback, counted for diagnostics |
| clock | `smoke_tick_ms()` (FreeRTOS tick, 1 ms) registered via `shlosilo_timing_set_clock_fn` |
| entropy | board TRNG (see `external/mh1903_lib`), never software fallback |
| generator cache | `src/flash/xmr_gen_cache_flash.c` — QSPI NOR slot `0x01E00000` (65×4 KB), `XGC1` magic + CRC32, XIP zero-copy load |
| I/O | LVGL display, FT6336 touch (hardware I2C0), SD card, QR via `src/ui` |

## Build

```sh
bash build.sh            # cargo build forms → strip → cmake/make → pad → sign
bash build.sh rebuild    # also wipes build/ and the embedded cargo target
bash build.sh simulator  # host simulator build instead of firmware
```

### Key-supply flavor (`SHLOSILO_WITH_SE`)

The board has two parallel, replaceable key sources: the seed-plate scan and the
secure element (ATECC608B + DS28S60). This carrier includes both by default; a
carrier without an SE builds the plate-only flavor:

```sh
SHLOSILO_WITH_SE=0 bash build.sh no_sign
```

That ONE variable drives both halves of the switch — the Rust `se` feature
(`--no-default-features` on the staticlib: no `SeKeySource`, no SE FFI entries in
the keep table) and the C source set (`-DSHLOSILO_WITH_SE=OFF`: no `keystore.c`,
`se_manager.c`, either SE driver, `se_smoke.c` or cryptoauthlib, and the
`ProductKeySeUnlock` / console call sites compile out). They cannot be switched
independently: the C product entry calls the Rust SE glue and the keystore sits
under it. CMake enforces the pair at configure time by reading
`libshlosilo.a`'s symbols, so a mismatched pair is a hard error instead of an
image that silently ships a dead module.

Two directory overrides keep a probe build away from the canonical artifacts:
`SHLOSILO_FORGEBOX_BUILD_DIR` and `SHLOSILO_FORGEBOX_STATICLIB_DIR` (the
`FORGEBOXSEISO` gate uses them to build the plate-only flavor in `build-no-se/` +
`shlosilo-no-se/`). Measured on this tree: the plate-only image is 84 KiB smaller
(1,220,608 vs 1,306,624 bytes of `.bin`, 83.5 KiB of `.text`).

`SMOKE_SCREEN=1` currently requires the SE flavor (the smoke screen routes the SE
console to the panel, and that console lives in the SE source set).

The build is self-contained: it bundles the forms static library
(`libshlosilo.a`) via `staticlib/` (feature set and runtime hooks live
there), runs a
**header sync gate** (cbindgen output must byte-equal the tracked
`<repo root>/shlosilo.h`, else the build fails), and copies both into
`shlosilo/` — those two files are build inputs and are gitignored, so they
can never drift from the source of truth.

The C-host runtime hooks — global allocator (`shlosilo_embedded_malloc/free`),
panic handler (`shlosilo_panic_hook`), critical-section impl — plus the
feature set compiled into the .a live in `staticlib/`. A Rust-native
appearance (pico2) consumes the core directly and none of this applies.

Output: `build/forgebox.bin` — the single-layer signed firmware to copy to the
SD card root (recovery-mode load). `build/mh1903_full.bin` is an intermediate;
never flash it directly, and never pad by hand (the script pads exactly once).

The final **signing step is optional and local**: it runs only when the
`forgebox` CLI is on PATH and `~/.forgebox/keys/private.pem` exists;
otherwise the script stops after padding, prints a note, and exits
successfully with only the unsigned intermediate in `build/`. A byte-exact
signed image therefore depends on the local CLI + key — neither is vendored
in the repository (deliberately: the key is a secret), so a "self-contained"
signed build means provisioning both.

## Notes

- `shlosilo/libshlosilo.a` and `shlosilo/shlosilo.h` are **not tracked**.
- The C host talks to forms through the C ABI (`shlosilo.h`); it never touches
  Rust internals. See `docs/l3-contract.md` in the repository root.
- Deeper background (board bring-up, probe workflow, measurement history) lives
  in the shlosilo project ledger; this README covers only the host itself.
