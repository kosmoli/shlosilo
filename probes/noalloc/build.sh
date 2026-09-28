#!/usr/bin/env bash
# Z6 allocation-face measurement — build + link + measure.
#
# The probe staticlib carries a FORBIDDING allocator (the crate graph still
# links `alloc` for the non-signing surfaces, so rustc's lang-item check
# needs a definition). The security claim is NOT "it linked" — it is the
# disassembly measurement in measure.py: no code reachable from
# `z6_probe_run` may call the allocator.
#
# Exit: 0 = REACHABLE-CLEAN, 10 = reachable debt (listed), else build broke.
set -euo pipefail
cd "$(dirname "$0")"

TARGET=thumbv7em-none-eabihf
cargo build --release --target "$TARGET" --manifest-path Cargo.toml

LIB=target/$TARGET/release/libz6_noalloc_probe.a
[ -f "$LIB" ] || { echo "missing $LIB"; exit 1; }

arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard -nostartfiles --specs=nosys.specs \
    -o z6_probe.elf probe.c "$LIB" -Wl,--gc-sections -Wl,-e,main

python3 measure.py z6_probe.elf --entry z6_probe_run --json z6_report.json
