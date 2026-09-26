#!/usr/bin/env bash
# Z6 link proof: build the no_std probe staticlib (thumbv7em) and link it
# against a C main. The probe carries a FORBIDDING allocator (the crate graph
# still pulls `alloc` for the Z4-pending convenience layer, so rustc's eager
# check needs a definition); the security claim is the disassembly: no code
# reachable from `z6_probe_run` may CALL the allocator.
set -euo pipefail
cd "$(dirname "$0")"

TARGET=thumbv7em-none-eabihf
cargo build --release --target "$TARGET" --manifest-path Cargo.toml

LIB=target/$TARGET/release/libz6_noalloc_probe.a
[ -f "$LIB" ] || { echo "missing $LIB"; exit 1; }

arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard -nostartfiles --specs=nosys.specs \
    -o z6_probe.elf probe.c "$LIB" -Wl,--gc-sections -Wl,-e,main

# NOTE: match the allocator ENTRY POINTS at symbol end (`>`); the OOM glue
# (`handle_alloc_error` -> `__rust_alloc_error_handler`) is an unreachable
# dead pair the linker retains and must not be counted as an allocation.
CALLS=$(arm-none-eabi-objdump -d z6_probe.elf | grep -cE "bl.*__(rust_alloc|rust_dealloc|rust_realloc|rust_alloc_zeroed)>" || true)
if [ "$CALLS" != "0" ]; then
    echo "Z6 LINK PROOF FAILED: $CALLS allocator call sites reachable"
    arm-none-eabi-objdump -d z6_probe.elf | grep -B2 -E "bl.*__rust_(alloc|dealloc|realloc|alloc_zeroed)" | head -30
    exit 1
fi
echo "Z6 LINK PROOF OK: z6_probe.elf linked; 0 allocator call sites in reachable code"
