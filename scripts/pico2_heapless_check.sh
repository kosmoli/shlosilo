#!/usr/bin/env bash
# #74 / A4-05: a pico2 image that carries the sign path must be linkable with NO allocator.
#
# The audit's point: the device image registered `#[global_allocator] static HEAP: DualHeap`
# unconditionally, so "the device face needs no heap" was a comment, not a property. The allocator
# and the heap now ride on this carrier's `console` feature (which is what actually needs a heap:
# the USB shell's UR/QR session shells). This gate builds the flavor WITHOUT it and measures the
# artifact:
#
#   1. zero allocator symbols of any kind (alloc/dealloc/realloc/alloc_zeroed) - if anything in
#      the graph still touches `alloc`, the link fails before we get here;
#   2. the sign path is PRESENT (`sign_pool::sign_stretch`). A heap-free image with no sign path
#      proves nothing, and without the keep reference the linker collects it into a 19 KiB image;
#   3. sensitivity control: the default (console) flavor is rebuilt afterwards and MUST show
#      allocator symbols, so a zero above cannot be an instrument artefact - and the canonical
#      artifact on disk is left as the console flavor, which is what the other gates measure.
#
# Exit: 0 = the claim holds both ways, 1 = artifact/tool problem, 10 = allocator in the heap-free
# image, 11 = sign path missing (vacuous) or the control shows nothing.
set -euo pipefail
cd "$(dirname "$0")/.."

ELF=${PICO2_ELF:-target/thumbv8m.main-none-eabihf/release/shlosilo-pico2}
TARGET=thumbv8m.main-none-eabihf
BUILD_LOG=/tmp/pico2_heapless_build.log

allocator_count() {
    arm-none-eabi-nm "$1" 2>/dev/null | grep -cE "___rust_(alloc|dealloc|realloc|alloc_zeroed)" || true
}
sign_path_count() {
    arm-none-eabi-nm "$1" 2>/dev/null | grep -cE "^[0-9a-f]+ [tT] [^ ]*sign_pool12sign_stretch$" || true
}

echo "== part 1: build the heap-free flavor (--no-default-features: no console, no allocator)"
if ! SHLOSILO_LIMITS=pico2 cargo build --offline --locked --release --target "$TARGET" \
        --manifest-path flux/pico2/Cargo.toml --no-default-features > "$BUILD_LOG" 2>&1; then
    echo "PICO2HEAPLESS: FAIL - the heap-free flavor does not build/link (exit $?)" >&2
    tail -20 "$BUILD_LOG" >&2
    exit 1
fi
[ -f "$ELF" ] || { echo "PICO2HEAPLESS: FAIL - no $ELF" >&2; exit 1; }
size=$(stat -c%s "$ELF")
echo "   heap-free image: $size bytes"

echo "== part 2: no allocator symbol may exist, and the sign path must be in the image"
alloc=$(allocator_count "$ELF")
sign=$(sign_path_count "$ELF")
echo "   allocator symbols = $alloc (want 0)"
echo "   sign_pool::sign_stretch = $sign (want 1)"
if [ "$alloc" -ne 0 ]; then
    echo "PICO2HEAPLESS: FAIL - the heap-free flavor still carries allocator support:" >&2
    arm-none-eabi-nm "$ELF" | grep -E "___rust_(alloc|dealloc|realloc|alloc_zeroed)" >&2
    exit 10
fi
if [ "$sign" -eq 0 ]; then
    echo "PICO2HEAPLESS: FAIL - the image has no sign path, so its clean allocator face is vacuous" >&2
    exit 11
fi

echo "== part 3: sensitivity control + leave the canonical flavor on disk"
if ! SHLOSILO_LIMITS=pico2 cargo build --offline --locked --release --target "$TARGET" \
        --manifest-path flux/pico2/Cargo.toml > "$BUILD_LOG" 2>&1; then
    echo "PICO2HEAPLESS: FAIL - the console flavor no longer builds" >&2
    tail -20 "$BUILD_LOG" >&2
    exit 1
fi
alloc_ctl=$(allocator_count "$ELF")
sign_ctl=$(sign_path_count "$ELF")
echo "   console flavor: allocator symbols = $alloc_ctl (want > 0), sign path = $sign_ctl"
if [ "$alloc_ctl" -eq 0 ]; then
    echo "PICO2HEAPLESS: FAIL - the console flavor shows no allocator either: the measurement is blind" >&2
    exit 11
fi
echo "PICO2HEAPLESS: OK - the sign path links without any allocator, and the switch is visible in both flavors"
