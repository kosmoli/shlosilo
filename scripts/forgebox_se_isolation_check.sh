#!/usr/bin/env bash
# Design 密钥供给 §11 (2026-11-21): the seed-plate and SE key-supply modules are parallel and
# replaceable, so a plate-only carrier must ship WITHOUT the SE module - not with a disabled copy
# of it. This measures both flavors of the device artifact.
#
# A #if is not evidence (the A4-06 lesson): part 1 builds the plate-only flavor
# (SHLOSILO_WITH_SE=0 drives BOTH halves - the Rust `se` feature via --no-default-features and
# the C source set via the CMake option) into its own build/staticlib dirs, so the canonical
# artifacts are never touched, and asserts the SE face is absent from the linked image.
#
# Part 2 is the part that makes part 1 mean anything: the same probes must be PRESENT in the
# canonical SE flavor. An instrument that cannot see these symbols at all would report the same
# clean "0" for the plate-only image, and the absence would be vacuous - the A4-15 blindness
# class, where a name-mangled lang item read as "no allocation sites".
#
# Requires the canonical image (the FORGEBOX gate builds it). Exit: 0 = the switch cuts in both
# directions, 1 = artifact/tool problem, 10 = SE code survived into the plate-only image,
# 11 = the probes are blind (positive control failed).
set -euo pipefail
cd "$(dirname "$0")/.."

ON_ELF=${FORGEBOX_ELF:-flux/forgebox/build/mh1903.elf}
NO_SE_BUILD_DIR=${SHLOSILO_NO_SE_BUILD_DIR:-flux/forgebox/build-no-se}
NO_SE_LIB_DIR=${SHLOSILO_NO_SE_STATICLIB_DIR:-flux/forgebox/shlosilo-no-se}
NO_SE_ELF="$NO_SE_BUILD_DIR/mh1903.elf"
BUILD_LOG=/tmp/g_forgebox_nose_build.log

# One probe per SE translation unit + the vendored driver library, each a symbol the module
# actually emits (names read off the objects, not guessed from source):
#   keystore.c.obj  -> LoadAccountEntropy / LoadAccountEntropyFromSE
#   se_manager.c.obj-> GetKeyPieceFromSE / SE_HmacEncryptRead / ...
#   se_smoke.c.obj  -> SeConsolePoll / SeSmokeProbe / SeSmokeSetLog / ...
#   drv_atecc608b.c -> Atecc608bAuthorize / ...
#   drv_ds28s60.c   -> g_ds28s60Info / ...
#   cryptoauthlib   -> atcab_* (29 symbols; only the SE drivers pull the library in)
PROBES=(
    "LoadAccountEntropy"      # keystore: the narrow entropy entry (se_manager is its transport)
    "GetKeyPieceFromSE"       # se_manager: the SE key-piece transport
    "SeConsolePoll"           # se_smoke: the dev console consumer polled by product_task
    "Atecc608bAuthorize"      # drv_atecc608b
    "g_ds28s60Info"           # drv_ds28s60
    "atcab_init"              # cryptoauthlib
)
# Present in BOTH flavors: proves each image is a real, complete build (a truncated or empty
# symbol table would otherwise read as a clean plate-only cut).
SHARED_PROBE="shlosilo_keysource_qr_open_ffi"

count_syms() {
    # $1 = elf, $2 = symbol regex
    local n
    n=$(arm-none-eabi-nm "$1" 2>/dev/null | grep -cE "$2" || true)
    echo "${n:-0}"
}

echo "== part 1: build the plate-only flavor (SHLOSILO_WITH_SE=0)"
rm -rf "$NO_SE_BUILD_DIR"
set +e
SHLOSILO_WITH_SE=0 \
SHLOSILO_FORGEBOX_BUILD_DIR="$(pwd)/$NO_SE_BUILD_DIR" \
SHLOSILO_FORGEBOX_STATICLIB_DIR="$(pwd)/$NO_SE_LIB_DIR" \
    bash flux/forgebox/build.sh no_sign >"$BUILD_LOG" 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
    echo "FORGEBOXSEISO: FAIL - the plate-only flavor does not build (exit $rc)" >&2
    tail -30 "$BUILD_LOG" >&2
    exit 1
fi
if [ ! -f "$NO_SE_ELF" ]; then
    echo "FORGEBOXSEISO: FAIL - plate-only build produced no $NO_SE_ELF" >&2
    exit 1
fi
grep -E "^key supply:" "$BUILD_LOG" || true
echo "   plate-only image: $NO_SE_ELF ($(stat -c%s "$NO_SE_ELF") bytes)"

if [ ! -f "$ON_ELF" ]; then
    echo "FORGEBOXSEISO: missing $ON_ELF (build flux/forgebox first - the FORGEBOX gate does)" >&2
    exit 1
fi

echo "== part 2: the SE face must be ABSENT from $NO_SE_ELF"
leaked=0
for p in "${PROBES[@]}"; do
    n=$(count_syms "$NO_SE_ELF" "$p")
    printf "   %-24s %s\n" "$p" "$n"
    if [ "$n" -ne 0 ]; then
        leaked=$((leaked + n))
    fi
done
shared_no_se=$(count_syms "$NO_SE_ELF" "$SHARED_PROBE")
echo "   $SHARED_PROBE (plate face, want >0): $shared_no_se"
if [ "$shared_no_se" -eq 0 ]; then
    echo "FORGEBOXSEISO: FAIL - the plate-only image has no plate face either; the build is not what we think it is" >&2
    exit 1
fi
if [ "$leaked" -ne 0 ]; then
    echo "FORGEBOXSEISO: FAIL - $leaked SE symbol(s) survived into the plate-only image" >&2
    arm-none-eabi-nm "$NO_SE_ELF" | grep -E "$(IFS='|'; echo "${PROBES[*]}")" >&2 || true
    exit 10
fi

echo "== part 3: sensitivity control - the same probes must be PRESENT in $ON_ELF"
blind=0
for p in "${PROBES[@]}"; do
    n=$(count_syms "$ON_ELF" "$p")
    printf "   %-24s %s\n" "$p" "$n"
    if [ "$n" -eq 0 ]; then
        blind=$((blind + 1))
    fi
done
if [ "$blind" -ne 0 ]; then
    echo "FORGEBOXSEISO: FAIL - $blind probe(s) are invisible in the SE flavor, so part 2's zeros" >&2
    echo "               proved nothing (the instrument is blind, not the image clean)" >&2
    exit 11
fi

echo "FORGEBOXSEISO: OK - the SE module is absent from the plate-only image and present in the SE flavor"
