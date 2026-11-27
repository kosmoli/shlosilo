#!/usr/bin/env bash
# =============================================================================
# check_purity32.sh — forms must build and LINK for a 32-bit POSIX target with no
# external cross toolchain (chain-axis design §3, purity acceptance / S3).
#
# Why this exists: "forms is platform independent" has been a claim, and the only
# evidence was that it compiled for thumb (bare metal). The carriers now include a
# 32-bit Linux board (RV1103, uClibc, 26-bit-address free), so the honest question is
# whether the same source links into a runnable 32-bit binary. `armv7-unknown-linux-
# musleabihf` ships its own libc and `rust-lld` links it, so this needs nothing but
# rustup — no arm-linux cross gcc, no vendor SDK.
#
# What this does NOT prove (say it, do not imply it):
#   * It does not RUN the artifact. Running it needs qemu-user or the board itself; the
#     on-device artifact comparison lives in the S2/S3 receipt
#     (~/works/shlosilo-acceptance/s2-luckyfox/), where the 64-bit host, the 32-bit
#     board and the M33 all produced the same signed bytes.
#   * It does not check the no-allocator face — that is probes/noalloc's job.
#
# Exit codes: 0 ok, 10 target missing (fail closed: a silently skipped purity check is
# worse than none), 11 build/link failed, 12 artifact is not the shape claimed.
# =============================================================================
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 99

TARGET=armv7-unknown-linux-musleabihf
PKG=flux/desktop
OUT="target/$TARGET/release/shlosilo-flux-desktop"

if ! rustup target list --installed 2>/dev/null | grep -qx "$TARGET"; then
    echo "PURITY32: FAIL - target $TARGET is not installed." >&2
    echo "          rustup target add $TARGET" >&2
    echo "          (fail closed: a purity check that skips itself reads as a pass)" >&2
    exit 10
fi

echo "PURITY32: building $PKG for $TARGET (rust-lld, no cross toolchain required)"
if ! RUSTFLAGS="-C linker=rust-lld" cargo build --offline --release --target "$TARGET" \
        --manifest-path "$PKG/Cargo.toml" > /tmp/purity32_build.log 2>&1; then
    echo "PURITY32: FAIL - build/link failed; see /tmp/purity32_build.log" >&2
    tail -20 /tmp/purity32_build.log >&2
    exit 11
fi

[ -s "$OUT" ] || { echo "PURITY32: FAIL - no artifact at $OUT" >&2; exit 12; }

desc="$(file -b "$OUT")"
echo "PURITY32: artifact $OUT"
echo "PURITY32:   size   $(stat -c%s "$OUT") bytes"
echo "PURITY32:   type   $desc"
echo "PURITY32:   sha256 $(sha256sum "$OUT" | awk '{print $1}')"

case "$desc" in
    *"ELF 32-bit"*ARM*) ;;
    *) echo "PURITY32: FAIL - expected a 32-bit ARM ELF, got: $desc" >&2; exit 12 ;;
esac
case "$desc" in
    *"statically linked"*) ;;
    *) echo "PURITY32: FAIL - expected a static binary (a dynamic one needs the board's own libc): $desc" >&2; exit 12 ;;
esac

# `file` says "statically linked" from the absence of a PT_INTERP hint, but check the
# program headers directly: a binary with an interpreter would fail at run time on a uClibc
# board while every build-time check stayed green.
if readelf -l "$OUT" 2>/dev/null | grep -q 'INTERP'; then
    echo "PURITY32: FAIL - the artifact carries a PT_INTERP segment (not truly static)" >&2
    exit 12
fi

# Sensitivity control: the artifact must be OUR code, and it must contain BOTH this carrier's
# own surface and forms' own data. A stale file in target/ would satisfy every check above, and
# a binary that linked only one of the two would not be the thing this gate claims to check.
# NOTE: `strings | grep -q` under `pipefail` is a trap - grep exits at the first match, strings
# dies of SIGPIPE (141) and the pipeline reports failure for a string that IS present. Dump the
# strings once, then grep the dump.
strings -a "$OUT" > /tmp/purity32_strings.txt
for marker in "shlosilo-flux-desktop" "crypto-psbt" "v0.5.0-poc4+"; do
    if ! grep -q -- "$marker" /tmp/purity32_strings.txt; then
        echo "PURITY32: FAIL - marker '$marker' is missing from the artifact" >&2
        echo "          (a carrier string, a forms data string and the build identity must all be present)" >&2
        exit 12
    fi
done

echo "PURITY32: 32-bit ARM static link OK (run-time identity is the S2/S3 receipt's job)"
