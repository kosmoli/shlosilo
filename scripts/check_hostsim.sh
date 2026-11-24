#!/usr/bin/env bash
# =============================================================================
# host-sim run assertion — the ONE place these expectations live.
#
# Called by BOTH `scripts/gates_run.sh` (local gate batch) and
# `.github/workflows/ci.yml` (the "host-sim (POSIX) staticlib + keep gate + link
# + run" step). Before this file existed each side carried its own copy: CI
# grepped for the expected device output and the local batch only *printed*
# `grep -c` counts, so a changed exit shape turned CI red while the local batch
# stayed green — the two `0`/`1` lines in the local gate output were the failing
# assertion nobody was checking.
#
# What it pins: the ETH exit now returns the `ur:eth-signature` container, so
# the simulator prints `eth-signature container (<n> bytes):`. The byte count is
# part of the assertion on purpose — a silent shape change (a different container,
# a wrapped payload, an extra key) has to be a deliberate edit here.
#
# Prerequisite: `make host-sim` (or `bash flux/host-sim/build.sh`) has built the
# binary. This script only runs and asserts.
# =============================================================================
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

SIM=flux/host-sim/sim_l3
LOG=/tmp/sim_l3.log

if [ ! -x "$SIM" ]; then
    echo "ERROR: $SIM not built (run: make host-sim)" >&2
    exit 2
fi

if ! "$SIM" > "$LOG" 2>&1; then
    echo "ERROR: $SIM exited non-zero; output tail:" >&2
    tail -20 "$LOG" >&2
    exit 1
fi

fail() {
    echo "ERROR: $1" >&2
    echo "       expected lines missing from $LOG; output tail:" >&2
    tail -20 "$LOG" >&2
    exit 1
}

grep -q "eth-signature container (89 bytes)" "$LOG" \
    || fail 'host-sim did not print "eth-signature container (89 bytes)"'
grep -q "=== all steps completed ===" "$LOG" \
    || fail 'host-sim did not reach "=== all steps completed ==="'

echo "host-sim run OK (eth-signature container + all steps)"
