#!/bin/bash
# =============================================================================
# host-sim appearance: POSIX host simulator (no hardware, no RTOS)
#
# Builds the shlosilo *forms* static library for the host and links the C
# simulator against it. This appearance exists to exercise the C ABI on a
# developer machine: create_account / export_readonly / sign over the UR entry
# points, with plain stdio instead of a screen and QR hardware.
# =============================================================================

set -e
cd "$(dirname "${BASH_SOURCE[0]}")"
APP_ROOT="$(pwd)"
REPO_ROOT="$(cd ../.. && pwd)"

echo "=== shlosilo forms: cargo build -p shlosilo-host-sim --release (host) ==="
# The host-target staticlib bundle lives in staticlib/ (the core crate itself
# is rlib-only; each C host owns its staticlib shim). It produces
# target/release/libshlosilo.a, which the C simulator links via -lshlosilo.
#
# Chain axis batch 2 (L5): sim_l3.c also compiles against the GENERATED build identity
# header (`shlosilo_build_identity.h`: the chain set this build compiled + its
# BUILD_FINGERPRINT) and compares it with the library at run time. That header lives in
# the generated build identity header - so cargo is asked where
# it is instead of globbing `target/release/build/shlosilo-*/out`, which would happily
# pick a stale unit from an earlier feature set or profile.
# `json-render-diagnostics` renders diagnostics as usual and keeps stdout machine-
# readable; the identity header requirement is why this build captures the stream.
CARGO_JSON="$(mktemp /tmp/hostsim-cargo.XXXXXX.json)"
trap 'rm -f "$CARGO_JSON"' EXIT
if ! ( cd "$REPO_ROOT" && cargo build -p shlosilo-host-sim --release \
        --message-format=json-render-diagnostics > "$CARGO_JSON" ); then
    echo "ERROR: cargo build failed" >&2
    exit 1
fi
# The identity header lives at a STABLE path that build.rs writes (repo/build/build-identity/
# <target>/<profile>). It is deliberately not read from cargo's message stream: cargo replays a
# fresh build script's output but never re-emits `build-script-executed`, so a path taken from
# that stream works on a warm tree and vanishes on a clean checkout (that is how this step
# passed locally and failed in CI).
HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
ID_DIR="$REPO_ROOT/build/build-identity/$HOST_TRIPLE/release"
[ -f "$ID_DIR/shlosilo_build_identity.h" ] || {
    echo "ERROR: $ID_DIR/shlosilo_build_identity.h missing - build.rs must generate it" >&2
    exit 1
}
echo "    build identity header: $ID_DIR/shlosilo_build_identity.h"

echo "=== keep-table gate (sim_l3 calls must be pinned in the keep table) ==="
# Same discipline as forgebox: extern "C" declarations do not create LTO
# reachability, so every entry point the C side links against must be
# referenced through its real Rust path in staticlib/src/lib.rs. A new call
# in sim_l3.c without a keep-table entry fails the C link - this gate turns
# that late, confusing failure into an explicit one (audit #16 INFO).
lib="$REPO_ROOT/target/release/libshlosilo.a"
# Only CALL-SHAPED tokens (`shlosilo_x(`) are entry points. A bare `shlosilo_…` token can
# be a filename — sim_l3.c includes the GENERATED `shlosilo_build_identity.h` (chain axis
# batch 2), and that header's name is not a symbol to keep. Matching the call form keeps
# the gate's purpose ("every entry point this file CALLS must be reachable") exact.
for sym in $(grep -oE 'shlosilo_[a-z_0-9]+[[:space:]]*\(' "$APP_ROOT/sim_l3.c" |
    sed 's/[[:space:]]*($//' | sort -u); do
    if ! grep -q "$sym as \*const" "$APP_ROOT/staticlib/src/lib.rs"; then
        echo "ERROR: $sym is called by sim_l3.c but missing from the keep table" >&2
        echo "       (flux/host-sim/staticlib/src/lib.rs) - add a real Rust-path reference." >&2
        exit 1
    fi
    if ! nm "$lib" | grep -q " T $sym$"; then
        echo "ERROR: $sym undefined (U) in libshlosilo.a - LTO dropped it despite the keep table" >&2
        exit 1
    fi
done
echo "    keep table OK (sim_l3 call surface pinned and defined)"

echo "=== linking sim_l3 ==="
# -I "$ID_DIR" is where the generated build identity header came from: the simulator
# must compile against the SAME build the library came from, and run once to prove the
# header and the library agree (see the assertion in sim_l3.c).
gcc -Wall -Wextra \
    -o "$APP_ROOT/sim_l3" "$APP_ROOT/sim_l3.c" \
    -I "$REPO_ROOT" -I "$ID_DIR" -L "$REPO_ROOT/target/release" \
    -lshlosilo -lpthread -ldl -lm

echo "    built: flux/host-sim/sim_l3"
echo "    run:   $APP_ROOT/sim_l3"
