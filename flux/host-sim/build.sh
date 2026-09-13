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
( cd "$REPO_ROOT" && cargo build -p shlosilo-host-sim --release )

echo "=== keep-table gate (sim_l3 calls must be pinned in the keep table) ==="
# Same discipline as forgebox: extern "C" declarations do not create LTO
# reachability, so every entry point the C side links against must be
# referenced through its real Rust path in staticlib/src/lib.rs. A new call
# in sim_l3.c without a keep-table entry fails the C link - this gate turns
# that late, confusing failure into an explicit one (audit #16 INFO).
lib="$REPO_ROOT/target/release/libshlosilo.a"
for sym in $(grep -oE 'shlosilo_[a-z_0-9]+' "$APP_ROOT/sim_l3.c" | sort -u); do
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
gcc -Wall -Wextra \
    -o "$APP_ROOT/sim_l3" "$APP_ROOT/sim_l3.c" \
    -I "$REPO_ROOT" -L "$REPO_ROOT/target/release" \
    -lshlosilo -lpthread -ldl -lm

echo "    built: flux/host-sim/sim_l3"
echo "    run:   $APP_ROOT/sim_l3"
