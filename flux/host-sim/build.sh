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

echo "=== linking sim_l3 ==="
gcc -Wall -Wextra \
    -o "$APP_ROOT/sim_l3" "$APP_ROOT/sim_l3.c" \
    -I "$REPO_ROOT" -L "$REPO_ROOT/target/release" \
    -lshlosilo -lpthread -ldl -lm

echo "    built: flux/host-sim/sim_l3"
echo "    run:   $APP_ROOT/sim_l3"
