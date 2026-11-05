#!/bin/bash
# Audit #5 open item 03: Miri subset harness
# Scope: modules that are pure Rust — no C FFI, no asm, no external-crate FFI
# Usage: bash scripts/miri_subset.sh [--quick]
# Miri is ~50x slower; --quick runs only the core safety-boundary modules
# Note: proptest tests need MIRIFLAGS disable-isolation (getcwd for seed files)
set -uo pipefail
cd "$(dirname "$0")/.."

TOOLCHAIN=nightly-2026-05-22
export MIRIFLAGS="-Zmiri-disable-isolation"
FAIL=0
MODULES=(
    "types::secret_bytes"      # audit #5 P0-03 core defense line
    "derivation::path"         # MAX_DEPTH boundary
    "encoding::cbor"           # untrusted-input decoding
    "encoding::base58"
    "encoding::bytewords"      # multipart frame encoding
)

if [[ "${1:-}" != "--quick" ]]; then
    MODULES+=(
        "encoding::fountain"   # elimination / work budget
        "entropy::mnemonic"
        "entropy::dice_rolls"
    )
fi

echo "=== Miri subset (toolchain=$TOOLCHAIN, MIRIFLAGS=$MIRIFLAGS) ==="
for m in "${MODULES[@]}"; do
    echo "--- cargo +$TOOLCHAIN miri test --lib $m"
    if cargo "+$TOOLCHAIN" miri test --lib "$m" 2>&1 | tail -3; then
        echo "OK: $m"
    else
        echo "FAIL: $m"
        FAIL=1
    fi
done

exit $FAIL
