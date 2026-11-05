#!/bin/bash
# ForgeBox on-device firmware build (P6.2c path, verified on hardware, pinned 2026-08-29)
# Usage: bash scripts/build_forgebox_bin.sh
# Output: build/forgebox.bin → copy to the SD card root (the filename must stay forgebox.bin)
# The device loads it in recovery mode. USB works only for the first pubkey
# registration; after that always use the SD card.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$REPO/build"
export PATH="$HOME/.hermes/node/bin:$PATH"

# Pre-flight checks
for f in "$BUILD/mh1903.bin" "$BUILD/padding_bin_file.py"; do
    [ -f "$f" ] || { echo "ERROR: missing $f (run cmake --build build first)"; exit 1; }
done
[ -f ~/.forgebox/keys/private.pem ] || { echo "ERROR: missing ~/.forgebox/keys/private.pem"; exit 1; }
command -v forgebox >/dev/null || { echo "ERROR: forgebox CLI not in PATH (~/.hermes/node/bin)"; exit 1; }

cd "$BUILD"

# 1. padding: mh1903.bin → mh1903_full.bin (4K alignment + APP_END magic)
python3 padding_bin_file.py mh1903.bin

# 2. forgebox sign single-layer wrap (fwdata header + QuickLZ + dual ECDSA)
#    ⚠️ the input MUST be mh1903_full.bin; signing raw mh1903.bin lacks APP_END → verification failure
#    ⚠️ do NOT run fmm before sign — double wrapping → NO APP
forgebox sign --s mh1903_full.bin --d forgebox.bin --key ~/.forgebox/keys/private.pem

# 3. verify the header (characteristic bytes of a single-layer fwdata wrap)
HEADER=$(xxd -l 12 -p forgebox.bin)
EXPECTED="5c0100007e66776461746121"
echo "header: $HEADER"
case "$HEADER" in
    "$EXPECTED"*) echo "OK: single-layer fwdata header confirmed" ;;
    *) echo "WARNING: unexpected header — compare against the working PoC 3 case 5c01 0000 7e66 7764 6174 6121"; exit 1 ;;
esac

ls -la "$BUILD/forgebox.bin"
echo ""
echo "Next: copy build/forgebox.bin to the SD card root → boot the device into recovery mode to load it"
