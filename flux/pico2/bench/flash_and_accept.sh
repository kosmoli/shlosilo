#!/usr/bin/env bash
# Chain: wait for BOOTSEL → flash the given UF2 → run the pico2 XMR hardware acceptance.
# Everything after the physical BOOTSEL press is automatic.
set -uo pipefail
cd "$(dirname "$0")"
UF2=${1:?uf2 path}
WINDOW=${2:-3600}

if ! bash flash_when_bootsel.sh "$UF2" "$WINDOW"; then
    echo "CHAIN_FAIL: flash stage (no BOOTSEL drive inside the window, or copy failed)"
    exit 2
fi

# The freshly flashed firmware is the bench flavor with the sign path; give the console a moment.
sleep 5
bash xmr_hw_accept.sh
rc=$?
echo "CHAIN_EXIT=$rc"
exit $rc
