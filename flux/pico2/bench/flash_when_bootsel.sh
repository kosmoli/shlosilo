#!/usr/bin/env bash
# Wait for the RP2350 BOOTSEL drive, flash the given UF2, then report the banner.
# Used when the board is running the console firmware (no software path into the bootloader).
set -uo pipefail
UF2="$1"
DEADLINE=$(( $(date +%s) + ${2:-900} ))
MOUNT=""

echo "waiting for an RP2350/RPI-RP2 mass-storage mount (up to $(( ${2:-900} / 60 )) min)..."
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    MOUNT=$(ls -d /run/media/*/RP2350 /run/media/*/RPI-RP2 /media/*/RP2350 /media/*/RPI-RP2 2>/dev/null | head -1)
    if [ -n "$MOUNT" ]; then
        break
    fi
    sleep 2
done
if [ -z "$MOUNT" ]; then
    echo "TIMEOUT: no BOOTSEL drive appeared; nothing flashed"
    exit 2
fi
echo "BOOTSEL drive: $MOUNT"
cp "$UF2" "$MOUNT/" || { echo "copy failed"; exit 1; }
sync
echo "flashed $(basename "$UF2") ($(stat -c%s "$UF2") bytes)"

echo "waiting for the console to enumerate..."
for _ in $(seq 1 30); do
    if [ -e /dev/ttyACM0 ]; then
        sleep 3
        python3 "$(dirname "$0")/../pico2/bench/p2_console.py" --dev /dev/ttyACM0 --drain 6 2>&1 | grep -E "\[hb\]|\[psram\]|\[ver\]" | head -4
        echo "FLASH_AND_REBOOT_OK"
        exit 0
    fi
    sleep 1
done
echo "flashed, but no /dev/ttyACM0 yet"
exit 3
