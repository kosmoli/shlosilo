#!/usr/bin/env bash
# One-shot hardware acceptance for the pico2 static sign pool (#73 / A4-04).
#
# Preconditions: bench firmware on /dev/ttyACM0, and the frames file regenerated from the
# DEVICE-KEY fixture (the watch-only one cannot be decrypted by the device):
#
#   P64_ENC_PATH=tests/fixtures/unsigned_txset_2in_dev.bin \
#       cargo test --release --test p64_xmr_multi_input encode_ur_frames -- --ignored --nocapture
#
# Steps: clear the heap peak → sign the fixture on the device → read the peak back → compare the
# blob with the host baseline. The point of the peak reading: with the static pool the sign
# workspace must NOT appear in the PSRAM heap peak.
set -uo pipefail
cd "$(dirname "$0")"
DEV=${DEV:-/dev/ttyACM0}
FRAMES=/tmp/xmr_2in_frames.txt

[ -e "$DEV" ] || { echo "FAIL: $DEV missing (board not plugged in)"; exit 1; }
[ -f "$FRAMES" ] || { echo "FAIL: $FRAMES missing - regenerate from unsigned_txset_2in_dev.bin"; exit 1; }

echo "== firmware identity =="
python3 p2_console.py --dev "$DEV" --drain 3 --after 2 version | grep -E "\[ver\]"

echo "== heap baseline (peak cleared) =="
python3 p2_console.py --dev "$DEV" --drain 1 --after 2 "heap reset" | grep -E "\[heap\]"

echo "== device sign (fixture, fixed entropy A/B) =="
python3 xmr_2in_bringup.py || { echo "FAIL: sign run"; exit 10; }

echo "== heap after the sign (peak is what the allocator saw) =="
python3 p2_console.py --dev "$DEV" --drain 1 --after 2 heap | grep -E "\[heap\]"

echo "== device blob vs host baseline =="
python3 xmr_2in_compare.py || { echo "FAIL: blob mismatch"; exit 11; }

echo "ACCEPTANCE_OK"
