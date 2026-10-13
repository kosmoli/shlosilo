#!/bin/bash
# =============================================================================
# crash-forensics blackbox host test
#
# Builds the PRODUCTION pure logic (src/diag/crash_record.c + the append-log
# layer src/diag/crash_store.c) with host gcc — no hardware: the flash/RTOS
# glue (crash_blackbox.c) is firmware-only and thin over crash_store. Run:
# bash run.sh
# =============================================================================
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"
SRC=../../src

echo "=== building crash-record host test (gcc) ==="
gcc -std=gnu11 -Wall -Wextra -Werror -O1 -g \
    -I "$SRC/diag" \
    "$SRC/diag/crash_record.c" \
    "$SRC/diag/crash_store.c" \
    crash_host_test.c \
    -o crash_host_test

echo "=== running ==="
./crash_host_test
