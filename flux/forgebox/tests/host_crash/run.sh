#!/bin/bash
# =============================================================================
# crash-forensics blackbox host test
#
# Builds the PRODUCTION pure record logic (src/diag/crash_record.c) with host
# gcc — no hardware: the flash/FreeRTOS layer (crash_blackbox.c) is firmware-
# only and pinned by the write discipline shared with the panic path. Run:
# bash run.sh
# =============================================================================
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"
SRC=../../src

echo "=== building crash-record host test (gcc) ==="
gcc -std=gnu11 -Wall -Wextra -Werror -O1 -g \
    -I "$SRC/diag" \
    "$SRC/diag/crash_record.c" \
    crash_host_test.c \
    -o crash_host_test

echo "=== running ==="
./crash_host_test
