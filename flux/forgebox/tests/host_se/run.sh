#!/bin/bash
# =============================================================================
# SE communication-plane host test (Task 7)
#
# Builds the PRODUCTION se_manager.c (the real dual-SE key-piece glue) with
# host gcc against the behavioural driver shims (se_shims.c) and pins it to
# the independent Python oracle (oracle_se.py). Run: bash run.sh
# =============================================================================
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"
SRC=../../src

echo "=== oracle: generating golden_se_vectors.h (hashlib/hmac) ==="
python3 oracle_se.py > golden_se_vectors.h

echo "=== building SE-plane host test (gcc) ==="
gcc -std=gnu11 -Wall -Wextra -Wno-unused-parameter -O1 -g \
    -I . \
    -I ../host_keystore/host_include \
    -I "$SRC" \
    -I "$SRC/keystore" \
    -I "$SRC/crypto" \
    -I "$SRC/driver" \
    -I "$SRC/utils" \
    -I "$SRC/ram" \
    -I ../../external/cryptoauthlib/lib \
    "$SRC/keystore/se_manager.c" \
    "$SRC/crypto/sha256.c" \
    "$SRC/crypto/sha512.c" \
    "$SRC/crypto/hmac.c" \
    "$SRC/crypto/hash_and_salt.c" \
    "$SRC/utils/user_utils.c" \
    "$SRC/utils/err_code.c" \
    se_shims.c \
    se_host_test.c \
    -o se_host_test

echo "=== running ==="
./se_host_test
