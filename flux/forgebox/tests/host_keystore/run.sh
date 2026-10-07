#!/bin/bash
# =============================================================================
# keystore data-plane host test (Task 6)
#
# Builds the PRODUCTION keystore.c + crypto sources with host gcc against the
# in-memory SE/OTP sim (host_shims.c) and pins them to the independent
# Python/OpenSSL oracle (oracle_golden.py). Run: bash run.sh
# =============================================================================
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"
SRC=../../src

echo "=== oracle: generating golden_vectors.h (hashlib/hmac + OpenSSL) ==="
python3 oracle_golden.py > golden_vectors.h

echo "=== building keystore host test (gcc) ==="
gcc -std=gnu11 -Wall -Wextra -Wno-unused-parameter -O1 -g \
    -I host_include \
    -I . \
    -I "$SRC" \
    -I "$SRC/keystore" \
    -I "$SRC/crypto" \
    -I "$SRC/driver" \
    -I "$SRC/utils" \
    -I "$SRC/ram" \
    -I ../../external/mh1903_lib/ctaes \
    "$SRC/keystore/keystore.c" \
    "$SRC/crypto/sha256.c" \
    "$SRC/crypto/sha512.c" \
    "$SRC/crypto/hmac.c" \
    "$SRC/crypto/hash_and_salt.c" \
    "$SRC/utils/user_utils.c" \
    ../../external/mh1903_lib/ctaes/ctaes.c \
    host_shims.c \
    keystore_host_test.c \
    -o keystore_host_test

echo "=== running ==="
./keystore_host_test
