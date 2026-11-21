#!/usr/bin/env bash
# Design 密钥供给 §11 (2026-11-21): the shipped device image must not contain a way to pull a seed
# out of the SE.
#
# The Rust key face asks for `LoadAccountEntropy` (32-byte entropy + length). The keystone3-parity
# full-record read (`LoadAccountSecret` -> AccountSecret_t, entropy AND seed AND SLIP-39/TON tail)
# is compiled out of the device build; it still exists in source for format archaeology and is
# exercised by the host test build, which turns it back on.
#
# A comment cannot enforce that, so this measures the artifact: the seed-returning entry points
# must be ABSENT, the narrow one PRESENT. If someone re-enables SHLOSILO_KEYSTORE_FULL_RECORD_API
# in the firmware build, this fails.
set -euo pipefail
cd "$(dirname "$0")/.."

ELF=${FORGEBOX_ELF:-flux/forgebox/build/mh1903.elf}
if [ ! -f "$ELF" ]; then
    echo "KEYSTORESURFACE: missing $ELF (build flux/forgebox first)" >&2
    exit 1
fi

forbidden=$(arm-none-eabi-nm "$ELF" | grep -cE " (T|t) LoadAccountSecret(FromSE)?$" || true)
narrow=$(arm-none-eabi-nm "$ELF" | grep -cE " (T|t) LoadAccountEntropy(FromSE)?$" || true)

echo "KEYSTORESURFACE: seed-returning entry points = $forbidden (want 0)"
echo "KEYSTORESURFACE: entropy-only entry points   = $narrow (want 2: wrapper + impl)"

if [ "$forbidden" -ne 0 ]; then
    echo "KEYSTORESURFACE: FAIL - the image can still read a seed out of the SE:" >&2
    arm-none-eabi-nm "$ELF" | grep -E " (T|t) LoadAccountSecret(FromSE)?$" >&2
    exit 1
fi
if [ "$narrow" -lt 2 ]; then
    echo "KEYSTORESURFACE: FAIL - the entropy-only path is not in the image either" >&2
    exit 1
fi
echo "KEYSTORESURFACE: OK - only the entropy face is reachable from the device"
