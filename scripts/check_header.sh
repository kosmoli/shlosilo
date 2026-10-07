#!/usr/bin/env bash
# =============================================================================
# C header sync gate: cbindgen output must byte-equal the tracked shlosilo.h.
#
# The tracked header is the C host's single declaration source; if it drifts
# from the Rust public surface, the host compiles against a stale ABI. This
# gate is shared by the forgebox build (flux/forgebox/build.sh) and CI
# (audit #16 P1-01: the header gate must run outside the C-host build too).
#
# cbindgen's output format is version-sensitive: keep the pinned version in
# sync with CI (0.27.0 as of audit #16).
# =============================================================================
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v cbindgen >/dev/null 2>&1; then
    echo "ERROR: cbindgen not found (cargo install cbindgen --version 0.27.0 --locked)." >&2
    exit 1
fi

tmp="$(mktemp /tmp/shlosilo_regen.XXXXXX.h)"
trap 'rm -f "$tmp"' EXIT

# P2 gate (Task 5b): cbindgen regen reproduces the cbindgen.toml trailer
# VERBATIM, so a changed Rust signature in the flux/keysource glue would keep
# the byte-equal diff below green while the C host compiles against a stale
# ABI. Compare the trailer declarations against the real Rust signatures too
# (normalized name/return/params) so that drift turns this gate red.
python3 scripts/check_ffi_decls.py

cbindgen --config cbindgen.toml --crate shlosilo --output "$tmp" >/dev/null

if ! diff -q "$tmp" shlosilo.h >/dev/null; then
    echo "ERROR: tracked shlosilo.h differs from cbindgen output." >&2
    echo "       Regenerate and commit shlosilo.h before building a C host:" >&2
    echo "       cbindgen --config cbindgen.toml --crate shlosilo --output shlosilo.h" >&2
    diff "$tmp" shlosilo.h | head -40 >&2 || true
    exit 1
fi

echo "header OK (tracked == cbindgen regen)"
