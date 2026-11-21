#!/usr/bin/env bash
# A4-15 — the forgebox device artifact's allocation face, with a sensitivity self-check.
#
# The audit (A4-15) said the device shim registers `#[global_allocator] EMBEDDED_ALLOCATOR`
# unconditionally and that, without a final link graph, nobody could tell whether the signing path
# calls it. This measures the REAL forgebox image with disassembly reachability (probes/noalloc/
# measure.py) from the FFI symbols the product C code actually calls.
#
# The self-check matters more than the claim: Rust reaches the allocator through name-mangled
# lang items (`_RNvCs..._7cfg___rustc12___rust_alloc`), and a naive symbol-equality check reports
# "0 allocation sites" on an image that allocates 320 KiB per sign. Part 2 therefore runs the same
# instrument on the pico2 image, which is KNOWN to allocate; if the instrument cannot see those
# calls, part 1's clean verdict is vacuous and this gate fails.
#
# Requires built images: flux/forgebox/build.sh (the FORGEBOX gate) and the pico2 build (PICO2).
# Exit: 0 = clean and sensitive, 10 = reachable allocator calls, 1 = artifact/tool problem.
set -euo pipefail
cd "$(dirname "$0")/.."

ELF=${FORGEBOX_ELF:-flux/forgebox/build/mh1903.elf}
PICO2_ELF=${PICO2_ELF:-target/thumbv8m.main-none-eabihf/release/shlosilo-pico2}

if [ ! -f "$ELF" ]; then
    echo "FORGEBOXNOALLOC: missing $ELF (build flux/forgebox first)" >&2
    exit 1
fi

# The product faces the C side calls (grep of flux/forgebox/src/*.c). Signing first: those are the
# ones the zero-heap claim is about. Review/decode/export sit on the same user-visible path, so a
# stray allocation there would put the heap back into the product.
ENTRIES="shlosilo_sign_ur_ffi,shlosilo_sign_typed_ffi,shlosilo_sign_session_view_ffi,shlosilo_review_ffi,shlosilo_ur_decode_uri_ffi,shlosilo_export_readonly_ffi,shlosilo_create_account_ffi"

echo "== part 1: forgebox product image ($ELF)"
set +e
python3 probes/noalloc/measure.py "$ELF" \
    --entry "$ENTRIES" \
    --json probes/noalloc/forgebox_report.json
rc=$?
set -e
echo "FORGEBOXNOALLOC: report written to probes/noalloc/forgebox_report.json"
if [ "$rc" -ne 0 ]; then
    echo "FORGEBOXNOALLOC: FAIL — reachable allocator call(s) in a product face" >&2
    exit 10
fi

# Part 2: sensitivity. An instrument that cannot see known allocations may not report cleanliness.
echo "== part 2: sensitivity control on the pico2 image (known to allocate)"
if [ ! -f "$PICO2_ELF" ]; then
    echo "FORGEBOXNOALLOC: WARNING — $PICO2_ELF not built, sensitivity control skipped" >&2
    echo "FORGEBOXNOALLOC: build the pico2 firmware (PICO2 gate) to make this gate non-vacuous" >&2
    exit 1
fi

set +e
python3 probes/noalloc/measure.py "$PICO2_ELF" --entry main \
    --json /tmp/pico2_alloc_control.json > /tmp/pico2_alloc_control.txt 2>&1
set -e
sites=$(python3 -c 'import json;print(json.load(open("/tmp/pico2_alloc_control.json"))["alloc_sites_linked"])')
symbols=$(python3 -c 'import json;print(len(json.load(open("/tmp/pico2_alloc_control.json"))["allocator_symbols"]))')
echo "   pico2 control: allocator symbols in image = $symbols, alloc call sites = $sites"
if [ "$sites" -eq 0 ] || [ "$symbols" -eq 0 ]; then
    echo "FORGEBOXNOALLOC: FAIL — the instrument is blind: the pico2 image allocates in every sign" >&2
    echo "                 yet it reported no call sites. Part 1's clean verdict would be vacuous." >&2
    exit 1
fi
echo "FORGEBOXNOALLOC: OK — forgebox product faces are REACHABLE-CLEAN and the instrument is sensitive"
