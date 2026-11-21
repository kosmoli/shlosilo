#!/usr/bin/env bash
# #73 / A4-04: the pico2 sign path must not go through the allocator.
#
# The audit's point was that "forms takes a caller slice" does not prove the device sign path
# allocates nothing: the console used to build the workspace out of ~20 heap `Vec`s per sign
# (128 KiB `tx_bytes` alone). That half is fixed - the workspace is now one caller-owned static
# arena carved with `SignWsLayout` - and this gate keeps it fixed by MEASURING THE IMAGE.
#
# Two faces, both required:
#   1. the sign stretch's symbol exists and is measurable (an inlined-away body would make every
#      "0 allocation sites" below vacuous - the A4-15 blindness class);
#   2. from that symbol, no allocation site is reachable EXCEPT the frozen third-party debt list
#      below. New allocation in our own code turns this red; the vendor entries are named so the
#      debt stays visible instead of being averaged away.
#
# Debt list (2026-11-22, measured): five sites inside the vendored crypto crates
# (monero-clsag::core x2 dealloc, monero-bulletproofs::Bulletproof::serialize_into alloc,
# RawVecInner::finish_grow realloc for both). The HOST runtime pin for the same flow reports zero
# allocations (tests/xmr_sign_zero_alloc), so these are static over-approximations of variants the
# measured shapes never take - static reachability cannot tell. Pinned, not excused: if a future
# change makes one of them live on the device, the runtime face has to be re-measured and this
# list re-justified.
#
# Sensitivity control: the same instrument must find allocation sites from a KNOWN-allocating
# entry (the console's UR dispatch, which stages Vec-based shells) in the same image.
#
# Exit: 0 = clean-or-frozen-debt, 1 = artifact/tool problem, 10 = new allocation on the sign path,
#       11 = instrument is blind (entry missing or control produced nothing).
set -euo pipefail
cd "$(dirname "$0")/.."

ELF=${PICO2_ELF:-target/thumbv8m.main-none-eabihf/release/shlosilo-pico2}

# Own the artifact: `scripts/check_pico2_flavors.sh` leaves the BENCH/PERF build at this path
# (same cargo output path per flavor), and the perf flavor legitimately reaches more of the graph
# than production does. Measuring whatever happens to be there would make the verdict depend on
# step order, so build the production flavor explicitly - it is cached when the batch already
# built it.
echo "PICO2SIGNAlloc: building the production flavor (the measured artifact)"
SHLOSILO_LIMITS=${SHLOSILO_LIMITS:-pico2} cargo build --offline --locked --release \
    --target thumbv8m.main-none-eabihf --manifest-path flux/pico2/Cargo.toml \
    > /tmp/pico2_sign_alloc_build.log 2>&1 || {
        echo "PICO2SIGNAlloc: FAIL - production build failed; see /tmp/pico2_sign_alloc_build.log" >&2
        tail -10 /tmp/pico2_sign_alloc_build.log >&2
        exit 1
    }
REPORT=${PICO2_SIGN_ALLOC_REPORT:-probes/noalloc/pico2_sign_report.json}
CONTROL_REPORT=/tmp/pico2_sign_alloc_control.json

if [ ! -f "$ELF" ]; then
    echo "PICO2SIGNAlloc: missing $ELF (build the pico2 production flavor first)" >&2
    exit 1
fi

entry=$(arm-none-eabi-nm "$ELF" | grep -E "^[0-9a-f]+ [tT] [^ ]*console12sign_stretch$" | awk '{print $3}' | head -1)
if [ -z "$entry" ]; then
    echo "PICO2SIGNAlloc: FAIL - no 'sign_stretch' symbol in the image." >&2
    echo "                The sign stretch got inlined (or renamed); with no entry point every" >&2
    echo "                'no allocation sites' claim below would be vacuous (A4-15 class)." >&2
    exit 11
fi
echo "PICO2SIGNAlloc: entry = $entry"

set +e
python3 probes/noalloc/measure.py "$ELF" --entry "$entry" --json "$REPORT" > /tmp/pico2_sign_alloc.txt 2>&1
set -e
python3 - "$REPORT" <<'PY'
import json
import re
import sys

report = json.load(open(sys.argv[1]))
# The instrument's JSON carries one record per call site: {"caller", "target", "reachable"}.
sites = [s for s in report.get("sites", []) if s.get("reachable")]
functions = report.get("functions")
linked = report.get("alloc_sites_linked")
reachable = report.get("alloc_sites_reachable")

# The frozen third-party debt: caller symbol must contain one of these, once per expected site.
# Match on crate name + item, never on the crate hash: the hash changes with the feature set,
# so a hash-keyed allow-list silently rots into "everything is unexplained".
ALLOWED = [
    (r"12monero_clsag4core", "monero-clsag::core"),
    (r"19monero_bulletproofsNtB2_11Bulletproof14serialize_into", "bulletproofs::serialize_into"),
    (r"RawVecInner11finish_grow.*12monero_clsag", "clsag RawVec::finish_grow"),
    (r"RawVecInner11finish_grow.*19monero_bulletproofs", "bulletproofs RawVec::finish_grow"),
]

def caller_of(site):
    if isinstance(site, dict):
        return site.get("caller", "")
    return str(site)

callers = [caller_of(s) for s in sites]
unexplained = []
for caller in callers:
    if not any(re.search(pat, caller) for pat, _ in ALLOWED):
        unexplained.append(caller)

print(f"PICO2SIGNAlloc: functions reachable from the sign stretch = {functions}")
print(f"PICO2SIGNAlloc: allocator symbols in image = {len(report.get('allocator_symbols', []))}")
print(f"PICO2SIGNAlloc: alloc sites linked/reachable = {linked}/{reachable}")
for caller in callers:
    label = next((name for pat, name in ALLOWED if re.search(pat, caller)), "UNEXPLAINED")
    print(f"    [{label}] {caller.split('_')[-1][:40]}")

if unexplained:
    print("PICO2SIGNAlloc: FAIL - allocation reachable from the sign stretch in OUR code:", file=sys.stderr)
    for caller in unexplained:
        print(f"    {caller}", file=sys.stderr)
    sys.exit(10)
if not sites:
    # Not automatically a pass: say so, and let the reachable-function count below decide.
    print("PICO2SIGNAlloc: note - the call-graph walk found no allocator call site at all")
if functions is None or functions == 0:
    print("PICO2SIGNAlloc: FAIL - the entry has no reachable functions at all", file=sys.stderr)
    sys.exit(11)
print("PICO2SIGNAlloc: sign path allocates nothing beyond the frozen third-party debt list")
PY

# Sensitivity control: the instrument must still SEE allocations in this image, from an entry that
# is known to allocate. `ConsoleState::feed` is the console dispatcher and still builds the Vec-based
# UR/QR session shells (that half is A4-05, not this gate), so it is the natural control. Almost
# everything else the console does is inlined into the task poll, which is why the control has to be
# this specific symbol rather than "any command handler".
# nm lists local labels/branch tables for the same name (`.Lswitch.table...`); keep only a real
# function symbol (`t`/`T`), or the measurement runs against a non-entry and fails as a tool error.
control=$(arm-none-eabi-nm "$ELF" | grep -E "^[0-9a-f]+ [tT] [^ ]*console[^ ]*ConsoleState4feed$" | awk '{print $3}' | head -1)
if [ -z "$control" ]; then
    echo "PICO2SIGNAlloc: FAIL - no control symbol: without one, a clean sign verdict proves nothing" >&2
else
    set +e
    python3 probes/noalloc/measure.py "$ELF" --entry "$control" --json "$CONTROL_REPORT" > /tmp/pico2_sign_alloc_ctl.txt 2>&1
    set -e
    if ! sites=$(python3 -c 'import json;print(json.load(open("/tmp/pico2_sign_alloc_control.json"))["alloc_sites_reachable"])' 2>/tmp/pico2_ctl_err.txt); then
        echo "PICO2SIGNAlloc: FAIL - control measurement produced no report:" >&2
        tail -5 /tmp/pico2_sign_alloc_ctl.txt >&2 || true
        exit 11
    fi
    echo "PICO2SIGNAlloc: control ($control) reachable alloc sites = $sites (want > 0)"
    if [ "$sites" -eq 0 ]; then
        echo "PICO2SIGNAlloc: FAIL - the instrument is blind: a known-allocating entry reports zero," >&2
        echo "                so the sign path's clean verdict above proves nothing." >&2
        exit 11
    fi
fi

echo "PICO2SIGNAlloc: OK"
