#!/usr/bin/env bash
# =============================================================================
# Chain axis matrix (design note 「链轴积木化」 §9.3-2 / §9.4, batch 1)
#
# What this gate proves, in order:
#
# 1. COMBINATION MATRIX — the 3 single-chain, 3 double-chain and 1 all-on builds
#    each compile on the host face:
#        cargo check --offline --no-default-features \
#                    --features "std,alloc-fallback,<combo>"
#    The features are additive (Cargo union semantics), so no two chains are
#    mutually exclusive; the matrix is about *presence*, never about exclusion.
#
# 2. PROFILE AGREEMENT — every combination is built against a profile whose
#    `[chains]` block declares exactly that combination. `build.rs` cross-checks
#    the declaration against the compiled `chain-*` features in BOTH directions
#    and refuses a mismatch, so this script cannot silently test a build the
#    profile does not describe. The profiles are derived from `limits/host.toml`
#    with ONLY the `[chains]` block rewritten (every numeric ceiling is copied
#    byte for byte — this gate never invents a limit), are named
#    `limits/chainaxes-<combo>.toml`, and are removed on exit.
#
# 3. DOUBLE-EDGED SYMBOL CRITERION (§9.4, the FORGEBOXSEISO lesson) — for every
#    combination, each DISABLED chain must own ZERO symbols in the rlib, and each
#    ENABLED chain's sampled symbols must be PRESENT in the same rlib. The second
#    half is what makes the first half mean something: a grep that cannot see a
#    symbol cannot distinguish "compiled out" from "instrument broken / rlib
#    stale / wrong artifact".
#
#    Sampling method (measured, not assumed): the build uses the v0 legacy symbol
#    mangling, so a function's mangled name carries its module path as plain text
#    with length prefixes. Verified on the all-on rlib with
#        nm --defined-only target/debug/deps/libshlosilo-*.rlib | grep 5chain3btc
#    which yields e.g.
#        T _RNvNtNtNtCs5WnKgDvi3YV_8shlosilo5chain3btc6p2wpkh16sign_p2wpkh_core
#        T _RNvNtNtNtCs5WnKgDvi3YV_8shlosilo5chain3eth8from_rlp17parse_eip1559_raw
#        T _RNvNtNtNtCs5WnKgDvi3YV_8shlosilo5chain3xmr10subaddress22calc_output_key_offset
#    i.e. `8shlosilo` + `5chain` + `3<chain>` prefixes the module path. The
#    samples are therefore non-generic free functions whose mangled names contain
#    that path (generic items get monomorphized names that could survive an
#    unrelated instantiation, so they are not used as the criterion):
#        btc: chain3btc4psbt14parse_psbt_any     chain3btc6p2wpkh16sign_p2wpkh_core
#        eth: chain3eth8from_rlp17parse_eip1559_raw  chain3eth8calldata15decode_calldata
#        xmr: chain3xmr10subaddress22calc_output_key_offset  chain3xmr5clsag.*ClsagProof8to_bytes
#    The per-chain module marker (`5chain3btc` / `5chain3eth` / `5chain3xmr`) is
#    asserted too: it is broader than the per-function samples, so it catches a
#    module that leaks without contributing one of the sampled functions.
#
# 4. SIZE ACCOUNT (§9.4) — each combination's `size` text total is printed with
#    its delta against the all-on build. Batch 1 only adds the switches and the
#    cross-checks: the code is compiled out, but the dependency graph is not yet
#    sliced (optional deps land in batch 2), so the text delta measures the
#    switch's own effect and nothing else.
#
# Usage: bash scripts/check_chain_axes.sh
# =============================================================================
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

COMBOS=(btc eth xmr btc,eth btc,xmr eth,xmr btc,eth,xmr)
PROFILE_PREFIX="chainaxes-"
BASE_FEATURES="std,alloc-fallback"
# Same flags on both faces: the local batch must not touch the network (--offline),
# CI wants the reviewed lockfile pinned (--locked). Caller decides, as with
# scripts/test_zero_on_alloc.sh.
CARGO_FLAGS="${CARGO_FLAGS:---offline}"
TMP_DIR="$(mktemp -d /tmp/chainaxes.XXXXXX)"
trap 'rm -f limits/${PROFILE_PREFIX}*.toml; rm -rf "$TMP_DIR"' EXIT

fail=0
note() { printf '%s\n' "$*"; }
bad() { printf 'FAIL: %s\n' "$*"; fail=1; }

# chain → the symbol patterns that must exist only while that chain is compiled in.
chain_samples() {
    case "$1" in
        btc) printf '%s\n' "5chain3btc4psbt14parse_psbt_any" "5chain3btc6p2wpkh16sign_p2wpkh_core" ;;
        eth) printf '%s\n' "5chain3eth8from_rlp17parse_eip1559_raw" "5chain3eth8calldata15decode_calldata" ;;
        xmr) printf '%s\n' "5chain3xmr10subaddress22calc_output_key_offset" "5chain3xmr5clsag" ;;
    esac
}

combo_profile() { printf '%s%s' "$PROFILE_PREFIX" "${1//,/-}"; }

# Chain names (as the profile declares them) -> cargo feature names, in order.
combo_features() {
    local out="" c
    for c in ${1//,/ }; do out="${out:+$out,}chain-$c"; done
    printf '%s' "$out"
}

# Derive this combination's profile from limits/host.toml: same numeric ceilings,
# `[chains]` rewritten to declare exactly this combination.
gen_profile() {
    python3 - "$1" > "limits/$(combo_profile "$1").toml" <<'PY'
import sys

combo = sys.argv[1].split(",")
text = open("limits/host.toml", "r", encoding="utf-8").read()

out = [
    "# @generated by scripts/check_chain_axes.sh - do not edit, do not commit.\n",
    "# Same ceilings as limits/host.toml; only the [chains] block differs, so this\n",
    "# profile declares exactly the combination the matrix is building.\n",
    "[chains]\n",
]
for chain in ("btc", "eth", "xmr"):
    out.append("%s = %s\n" % (chain, "true" if chain in combo else "false"))
out.append("\n")

# Copy every [limits] line verbatim (values untouched), skipping host's own
# `[chains]` block and every comment that precedes the first section header (the
# header above that block describes the [chains] declaration we just replaced).
section = None
for line in text.splitlines(True):
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        section = stripped[1:-1]
        if section == "chains":
            continue
        out.append(line)
        continue
    if section is None or section == "chains":
        continue
    out.append(line)
sys.stdout.write("".join(out))
PY
}

# The rlib cargo just produced for the current feature set (the artifact list is
# keyed by feature set, so this names exactly the unit under test).
rlib_of() {
    cargo build $CARGO_FLAGS --lib --no-default-features --features "$BASE_FEATURES,$1" \
        --message-format=json 2>/dev/null |
        python3 -c '
import sys, json
for line in sys.stdin:
    try:
        m = json.loads(line)
    except Exception:
        continue
    if m.get("reason") != "compiler-artifact":
        continue
    t = m.get("target") or {}
    # The core crate declares `crate-type = ["rlib"]`, so cargo reports the lib kind
    # as ["rlib"] (not ["lib"]); accept both and take the .rlib filename.
    if t.get("name") != "shlosilo" or not ({"lib", "rlib"} & set(t.get("kind") or [])):
        continue
    for f in m.get("filenames") or []:
        if f.endswith(".rlib"):
            print(f)
'
}

index=0
for combo in "${COMBOS[@]}"; do
    index=$((index + 1))
    profile="$(combo_profile "$combo")"
    gen_profile "$combo" || { bad "$combo: profile generation"; continue; }

    note ""
    note "== [$index/${#COMBOS[@]}] chains: $combo  (profile SHLOSILO_LIMITS=$profile)"

    # 1. compile matrix (the assertion the design note names)
    if SHLOSILO_LIMITS="$profile" cargo check $CARGO_FLAGS --no-default-features \
        --features "$BASE_FEATURES,$(combo_features "$combo")" > "$TMP_DIR/check-$index.log" 2>&1; then
        note "   check: exit 0"
    else
        bad "$combo: cargo check failed (log: $TMP_DIR/check-$index.log)"
        tail -20 "$TMP_DIR/check-$index.log" | sed 's/^/      /'
        continue
    fi

    # 2. object code for the symbol + size assertions
    rlib="$(SHLOSILO_LIMITS="$profile" rlib_of "$(combo_features "$combo")" | tail -1)"
    if [ -z "$rlib" ] || [ ! -f "$rlib" ]; then
        bad "$combo: no rlib artifact found"
        continue
    fi
    nm --defined-only "$rlib" > "$TMP_DIR/nm-$index.txt" 2>/dev/null
    total=$(wc -l < "$TMP_DIR/nm-$index.txt")
    # Sensitivity control: an rlib with a handful of symbols means nm (or the
    # artifact) is wrong, and every "zero occurrences" below would be vacuous.
    if [ "$total" -lt 1000 ]; then
        bad "$combo: instrument blind — only $total defined symbols in $rlib"
        continue
    fi

    # 3. double-edged symbol criterion
    for chain in btc eth xmr; do
        present=0
        case ",$combo," in
            *",$chain,"*) present=1 ;;
        esac
        marker="5chain3$chain"
        hits=$(grep -c "$marker" "$TMP_DIR/nm-$index.txt")
        if [ "$present" -eq 1 ]; then
            if [ "$hits" -eq 0 ]; then
                bad "$combo: chain $chain is COMPILED IN but '$marker' has zero symbols (instrument or artifact problem)"
            else
                note "   $chain: ON   $marker -> $hits symbols"
            fi
            while IFS= read -r sym; do
                [ -n "$sym" ] || continue
                n=$(grep -c "$sym" "$TMP_DIR/nm-$index.txt")
                if [ "$n" -eq 0 ]; then
                    bad "$combo: enabled chain $chain lost its sampled symbol $sym"
                fi
            done < <(chain_samples "$chain")
        else
            if [ "$hits" -ne 0 ]; then
                bad "$combo: chain $chain is OFF but '$marker' still has $hits symbols (symbol leak)"
            else
                note "   $chain: off  $marker -> 0 symbols"
            fi
            while IFS= read -r sym; do
                [ -n "$sym" ] || continue
                n=$(grep -c "$sym" "$TMP_DIR/nm-$index.txt")
                if [ "$n" -ne 0 ]; then
                    bad "$combo: disabled chain $chain leaked sampled symbol $sym ($n hits)"
                fi
            done < <(chain_samples "$chain")
        fi
    done

    # 4. size account
    # `size` on an archive prints one row per member object; -t adds the (TOTALS)
    # line, whose first column is the whole archive's .text — the figure this account
    # compares across combinations.
    text_bytes=$(size -t "$rlib" 2>/dev/null | awk '/TOTALS/ {print $1}' | tail -1)
    printf '%s\n' "$combo|${text_bytes:-?}|$rlib" >> "$TMP_DIR/sizes.txt"
    note "   text: ${text_bytes:-?} bytes  ($(basename "$rlib"))"
done

note ""
note "== size account (rlib .text total, delta vs the all-on build)"
if [ -f "$TMP_DIR/sizes.txt" ]; then
    all_text=$(awk -F'|' '$1 == "btc,eth,xmr" {print $2}' "$TMP_DIR/sizes.txt")
    while IFS='|' read -r combo text _; do
        if [ -n "${all_text:-}" ] && [ "$text" != "?" ] && [ "$all_text" != "?" ]; then
            delta=$((all_text - text))
            printf '   %-14s text=%s  delta=%+d (vs all-on %s)\n' "$combo" "$text" "$delta" "$all_text"
        else
            printf '   %-14s text=%s\n' "$combo" "$text"
        fi
    done < "$TMP_DIR/sizes.txt"
else
    bad "no size data collected"
fi

note ""
if [ "$fail" -eq 0 ]; then
    note "CHAIN AXES: OK (${#COMBOS[@]} combinations, no symbol leak, all-on symbols present)"
else
    note "CHAIN AXES: RED (see FAIL lines above)"
fi
exit "$fail"
