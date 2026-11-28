#!/usr/bin/env bash
# =============================================================================
# CHAINAXIS_SCOPE — the assumption behind the strict chain check, made executable
# (design note §9.3-quater L2 ★)
#
# WHAT IT ASSERTS
#   `cfg(feature = "chain-…")` appears ONLY under `forms/`. Every crate that ships
#   chain-conditional code has its own feature set, and `build.rs` can only compare a
#   declaration against the feature set of THE crate it belongs to (`forms`). As long as
#   the chain axis exists in exactly one crate, one cross-check covers the whole product.
#
# WHY IT IS A GATE AND NOT A COMMENT
#   The alternative would be a cross-check inside every crate's build script — which is
#   noise today (there is nothing to check) and would rot immediately. Instead the
#   PRECONDITION is pinned: the day a second crate grows a chain axis, this step goes red.
#
# THE ONE REGISTERED EXCEPTION (batch S6, 2026-11-27)
#   `flux/forgebox/staticlib/src/lib.rs` — the C-host bundle — now has a chain axis of its own,
#   because its KEEP TABLE is generated per chain set: `#[cfg(feature = "chain-xmr")]` on an
#   entry keeps the table from referencing an entry point a subset build does not link (it used
#   to be unconditional, i.e. an unresolved symbol). That is table gating, not semantic gating,
#   so it is registered here under conditions that keep it from becoming a real second axis:
#     (a) every chain cfg in that file sits INSIDE the generated keep-table block;
#     (b) the crate's `chain-*` features FORWARD to `shlosilo/chain-*` (they cannot decouple);
#     (c) its `default` enables all three chains (the product face is unchanged);
#     (d) the cfg count matches the number of gated entries the generator produced.
#   Any chain cfg elsewhere in that file, in any other flux file, or a forwarding feature that
#   is missing/renamed, still goes red. Widening THIS into an allowlist is not the fix either.
#
# TRIGGER CONDITION (what the person who sees this fail MUST do)
#   A hit outside `forms/` means a crate other than the core now compiles differently per
#   chain — a real second axis, not a style problem. The fix is NOT to widen the allowlist
#   here: that crate must be brought into the same consistency check (its own build
#   script comparing SHLOSILO_CHAINS against its own `CARGO_FEATURE_CHAIN_*`, and its
#   carriers named in the matrix), because from then on "the declared chains" and "the
#   compiled chains" can disagree per crate — e.g. a flux crate linked against BTC+XMR
#   while the core was built BTC+ETH. That divergence is exactly what the forms-only
#   check can no longer see.
#
# SCOPE (what is deliberately NOT scanned)
#   Test and example faces: `tests/`, `*/tests/`, `examples/`, `*/examples/`, `benches/`,
#   `*/benches/`, `fuzz/`, `probes/`. A `#![cfg(feature = "chain-btc")]` at the top of an
#   integration test gates a TEST TARGET on the axis; it cannot compile a chain into a
#   shipped binary and it has no feature set of its own to disagree with. Third-party code
#   (`vendor/`) and build output (`target/`) are out of scope for the same reason.
#
# SENSITIVITY CONTROL
#   The scan must find a substantial number of hits in `forms/` (batch 1 gated ~240 sites).
#   A scan that finds nothing would pass while verifying nothing — the same failure mode
#   the FORGEBOXSEISO and chain-symbol gates were written against.
#
# Usage: bash scripts/check_chainaxis_scope.sh
# =============================================================================
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# The pattern: a cfg attribute or cfg! macro mentioning a chain feature. Written broadly
# on purpose (`cfg(...)` / `cfg!(...)` / `#[cfg(any(...))]` / multi-line attribute) —
# the question is "does this FILE switch on a chain feature", not "in which syntax".
PATTERN='cfg.*feature[[:space:]]*=[[:space:]]*"chain-'
# Below this many hits in forms/ the instrument is assumed broken, not clean.
MIN_FORMS_HITS=100

note() { printf '%s\n' "$*"; }

out_of_scope() {
    case "$1" in
        tests/* | */tests/* | examples/* | */examples/* | benches/* | */benches/*) return 0 ;;
        fuzz/* | probes/* | vendor/* | target/*) return 0 ;;
    esac
    return 1
}

# Tracked AND new-untracked sources: the gate must see the tree as it is, not only what
# has already been committed (a second axis introduced in an uncommitted file is still a
# second axis, and batch work always starts uncommitted).
mapfile -t sources < <(git ls-files --cached --others --exclude-standard -- '*.rs')

# The single file allowed to carry chain cfgs outside forms/ — registered with the structural
# conditions in the header, never as a blanket allowlist entry.
REGISTERED_SHIM="flux/forgebox/staticlib/src/lib.rs"
declare -a violations=()
forms_hits=0
shim_hits=0
declare -a per_dir=()

for f in "${sources[@]}"; do
    out_of_scope "$f" && continue
    [ -f "$f" ] || continue
    hits=$(grep -cE "$PATTERN" "$f" 2>/dev/null) || hits=0
    [ "$hits" -eq 0 ] && continue
    case "$f" in
        forms/*) forms_hits=$((forms_hits + hits)) ;;
        "$REGISTERED_SHIM") shim_hits=$hits ;;
        *) violations+=("$f ($hits hit(s))") ;;
    esac
done

# ── the one registered exception, held to structural conditions (see header) ──────────────
if [ "${shim_hits:-0}" -gt 0 ]; then
    note "== registered second axis: $REGISTERED_SHIM ($shim_hits chain cfg hit(s))"
    marker='// ── C-ABI keep-table (generated by scripts/gen_ffi_keep.py) ──'
    if ! grep -qF "$marker" "$REGISTERED_SHIM" 2>/dev/null; then
        violations+=("$REGISTERED_SHIM: chain cfgs but no keep-table marker (cannot be table gating)")
    else
        # (a) every chain cfg must sit inside the generated block
        before=$(sed -n "1,/$(printf '%s' "$marker" | sed 's/[][\.*^$/]/\\&/g')/p" "$REGISTERED_SHIM" \
                 | grep -cE "$PATTERN" || true)
        if [ "${before:-0}" -ne 0 ]; then
            violations+=("$REGISTERED_SHIM: $before chain cfg(s) OUTSIDE the keep-table block — that is semantic gating, not table gating")
        fi
        # (d) cfg count == gated entry count the generator produces for the all-on set
        gated=$(python3 scripts/gen_ffi_keep.py --features se,chain-btc,chain-eth,chain-xmr --out /dev/stdout \
                | grep -cE "$PATTERN" || true)
        if [ "${gated:-0}" -ne "$shim_hits" ]; then
            violations+=("$REGISTERED_SHIM: $shim_hits chain cfg(s) but the generator emits $gated gated entry point(s) — the table drifted from its generator")
        fi
        note "   inside the keep-table block only; $shim_hits cfg(s) == $gated generated gated entr(ies)"
    fi
    # (b) + (c) the forwarding features and the product face
    shim_manifest="$(dirname "$REGISTERED_SHIM")/../Cargo.toml"
    for chain in btc eth xmr; do
        # The requirement is that this feature forwards to the CORE crate's chain feature, not
        # that the list holds nothing else: a shim may need to forward the same axis to another
        # workspace member (flux/keysource also consumes `shlosilo` and must follow the same set,
        # otherwise its QR key path silently degrades to "not implemented" instead of tracking the
        # carrier's chains). Anchored so the core forwarding cannot be dropped.
        if ! grep -qE "^chain-$chain *= *\[.*\"shlosilo/chain-$chain\"" "$shim_manifest"; then
            violations+=("$shim_manifest: feature chain-$chain does not forward to shlosilo/chain-$chain")
        fi
        if ! grep -qE '^default *= *\[' "$shim_manifest" \
                || ! sed -n '/^default *=/,/]/p' "$shim_manifest" | grep -q "chain-$chain"; then
            violations+=("$shim_manifest: default does not enable chain-$chain (the product face would change)")
        fi
    done
    note "   forwarding features + default chain set verified in $shim_manifest"
fi

note "== chain-axis conditionals found in shipping sources (test/example faces excluded)"
# Where the axis lives today: a per-directory count, so a drift inside forms/ is visible
# in the gate log without opening the tree.
while IFS= read -r line; do
    note "   $line"
done < <(grep -rlE "$PATTERN" --include='*.rs' forms 2>/dev/null |
    awk -F/ '{d=$1"/"$2; n[d]++} END {for (k in n) print k" -> "n[k]" file(s)"}' | sort)

if [ "${#violations[@]}" -ne 0 ]; then
    note ""
    note "FAIL: cfg(feature = \"chain-…\") outside forms/ — a second chain axis appeared:"
    for v in "${violations[@]}"; do note "   $v"; done
    note ""
    note "   Do NOT widen the allowlist. Bring that crate into the consistency check (its own"
    note "   SHLOSILO_CHAINS vs CARGO_FEATURE_CHAIN_* cross-check) and name it in the matrix;"
    note "   see the TRIGGER CONDITION in this script's header."
    note "CHAINAXIS_SCOPE: RED"
    exit 1
fi

if [ "$forms_hits" -lt "$MIN_FORMS_HITS" ]; then
    note ""
    note "FAIL: instrument blind — only $forms_hits chain-axis conditional(s) found in forms/,"
    note "      expected at least $MIN_FORMS_HITS (batch 1 gated ~240 sites). Either the"
    note "      scan pattern or the source tree is wrong; a clean result here would be vacuous."
    note "CHAINAXIS_SCOPE: RED"
    exit 1
fi

note "   forms/ total: $forms_hits conditional(s) (min $MIN_FORMS_HITS); outside forms/: none except the registered keep-table in $REGISTERED_SHIM"
note "CHAINAXIS_SCOPE: OK (semantic chain axis lives in forms/ only; the shim carries table"
note "                  gating inside its generated keep-table block, with forwarding features pinned)"
