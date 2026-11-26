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

declare -a violations=()
forms_hits=0
declare -a per_dir=()

for f in "${sources[@]}"; do
    out_of_scope "$f" && continue
    [ -f "$f" ] || continue
    hits=$(grep -cE "$PATTERN" "$f" 2>/dev/null) || hits=0
    [ "$hits" -eq 0 ] && continue
    case "$f" in
        forms/*) forms_hits=$((forms_hits + hits)) ;;
        *) violations+=("$f ($hits hit(s))") ;;
    esac
done

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

note "   forms/ total: $forms_hits conditional(s); no hits outside forms/ (min $MIN_FORMS_HITS)"
note "CHAINAXIS_SCOPE: OK (the chain axis lives in forms/ only — one cross-check covers the product)"
