#!/usr/bin/env bash
# =============================================================================
# build_declared.sh — build through a DECLARED build manifest (chain axis §9.3-ter)
#
#   scripts/build_declared.sh <manifest> [--receipt <path> | --receipt-dry-run] \
#                            [-- <cargo subcommand and its arguments>]
#
# Examples:
#   bash scripts/build_declared.sh builds/host-all.toml -- check -p shlosilo
#   bash scripts/build_declared.sh builds/pico2-btc.toml \
#        -- check -p shlosilo --target thumbv8m.main-none-eabihf
#   bash scripts/build_declared.sh builds/pico2-btc.toml --receipt out/receipt.txt \
#        -- build -p shlosilo --release --target thumbv8m.main-none-eabihf
#
# WHAT IT DOES
#   1. reads the manifest (`builds/<name>.toml`: limits / target / role / [chains]) and
#      exports the declaration into the build environment:
#        SHLOSILO_LIMITS=<limits>            (a NAME — limits files are referenced, never copied)
#        SHLOSILO_CHAINS=<btc,eth,xmr subset> (canonical order)
#        SHLOSILO_BUILD_ROLE=<role>
#        SHLOSILO_BUILD_MANIFEST{,_SHA256}    (receipt breadcrumbs; not fingerprint inputs)
#   2. projects the chain set onto cargo features: ALWAYS `--no-default-features`
#      (this crate's `default` carries all three chains, so keeping it would re-add every
#      chain a manifest switched off) plus an explicit `--features` list. The base half of
#      that list follows the target, not the manifest: `std,alloc-fallback` on a host
#      target, nothing on `*-none-eabi*` (std cannot be enabled there).
#      (additive; any `--features` the caller passed is UNIONED in, never replaced, so a
#      caller cannot accidentally drop a declared chain — and cannot sneak an undeclared
#      one past the check either, see 3).
#   3. runs cargo. `build.rs` then compares the DECLARED set with the feature set cargo
#      actually resolved and refuses a mismatch in either direction.
#
# WHY THE CHECK IS NOT HERE
#   This script cannot see feature unification: if a transitive dependency turns a chain
#   on, the wrapper's command line still looks exactly as written. `build.rs` reads
#   `CARGO_FEATURE_CHAIN_*` — the post-unification truth for the core crate — so the
#   refusal lives there. This script only declares.
#   (`--all-features` is therefore not accepted in the cargo arguments: it would enable
#   every chain, which a manifest declaring a subset can never match, and cargo rejects it
#   alongside `--features` anyway.)
#
# ROLE (L3): purpose and receipt rights, never strictness.
#   delivery     may produce a receipt; REQUIRES a clean working tree (L4: `HEAD ≠ source`,
#                so a delivery build from uncommitted sources is refused, not footnoted).
#   development  the everyday dev build — no receipt.
#   test         gate/matrix faces — no receipt.
#   benchmark    measurement faces — no receipt.
#   A build with no manifest at all (bare `cargo build`) is the only unchecked face, and
#   it produces no receipt either: "BTC-only firmware" must never be a claim nobody
#   declared.
#
# THE RECEIPT (L6) records: manifest name + content digest, limits profile, the ACTUAL
#   chain set (read back from `build.rs`, never re-derived here), BUILD_FINGERPRINT
#   (full SHA-256 + the 64-bit projection), the FNV limits tripwire, the version string
#   the device shows, HEAD, tree state, the cargo command line, and the sha256 of every
#   artifact the build produced.
#   It is an ENGINEERING CONSISTENCY record: it says "this receipt, that manifest, these
#   chains and this binary were one build". It is NOT an attestation — it carries no
#   signature and proves nothing about provenance to a third party. Do not present it as
#   one.
#
# `--receipt-dry-run` prints the receipt body with a loud banner and writes NO file: it
#   exists so the rendering path is testable before a clean tree (and therefore a real
#   delivery receipt) is available.
# =============================================================================
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 99

usage() {
    sed -n '3,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-2}"
}

[ $# -ge 1 ] || usage 2
MANIFEST="$1"
shift

RECEIPT=""
DRY_RUN=0
while [ $# -gt 0 ]; do
    case "$1" in
        --receipt)
            [ $# -ge 2 ] || { echo "ERROR: --receipt needs a path" >&2; exit 2; }
            RECEIPT="$2"; shift 2 ;;
        --receipt-dry-run)
            DRY_RUN=1; shift ;;
        --)
            shift; break ;;
        -h|--help)
            usage 0 ;;
        *)
            echo "ERROR: unexpected argument before '--': $1" >&2
            usage 2 ;;
    esac
done
CARGO_ARGV=("$@")
[ "${#CARGO_ARGV[@]}" -gt 0 ] || {
    echo "ERROR: no cargo command line given (usage: ... -- <cargo subcommand> [args])" >&2
    usage 2
}
[ -f "$MANIFEST" ] || { echo "ERROR: manifest not found: $MANIFEST" >&2; exit 2; }

# ── 1. parse the manifest ────────────────────────────────────────────────────
# python3/tomllib rather than a bash parser: a manifest is a declaration, and a
# declaration that is silently mis-parsed is worse than no declaration (same reason
# scripts/check_ffi_decls.py parses instead of greps).
MANIFEST_FIELDS="$(python3 - "$MANIFEST" <<'PY'
import sys, tomllib

path = sys.argv[1]
with open(path, "rb") as fh:
    doc = tomllib.load(fh)

KNOWN = {"limits", "target", "role", "chains"}
unknown = sorted(set(doc) - KNOWN)
if unknown:
    sys.exit(f"{path}: unknown manifest keys {unknown} (schema: {sorted(KNOWN)})")

limits = doc.get("limits")
if not isinstance(limits, str) or not limits:
    sys.exit(f"{path}: `limits` is required and must name a profile in limits/<name>.toml")
role = doc.get("role")
if not isinstance(role, str) or not role:
    sys.exit(f"{path}: `role` is required (delivery | development | test | benchmark)")
target = doc.get("target", "")
if not isinstance(target, str):
    sys.exit(f"{path}: `target` must be a string (omit it for the host triple)")

chains = doc.get("chains")
if not isinstance(chains, dict):
    sys.exit(f"{path}: a [chains] table is required (btc/eth/xmr = true/false)")
unknown = sorted(set(chains) - {"btc", "eth", "xmr"})
if unknown:
    sys.exit(f"{path}: unknown [chains] keys {unknown} (schema: ['btc', 'eth', 'xmr'])")
on = []
for name in ("btc", "eth", "xmr"):
    value = chains.get(name)
    if not isinstance(value, bool):
        sys.exit(f"{path}: [chains] {name} must be true or false (got {value!r})")
    if value:
        on.append(name)
if not on:
    sys.exit(f"{path}: [chains] enables nothing — a manifest declares at least one chain")

print(f"LIMITS={limits}")
print(f"ROLE={role}")
print(f"TARGET={target}")
print(f"CHAINS={','.join(on)}")
PY
)" || { echo "ERROR: cannot parse $MANIFEST" >&2; exit 2; }

LIMITS="$(printf '%s\n' "$MANIFEST_FIELDS" | sed -n 's/^LIMITS=//p')"
ROLE="$(printf '%s\n' "$MANIFEST_FIELDS" | sed -n 's/^ROLE=//p')"
MF_TARGET="$(printf '%s\n' "$MANIFEST_FIELDS" | sed -n 's/^TARGET=//p')"
CHAINS="$(printf '%s\n' "$MANIFEST_FIELDS" | sed -n 's/^CHAINS=//p')"

case "$ROLE" in
    delivery|development|test|benchmark) ;;
    *) echo "ERROR: $MANIFEST: unknown role '$ROLE' (delivery | development | test | benchmark)" >&2; exit 2 ;;
esac
# A profile NAME is interpolated into a path by build.rs; keep it to a shape that
# cannot leave limits/ (build.rs whitelists the names as well — belt and braces).
case "$LIMITS" in
    *[!a-z0-9-]*|"") echo "ERROR: $MANIFEST: illegal limits profile name '$LIMITS'" >&2; exit 2 ;;
esac
[ -f "limits/$LIMITS.toml" ] || { echo "ERROR: $MANIFEST: no such limits profile: limits/$LIMITS.toml" >&2; exit 2; }

MANIFEST_NAME="$(basename "$MANIFEST" .toml)"

# ── 2. locate the cargo subcommand (token order is the caller's business) ────
# `... -- -p shlosilo --target X check` is the shape people write, and cargo itself
# wants the subcommand first. Pull the first recognised subcommand to the front
# instead of rejecting the line: a wrapper that refuses a correct intent teaches
# people to bypass it.
SUBCOMMANDS="check build clippy test run doc rustc bench fix"
SUB_INDEX=-1
for i in "${!CARGO_ARGV[@]}"; do
    for sub in $SUBCOMMANDS; do
        if [ "${CARGO_ARGV[$i]}" = "$sub" ]; then SUB_INDEX=$i; break 2; fi
    done
done
if [ "$SUB_INDEX" -lt 0 ]; then
    echo "ERROR: no cargo subcommand found in: ${CARGO_ARGV[*]}" >&2
    echo "       (expected one of: $SUBCOMMANDS)" >&2
    exit 2
fi
SUBCOMMAND="${CARGO_ARGV[$SUB_INDEX]}"
PASSTHRU=()
for i in "${!CARGO_ARGV[@]}"; do
    [ "$i" -eq "$SUB_INDEX" ] && continue
    PASSTHRU+=("${CARGO_ARGV[$i]}")
done

# ── 3. caller-supplied target must agree with the declaration ────────────────
CALLER_TARGET=""
for i in "${!PASSTHRU[@]}"; do
    case "${PASSTHRU[$i]}" in
        --target) CALLER_TARGET="${PASSTHRU[$((i + 1))]:-}" ;;
        --target=*) CALLER_TARGET="${PASSTHRU[$i]#--target=}" ;;
    esac
done
if [ -n "$CALLER_TARGET" ] && [ -n "$MF_TARGET" ] && [ "$CALLER_TARGET" != "$MF_TARGET" ]; then
    echo "ERROR: $MANIFEST declares target '$MF_TARGET' but the build asks for '$CALLER_TARGET'." >&2
    echo "       The manifest is the declaration a receipt would name; fix one of them." >&2
    exit 2
fi
EFFECTIVE_TARGET="${CALLER_TARGET:-$MF_TARGET}"
TARGET_ARGS=()
if [ -n "$MF_TARGET" ] && [ -z "$CALLER_TARGET" ]; then
    TARGET_ARGS=(--target "$MF_TARGET")
fi

# ── 4. feature projection: base + declared chains + whatever the caller added ─
# Caller features are UNIONED (never replaced) and removed from the passthrough so
# exactly one --features flag reaches cargo. `--features=...` and `--features ...`
# are the same flag; both are absorbed here.
CALLER_FEATURES=""
NEW_PASSTHRU=()
i=0
while [ "$i" -lt "${#PASSTHRU[@]}" ]; do
    arg="${PASSTHRU[$i]}"
    case "$arg" in
        --features)
            CALLER_FEATURES="${CALLER_FEATURES:+$CALLER_FEATURES,}${PASSTHRU[$((i + 1))]:-}"
            i=$((i + 2)); continue ;;
        --features=*)
            CALLER_FEATURES="${CALLER_FEATURES:+$CALLER_FEATURES,}${arg#--features=}"
            i=$((i + 1)); continue ;;
        -F)
            CALLER_FEATURES="${CALLER_FEATURES:+$CALLER_FEATURES,}${PASSTHRU[$((i + 1))]:-}"
            i=$((i + 2)); continue ;;
        -F*)
            CALLER_FEATURES="${CALLER_FEATURES:+$CALLER_FEATURES,}${arg#-F}"
            i=$((i + 1)); continue ;;
    esac
    NEW_PASSTHRU+=("$arg")
    i=$((i + 1))
done
PASSTHRU=("${NEW_PASSTHRU[@]}")

CHAIN_FEATURES=""
for c in ${CHAINS//,/ }; do CHAIN_FEATURES="${CHAIN_FEATURES:+$CHAIN_FEATURES,}chain-$c"; done
# The base feature set follows the TARGET, not the manifest: `std` cannot be enabled on a
# bare-metal target (it pulls `rand_core/std`, i.e. the std crate itself), while a host
# build wants std + the alloc-fallback generator path. This mirrors what the carriers and
# the embedded gate steps already do by hand (`--no-default-features --features chain-*`
# for thumb*, `std,alloc-fallback` for host), so a manifest never has to spell it out.
# `--no-default-features` is ALWAYS passed: this crate's `default` carries all three
# `chain-*` features, so leaving it on would silently re-add every chain the manifest
# switched off and the declaration would be a decoration. The wrapper names the whole
# feature set explicitly instead - that is the point of a manifest.
case "${EFFECTIVE_TARGET:-host}" in
    *none-eabi*)
        BASE_FEATURES=""
        BASE_NOTE="bare-metal target: no std (== --no-default-features)" ;;
    *)
        BASE_FEATURES="std,alloc-fallback"
        BASE_NOTE="std,alloc-fallback (== --no-default-features)" ;;
esac
BASE_FLAGS=(--no-default-features)
FEATURES="${BASE_FEATURES:+$BASE_FEATURES,}$CHAIN_FEATURES"
if [ -n "$CALLER_FEATURES" ]; then
    FEATURES="$FEATURES,$CALLER_FEATURES"
fi
# Normalise: split on commas AND whitespace (cargo accepts both as separators), drop
# empties and duplicates, keep first-appearance order. A malformed list reaching cargo
# would be a usage error at best and a silently different feature set at worst.
FEATURES="$(printf '%s' "$FEATURES" | tr ',[:space:]' '\n\n' | awk 'NF && !seen[$0]++' | paste -sd, -)"
[ -n "$FEATURES" ] || { echo "ERROR: projected an empty feature list" >&2; exit 2; }

# ── 5. delivery: a clean tree, or nothing ────────────────────────────────────
if [ "$ROLE" = "delivery" ]; then
    DIRTY="$(git status --porcelain 2>/dev/null)"
    if [ -n "$DIRTY" ]; then
        echo "ERROR: role=delivery refuses a dirty working tree (L4)." >&2
        echo "       HEAD would not be the source that was built, so any receipt would name" >&2
        echo "       a commit that does not describe this binary. git sees:" >&2
        printf '%s\n' "$DIRTY" | sed 's/^/         /' >&2
        echo "       Commit or stash, or build a manifest whose role is test/development" >&2
        echo "       (those never produce a receipt)." >&2
        exit 3
    fi
fi
if [ -n "$RECEIPT" ] && [ "$ROLE" != "delivery" ]; then
    echo "ERROR: --receipt needs role=delivery in $MANIFEST (L3/L6: only a delivery build" >&2
    echo "       may produce a receipt; a test/development receipt would be a claim nobody" >&2
    echo "       stands behind). Use --receipt-dry-run to render it without writing." >&2
    exit 2
fi

# ── 6. declare, then build ───────────────────────────────────────────────────
MANIFEST_SHA="$(sha256sum "$MANIFEST" | awk '{print $1}')"
export SHLOSILO_LIMITS="$LIMITS"
export SHLOSILO_CHAINS="$CHAINS"
export SHLOSILO_BUILD_ROLE="$ROLE"
export SHLOSILO_BUILD_MANIFEST="$MANIFEST"
export SHLOSILO_BUILD_MANIFEST_SHA256="$MANIFEST_SHA"

CMD=(cargo "$SUBCOMMAND" ${PASSTHRU[@]+"${PASSTHRU[@]}"} ${TARGET_ARGS[@]+"${TARGET_ARGS[@]}"} \
    ${BASE_FLAGS[@]+"${BASE_FLAGS[@]}"} --features "$FEATURES")

echo "== declared build: $MANIFEST"
echo "   limits=$LIMITS  chains=$CHAINS  role=$ROLE  target=${EFFECTIVE_TARGET:-<host>}"
echo "   base features: $BASE_NOTE"
echo "   ${CMD[*]}"

WANT_RECEIPT=0
[ -n "$RECEIPT" ] && WANT_RECEIPT=1
JSON_LOG=""
if [ "$WANT_RECEIPT" -eq 1 ] || [ "$DRY_RUN" -eq 1 ]; then
    # Only the receipt path needs cargo's JSON stream (build-script OUT_DIR + artifact
    # paths). Normal builds stay human-readable.
    JSON_LOG="$(mktemp /tmp/build_declared.XXXXXX.json)"
    trap 'rm -f "$JSON_LOG"' EXIT
    CMD+=(--message-format=json-render-diagnostics)
fi

if [ -n "$JSON_LOG" ]; then
    # stdout is cargo's JSON stream (kept for OUT_DIR/artifacts); stderr stays the
    # caller's terminal, where cargo renders the diagnostics *and* a build script's
    # failure text - which is what a chain-set mismatch must be readable in.
    "${CMD[@]}" | tee "$JSON_LOG"
    RC=${PIPESTATUS[0]}
else
    "${CMD[@]}"
    RC=$?
fi

if [ "$RC" -ne 0 ]; then
    echo "== declared build FAILED (cargo exit $RC)" >&2
    exit "$RC"
fi
if [ "$WANT_RECEIPT" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    echo "== declared build OK (declared == compiled chains verified by build.rs)"
    exit 0
fi

# ── 7. receipt (identity values are READ BACK from build.rs, not re-derived) ──
OUT_DIR="$(python3 scripts/cargo_msg.py out-dir "$JSON_LOG" 2>/dev/null)"
IDENTITY=""
if [ -n "$OUT_DIR" ] && [ -f "$OUT_DIR/build_identity.txt" ]; then
    IDENTITY="$OUT_DIR/build_identity.txt"
else
    echo "ERROR: cannot find the build identity (build_identity.txt) for this build." >&2
    echo "       The receipt must quote what the library carries, not a second derivation." >&2
    exit 4
fi
field() { sed -n "s/^$1=//p" "$IDENTITY" | head -1; }

BUILT_CHAINS="$(field chains)"
if [ "$BUILT_CHAINS" != "$CHAINS" ]; then
    # build.rs already refuses this; re-checking here is what makes the receipt's own
    # "chains_declared / chains_built" pair impossible to fake.
    echo "ERROR: declared chains '$CHAINS' != chains in the built library '$BUILT_CHAINS'" >&2
    exit 5
fi

RECEIPT_BODY="$(mktemp /tmp/build_declared.XXXXXX.receipt)"
trap 'rm -f "$RECEIPT_BODY"; [ -n "${JSON_LOG:-}" ] && rm -f "$JSON_LOG"' EXIT
{
    echo "shlosilo build receipt"
    echo "======================"
    echo "WHAT THIS IS   Engineering consistency record: this manifest, this declared chain"
    echo "               set, this BUILD_FINGERPRINT and these binaries were one build."
    echo "               It is NOT an attestation - no signature, no third-party provenance"
    echo "               claim (chain axis note, L6)."
    echo "manifest       $MANIFEST"
    echo "manifest_sha256 $MANIFEST_SHA"
    echo "limits_profile $LIMITS"
    echo "role           $ROLE"
    echo "target         ${EFFECTIVE_TARGET:-<host>}"
    echo "chains_declared $CHAINS"
    echo "chains_built   $BUILT_CHAINS"
    echo "build_fingerprint_sha256 $(field build_fingerprint_sha256)"
    echo "build_fingerprint_u64    $(field build_fingerprint_u64)"
    echo "limits_fingerprint       $(field limits_fingerprint)  (FNV tripwire, not an identity)"
    echo "version_string $(field version_string)"
    echo "git_head       $(field git_head)"
    echo "tree_state     $(field tree_state)"
    echo "cargo          ${CMD[*]}"
    echo "artifacts"
    ARTS="$(python3 scripts/cargo_msg.py artifacts "$JSON_LOG" 2>/dev/null)"
    if [ -n "$ARTS" ]; then
        while IFS= read -r art; do
            [ -n "$art" ] || continue
            printf '  %s  %s\n' "$(sha256sum "$art" | awk '{print $1}')" "$art"
        done <<< "$ARTS"
    else
        echo "  (none: 'cargo $SUBCOMMAND' produced no artifact file — a receipt for a"
        echo "   type-check surface records the identity, not a binary)"
    fi
} > "$RECEIPT_BODY"

if [ "$DRY_RUN" -eq 1 ]; then
    echo ""
    echo "########## RECEIPT DRY RUN — NOT A DELIVERY RECEIPT, NOTHING WRITTEN ##########"
    cat "$RECEIPT_BODY"
    echo "##############################################################################"
    exit 0
fi

mkdir -p "$(dirname "$RECEIPT")"
cp "$RECEIPT_BODY" "$RECEIPT"
echo "== declared build OK; receipt -> $RECEIPT"
