#!/usr/bin/env bash
# =============================================================================
# Chain axis matrix (design note 「链轴积木化」 §9.3-2 / §9.4; batch 2 = manifests)
#
# What this gate proves, in order:
#
# 1. COMBINATION MATRIX — the 3 single-chain, 3 double-chain and 1 all-on builds
#    each compile on the host face. Since batch 2 they are built through
#    `scripts/build_declared.sh`, i.e. through a real BUILD MANIFEST:
#        builds/<tmp>/<combo>.toml  (limits = host, role = test, chains = combo)
#    The manifests are generated in a TEMP DIRECTORY and never touch the tree — no
#    `limits/*.toml` is created, copied or generated any more (L1: a limits profile
#    carries resource ceilings only, and one profile per chain subset would duplicate
#    every number in it).
#
# 2. DECLARATION CHECK — the wrapper exports SHLOSILO_CHAINS from each manifest and
#    `build.rs` requires STRICT equality with the feature set cargo actually resolved.
#    So every row of the matrix is simultaneously a test that a truthful manifest
#    builds, which is the property the delivery face depends on.
#
# 3. NEGATIVE TEST (L2, §9.3-quater) — a manifest that declares btc-only while the
#    build is given `chain-eth` extra MUST FAIL, and the failure must name the set
#    difference. Without this the strict check is only ever exercised on inputs that
#    agree with it, i.e. it is untested where it matters.
#
# 4. DOUBLE-EDGED SYMBOL CRITERION (§9.4, the FORGEBOXSEISO lesson) — for every
#    combination, each DISABLED chain must own ZERO symbols in the rlib, and each
#    ENABLED chain's sampled symbols must be PRESENT in the same rlib. The second
#    half is what makes the first half mean something: a grep that cannot see a
#    symbol cannot distinguish "compiled out" from "instrument broken / rlib stale /
#    wrong artifact".
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
# 5. SIZE ACCOUNT (§9.4) — each combination's `size` text total is printed with
#    its delta against the all-on build, and since batch 3 the DEPENDENCY account
#    next to it (`cargo tree` node count + the XMR-exclusive crates' presence) means
#    a delta can be read correctly: batch 1/2 could only compile code out (every
#    chain crate stayed linked, so a text delta measured the switch's own effect),
#    batch 3 makes the XMR-exclusive dependencies real optional dependencies carried
#    by `chain-xmr`, so a chain-off build now also drops their nodes.
#
# 6. DEPENDENCY ACCOUNT (batch 3, L7 lifted) — for every combination the resolved
#    graph (normal + build edges; dev-dependencies are deliberately excluded, they
#    never reach a product graph) is counted and the XMR-exclusive crates are looked
#    for. Both directions are asserted: a combo WITHOUT xmr must show zero of them
#    (the graph followed the declaration), and the ALL-ON combo must show all of them
#    (the instrument can see what it claims is absent). A count alone cannot
#    distinguish "graph sliced" from "instrument blind", so the second half is what
#    makes the first half mean anything.
#
# Usage: bash scripts/check_chain_axes.sh
#   CARGO_FLAGS=--locked ...  forwarded to cargo (CI), default --offline.
# =============================================================================
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

COMBOS=(btc eth xmr btc,eth btc,xmr eth,xmr btc,eth,xmr)
LIMITS_PROFILE="host"
BUILD_ROLE="test"
# Same flags on both faces: the local batch must not touch the network (--offline),
# CI wants the reviewed lockfile pinned (--locked). Caller decides, as with
# scripts/test_zero_on_alloc.sh.
CARGO_FLAGS="${CARGO_FLAGS:---offline}"
TMP_DIR="$(mktemp -d /tmp/chainaxes.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

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

# Crates that exist ONLY for the XMR chain (batch 3 made them optional deps carried
# by `chain-xmr`). One regex, used by BOTH halves of the dependency criterion.
#   - monero-* / cuprate-cryptonight / std-shims: the CLSAG + Bulletproofs+ stack and
#     the monero-oxide alloc/io shims under it;
#   - chacha20 (the XMR wire cipher) and hkdf (the XMR purpose-subdomain RNG).
# Deliberately absent: curve25519-dalek, ed25519-dalek and base58-monero. They look
# XMR-shaped but are reached from UNGATED code (the Ed25519 Layer-A primitive that
# SOL/Cardano/slip10/edDSA share, and the export-protocol face), so gating them would
# move a capability axis rather than this one. See the Cargo.toml feature note.
XMR_ONLY_RE='(monero-clsag|monero-bulletproofs|monero-bulletproofs-generators|monero-ed25519|monero-io|cuprate-cryptonight|std-shims|chacha20|hkdf) v'
# Crates owned by the PRIMITIVE axis (S9): they must vanish when the primitive that owns them
# is off, and must be present when it is on. Same double-edged argument as above — a count alone
# cannot tell "dependency cut" from "instrument blind", and after S9 the btc-only face is the
# first build in this repository that genuinely drops them.
PRIM_ED25519_RE='(ed25519-dalek|curve25519-dalek) v'
PRIM_B58_MONERO_RE='base58-monero v'

# Positional count of the resolved graph: `cargo tree -e normal,build` lists one line
# per node (build-dependencies are indented under an explicit marker line, which the
# `^[^ ]` filter excludes, so the count is crate nodes, not lines).
dep_feature_list() {
    # Base features mirror `scripts/build_declared.sh`'s rule for a host target
    # (`std,alloc-fallback`); the chain half is the combination under test.
    local feats="std,alloc-fallback" chain
    for chain in btc eth xmr; do
        case ",$1," in
            *",$chain,"*) feats="$feats,chain-$chain" ;;
        esac
    done
    printf '%s' "$feats"
}

dep_account() {
    local combo="$1" feats tree_out nodes hits
    feats="$(dep_feature_list "$combo")"
    tree_out="$(cargo tree -e normal,build -p shlosilo $CARGO_FLAGS \
        --no-default-features --features "$feats" 2>/dev/null)" || { printf 'ERR'; return; }
    nodes=$(printf '%s\n' "$tree_out" | grep -cE '^[^ ]')
    hits=$(printf '%s\n' "$tree_out" | grep -cE "$XMR_ONLY_RE")
    ed25519=$(printf '%s\n' "$tree_out" | grep -cE "$PRIM_ED25519_RE" || true)
    b58monero=$(printf '%s\n' "$tree_out" | grep -cE "$PRIM_B58_MONERO_RE" || true)
    printf '%s|%s|%s|%s' "$nodes" "$hits" "$ed25519" "$b58monero"
}

# Write a manifest for one combination: limits referenced BY NAME, chains explicitly
# declared, role = test (this face never produces a receipt). Lives in $TMP_DIR only.
write_manifest() {
    local combo="$1" path="$TMP_DIR/chainaxes-${1//,/-}.toml"
    {
        printf '# @generated by scripts/check_chain_axes.sh — never committed, never in-tree.\n'
        printf '# The matrix builds a DECLARED chain subset against unchanged resource\n'
        printf '# ceilings: limits profiles carry no chain set (batch 2 / L1).\n'
        printf 'limits = "%s"\n' "$LIMITS_PROFILE"
        printf 'role = "%s"\n' "$BUILD_ROLE"
        printf '\n[chains]\n'
        for chain in btc eth xmr; do
            case ",$combo," in
                *",$chain,"*) printf '%s = true\n' "$chain" ;;
                *) printf '%s = false\n' "$chain" ;;
            esac
        done
    } > "$path"
    printf '%s' "$path"
}

# The rlib cargo just produced for the current declaration (the artifact list is keyed
# by feature set, so this names exactly the unit under test). Built through the wrapper
# too: the symbol/size evidence must come from the same declared build the check ran in,
# otherwise the matrix could certify an rlib nobody declared.
rlib_of() {
    local manifest="$1" log="$TMP_DIR/rlib.json"
    bash scripts/build_declared.sh "$manifest" -- $CARGO_FLAGS --message-format=json \
        build --lib -p shlosilo | tee "$log" >/dev/null
    python3 - "$log" <<'PY'
import json, sys
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line.startswith("{"):
        continue
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
PY
}

index=0
for combo in "${COMBOS[@]}"; do
    index=$((index + 1))
    manifest="$(write_manifest "$combo")"
    [ -f "$manifest" ] || { bad "$combo: manifest generation"; continue; }

    note ""
    note "== [$index/${#COMBOS[@]}] chains declared: $combo  (manifest $manifest)"

    # 1. compile matrix through the declared wrapper (the assertion §9.4 names)
    if bash scripts/build_declared.sh "$manifest" -- $CARGO_FLAGS check -p shlosilo \
        > "$TMP_DIR/check-$index.log" 2>&1; then
        note "   check: exit 0 (declared == compiled)"
    else
        bad "$combo: declared check failed (log: $TMP_DIR/check-$index.log)"
        tail -25 "$TMP_DIR/check-$index.log" | sed 's/^/      /'
        continue
    fi

    # 2. object code for the symbol + size assertions
    # The artifact cargo reports is the UPLIFTED `target/debug/libshlosilo.rlib`, which the
    # next combination overwrites. Take a private copy per combination so the evidence this
    # row prints belongs to THIS feature set and cannot be re-read from a later build.
    built_rlib="$(rlib_of "$manifest" 2> "$TMP_DIR/rlib-$index.log" | tail -1)"
    if [ -z "$built_rlib" ] || [ ! -f "$built_rlib" ]; then
        bad "$combo: no rlib artifact found (log: $TMP_DIR/rlib-$index.log)"
        tail -10 "$TMP_DIR/rlib-$index.log" | sed 's/^/      /'
        continue
    fi
    rlib="$TMP_DIR/libshlosilo-chains-${combo//,/-}.rlib"
    cp "$built_rlib" "$rlib" || { bad "$combo: cannot copy the rlib artifact"; continue; }
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

    # 4b. dependency account (batch 3) — see header note 6. Printed for every row and
    # asserted in both directions: a disabled chain must contribute no nodes, and the
    # all-on build must still show them (otherwise "absent" and "invisible" look alike).
    dep="$(dep_account "$combo")"
    IFS='|' read -r dep_nodes dep_xmr dep_ed dep_b58 <<< "$dep"
    case ",$combo," in
        *",xmr,"*)
            if [ "${dep_xmr:-0}" -eq 0 ]; then
                bad "$combo: chain-xmr is ON but zero XMR-exclusive crates resolved (instrument blind, or the graph regressed)"
            else
                note "   deps: ${dep_nodes:-?} nodes, ${dep_xmr} XMR-exclusive (chain on: expected > 0)"
            fi
            ;;
        *)
            if [ "${dep_xmr:-0}" -ne 0 ]; then
                bad "$combo: chain-xmr is OFF but ${dep_xmr} XMR-exclusive crate node(s) are still resolved"
            else
                note "   deps: ${dep_nodes:-?} nodes, 0 XMR-exclusive (graph sliced with the declaration)"
            fi
            ;;
    esac
    printf '%s\n' "$combo|${dep_nodes:-?}|${dep_xmr:-?}|${dep_ed:-?}|${dep_b58:-?}" >> "$TMP_DIR/deps.txt"
done

# ── 5. NEGATIVE TEST (L2) ───────────────────────────────────────────────────
# A manifest that declares btc-only, built with an extra chain-eth feature, MUST be
# refused by build.rs - and the refusal has to name both sets, because "the build
# failed" is not the property being pinned: "it failed for THIS reason" is.
note ""
note "== negative test: declared btc-only, build asked for chain-btc,chain-eth"
neg_manifest="$TMP_DIR/negative-btc-only.toml"
{
    printf '# @generated by scripts/check_chain_axes.sh — negative test fixture.\n'
    printf 'limits = "%s"\n' "$LIMITS_PROFILE"
    printf 'role = "%s"\n\n' "$BUILD_ROLE"
    printf '[chains]\nbtc = true\neth = false\nxmr = false\n'
} > "$neg_manifest"
neg_log="$TMP_DIR/negative.log"
if bash scripts/build_declared.sh "$neg_manifest" -- $CARGO_FLAGS check -p shlosilo \
    --features chain-btc,chain-eth > "$neg_log" 2>&1; then
    bad "negative test: an undeclared chain was accepted (declared btc, built btc+eth)"
    tail -20 "$neg_log" | sed 's/^/      /'
else
    if grep -q "declared chains = \[btc\]" "$neg_log" \
        && grep -q "compiled chains = \[btc,eth\]" "$neg_log"; then
        note "   refused with the set difference:"
        grep -E "declared chains =|compiled chains =" "$neg_log" | sed 's/^/      /'
    else
        bad "negative test: build failed, but not with the declared/compiled set difference"
        tail -25 "$neg_log" | sed 's/^/      /'
    fi
fi

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
note "== dependency account (resolved graph nodes: normal + build edges, dev excluded)"
if [ -f "$TMP_DIR/deps.txt" ]; then
    while IFS='|' read -r combo nodes xmr ed25519 b58; do
        printf '   %-14s nodes=%s  xmr-exclusive=%s  ed25519-dalek+curve25519-dalek=%s  base58-monero=%s\n' \
            "$combo" "$nodes" "$xmr" "$ed25519" "$b58"
        # primitive axis, both directions (§9.4's lesson applied to S9)
        case ",$combo," in
            *",xmr,"*) want_ed=1 want_b58=1 ;;
            *)         want_ed=0 want_b58=0 ;;
        esac
        if [ "$want_ed" -eq 0 ] && [ "${ed25519:-0}" -ne 0 ]; then
            bad "deps $combo: primitive ed25519 is OFF but ${ed25519} Ed25519 crate(s) are still in the graph"
        fi
        if [ "$want_ed" -eq 1 ] && [ "${ed25519:-0}" -eq 0 ]; then
            bad "deps $combo: primitive ed25519 is ON but no Ed25519 crate appears — instrument blind"
        fi
        if [ "$want_b58" -eq 0 ] && [ "${b58:-0}" -ne 0 ]; then
            bad "deps $combo: primitive base58-monero is OFF but the crate is still in the graph"
        fi
        if [ "$want_b58" -eq 1 ] && [ "${b58:-0}" -eq 0 ]; then
            bad "deps $combo: primitive base58-monero is ON but the crate is absent — instrument blind"
        fi
    done < "$TMP_DIR/deps.txt"
else
    bad "no dependency account collected"
fi

note ""
note "== combination tests: the lib suite runs under every declaration (host face)"
# Compiling a subset is not the same as the subset being correct. Code that assumes another
# chain's types or fixtures are present still compiles and fails only when exercised, which a
# matrix of `check`s can never see. Cheap (a lib run per combination); the count guard is there
# because a filtered-out suite also prints "ok".
for combo in "${COMBOS[@]}"; do
    feats="$(dep_feature_list "$combo")"
    log="$TMP_DIR/test-${combo//,/-}.log"
    if cargo test $CARGO_FLAGS --lib --no-default-features --features "$feats" > "$log" 2>&1; then
        line=$(grep -E '^test result:' "$log" | tail -1)
        passed=$(printf '%s' "$line" | sed -n 's/.* \([0-9]\+\) passed.*/\1/p')
        if [ -z "$passed" ] || [ "$passed" -eq 0 ]; then
            bad "tests $combo: no passing test ($line) — a vacuous pass"
        else
            note "   $combo: $line"
        fi
    else
        bad "tests $combo: lib suite failed (log: $log)"
        grep -E '^(test .* FAILED|failures:|error\[)' "$log" | head -6 | sed 's/^/      /'
    fi
done

note ""
note "== carrier matrix: pico2 (thumbv8m.main-none-eabihf) — the DEVICE face of the same declaration"
# The host matrix proves the declaration→feature projection for the core crate. This proves it
# for a CARRIER build, where the chain switches live in flux/pico2's own forwarding features:
# the carrier names its subset, the core's build.rs enforces the declaration, and the target is
# bare metal. Subset choice is the three singles plus all-on ON PURPOSE — an MCU carrier ships
# one product face, and the three double combinations would buy six cross builds to prove what
# the host matrix already proves.
PICO2_COMBOS=(btc eth xmr btc,eth,xmr)
pindex=0
for combo in "${PICO2_COMBOS[@]}"; do
    pindex=$((pindex + 1))
    manifest="$TMP_DIR/pico2-${combo//,/-}.toml"
    {
        printf '# @generated by scripts/check_chain_axes.sh — pico2 carrier row.\n'
        printf 'limits = "pico2"\n'
        printf 'target = "thumbv8m.main-none-eabihf"\n'
        printf 'role = "test"\n\n[chains]\n'
        for chain in btc eth xmr; do
            case ",$combo," in
                *",$chain,"*) printf '%s = true\n' "$chain" ;;
                *) printf '%s = false\n' "$chain" ;;
            esac
        done
    } > "$manifest"
    log="$TMP_DIR/pico2-check-$pindex.log"
    note "   pico2[$pindex/${#PICO2_COMBOS[@]}] chains=$combo"
    if bash scripts/build_declared.sh "$manifest" -- $CARGO_FLAGS check \
            --manifest-path flux/pico2/Cargo.toml -p shlosilo-pico2 --features console \
            > "$log" 2>&1; then
        # Identity evidence, not just "it compiled": build.rs reports the chain set it actually
        # compiled, so this row also proves the carrier's forwarding features reached the core.
        got=$(grep -oE 'chains \[[a-z,]+\]' "$log" | head -1)
        want="chains [${combo}]"
        if [ "$got" = "$want" ]; then
            note "      check exit 0; build.rs reports $got"
        else
            bad "pico2 $combo: build.rs reported '${got:-<nothing>}', declared '$want'"
        fi
    else
        bad "pico2 $combo: declared carrier check failed (log: $log)"
        tail -15 "$log" | sed 's/^/      /'
    fi
done

note ""
if [ "$fail" -eq 0 ]; then
    note "CHAIN AXES: OK (${#COMBOS[@]} declared combinations + negative test, no symbol leak,"
    note "             all-on symbols present, undeclared chain refused with the set difference,"
    note "             dependency graph follows the declaration in both directions,"
    note "             lib suite green under every combination, ${#PICO2_COMBOS[@]} pico2 carrier rows)"
else
    note "CHAIN AXES: RED (see FAIL lines above)"
fi
exit "$fail"
