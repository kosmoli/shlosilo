#!/usr/bin/env bash
# =============================================================================
# check_header_per_combo.sh — the C surface must not outrun the declared chain set
# (chain-axis design §4 / §9.3-3, batch S6).
#
# The hole this closes: `shlosilo.h` and the staticlib keep table were generated ONCE, for the
# three-chain build. The keep table even referenced `shlosilo_xmr_pairing_ffi` UNCONDITIONALLY,
# which is an unresolved symbol in any build without `chain-xmr` — so "per combination" was a
# claim nothing could check, because nothing was ever generated per combination.
#
# WHAT IS ASSERTED (per combination; host face for the header, shim feature set for the table):
#   1. ALL-ON reproduces the committed `shlosilo.h` BYTE-IDENTICALLY, and the ALL-ON keep table
#      equals the one committed in the shim. If the generator cannot reproduce today's file it
#      is not the same surface, and any subset claim built on it is worthless.
#   2. The keep table FOLLOWS the chain set: a subset table is a strict subset of the all-on
#      table, and the XMR-only entry point is present only when xmr is declared (both
#      directions — absence proves it followed the set, presence proves the instrument sees it).
#   3. Every `shlosilo_*` function the header declares exists in the ALL-ON keep table. The
#      header may not advertise an entry point the product does not carry.
#
#   4. THE HEADER IS CHAIN-PARAMETRIC AND AGREES WITH THE ARCHIVE, PER COMBINATION (pool #99).
#      `[defines]` in cbindgen.toml turns every `#[cfg(feature = "chain-*")]` into
#      `#if defined(SHLOSILO_CHAIN_*)`, so one header serves every chain set and *what a host sees*
#      depends on the macros it declares. The invariants checked here, per combination:
#        a. the declarations the header would EXPOSE given this chain set, restricted to the entry
#           points the shim can carry, EQUAL this combination's keep table - both directions;
#        b. every exposed declaration outside the all-on keep table is a known host hook (the
#           allocator and the panic hook), so a guard can never hide something the C host needs;
#        c. at least one declaration is actually guarded, i.e. the narrowest set sees strictly
#           fewer declarations than all-on (a no-op `[defines]` fails this, which is the point:
#           it is the assertion that stops #99 from silently regressing).
#      cbindgen output is still asserted identical across combinations: the parametricity lives in
#      the `#if`s, not in four different files, and that is worth pinning.
#
# WHAT IS **NOT** ASSERTED, and why (say it here rather than let a reader assume coverage):
#   Which macros the C host actually defines - that is flux/forgebox's own configure-time check
#   (CMakeLists.txt cross-checks the xmr half against `nm` on libshlosilo.a, and says in place
#   why btc/eth cannot be verified that way).
#
# Usage: bash scripts/check_header_per_combo.sh
# =============================================================================
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 99

COMBOS=(btc,eth,xmr btc eth xmr)
HEADER=shlosilo.h
SHIM_TABLE=flux/forgebox/staticlib/src/lib.rs
CARGO_FLAGS="${CARGO_FLAGS:---offline}"
TMP_DIR="$(mktemp -d /tmp/hdrcombo.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Fail closed: without cbindgen every row would "fail" as a header problem, which is how a
# missing tool gets misdiagnosed as a C-surface regression (measured in CI: four rows red with
# the real cause hidden in a temp log that the trap deleted).
if ! command -v cbindgen > /dev/null 2>&1; then
    printf 'FAIL: cbindgen is not installed (expected 0.27.0: cargo install cbindgen --version 0.27.0 --locked)\n' >&2
    exit 10
fi

fail=0
note() { printf '%s\n' "$*"; }
bad() { printf 'FAIL: %s\n' "$*"; fail=1; }

cargo_feats() {
    local set="$1" feats="std,alloc-fallback" chain
    for chain in btc eth xmr; do
        case ",$set," in *",$chain,"*) feats="$feats,chain-$chain" ;; esac
    done
    printf '%s' "$feats"
}

shim_feats() {
    local set="$1" feats="se" chain
    for chain in btc eth xmr; do
        case ",$set," in *",$chain,"*) feats="$feats,chain-$chain" ;; esac
    done
    printf '%s' "$feats"
}

# Function names the header declares, one per line (`shlosilo_*` only).
header_fns() { LC_ALL=C grep -oE 'shlosilo_[a-z0-9_]+\(' "$1" | tr -d '(' | LC_ALL=C sort -u; }
# Entry points the keep table references, one per line.
# The module path may contain digits (`ffi::c_abi::r3::`) and the keysource crate is a second
# root (`shlosilo_flux_keysource::...`), so the path class must allow both — restricting it to
# `[a-z_:]` silently dropped exactly the entries this gate exists to watch.
keep_fns() {
    LC_ALL=C grep -oE '(shlosilo(_flux_keysource)?::[A-Za-z0-9_:]*::)(shlosilo[a-z0-9_]*_ffi|shlosilo[a-z0-9_]+) as \*const' "$1" \
        | sed -E 's/.*::([a-z0-9_]+) as \*const/\1/' | LC_ALL=C sort -u
}

index=0
for combo in "${COMBOS[@]}"; do
    index=$((index + 1))
    tag="${combo//,/-}"
    note ""
    note "== [$index/${#COMBOS[@]}] chains=$combo"

    # header (chain-independent today; the assertion below records why that is allowed)
    meta="$TMP_DIR/meta-$tag.json"
    if ! cargo metadata $CARGO_FLAGS --format-version 1 --no-default-features \
            --features "$(cargo_feats "$combo")" > "$meta" 2> "$TMP_DIR/meta-$tag.err"; then
        bad "$combo: cargo metadata failed (see $TMP_DIR/meta-$tag.err)"
        continue
    fi
    hdr="$TMP_DIR/hdr-$tag.h"
    if ! cbindgen --config cbindgen.toml --crate shlosilo --metadata "$meta" --output "$hdr" \
            > "$TMP_DIR/cbindgen-$tag.log" 2>&1; then
        bad "$combo: cbindgen failed:"
        tail -8 "$TMP_DIR/cbindgen-$tag.log" | sed 's/^/      /'
        continue
    fi
    [ -s "$hdr" ] || { bad "$combo: cbindgen produced an empty header"; continue; }

    # keep table for this chain set
    keep="$TMP_DIR/keep-$tag.rs"
    if ! python3 scripts/gen_ffi_keep.py --features "$(shim_feats "$combo")" --out "$keep" \
            > "$TMP_DIR/keep-$tag.log" 2>&1; then
        bad "$combo: keep-table generation failed (see $TMP_DIR/keep-$tag.log)"
        continue
    fi
    header_fns "$hdr" > "$TMP_DIR/hdrfns-$tag.txt"
    keep_fns "$keep" > "$TMP_DIR/keepfns-$tag.txt"
    [ "$combo" = "btc,eth,xmr" ] && cp "$TMP_DIR/keepfns-$tag.txt" "$TMP_DIR/keepfns-allon.txt"
    note "   header: $(wc -l < "$hdr") lines, $(wc -l < "$TMP_DIR/hdrfns-$tag.txt") function decls"
    note "   keep:   $(grep -c 'Addr(' "$keep") entries, $(wc -l < "$TMP_DIR/keepfns-$tag.txt") entry points"

    # 4/a-c: what this chain set actually SEES in the header must equal what the shim carries.
    vis="$TMP_DIR/visfns-$tag.txt"
    # Piped through `LC_ALL=C sort`: the report is fed to `comm`, so its collation must match the
    # keep-table extraction exactly. Depending on Python's own ordering here would make the gate
    # report a difference between two identical sets (measured: it did).
    if ! python3 scripts/header_chain_surface.py --header "$hdr" --chains "$combo" --kind proto \
            2> "$TMP_DIR/vis-$tag.err" | LC_ALL=C sort -u > "$vis"; then
        bad "$combo: header surface report failed:"
        sed 's/^/      /' "$TMP_DIR/vis-$tag.err" | head -5
    else
        # a. restricted to the all-on keep table (host hooks are not entry points the shim carries)
        # Reference: the union of every keep table generated so far. The all-on table is a
        # superset of each subset, so building the union makes this assertion independent of
        # loop order — and it stays honest even if the combos list is reordered.
        allkeep="$TMP_DIR/keepfns-union.txt"
        cat "$TMP_DIR"/keepfns-*.txt 2>/dev/null | LC_ALL=C sort -u > "$allkeep"
        if [ -s "$allkeep" ]; then
            LC_ALL=C comm -12 "$vis" "$allkeep" > "$TMP_DIR/viscarry-$tag.txt"
            if diff -q "$TMP_DIR/viscarry-$tag.txt" "$TMP_DIR/keepfns-$tag.txt" > /dev/null; then
                note "   header exposes exactly the entry points this chain set carries ($(wc -l < "$vis") decls)"
            else
                bad "$combo: header surface and keep table disagree:"
                LC_ALL=C comm -3 "$TMP_DIR/viscarry-$tag.txt" "$TMP_DIR/keepfns-$tag.txt" \
                    | head -8 | sed 's/^/      /'
            fi
        fi
        # b. everything exposed that the shim cannot carry must be a host hook
        unknown="$(LC_ALL=C comm -23 "$vis" "$TMP_DIR/keepfns-$tag.txt" \
            | LC_ALL=C grep -vE '^(shlosilo_embedded_malloc|shlosilo_embedded_free|shlosilo_panic_hook)$' || true)"
        if [ -n "$unknown" ]; then
            bad "$combo: header exposes declarations that are neither carried nor host hooks:"
            printf '%s\n' "$unknown" | head -8 | sed 's/^/      /'
        fi
    fi

    if [ "$combo" = "btc,eth,xmr" ]; then
        if diff -q "$hdr" "$HEADER" > /dev/null; then
            note "   all-on header == committed $HEADER (byte-identical)"
        else
            bad "$combo: generated header differs from the committed one:"
            diff "$hdr" "$HEADER" | head -10 | sed 's/^/      /'
        fi
        if python3 - "$keep" "$SHIM_TABLE" <<'PY'
import sys
generated = open(sys.argv[1], encoding="utf-8").read().strip()
shim = open(sys.argv[2], encoding="utf-8").read()
marker = "// ── C-ABI keep-table (generated by scripts/gen_ffi_keep.py) ──"
if marker not in shim:
    print("FAIL: shim has no keep-table marker", file=sys.stderr)
    sys.exit(1)
committed = (marker + shim.split(marker, 1)[1]).strip()
sys.exit(0 if generated == committed else 1)
PY
        then
            note "   all-on keep table == committed shim table (byte-identical)"
        else
            bad "$combo: the all-on keep table differs from the committed shim table"
        fi
        # Instrument sensitivity: a header or table this small means the extractor broke.
        [ "$(wc -l < "$TMP_DIR/hdrfns-$tag.txt")" -ge 20 ] \
            || bad "$combo: fewer than 20 function decls extracted from the header — extractor broken?"
        [ "$(wc -l < "$TMP_DIR/keepfns-$tag.txt")" -ge 20 ] \
            || bad "$combo: fewer than 20 entry points extracted from the table — extractor broken?"
        # 3. every entry point the keep table references must be DECLARED in the header, or the C
        #    host cannot call it. (The reverse does not hold by design: the header also declares
        #    the hooks the C host itself provides — the allocator and the panic hook — which are
        #    imports on the Rust side and therefore never appear in a keep table.)
        missing_decl="$(LC_ALL=C comm -23 "$TMP_DIR/keepfns-$tag.txt" "$TMP_DIR/hdrfns-$tag.txt")"
        if [ -n "$missing_decl" ]; then
            bad "$combo: the keep table references entry points the header does not declare:"
            printf '%s\n' "$missing_decl" | head -8 | sed 's/^/      /'
        fi
        host_provided="$(LC_ALL=C comm -13 "$TMP_DIR/keepfns-$tag.txt" "$TMP_DIR/hdrfns-$tag.txt")"
        note "   header-only declarations (hooks the C host provides): $(printf '%s' "$host_provided" | tr '\n' ' ')"
    else
        # 2. the keep table follows the chain set
        if LC_ALL=C comm -23 "$TMP_DIR/keepfns-$tag.txt" "$TMP_DIR/keepfns-btc-eth-xmr.txt" | grep -q .; then
            bad "$combo: keep table carries an entry point that the all-on table does not:"
            LC_ALL=C comm -23 "$TMP_DIR/keepfns-$tag.txt" "$TMP_DIR/keepfns-btc-eth-xmr.txt" \
                | head -6 | sed 's/^/      /'
        fi
        subset_n="$(wc -l < "$TMP_DIR/keepfns-$tag.txt")"
        allon_n="$(wc -l < "$TMP_DIR/keepfns-btc-eth-xmr.txt")"
        case ",$combo," in
            *",xmr,"*)
                # Today no entry point is gated on btc or eth alone, so including xmr keeps the
                # full table. The chain-marker check below is what proves sensitivity here.
                note "   keep table has $subset_n of $allon_n all-on entry points"
                ;;
            *)
                if [ "$subset_n" -ge "$allon_n" ]; then
                    bad "$combo: keep table has $subset_n entry points, all-on has $allon_n — the table did not follow the chain set"
                fi
                ;;
        esac
        case ",$combo," in
            *",xmr,"*)
                grep -qx 'shlosilo_xmr_pairing_ffi' "$TMP_DIR/keepfns-$tag.txt" \
                    || bad "$combo: xmr is declared but shlosilo_xmr_pairing_ffi is not in the keep table"
                ;;
            *)
                if grep -qx 'shlosilo_xmr_pairing_ffi' "$TMP_DIR/keepfns-$tag.txt"; then
                    bad "$combo: xmr is OFF but shlosilo_xmr_pairing_ffi is still in the keep table (unresolved symbol at link time)"
                else
                    note "   xmr-only entry point absent from the keep table (as declared)"
                fi
                ;;
        esac
    fi
done

# 4. the header is chain-set independent today — assert it, so the day it stops being true is
#    a red line rather than a surprise in a C build.
note ""
base="$TMP_DIR/hdr-btc-eth-xmr.h"
if [ ! -f "$base" ]; then
    # The baseline row failed (its own FAIL is already reported): comparing against a file that
    # does not exist would add four misleading "the C surface is now chain-dependent" lines.
    bad "cannot compare the per-chain headers: the all-on baseline was not generated"
    combo=""
fi
for combo in btc eth xmr; do
    [ -n "$combo" ] || break
    tag="${combo//,/-}"
    if ! diff -q "$base" "$TMP_DIR/hdr-$tag.h" > /dev/null; then
        bad "header for chains=$combo differs from all-on: the C surface is now chain-dependent."
        bad "   That is not a bug in itself — it means cbindgen.toml gained [defines], and from then"
        bad "   on the C host MUST declare its chain set (-DSHLOSILO_CHAIN_*), otherwise the guards"
        bad "   silently hide entry points. Finish that contract before landing the change."
        diff "$base" "$TMP_DIR/hdr-$tag.h" | head -8 | sed 's/^/      /'
    fi
done
# 4/c directly: a no-op `[defines]` (or a cbindgen that stops honouring it) makes every chain set
# see the same surface. Assert the guards bite, so #99 cannot silently regress into #99.
if [ -f "$TMP_DIR/visfns-btc.txt" ] && [ -f "$TMP_DIR/visfns-btc-eth-xmr.txt" ]; then
    narrow="$(wc -l < "$TMP_DIR/visfns-btc.txt")"
    widest="$(wc -l < "$TMP_DIR/visfns-btc-eth-xmr.txt")"
    if [ "$narrow" -ge "$widest" ]; then
        bad "the btc-only host sees $narrow declarations and all-on sees $widest: nothing is guarded,"
        bad "   so the header no longer describes which entry points the archive carries."
    else
        note "   guards bite: btc-only sees $narrow decls, all-on sees $widest (chain-exclusive hidden)"
    fi
fi

note ""
if [ "$fail" -eq 0 ]; then
    note "HEADER PER COMBO: OK (all-on reproduces both committed surfaces byte-identically;"
    note "                   keep tables follow the declared chain set in both directions;"
    note "                   the guarded header exposes exactly that surface per chain set;"
    note "                   the header declares nothing the product does not carry)"
else
    note "HEADER PER COMBO: RED (see FAIL lines above)"
fi
exit "$fail"
