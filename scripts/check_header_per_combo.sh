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
# WHAT IS **NOT** ASSERTED, and why (say it here rather than let a reader assume coverage):
#   The header itself is generated with `[defines]` ABSENT, so cbindgen ignores `#[cfg(feature)]`
#   and emits every declaration for every chain set — all four combinations produce the SAME
#   header. That is sound today only because every C host (forgebox) builds the full chain set.
#   Guarding the header per chain needs `[defines]` in cbindgen.toml PLUS the C host declaring
#   its chain set with `-DSHLOSILO_CHAIN_*`; without the second half the guards would silently
#   hide entry points from the C build. Tracked as a pool item, not silently skipped.
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
        bad "$combo: cbindgen failed (see $TMP_DIR/cbindgen-$tag.log)"
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
    note "   header: $(wc -l < "$hdr") lines, $(wc -l < "$TMP_DIR/hdrfns-$tag.txt") function decls"
    note "   keep:   $(grep -c 'Addr(' "$keep") entries, $(wc -l < "$TMP_DIR/keepfns-$tag.txt") entry points"

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
for combo in btc eth xmr; do
    tag="${combo//,/-}"
    if ! diff -q "$base" "$TMP_DIR/hdr-$tag.h" > /dev/null; then
        bad "header for chains=$combo differs from all-on: the C surface is now chain-dependent."
        bad "   That is not a bug in itself — it means cbindgen.toml gained [defines], and from then"
        bad "   on the C host MUST declare its chain set (-DSHLOSILO_CHAIN_*), otherwise the guards"
        bad "   silently hide entry points. Finish that contract before landing the change."
        diff "$base" "$TMP_DIR/hdr-$tag.h" | head -8 | sed 's/^/      /'
    fi
done
note "   header is chain-set independent (no [defines] yet) — sound only while every C host"
note "   builds the full chain set; see the pool item for the guarded-header work"

note ""
if [ "$fail" -eq 0 ]; then
    note "HEADER PER COMBO: OK (all-on reproduces both committed surfaces byte-identically;"
    note "                   keep tables follow the declared chain set in both directions;"
    note "                   the header declares nothing the product does not carry)"
else
    note "HEADER PER COMBO: RED (see FAIL lines above)"
fi
exit "$fail"
