#!/usr/bin/env bash
# fixture tracking gate (2026-10-20, clean-checkout CI breakage class).
#
# Scans every *.rs file in the repo for include_bytes!/include_str! literal
# paths, resolves each path relative to its source file, and asserts the
# target is tracked by git (`git ls-files --error-unmatch`).
#
# Why: tests/fixtures/tx2_cake_real_unsigned.bin was referenced by
# include_bytes! but silently swallowed by the repo-wide `*.bin` gitignore
# rule, so it never entered the index - dev trees compiled (the file was
# on disk) while every clean-checkout CI run died in the include_bytes!
# expansion with a cryptic "No such file or directory". This gate turns
# that class of failure into an explicit untracked/missing list before
# anything compiles.
#
# Sources scanned: tracked + staged + untracked-but-not-ignored *.rs (so
# a WIP test file is caught before commit, while ignored build products
# under target/ stay out via .gitignore).
#
# Only string literals are resolved; non-literal arguments (concat!/env!
# driven paths) cannot be resolved statically and are reported as SKIP
# lines (warning, not failure).
#
# Run from anywhere; CI runs the same script (Test + Lint job, step
# "fixture tracking gate").
set -euo pipefail

cd "$(dirname "$0")/.."

# core.quotePath=false keeps non-ASCII paths unquoted so they match disk
# names verbatim.
mapfile -t SOURCES < <(git -c core.quotePath=false ls-files \
    --cached --others --exclude-standard -- '*.rs')

if [ "${#SOURCES[@]}" -eq 0 ]; then
    echo "ERROR: no *.rs sources found - run inside the shlosilo-poc4 checkout" >&2
    exit 2
fi

# Lexical path normalization; targets may be missing on disk, so no
# realpath()/cd() resolution is possible.
normalize() {
    local path="$1" part
    local -a out=()
    local IFS=/
    for part in $path; do
        case "$part" in
            ''|.) continue ;;
            ..)
                if [ "${#out[@]}" -gt 0 ] && [ "${out[-1]}" != ".." ]; then
                    unset "out[$((${#out[@]} - 1))]"
                else
                    out+=("..")
                fi
                ;;
            *) out+=("$part") ;;
        esac
    done
    (IFS=/; echo "${out[*]}")
}

# Path literal of an include_bytes!/include_str! invocation. [[:space:]]
# (not \s) and matches across joined continuation lines.
RE_LITERAL='include_(bytes|str)![[:space:]]*\([[:space:]]*(r#*)?"([^"]*)"'

declare -A REFS=()          # resolved target -> "src:line src:line ..."
declare -a SKIPS=()         # non-literal invocations (warning only)
ref_count=0
skip_count=0

record_ref() {
    local path="$1" src="$2" line="$3" target
    ref_count=$((ref_count + 1))
    if [[ "$path" == /* ]]; then
        target="$path"      # absolute include: kept verbatim, flagged in verify
    else
        target="$(normalize "$(dirname "$src")/$path")"
    fi
    REFS["$target"]="${REFS[$target]:+${REFS[$target]} }$src:$line"
}

record_skip() {
    skip_count=$((skip_count + 1))
    SKIPS+=("$1 (non-literal include_*! argument, not statically checkable)")
}

scan_source() {
    local src="$1" n=0 text cand matched start
    local pending="" pending_line=0
    while IFS= read -r text || [ -n "$text" ]; do
        n=$((n + 1))
        if [ -n "$pending" ]; then
            cand="$pending $text"   # multi-line invocation continuation
            start=$pending_line
        elif [[ $text == *"include_bytes!"* || $text == *"include_str!"* ]]; then
            cand="$text"
            start=$n
        else
            continue
        fi
        matched=0
        while [[ $cand =~ $RE_LITERAL ]]; do
            matched=1
            record_ref "${BASH_REMATCH[3]}" "$src" "$start"
            cand="${cand#*"${BASH_REMATCH[0]}"}"
        done
        if [ "$matched" -eq 1 ]; then
            pending=""
        elif [[ $cand == *")"* ]]; then
            # invocation closes without any string literal -> non-literal arg
            record_skip "$src:$start"
            pending=""
        else
            pending="$cand"         # keep accumulating continuation lines
            pending_line=$start
        fi
    done < "$src"
}

for src in "${SOURCES[@]}"; do
    scan_source "$src"
done

echo "==> scanning ${#SOURCES[@]} *.rs files for include_bytes!/include_str! literals"
for s in "${SKIPS[@]-}"; do
    [ -n "$s" ] && echo "    SKIP: $s"
done

fail_count=0
declare -a BAD=()
if [ "${#REFS[@]}" -gt 0 ]; then
    mapfile -t sorted_targets < <(printf '%s\n' "${!REFS[@]}" | LC_ALL=C sort)
else
    sorted_targets=()
fi
for target in "${sorted_targets[@]-}"; do
    [ -n "$target" ] || continue
    if [[ "$target" == /* ]]; then
        fail_count=$((fail_count + 1))
        BAD+=("  ABSOLUTE  $target  (referenced by ${REFS[$target]})")
        continue
    fi
    if [[ "$target" == ../* ]]; then
        fail_count=$((fail_count + 1))
        BAD+=("  OUT-OF-REPO  $target  (referenced by ${REFS[$target]})")
        continue
    fi
    if git ls-files --error-unmatch -- "$target" >/dev/null 2>&1; then
        continue
    fi
    fail_count=$((fail_count + 1))
    local_ign=""
    if [ -e "$target" ]; then
        reason="UNTRACKED"
        local_ign=$(git check-ignore -v -- "$target" 2>/dev/null | head -n 1 || true)
        if [ -n "$local_ign" ]; then
            reason="UNTRACKED (silently ignored: $local_ign)"
        fi
    else
        reason="MISSING"
    fi
    BAD+=("  $reason  $target  (referenced by ${REFS[$target]})")
done

if [ "$fail_count" -gt 0 ]; then
    echo "ERROR: $fail_count include target(s) not tracked by git:" >&2
    for b in "${BAD[@]}"; do
        echo "$b" >&2
    done
    echo "fix: git add -f <target> (the repo-wide *.bin ignore rule needs -f)" >&2
    exit 1
fi

echo "    ok: $ref_count include references -> ${#REFS[@]} unique targets, all tracked by git"
if [ "$skip_count" -gt 0 ]; then
    echo "    note: $skip_count non-literal include_*! invocation(s) skipped (see SKIP lines)"
fi
