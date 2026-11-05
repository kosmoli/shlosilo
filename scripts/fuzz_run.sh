#!/bin/bash
# Audit #5 open item 04 + audit #6 engineering item: single cargo-fuzz entry point
# (pinned nightly toolchain).
# Background: cargo fuzz defaults to stable and fails for lack of -Zsanitizer; the
# nightly toolchain MUST be pinned.
# Review round 5, engineering item #1: the toolchain constraint belongs here, not in
# the caller's environment.
#
# Usage:
#   bash scripts/fuzz_run.sh              # 90s smoke per target (default)
#   bash scripts/fuzz_run.sh 300          # 300s per target
#   bash scripts/fuzz_run.sh 0            # run continuously (Ctrl-C to stop)
#
# Audit #12: the seed corpus is checked in (fuzz/seedcorpus/<target>/, fixed
# boundary samples); runtime products (corpus/) stay out of the repo — CI and a
# clean clone get a deterministic starting point, and no mutable artifacts
# accumulate locally. fuzz_run copies the seeds into the working corpus dir
# (libFuzzer has no -seed_corpus flag; the working corpus persists, so the seeds
# are re-merged on every run).
#
# sanitizer environment options (important):
#   ASAN_OPTIONS=detect_leaks=0           # for when libFuzzer+leak detection conflicts with the alloc-budget tests
#   RUST_LIB_BACKTRACE=1                 # print a Rust backtrace on crash
#
# Output: crash-* files under fuzz/artifacts/<target>/; exit code 0 when there is no crash
set -uo pipefail
cd "$(dirname "$0")/.."

NIGHTLY="nightly-2026-05-22"
SECS="${1:-90}"
SEED="${SEED:-20260902}"

TARGETS=(parse_psbt multipart_decoder cbor_eth_sign xmr_unsigned_txset)
rc_total=0

for t in "${TARGETS[@]}"; do
    echo "=== fuzz: $t (${SECS}s) ==="
    # Seed corpus (libFuzzer has no -seed_corpus flag; the working corpus dir is
    # persistent, so every run includes the deterministic starting point once the
    # seeds are copied in; corpus/ itself is not checked in)
    mkdir -p "fuzz/corpus/$t"
    if compgen -G "fuzz/seedcorpus/$t/*" > /dev/null; then
        cp fuzz/seedcorpus/"$t"/* "fuzz/corpus/$t/"
    fi
    if [ "$SECS" = "0" ]; then
        RUSTUP_TOOLCHAIN="$NIGHTLY" cargo fuzz run "$t" -- -seed="$SEED" -rss_limit_mb=2560
    else
        RUSTUP_TOOLCHAIN="$NIGHTLY" cargo fuzz run "$t" -- -max_total_time="$SECS" -seed="$SEED" -rss_limit_mb=2560
    fi
    rc=$?
    if [ $rc -ne 0 ]; then
        echo "FAIL: $t exited $rc (see fuzz/artifacts/$t/)"
        rc_total=1
    else
        echo "OK: $t no crash"
    fi
done

exit $rc_total
