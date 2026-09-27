#!/usr/bin/env bash
# Z6 lang-item graph probe: build the no-alloc staticlib WITHOUT the
# allocator stub. While `alloc` is anywhere in the crate graph rustc reports
# `no global memory allocator found but one is required`; a CLEAN build means
# the graph is alloc-free and the stub can go for good.
#
# Exit codes: 0 = GRAPH-CLEAN, 10 = ALLOC-IN-GRAPH (expected during the
# campaign), anything else = build broke (real error).
set -uo pipefail
cd "$(dirname "$0")/.."
log="$(mktemp /tmp/z6_langitem.XXXXXX.log)"
if cargo build --release --target thumbv7em-none-eabihf \
     --manifest-path probes/noalloc/Cargo.toml --no-default-features \
     > "$log" 2>&1; then
    echo "GRAPH-CLEAN: the crate graph needs no allocator"
    rm -f "$log"
    exit 0
fi
if grep -q "no global memory allocator found" "$log"; then
    echo "ALLOC-IN-GRAPH: the crate graph still references alloc"
    rm -f "$log"
    exit 10
fi
echo "BUILD-BROKE: real error (see $log)"
grep -E "^error" "$log" | head -5
exit 1
