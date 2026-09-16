#!/usr/bin/env bash
# Local entry for every clippy gate CI runs (kept in sync with
# .github/workflows/ci.yml): the core crate on the host (default + all
# features, the `test` job) and the three appearance bundles on their real
# targets (the `appearances` job). vendor/ and fuzz/ are outside the
# workspace, so they never reach these gates.
#
# Audit #16 follow-up: the previous version only linted the root lib and
# could pass while CI failed (the appearance crates and the embedded lint
# surface - e.g. c_char signedness - were not covered). This now mirrors
# CI, so a green `make check` means green lint gates.
#
# Usage: scripts/clippy.sh   (or `make check`)
set -euo pipefail
cd "$(dirname "$0")/.."

INSTALLED=$(rustup target list --installed)
for t in thumbv7em-none-eabihf thumbv8m.main-none-eabihf; do
  if [[ "$INSTALLED" != *"$t"* ]]; then
    echo "==> rustup target add $t"
    rustup target add "$t"
  fi
done

run() {
  echo "==> $*"
  "$@"
}

# Core crate, host (CI `test` job: "Clippy (all targets)" x2).
run cargo clippy --all-targets -- -D warnings
run cargo clippy --all-targets --all-features -- -D warnings

# Appearance bundles, real targets (CI `appearances` job: "Appearance
# crates: clippy"). pico2 covers the bench/perf surface via --all-features.
run cargo clippy -p shlosilo-pico2 --release --target thumbv8m.main-none-eabihf --all-features -- -D warnings
run cargo clippy -p shlosilo-forgebox --release --target thumbv7em-none-eabihf -- -D warnings
run cargo clippy -p shlosilo-host-sim --release -- -D warnings

echo "==> all green"
