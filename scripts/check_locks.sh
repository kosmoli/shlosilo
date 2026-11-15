#!/usr/bin/env bash
# Every tracked Cargo.lock must be complete and CURRENT.
#
# Why: the locks are in the index, but cargo silently rewrites them when a manifest
# asks for something the lock cannot satisfy, so a green build can be produced on
# dependency versions nobody reviewed. `cargo metadata --locked` turns that silent
# rewrite into a hard error. CI also passes `--locked` explicitly to every cargo
# command it can; this gate covers the make/script paths where a flag cannot be
# injected, plus the locks a build might rewrite behind make.
#
# Usage:
#   check_locks.sh          pre-flight: metadata --locked over the resolvable
#                           manifests, plus "no lock is dirty"
#   check_locks.sh --diff   post-build: only the "no lock is dirty" half, so a lock
#                           that a build rewrote is caught before the job is green
#
# Scope: only locks cargo can resolve on their own are checked by the metadata half.
# The rest live inside the workspace directory but are not standalone-resolvable —
# `base58-monero` and `std-shims` are nested under the root workspace without being
# members (cargo refuses: "current package believes it's in a workspace when it's
# not"), and `monero-clsag`, `g2p`, `g2poly`, `rqrr` need the workspace's `[patch]`
# context to select versions at all. Those are covered by the --diff half.
set -uo pipefail
mode="${1:-}"

root=$(git rev-parse --show-toplevel) || exit 99
cd "$root" || exit 99

RESOLVABLE=(
  "Cargo.lock"
  "fuzz/Cargo.lock"
  "probes/noalloc/Cargo.lock"
  "vendor/cryptonight/Cargo.lock"
  "vendor/monero-bulletproofs/Cargo.lock"
)

rc=0

if [ "$mode" != "--diff" ]; then
  for lock in "${RESOLVABLE[@]}"; do
    if [ ! -f "$lock" ]; then
      echo "MISSING LOCK: $lock"
      rc=1
      continue
    fi
    dir=$(dirname "$lock")
    if ! ( cd "$dir" && cargo metadata --locked --format-version 1 >/dev/null 2>/tmp/lock_err.log ); then
      echo "LOCK DRIFT: $lock"
      sed -n '1,6p' /tmp/lock_err.log
      rc=1
    fi
  done
fi

# A modified-but-uncommitted lock is drift too: CI checks out a clean tree, so any
# diff here means the run and the review are looking at different dependency sets.
if ! git diff --quiet -- '*Cargo.lock'; then
  echo "LOCK MODIFIED IN THE WORKING TREE:"
  git diff --name-only -- '*Cargo.lock'
  rc=1
fi

echo "LOCKS=$rc"
exit "$rc"
