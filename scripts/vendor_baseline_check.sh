#!/usr/bin/env bash
# T-12 vendor baseline check: every vendor tree must be EXACTLY reproducible
# from its documented anchor + the replayable diff in patches/baseline/.
# Zero residue is the contract (vendor/BASELINE.md).
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# tree | anchor source | baseline diff
CHECKS=(
  "quircs|https://static.crates.io/crates/quircs/quircs-0.10.2.crate|patches/baseline/quircs-vs-crates-io-0.10.2.diff"
  "rqrr|https://static.crates.io/crates/rqrr/rqrr-0.11.0.crate|patches/baseline/rqrr-vs-crates-io-0.11.0.diff"
  "g2p|https://static.crates.io/crates/g2p/g2p-1.2.2.crate|patches/baseline/g2p-vs-crates-io-1.2.2.diff"
  "g2poly|https://static.crates.io/crates/g2poly/g2poly-1.2.2.crate|patches/baseline/g2poly-vs-crates-io-1.2.2.diff"
  "curve25519-dalek|https://static.crates.io/crates/curve25519-dalek/curve25519-dalek-4.1.3.crate|patches/baseline/curve25519-dalek-vs-crates-io-4.1.3.diff"
  "cryptonight|https://codeload.github.com/Cuprate/cuprate/tar.gz/cf3137b7579bfc930303243a634ca4d66b7266ed|patches/baseline/cryptonight-vs-upstream-cf3137b7579b.diff"
  "monero-bulletproofs|https://static.crates.io/crates/monero-bulletproofs/monero-bulletproofs-0.1.0.crate|patches/baseline/monero-bulletproofs-vs-crates-io-0.1.0.diff"
  "monero-clsag|https://static.crates.io/crates/monero-clsag/monero-clsag-0.1.0.crate|patches/baseline/monero-clsag-vs-crates-io-0.1.0.diff"
  "monero-io|https://static.crates.io/crates/monero-io/monero-io-0.1.0.crate|patches/baseline/monero-io-vs-crates-io-0.1.0.diff"
  "monero-ed25519|https://static.crates.io/crates/monero-ed25519/monero-ed25519-0.1.0.crate|patches/baseline/monero-ed25519-vs-crates-io-0.1.0.diff"
  "std-shims|https://static.crates.io/crates/std-shims/std-shims-0.1.5.crate|patches/baseline/std-shims-vs-crates-io-0.1.5.diff"
)
# cryptonight 的基准是 tar 子目录（其余为 crate 根）
SUBDIR_cryptonight="cryptonight"

fail=0
for row in "${CHECKS[@]}"; do
  IFS='|' read -r tree url diff <<<"$row"
  echo "== $tree"
  d="$WORK/$tree"
  mkdir -p "$d/up"
  up="$d/up"
  # anchor cache: the crates.io download is flaky here — cache the tarball so
  # a transient failure cannot masquerade as a baseline regression (repeated
  # false reds in 2026-09).
  cache="$HOME/.cache/shlosilo-vendor-anchors/$(basename "$url")"
  mkdir -p "$HOME/.cache/shlosilo-vendor-anchors"
  if [ ! -s "$cache" ]; then
    curl -sSL --max-time 300 -o "$cache.tmp" "$url" && [ -s "$cache.tmp" ] && mv "$cache.tmp" "$cache"
  fi
  cp "$cache" "$d/src" 2>/dev/null || curl -sSL --max-time 300 -o "$d/src" "$url"
  case "$url" in
    *.crate) tar xzf "$d/src" -C "$d/up" --strip-components=1 ;;
    *)       tar xzf "$d/src" -C "$d/up" --strip-components=1
             up="$d/up/${SUBDIR_cryptonight}" ;;
  esac
  [ -d "${up:-$d/up}" ] || { echo "   anchor missing"; fail=1; continue; }
  cp -a "${up:-$d/up}" "$d/base"
  ( cd "$d/base" && patch -p1 --quiet -i "$ROOT/$diff" )
  if diff -ruN --exclude=target --exclude=Cargo.lock \
      --exclude=.cargo-checksum.json --exclude=.cargo-ok \
      "$d/base" "$ROOT/vendor/$tree" >"$d/residue"; then
    echo "   replay == tree  OK"
  else
    echo "   RESIDUE (drift beyond the recorded baseline):"
    head -20 "$d/residue"
    fail=1
  fi
done
exit $fail
