#!/usr/bin/env bash
# pico2 build-flavor gate (audit #17 P1-01).
#
# The fixed-entropy XMR command (`xmrseed`), the test-vector mnemonic
# loader (`entropy`) and the TRNG diagnostic command family are bench-only:
# they are compiled in only with the `bench` feature and MUST be absent
# from production images (anyone with console access must not be able to
# replace the signing randomness). This gate builds both flavors and
# checks the canary strings both ways:
#
#   - absent from the production image  (the security boundary), and
#   - present in the bench image        (positive control: a typo'd gate
#     that removes the code from both builds would otherwise pass the
#     negative check silently).
#
# The checks read `strings` output into a variable and test substrings in
# bash on purpose: `strings ... | grep -q` dies of SIGPIPE once grep finds
# a match, and with `set -o pipefail` that poisons the exit status (a
# negated pipeline test then takes the wrong branch in the match case).
#
# Also builds the perf-timing flavor (bench+perf; the XMR phase-probe
# firmware, including the codegen-compact dalek experiment) so the perf
# combination stays compileable and its surface marker (`xtiming`) is
# present.
#
# Run from anywhere; CI runs the same script (appearances job). Note: the
# builds share the cargo output path, and cargo re-points it (uplift) to
# whichever flavor the invocation requests - so the ELF is read immediately
# after its own build here.
set -euo pipefail

cd "$(dirname "$0")/.."

ELF=target/thumbv8m.main-none-eabihf/release/shlosilo-pico2
CANARIES=(xmrseed trngdump trngrst trngprobe trngemb "fixed entropy set" "session key set" \
          trngraw trngrawout trngcheck trngtrace "[traw]" "[tchk]" "[ttr]" "[temp]")

if ! command -v strings >/dev/null 2>&1; then
  echo "ERROR: strings (binutils) not found" >&2
  exit 1
fi

echo "==> production build (default features)"
(cd flux/pico2 && cargo build --release)
PROD_STRINGS=$(strings "$ELF")
for c in "${CANARIES[@]}"; do
  if [[ "$PROD_STRINGS" == *"$c"* ]]; then
    echo "ERROR: production pico2 image contains bench-only string: $c" >&2
    exit 1
  fi
done
echo "    clean: no bench-only commands in the production image"

echo "==> bench build (--features bench)"
(cd flux/pico2 && cargo build --release --features bench)
BENCH_STRINGS=$(strings "$ELF")
for c in "${CANARIES[@]}"; do
  if [[ "$BENCH_STRINGS" != *"$c"* ]]; then
    echo "ERROR: bench pico2 image lacks expected string: $c (positive control failed)" >&2
    exit 1
  fi
done
echo "    ok: bench-only surface present in the bench image"

echo "==> perf-timing build (bench,perf-timing,perf-bench,codegen-compact)"
(cd flux/pico2 && cargo build --release --features bench,perf-timing,perf-bench,codegen-compact)
PERF_STRINGS=$(strings "$ELF")
for c in "${CANARIES[@]}" xtiming perfbench; do
  if [[ "$PERF_STRINGS" != *"$c"* ]]; then
    echo "ERROR: perf-timing image lacks expected string: $c" >&2
    exit 1
  fi
done
echo "    ok: perf-timing surface present (probe firmware)"
