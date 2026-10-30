#!/usr/bin/env bash
# fp-chain coverage gate (pool #58, 2026-10-30).
#
# grep-as-truth manifest of the pins covering every link of the wallet-fp
# binding + visible-failure chain (same discipline as the expected-red
# manifest): fp derivation golden -> pairing fp stamping -> sign-leg foreign-fp
# filter -> gap/mismatch refusal -> kind->code mapping -> fixed screen word.
# A pin disappearing, being renamed, or going #[ignore] breaks this gate —
# test coverage of the fp chain is a gate, not a habit (the 2026-10-28/29
# review found the visibility chain with zero test face).
#
# Run:  bash scripts/check_fp_chain.sh    (exit 0 = full manifest intact)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Manifest: one pin per fp-chain link (fp golden x4, retention stamping,
# foreign-fp ignore, gap refusal, mismatch refusal, word tables, end-to-end
# chain x2, FFI signature).
PINS=(
  wallet_fp_golden_fixed_pair
  wallet_fp_golden_is_order_sensitive
  wallet_fp_from_seed_golden_64_byte_bip39_seed
  wallet_fp_from_seed_is_length_sensitive
  pairing_records_are_wallet_fp_stamped
  foreign_fp_records_are_ignored
  gap_without_records_refuses
  refuse_on_record_source_mismatch
  sign_failure_text_matches_fixed_vocabulary
  pairing_failure_words_match_fixed_vocabulary
  fp_mismatch_chain_reaches_visible_word
  fp_mismatch_error_reaches_fixed_screen_word
  ffi_failure_text_signature_pins
)

fail=0
for p in "${PINS[@]}"; do
  n=$({ grep -rn "fn ${p}(" tests/ forms/ || true; } | wc -l)
  if [ "$n" -ne 1 ]; then
    echo "FPCOV: pin '${p}' expected exactly once, found ${n}" >&2
    fail=1
    continue
  fi
  if { grep -rn -B3 "fn ${p}(" tests/ forms/ || true; } | grep -q "#\[ignore"; then
    echo "FPCOV: pin '${p}' is #[ignore]d — the coverage is gone" >&2
    fail=1
  fi
done

# The fixed-vocabulary single source must exist (拆码红线 word table).
if [ ! -f forms/failure_text.rs ]; then
  echo "FPCOV: forms/failure_text.rs missing — word table lost its home" >&2
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "FPCOV: ${#PINS[@]} pins intact"
fi
exit "$fail"
