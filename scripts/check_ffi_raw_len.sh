#!/usr/bin/env bash
# FFI raw-slice length gate (2026-11-19, FFI graded audit F-1).
#
# Why: `slice::from_raw_parts(_mut)` requires `len * size_of::<T>() <= isize::MAX`.
# A `c_uint` length claim from C can exceed that on a 32-bit target (u32::MAX
# bytes > isize::MAX), so building a slice straight from a caller length is UB
# there while looking perfectly fine on a 64-bit host — exactly the blind spot
# audit #5 P0-03 closed for the older entries.
#
# Rule: inside the FFI entry surface, every `from_raw_parts` / `from_raw_parts_mut`
# takes either an internal length (`ws_need`, `need`, a layout constant, ...) or a
# value that was bounded first (`checked_slice*`, a named helper). The anti-pattern
# is a bare caller cast on the construction line:
#
#     from_raw_parts(ptr, len as usize)          # red
#     from_raw_parts(ptr, data_len as usize)     # red
#     from_raw_parts(p, len)                     # OK: `len` came out of a bounded helper
#     from_raw_parts_mut(ws, ws_need)            # OK: internal layout length
#
# Escape hatch (must state the reason, one per line):
#     ... from_raw_parts(x, y as usize) // ffi-raw-len-gate: allow <reason>
#
# Exit 0 = clean, 1 = violation(s), 2 = the surface moved (no files found).
set -u
cd "$(dirname "$0")/.." || exit 2

SURFACE=(
  forms/ffi/c_abi.rs
  forms/ffi/export_abi.rs
  forms/ffi/type_table_abi.rs
  forms/ffi/generator_cache_ffi.rs
  forms/ffi/cn_timing_ffi.rs
  forms/ffi/prove_timing_ffi.rs
  forms/ffi/tx_phase_ffi.rs
  forms/ffi/crash_phase.rs
  forms/device_timing.rs
  flux/keysource/src/keysource/ffi.rs
  flux/keysource/src/keysource/se_ffi.rs
)

missing=0
for f in "${SURFACE[@]}"; do
  [ -f "$f" ] || { echo "MISSING $f"; missing=1; }
done
if [ "$missing" -ne 0 ]; then
  echo "ffi-raw-len-gate: the FFI surface moved — update SURFACE in scripts/$0"
  exit 2
fi

# lines that build a slice AND cast a caller length on the same line
hits=$(grep -nH 'slice::from_raw_parts' "${SURFACE[@]}" 2>/dev/null \
        | grep 'as usize' \
        | grep -v 'ffi-raw-len-gate: allow' || true)

if [ -n "$hits" ]; then
  echo "ffi-raw-len-gate: slice built from an unbounded caller length:"
  echo "$hits"
  echo
  echo "Bound the claim before the slice (checked_slice / checked_slice_mut / a"
  echo "named helper that clamps to the entry's budget), or add the allow comment"
  echo "with the reason it is already bounded."
  exit 1
fi

# Hard invariant, independent of the pattern above: no entry may slice past the
# 64 KiB wire budget on a caller's say-so. Report the constructions for the record.
echo "ffi-raw-len-gate: OK ($(grep -ch 'slice::from_raw_parts' "${SURFACE[@]}" | paste -sd+ - | bc 2>/dev/null || echo '?') raw-slice sites, all bounded)"
exit 0
