#!/usr/bin/env bash
# Write the resource-budget report for one platform profile.
#
#   scripts/limits_report.sh [profile]     (default: host)
#
# Production rule: the report is produced by a program *built for the profile it
# describes*, and it records where it ran (`computed_on`). A host report for a 32-bit
# device profile is not authoritative - `size_of::<usize>()` differs - so the per-profile
# numbers only become binding when a carrier produces them on its own target.
#
# Output: build/<profile>/limits-report.json (per-profile directory: two profiles must
# never share a path, or a report can be read back for the wrong configuration).
set -euo pipefail
cd "$(dirname "$0")/.."

PROFILE="${1:-host}"
mkdir -p "build/${PROFILE}"
OUT="build/${PROFILE}/limits-report.json"

SHLOSILO_LIMITS="${PROFILE}" cargo run --offline --locked --quiet \
    --example limits_report > "${OUT}"

echo "wrote ${OUT}"
cat "${OUT}"
