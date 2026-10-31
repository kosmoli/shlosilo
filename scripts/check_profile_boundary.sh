#!/usr/bin/env bash
# WP1 I1 (C4) — dependency direction: the core must never reference the
# profile layer. `profile → canonical ← core` is the ONLY allowed direction.
#
# Checked: forms/{types,business,chain,ur} + forms/canonical.rs.
# CODE references only — doc-comment prose may name the path; a comment
# creates no dependency. Whitelist: the dispatch registry single file
# (none exists yet; add its path here when the registry lands).
#
# Run: bash scripts/check_profile_boundary.sh   (exit 0 = direction clean)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

WHITELIST=()  # e.g. forms/dispatch.rs (the single sanctioned dispatch point)

CHECK=(forms/types forms/business forms/chain forms/ur forms/canonical.rs)
hits=$(grep -rn "crate::profile\|use crate::profile\|profile::" \
    "${CHECK[@]}" --include="*.rs" 2>/dev/null \
    | grep -v -E "^[^:]+:[0-9]+:[[:space:]]*(///|//!|//)" \
    || true)

# drop whitelisted files
if [ "${#WHITELIST[@]}" -gt 0 ] && [ -n "$hits" ]; then
    for w in "${WHITELIST[@]}"; do
        hits=$(echo "$hits" | grep -v "^$w:" || true)
    done
fi

if [ -n "$hits" ]; then
    echo "PROFILE-BOUNDARY: core references the profile layer (I1/C1 violation):" >&2
    echo "$hits" >&2
    exit 1
fi
echo "PROFILE-BOUNDARY: core clean (no code-level profile references)"
