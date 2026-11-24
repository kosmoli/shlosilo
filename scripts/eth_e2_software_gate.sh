#!/usr/bin/env bash
# =============================================================================
# ETH E-2 software acceptance gate — the hardware-free verdict.
#
# "Is the ETH exit acceptable?" without a wallet and without a board. Four
# independent oracles, each answering a different question:
#
#   1. mainnet recovery   — is our EIP-1559 digest and `v` semantics the one
#                           consensus accepts? Two real mainnet transactions,
#                           published signed bytes + published sender: recompute
#                           the hash with our code, recover the signer, compare.
#                           (tests/eth_mainnet_recovery.rs)
#   2. reference bytes    — does our personal_sign match the reference
#                           implementation byte for byte? keystone's published
#                           65-byte EIP-191 signature.
#                           (tests/eth_keystone_cross_validation.rs)
#   3. container + exit   — does the sign path emit the container the dialect
#                           expects (requestId echoed, r||s||v, v = yParity for
#                           1559 and 27/28 for EIP-191)? (lib pins)
#   4. wallet parser      — does the parser real wallets use accept our frames
#                           and read the same fields? keystone SDK 0.12.1.
#                           (tools/sdk-gate/run.mjs)
#
# What it does NOT prove: that a wallet's UI shows something sensible, and that
# a device build behaves like the host. Those need the board (E-2 hardware leg).
#
# Run from anywhere: bash scripts/eth_e2_software_gate.sh
# =============================================================================
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0
step() { printf '%-34s' "$1"; }

step "1. mainnet 1559 digest + v:"
if cargo test --offline --test eth_mainnet_recovery > /tmp/e2_mainnet.log 2>&1; then
    n=$(grep -c "^test .* ok$" /tmp/e2_mainnet.log)
    echo "PASS ($n pins)"
else
    echo "FAIL (see /tmp/e2_mainnet.log)"
    fail=1
fi

step "2. keystone EIP-191 bytes:"
if cargo test --offline --test eth_keystone_cross_validation > /tmp/e2_keystone.log 2>&1; then
    n=$(grep -c "^test .* ok$" /tmp/e2_keystone.log)
    echo "PASS ($n pins)"
else
    echo "FAIL (see /tmp/e2_keystone.log)"
    fail=1
fi

step "3. container + exit pins:"
if cargo test --offline --lib -- eth_signature sign_eth > /tmp/e2_exit.log 2>&1; then
    n=$(grep "test result" /tmp/e2_exit.log | head -1 | sed 's/.*ok\. \([0-9]*\) passed.*/\1/')
    echo "PASS ($n pins)"
else
    echo "FAIL (see /tmp/e2_exit.log)"
    fail=1
fi

step "4. keystone SDK parse:"
art=$(mktemp -d /tmp/e2_sdk.XXXXXX)
if cargo run --offline --quiet --example dump_sdk_artifacts -- "$art" > /tmp/e2_dump.log 2>&1 \
   && ( cd tools/sdk-gate && node run.mjs "$art" ) > /tmp/e2_sdk.log 2>&1; then
    n=$(grep -c "^ok - " /tmp/e2_sdk.log)
    ethn=$(grep -c "^ok - eth_signature" /tmp/e2_sdk.log)
    echo "PASS ($n SDK checks, $ethn on the ETH container)"
else
    echo "FAIL (see /tmp/e2_sdk.log)"
    fail=1
fi
rm -rf "$art"

if [ "$fail" -eq 0 ]; then
    echo "=== E-2 software verdict: PASS ==="
    exit 0
fi
echo "=== E-2 software verdict: FAIL ==="
exit 1
