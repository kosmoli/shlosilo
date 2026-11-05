#!/bin/bash
# Audit #5 open item 03: UBSan C simulator build + smoke
# Compiles sim_l3 with clang's -fsanitize=undefined, links the release .a
# Scope statement (audit #6 engineering item #4 correction): this script
# instruments only the C side, sim_l3. The linked Rust staticlib is a prebuilt
# artifact carrying no UBSan instrumentation — the safety argument for the Rust
# unsafe C-ABI boundary rests on code review + fuzz (target coverage) + Miri
# (pure-Rust subset); this script is NOT a dynamic-UB proof for the Rust side.
set -uo pipefail
cd "$(dirname "$0")/.."

export PATH="$HOME/.cargo/bin:$PATH"
cargo build --release 2>&1 | tail -1

echo "=== UBSan C simulator ==="
clang -Wall -Wextra -fsanitize=undefined -fno-sanitize-recover=all \
    -o /tmp/sim_l3_ubsan flux/host-sim/sim_l3.c \
    -I. -Ltarget/release -lshlosilo -lpthread -ldl -lm 2>&1 | head -5

echo "=== run with UBSan ==="
/tmp/sim_l3_ubsan
rc=$?
echo "UBSan simulator exit=$rc (0 = clean, no UB reported)"
exit $rc
