#!/bin/bash
# 审计 #5 开-03:UBSan C simulator 构建 + smoke
# 用 clang 的 -fsanitize=undefined 编译 sim_l3,链 release .a
# (Rust 侧纯 Rust 无 UB 面;C 侧边界是这里的检查目标)
set -uo pipefail
cd "$(dirname "$0")/.."

export PATH="$HOME/.cargo/bin:$PATH"
cargo build --release 2>&1 | tail -1

echo "=== UBSan C simulator ==="
clang -Wall -Wextra -fsanitize=undefined -fno-sanitize-recover=all \
    -o /tmp/sim_l3_ubsan simulator-l3/sim_l3.c \
    -I. -Ltarget/release -lshlosilo -lpthread -ldl -lm 2>&1 | head -5

echo "=== run with UBSan ==="
/tmp/sim_l3_ubsan
rc=$?
echo "UBSan simulator exit=$rc (0 = clean, no UB reported)"
exit $rc
