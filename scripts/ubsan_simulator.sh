#!/bin/bash
# 审计 #5 开-03:UBSan C simulator 构建 + smoke
# 用 clang 的 -fsanitize=undefined 编译 sim_l3,链 release .a
# 范围声明(审计 #6 工程项 #4 修正):本脚本只插桩 C 侧 sim_l3;
# 链入的 Rust staticlib 是预构建产物,不含 UBSan 插桩——Rust unsafe
# C-ABI 边界的安全论证依赖代码审阅 + fuzz(target 面已覆盖)+ Miri
# (纯 Rust 子集),本脚本不构成 Rust 侧动态 UB 证明。
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
