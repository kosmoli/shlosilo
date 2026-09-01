#!/bin/bash
# 审计 #5 开-03:Miri 子集 harness
# 范围:纯 Rust、无 C FFI / 无汇编 / 无外部 crate FFI 的模块
# 用法: bash scripts/miri_subset.sh [--quick]
# Miri 慢 ~50x;--quick 只跑核心安全边界模块
# 注:proptest 测试需要 MIRIFLAGS disable-isolation(getcwd 取种子文件)
set -uo pipefail
cd "$(dirname "$0")/.."

TOOLCHAIN=nightly-2026-05-22
export MIRIFLAGS="-Zmiri-disable-isolation"
FAIL=0
MODULES=(
    "types::secret_bytes"      # 审计 #5 P0-03 核心防线
    "derivation::path"         # MAX_DEPTH 边界
    "encoding::cbor"           # 不可信输入解码
    "encoding::base58"
    "encoding::bytewords"      # multipart 帧编码
)

if [[ "${1:-}" != "--quick" ]]; then
    MODULES+=(
        "encoding::fountain"   # 消元/work budget
        "entropy::mnemonic"
        "entropy::dice_rolls"
    )
fi

echo "=== Miri subset (toolchain=$TOOLCHAIN, MIRIFLAGS=$MIRIFLAGS) ==="
for m in "${MODULES[@]}"; do
    echo "--- cargo +$TOOLCHAIN miri test --lib $m"
    if cargo "+$TOOLCHAIN" miri test --lib "$m" 2>&1 | tail -3; then
        echo "OK: $m"
    else
        echo "FAIL: $m"
        FAIL=1
    fi
done

exit $FAIL
