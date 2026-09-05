#!/bin/bash
# 审计 #5 开-04 + 审计 #6 工程项:cargo-fuzz 统一入口(固定 nightly 工具链)
# 背景:cargo fuzz 默认用 stable 会因缺 -Zsanitizer 失败;必须固定 nightly。
# GPT 第五次复审工程项 #1:工具链应统一约束,避免依赖调用者环境。
#
# 用法:
#   bash scripts/fuzz_run.sh              # 每 target 90s smoke(默认)
#   bash scripts/fuzz_run.sh 300          # 每 target 300s
#   bash scripts/fuzz_run.sh 0            # 持续运行(Ctrl-C 停)
#
# 审计 #12: 种子 corpus 入库(fuzz/seedcorpus/<target>/, 固定边界样本),
# 运行时产物(corpus/)继续不入库——CI/干净 clone 有确定性起点, 本地不积累
# 可变产物。fuzz_run 把种子拷入工作 corpus 目录(libFuzzer 无 -seed_corpus
# flag;工作 corpus 持久, 种子随每次运行合并)。
#
# sanitizer 环境选项(重要):
#   ASAN_OPTIONS=detect_leaks=0           # libFuzzer+leak 检测与 alloc 预算测试冲突时用
#   RUST_LIB_BACKTRACE=1                 # crash 时打印 Rust backtrace
#
# 产出:fuzz/artifacts/<target>/ 下 crash-* 文件;无 crash 退出码 0
set -uo pipefail
cd "$(dirname "$0")/.."

NIGHTLY="nightly-2026-05-22"
SECS="${1:-90}"
SEED="${SEED:-20260902}"

TARGETS=(parse_psbt multipart_decoder cbor_eth_sign xmr_unsigned_txset)
rc_total=0

for t in "${TARGETS[@]}"; do
    echo "=== fuzz: $t (${SECS}s) ==="
    # 种子 corpus(libFuzzer 无 -seed_corpus flag;工作 corpus 目录是持久的,
    # 种子拷入后每次运行都包含确定性起点;corpus/ 本身不入库)
    mkdir -p "fuzz/corpus/$t"
    if compgen -G "fuzz/seedcorpus/$t/*" > /dev/null; then
        cp fuzz/seedcorpus/"$t"/* "fuzz/corpus/$t/"
    fi
    if [ "$SECS" = "0" ]; then
        RUSTUP_TOOLCHAIN="$NIGHTLY" cargo fuzz run "$t" -- -seed="$SEED" -rss_limit_mb=2560
    else
        RUSTUP_TOOLCHAIN="$NIGHTLY" cargo fuzz run "$t" -- -max_total_time="$SECS" -seed="$SEED" -rss_limit_mb=2560
    fi
    rc=$?
    if [ $rc -ne 0 ]; then
        echo "FAIL: $t exited $rc (see fuzz/artifacts/$t/)"
        rc_total=1
    else
        echo "OK: $t no crash"
    fi
done

exit $rc_total
