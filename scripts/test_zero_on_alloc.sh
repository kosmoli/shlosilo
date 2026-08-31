#!/bin/bash
# P6.4: host 测试端 zero-on-alloc（v2-安全 §3 条款4）
#
# X3 整改（2026-08-31）：原版 export MALLOC_CONF 对 glibc malloc 完全无效——
# MALLOC_CONF 是 jemalloc 专用配置，glibc 不读取；且 jemalloc 的 zero 选项
# 取 boolean 值（zero:true），旧值 zero:1 在 jemalloc 5 也会报
# "Invalid conf value" 而被忽略。实证（/tmp/zerotest：污染堆后重分配）：
#   glibc + MALLOC_CONF=zero:1          → nonzero=4096（无效，旧 bug）
#   LD_PRELOAD jemalloc + zero:true     → nonzero=0（生效）
#
# 机制：jemalloc MALLOC_CONF=zero:true 使 malloc 返回内存清零——让
# 「未初始化读」在 host 测试上表现出确定性行为（读到 0 而非旧密钥残留）。
#
# 用法: bash scripts/test_zero_on_alloc.sh   （代替裸 cargo test）
# 依赖: libjemalloc2（/lib/x86_64-linux-gnu/libjemalloc.so.2）

JEMALLOC=/lib/x86_64-linux-gnu/libjemalloc.so.2
if [ ! -f "$JEMALLOC" ]; then
    echo "ERROR: libjemalloc2 not installed (apt install libjemalloc2)" >&2
    exit 2
fi

# 自检：确认 zero-on-alloc 在本机真正生效（防再次出现"配置存在但无效"）
if command -v cc >/dev/null 2>&1 && [ ! -x /tmp/.zero_on_alloc_selfcheck ]; then
    cat > /tmp/.zero_on_alloc_selfcheck.c <<'EOF'
#include <stdlib.h>
int main(void) {
    char *p1 = malloc(4096);
    for (int i = 0; i < 4096; i++) p1[i] = 0xAA;
    free(p1);
    char *p2 = malloc(4096);
    for (int i = 0; i < 4096; i++) if (p2[i] != 0) return 1;
    return 0;
}
EOF
    cc /tmp/.zero_on_alloc_selfcheck.c -o /tmp/.zero_on_alloc_selfcheck
fi
if [ -x /tmp/.zero_on_alloc_selfcheck ]; then
    if ! LD_PRELOAD="$JEMALLOC" MALLOC_CONF="zero:true" /tmp/.zero_on_alloc_selfcheck; then
        echo "ERROR: zero-on-alloc selfcheck failed — jemalloc zero:true not effective" >&2
        exit 3
    fi
fi

export LD_PRELOAD="$JEMALLOC"
export MALLOC_CONF="zero:true"
exec cargo test "$@"
