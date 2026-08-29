#!/bin/bash
# P6.4: host 测试端 zero-on-alloc（v2-安全 §3 条款4）
# jemalloc 的 MALLOC_CONF=zero:1 使 malloc 返回内存清零——
# 让「未初始化读」在 host 测试上表现出确定性行为（读到 0 而非旧密钥）。
# 用法: bash scripts/test_zero_on_alloc.sh   （代替裸 cargo test）
export MALLOC_CONF="zero:1,narenas:1"
exec cargo test "$@"
