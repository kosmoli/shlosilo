#!/usr/bin/env bash
# P2-06: clippy 零告警门禁（本地/CI 通用入口）
# 排除 vendor/（第三方代码）；lib 必须零 warning 零 error
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> cargo clippy --lib -- -D warnings"
cargo clippy --lib -- -D warnings

echo "==> embedded check (thumbv7em-none-eabihf, no default features)"
cargo check --lib --no-default-features --target thumbv7em-none-eabihf

echo "==> all green"
