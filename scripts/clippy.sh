#!/usr/bin/env bash
# P2-06: clippy 零告警门禁（本地/CI 通用入口）
# 排除 vendor/（第三方代码）；lib 必须零 warning 零 error
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> cargo clippy --lib -- -D warnings"
cargo clippy --lib -- -D warnings

# The Rust-native embedded variant (no c-host-rt) cannot be checked as a
# standalone crate: with the staticlib crate-type, rustc demands the runtime
# lang items (global allocator + panic handler), which the Rust-native
# appearance supplies itself (flux/pico2). That path is validated by
# flux/pico2's own build; here we check the C-host configuration, which is
# what flux/forgebox ships.
echo "==> embedded check (thumbv7em-none-eabihf, C-host staticlib: c-host-rt)"
cargo check --lib --no-default-features --target thumbv7em-none-eabihf --features c-host-rt

echo "==> all green"
