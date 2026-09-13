#!/bin/bash
# ForgeBox 真机固件构建（P6.2c 实证路径，2026-08-29 固化）
# 用法: bash scripts/build_forgebox_bin.sh
# 产出: build/forgebox.bin → 拷贝到 SD 卡根目录（文件名必须是 forgebox.bin）
# 设备 recovery 模式加载。USB 仅首次注册公钥可用，之后一律走 SD 卡。
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$REPO/build"
export PATH="$HOME/.hermes/node/bin:$PATH"

# 前置检查
for f in "$BUILD/mh1903.bin" "$BUILD/padding_bin_file.py"; do
    [ -f "$f" ] || { echo "ERROR: missing $f (先跑 cmake --build build)"; exit 1; }
done
[ -f ~/.forgebox/keys/private.pem ] || { echo "ERROR: missing ~/.forgebox/keys/private.pem"; exit 1; }
command -v forgebox >/dev/null || { echo "ERROR: forgebox CLI not in PATH (~/.hermes/node/bin)"; exit 1; }

cd "$BUILD"

# 1. padding: mh1903.bin → mh1903_full.bin（4K 对齐 + APP_END 魔数）
python3 padding_bin_file.py mh1903.bin

# 2. forgebox sign 单层封装（fwdata header + QuickLZ + 双 ECDSA）
#    ⚠️ 输入必须是 mh1903_full.bin；签原始 mh1903.bin 会缺 APP_END → verification failure
#    ⚠️ 不要先跑 fmm 再 sign —— 双层封装 → NO APP
forgebox sign --s mh1903_full.bin --d forgebox.bin --key ~/.forgebox/keys/private.pem

# 3. 验证 header（单层 fwdata 封装的特征字节）
HEADER=$(xxd -l 12 -p forgebox.bin)
EXPECTED="5c0100007e66776461746121"
echo "header: $HEADER"
case "$HEADER" in
    "$EXPECTED"*) echo "OK: single-layer fwdata header confirmed" ;;
    *) echo "WARNING: unexpected header — 对照 PoC 3 成功案例 5c01 0000 7e66 7764 6174 6121"; exit 1 ;;
esac

ls -la "$BUILD/forgebox.bin"
echo ""
echo "下一步: 拷贝 build/forgebox.bin 到 SD 卡根目录 → 设备进 recovery mode 加载"
