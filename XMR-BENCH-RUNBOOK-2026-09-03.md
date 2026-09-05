# XMR 基准固件烧录与屏幕读数步骤 (2026-09-03 v2 — 无 UART 版)

## 固件
- 产物: `/home/komo/works/keystone3-firmware/build/forgebox-xmr-bench.bin` (6558576B, fwdata header 已验证)
- 变体: WEB3/multi-coins + monero + test_cmd (debug)
- 自测逻辑: `src/utils/xmr_bench.c`（unlock 成功后自动跑一次，屏幕绿字输出）

## 操作步骤
1. SD 卡根目录放 `forgebox.bin`（即上述文件改名）→ 设备 recovery mode 加载
2. **正常解锁设备**（输 PIN/密码，或指纹）——解锁成功即自动开始测试
3. 屏幕会出现绿字（黑底荧光绿），依次显示:
   - `XMR BENCH: start`
   - `parse err=0 XXX ms` ← UR/CBOR 解析耗时
   - `seed ret=0`
   - `phase: sign (CN derive)`
   - （等待，这一步最久）
   - `sign err=N XXXXX ms` ← 签名全程耗时（**抄这个**）
   - `TOTAL: parse X ms, sign Y ms`
   - `XMR BENCH: DONE`
4. 把 `sign` 那行的毫秒数发回来

## 预期与解读
- `sign err` 预期非 0（fixture 加密 key 与设备 seed 不匹配，decrypt 失败），**不影响计时有效性**——CN derive + verify 在 decrypt 之前完成
- PC 模拟器基准: 22.6s（CN IteratedScalar = 2^20 次 AES）
- 设备 M4 @ 无硬件 AES 时可能 3-5 倍慢；若明显更快 → 官方有硬件 AES 路径
- 若绿色字被锁定界面遮挡，按一下电源键息屏再亮屏后重新解锁即可重跑（每次解锁只跑一次，重启可再来）

## 注意
- DEBUG 构建带 test_cmd + 基准钩子，测完刷回官方固件
- 本地 git 改动保留（台账 A.21 证据）: test_cmd.c / xmr_test_cmd.rs / xmr_bench.{c,h} / gui_lock_view.c / Cargo.toml
