# tests/fixtures

测试 fixture 清单(审计 #4 P1-04 要求:来源、网络、SHA-256、用途)

## sparrow_signet_12k.psbt
- **来源**: Sparrow wallet 导出的真实 signet PSBT(P6.3 BTC 互验 fixture,原路径
  `~/testTX/test.psbt`,2026-08-26 signet 广播验证通过)
- **网络**: Bitcoin signet(单输入 P2WPKH,651,157 sat)
- **大小**: 12,437 bytes
- **SHA-256**: `2ff4898ffa9c2ac922e634e48ecfe72a38c2afb51fd748aece94d0fb4c54a934`
- **用途**:
  - `tests/p63_btc_sign.rs` — BTC PSBT 签名端到端(signet 广播已裁决合法)
  - `tests/p63_btc_psbt.rs` — 解析/派生路径/UTXO 类型判定
  - `forms/ffi/c_abi.rs` — P0-C typed sign 12.4 KiB E2E(单帧超限 → multipart 路径)
- **隐私**: 测试网隔离密钥,无真实资金;可公开提交

## unsigned_txset_2in.bin

- **来源**: 本地 monero-wallet-cli watch-only 转账生成(`sh_p2in_view` 钱包 →
  `transfer` → `unsigned_monero_tx`;任务 4 多输入 fixture)
- **网络**: Monero mainnet(单笔 0.0007 XMR;**2 输入** / 2 输出;fee 44,440,000 原子单位)
- **大小**: 3,529 bytes
- **SHA-256**: `f63e774cfd8f5730262744209fe4f8845126139b077fbd5c2ebc035315bf6542`
- **用途**: `tests/p64_xmr_multi_input.rs` — 2-input 解密/解析/签名(host 侧多输入
  回归基线;设备密钥版 fixture 另行生成)
- **隐私**: 主网小额测试钱包(多输入回归原料),无真实资金

## unsigned_txset_2in_dev.bin

- **来源**: 同上流程,但钱包 = **设备确定性钱包**(entropy → Keystone Monero 路径
  m/44'/128'/0'/0/0 → spend/view;地址 4844Nk4X…;`sh_dev_correct` watch-only)
- **网络**: Monero mainnet(2 输入 × 0.00035 / 2 输出;fee 44,380,000 原子单位)
- **大小**: 3,450 bytes
- **SHA-256**: `8c25c47fd3e6dc1d4c6144d7b96c41f71c24c7b20540c496cd4806864e374791`
- **用途**: 设备端 2-input 签名回归输入(`entropy <dev entropy>` + multipart UR
  分帧喂料 + `xmrseed 77×32` A/B;驱动 `flux/pico2/bench/xmr_2in_bringup.py`)
- **隐私**: 主网小额测试钱包,无真实资金(加密于测试钱包 view key 之下)
- **✅ 已广播上链(2026-09-15 主网)**: 设备签名(2-input, 19.27 s, blob 6119 B,
  与 host A/B 逐字节一致 `d504cf77…`）→ 解密提取 raw tx(2219 B, 与 host 测量一致)
  → monerod `send_raw_transaction` **全项验证通过**(double_spend/invalid_input/
  overspend/sanity/low_mixin 全 false)→ 打包 **h=3763087**, tx
  `ebc663d6314c0814dec471b334d5cb4e494aabaad3ab3f6d8cc08806f8c9b6d1`
  (收款侧 p2in 0.00065 已确认)。广播脚本 `flux/pico2/bench/xmr_broadcast.py`。
- **✅ 互操作缺口已修复（2026-09-15）**: 根因 = `tx_destination_entry.amount` 在 monero 里是
  **VARINT**（`VARINT_FIELD(amount)`；与 `tx_source_entry.amount` 的固定 8B 不对称——经典坑）。
  旧 writer 写成固定 u64 → 每个 destination entry 后错位 7 字节 → monero 拒绝整份文件。
  修复后（commit `e0fe4d1`）**两侧均验证**：
  - host 签的文件 → `submit_transfer` 全流程接受（解析 → 确认 → key images → 提交）；
  - **设备（fce3d9d 固件）签的文件** → 同样全流程接受（blob 6098 B，
    sha256 `cf724941…`，与 host 参考逐字节一致；设备输出格式 = 修复后格式）。
  - 固定熵下 txid `ebc663d6…` 与 raw-tx 路径广播的同一交易（修复只改容器不改语义）。


