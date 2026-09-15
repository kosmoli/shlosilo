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
