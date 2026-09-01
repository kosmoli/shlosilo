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
  - `src/ffi/c_abi.rs` — P0-C typed sign 12.4 KiB E2E(单帧超限 → multipart 路径)
- **隐私**: 测试网隔离密钥,无真实资金;可公开提交
