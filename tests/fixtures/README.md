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

## unsigned_txset_1in_fresh.bin / signed_txset_1in_fresh.bin

- **来源**: 全新收官链（2026-09-15 深夜）——A' 充值 0.0009 → watch-only（key images 校正后）
  `transfer 0.0006 → p2in` 生成 unsigned；设备（fce3d9d）签名产出 signed。
- **unsigned**: 1,970 B；sha256 `f97b60ac…`；**单输入**（0.0009）/ 2 输出（0.0006 + 找零 0.00026942；
  fee 30,580）。
- **signed**: 3,986 B；sha256 `c89ba0fc…`；固定熵（0x77×32）A/B —— **设备输出与 host 参考逐字节一致**。
- **链上记录**: `submit_transfer` 提交 → 打包 **h=3763123**，tx
  `2d2c40d1c22d9a4cb140d46b46fd5114f389a864f1767d872e1a862f55ce5ca3`（收款方 p2in 0.0006 已确认；
  发送方输入 spent=True、找零入账）。
- **用途**: 单输入回归 vector + 设备固件输出对照（signed 文件是设备签名回归的期望值）。
- **隐私**: 主网小额测试钱包数据，无真实资金。

## tx2_cake_real_unsigned.bin

- **来源**: 真实 Cake Wallet 构造的 unsigned 容器（tx2 案：add-keys funding tx 的 change
  input；2026-10-17 归档，d0cd00c 取证探针同批）
- **网络**: Monero mainnet
- **大小**: 2,068 bytes
- **SHA-256**: `5a20f5288bd024d0150518dc30ea94b416b4a252b0d9f1731da517e1c212aa1a`
- **用途**: `tests/tx2_whitebox_tools.rs` 两个 CI pin 的唯一输入——
  `sign_real_cake_unsigned_addkeys_change_input`（MUST-RED 红钉：add-keys
  change input 签名路拒收）+ `control_sign_real_cake_unsigned_addkeys_stripped_signs`
  （剥 add-keys 后必过，证明 key 选择是唯一 blocker）
- **隐私**: 加密于 `TX2_LAB_VIEW_SK`（lab 测试钱包 view key，密钥本身已内嵌
  `tests/tx2_whitebox_tools.rs` 公开）；容器不含任何 spend secret。按「公开 fixture
  密钥可内嵌进仓换覆盖」政策入库——pin 须 enforced 进 CI，不留 env 门禁。
- **⚠️ 入库教训**: `.gitignore` 的 `*.bin` 规则会静默吞掉新 fixture（本文件曾因此缺席，
  clean-checkout CI 39365890921 编译挂）——新增 fixture 后必须 `git add -f` 并
  `git ls-files` 核实真在索引里。

## test0830_outputs_all.bin / test0830_cli_ki_all.bin

- **来源**: monero-wallet-cli（test0830 主网测试钱包，曾收 0.001 XMR 实验金）：
  `export_outputs all`（output export 请求容器）+ `export_key_images all`
  （CLI 自算 key image **金标**容器）。2026-10-08 watch-only 对拍实验产出，
  原存 `/tmp/test0830_*`（real_fixture.rs 的 ignored 材料），2026-10-20 入库。
- **网络**: Monero mainnet
- **大小**: 240 / 260 bytes
- **SHA-256**: `2f3e238ae3de63452521d8311a6cdf6fb2dc52e429847bab668f2ebc3d9f59ee` /
  `504395b804b72160668caecd755f058ab4d7474ed9a319c56ddbc1d48b3a68cb`
- **用途**: `tests/golden_wallet2_bytes.rs` —
  output export 金标（容器 magic 版本字节 `\x04` + 明文 epee 解析字段逐项钉值）；
  key image export 金标（**我方计算的 key image == CLI 自算金标 32B 逐字节**；
  容器版本字节 `\x03`；record wire parse→re-serialize 恒等；64B 伴随签名/信封
  含随机 nonce，只验签不比字节）。
- **隐私**: 主网测试钱包（dust 级）；spend/view 密钥内嵌
  `tests/golden_wallet2_bytes.rs`（`TEST0830_*_SK_HEX`），按「公开 fixture 密钥
  可内嵌进仓换覆盖」政策（tx2 先例）。⚠️ 含 spend secret——若 Kosmo 不接受，
  撤下密钥改 env 门禁即可（测试代码已集中两个常量）。

## unsigned_fc_addkeys3.bin

- **来源**: `~/works/xmr-stagenet-lab/watchonly_probe/signed_rt/fc/unsigned_monero_tx`
  —— monero-wallet-cli v0.18.5.1 `--stagenet` watch-only `transfer` 产出（真链
  add-keys 形状：注资 tx 付两个 own subaddress → extra 带 **3 条 additional tx
  keys**；SIGNED_TX_PARSE_FAIL_REPORT.md §9.2）。
- **网络**: Monero stagenet
- **大小**: 2,752 bytes
- **SHA-256**: `78f5528192e2e9de49b5f7cd2270d450b77623808495b10f0b0d19a5defbe58f`
- **用途**: `tests/golden_wallet2_bytes.rs` — 池 §40「additional_tx_keys 非空真链
  情形」的 parse→re-serialize 逐字节对拍（fixture guard 断言 add_keys==3）。
- **隐私**: stagenet 实验钱包；lab 密钥由公开 fixture 熵 `[0x22;32]` 派生（已在
  `tests/xmr_subaddr_sign_roundtrip.rs` 公开），无真实资金。

## unsigned_fa_subaddr.bin / unsigned_fb_change.bin

- **来源**: 同批 `signed_rt/{fa,fb}/unsigned_monero_tx`（wallet2 CLI watch-only
  `transfer`）：F_A = subaddress-input 形状（spend from index 1）、F_B =
  change-input 形状（change 回 own address，主 tx key 派生）。
- **网络**: Monero stagenet
- **大小**: 1,970 / 1,974 bytes
- **SHA-256**: `6fa318d3a5a3ada2b6adc29b882e4affcbbc07e59938aa1256e05df6f65e7e8f` /
  `f0ba89f6db649899b0410508fc764d7db2e491dfcbf001799bb0f2dff4faf251`
- **用途**: `tests/golden_wallet2_bytes.rs` — 两种真链 source 形状的
  parse→re-serialize 对拍；fa 另作固定熵 re-sign 金标的输入。
- **隐私**: 同 fc。

## gold_signed_fa.bin

- **来源**: `signed_rt/fa/gold_signed.bin` —— **monero-wallet-cli v0.18.5.1
  `sign_transfer` 自签金标**（2026-10-16 三重对拍轮，SIGNED_TX_PARSE_FAIL_REPORT §3）。
- **网络**: Monero stagenet
- **大小**: 4,110 bytes
- **SHA-256**: `a07804aeef14c995fa86859e85441b806a8bdd6dca09dc4e05fb7816d702d462`
- **用途**: `tests/golden_wallet2_bytes.rs` — **跨实现**确定性区段逐字节对拍：
  我方签名明文前 78B（ring 偏移 + key image）== wallet2 金标明文前 78B；
  78B 后按设计分歧（vout output key 含随机 r），首个分歧点=78 被钉死。
- **隐私**: 同 fc（加密于 lab view key 下；key 由公开 fixture 熵派生）。

## ours_signed_fa.bin

- **来源**: `signed_rt/fa/ours_signed.bin` 一脉的我方产出 ——
  `xmr_subaddr_sign_roundtrip::sign_real_fixture_for_wallet2_compare` 同路径
  （`business::sign::sign_with_entropy`，wallet 熵 `[0x22;32]`、签名固定熵
  `0x77×32`）host 侧重生成。**2026-10-20 重生成**（construction_data.extra
  修复后 signed wire 变更：per-tx context digest 吸收 `extra`，该 digest 参与
  派生 tx key `r`，故整笔 tx 全变；同时现 writer 的 `key_images` 为
  wallet-indexed 填充）。旧件（2026-10-16，3,937 B，sha256 `253f1a68…`，
  `submit_transfer` 全流程接受）已退役。
- **网络**: Monero stagenet
- **大小**: 4,013 bytes
- **SHA-256**: `e582f0f9e0649bbe523f3c3c1d702cb65f34267afa71207b78103aa8e022a0d4`
- **用途**: `tests/golden_wallet2_bytes.rs` — 固定熵 re-sign 确定性金标：
  **整容器逐字节恒等**（信封 + tx_bytes（vout keys + CLSAG）+ construction
  data（含 `extra`）+ key_images 尾部）。跨实现对拍的「我方」一侧亦取此件。
- **隐私**: 同 fc。

## st1019_signed_container.bin / st1019_signed_plain.bin

- **来源**: 2026-10-19 手机双花案取证（池 §47）：`~/works/1019-st/` 30 帧 QR 照片
  → fountain 重组出真机容器（原 `/tmp/st1019_blob_full.bin`）+ 其解密明文
  （原 `/tmp/st1019_plain_full.bin`，/tmp 会被清理故入库）。
- **网络**: Monero mainnet（tx2 案真链流程）
- **大小**: 5,865 / 5,772 bytes
- **SHA-256**: `fbe7ef83da221037fe666497f8ea77d798e760dc18779ebee248f67e84cde55f` /
  `99416f22dfe9fb3dca07763ea86d6eb052623ddc8bb63434f7c4f151f6a2d087`
- **用途**: `tests/golden_wallet2_bytes.rs` — 真机流程容器
  **decrypt == 金标明文逐字节**（信封验签 + ChaCha keystream 全链恒等）。
  signed 明文无 parser → parse→re-serialize 面为缺口（见任务报告）。
- **隐私**: 主网 tx2 lab 钱包产物；容器不含 spend secret；解密 view key 由公开
  fixture 熵 `[0x22;32]` 派生（已随 `TX2_LAB_VIEW_SK` 公开）。

## oracle_unsigned.bin

- **来源**: wallet2 `monero-wallet-rpc` `transfer` JSON-RPC 响应截留
  （2026-10-07，`/tmp/unsigned_resp.json` → `take_oracle.py` 抽出
  `unsigned_txset`；amount 150000000 / fee 30580000，单输入）。
- **网络**: Monero mainnet（DEV 钱包 A'）
- **大小**: 2,045 bytes
- **SHA-256**: `17ac0c377378ac3738fc55d041599cb2db7f4ac21df2e2aad4df5070369c7c97`
- **用途**: `tests/golden_wallet2_bytes.rs` — wallet2 **RPC 路径**产出的 unsigned
  容器 parse→re-serialize 对拍（与 CLI 路径互补）。
- **隐私**: 主网测试钱包 A'（DEV，dust 级）；密钥 = 公开 fixture 熵
  （`DEV_WALLET_ENTROPY`，等价于已公开的 `DEV_SPEND_SK`）。


