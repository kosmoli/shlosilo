# P1-06 XMR CLSAG 签名排查交接文档

> 目的：shlosilo（离线签名器，Rust no_std）生成的 Monero CLSAG 交易被 monerod 拒收，
> 自建验证全绿但权威 oracle 拒绝。本文档供外部 LLM（GPT-5.6）作为 prompt 提供线索。
> 生成时间：2026-08-27 晚。所有事实均经工具实证，非推测。

---

## 1. 一句话问题陈述

我们用 `monero-clsag` crate (serai, 0.1.0) 签出 CLSAG，按官方 wire 格式序列化整笔交易，
投递到 monerod `send_raw_transaction`（do_not_relay=true, do_sanity_checks=false）。
monerod 的完整流水线中**只剩 verRctCLSAGSimple(input 0) 失败**——语义检查
(sum check、BP+ verify)、解析、输出格式全部通过。CLSAG 环签名数学与官方实现不一致。

## 2. 当前确凿状态（错误阶梯已推进到底）

错误演进史（每一步都被修复证实）：

1. ~~BTC 风格 varint~~ → 改 LEB128 → parse 通过
2. ~~HF15 输出非 tagged key~~ → 加 0x03 view tag → invalid_output 通过
3. ~~pseudo_mask 语义错位~~ → sum_outputs=Σ输出masks → RCT semantics 通过
4. ~~"Failed to check ringct signatures!"~~ → 定位仅 RCTTypeFull 路径，type=6 走 CLSAGSimple
5. **当前：verRctCLSAGSimple failed for input 0，静默 return false，无日志**

PERF 日志实证：verRctSemanticsSimple 通过 → verRctNonSemanticsSimple 失败在 CLSAG 批验内层。

## 3. 已彻底排除的方向（每项都有实证）

| # | 排除项 | 实证方法 |
|---|---|---|
| 1 | ring 数据错误 | fixture ring outputs[13].dest=24a6ee72… mask=2287fdb3… 与 get_outs 返回逐字节一致；本轮又对全部16个 output 用 get_outs 批量比对全对 |
| 2 | prefix_hash vout amount | TxOutput::serialize 曾用 8B LE，已改 varint(0)；new_tagged 传 0 |
| 3 | wire 布局错位（BP+ L/R count） | 之前怀疑 monero-bulletproofs write_vec 的 varint(len) 是 bug——**证伪**：链上真实 BP+ 交易实测 L/R 各带 varint(7)，serai 与官方一致 |
| 4 | wire 布局错位（609 vs 640） | 之前诊断脚本漏读 R 的 count varint 导致假线索——修正后 remain=608=ss[16]·32+c1/D64+po32 精确吻合。wire 无任何错位 |
| 5 | CLSAGs/pseudoOuts/s 多写或漏写 count | 官方 pool tx JSON: key_offsets=16 == CLSAGs[0].s=16 == pseudoOuts=1；rctTypes.h 注释明说 "save its arrays without the size prefixes"。我们的 wire 与之逐字节吻合 |
| 6 | ecdhInfo 写 64B/输出 | rctTypes.h:368-381：BP+/CLSAG 只写 8B trunc_amount。base=85B 已对齐 |
| 7 | ring commitment 语义用错 | OutputEntry.mask 是链上 C 点（非 blinding），曾错当 blinding 重算所有 C——已修：ring 直接传 C 点字节，real blinding 用 TxSourceEntry.mask (=ccd0f90c…真blinding) |
| 8 | input_sk 派生 | monero-clsag sign 内部 assert sk·G==ring[real].dest 通过；keystone 官方向量 7 passed |
| 9 | msg_hash 三段式公式 | get_pre_mlsag_hash = keccak(prefix‖H(base)‖keccak(A,A1,B,r1,s1,d1,L*,R*))，与 device_default::mlsag_prehash 一致；python 独立重算一致 |
| 10 | pseudo_out/dummy mask 公式 | genRctSimple a[last]=Σout−Σin；单输入 pseudo_mask=Σout_masks（库内自洽） |

## 4. 值得怀疑的地方（按嫌疑排序）

### S1【最大嫌疑】hash_to_point / Hp 实现
- monerod 用 ref10 `ge_fromfe_frombytes_vartime`；serai `monero-generators` 用 curve25519-dalek isogenous 映射 + mul_by_cofactor。
- **两者数学上等价，但如果我们的调用链某处用了错误的 H 定义**（例如把 bp 的 H 和 clsag 的 H 混淆，或 INV_EIGHT 因子重复应用/遗漏），c_to_hash 中 R = s·Hp(dest) + c_p·I + c_c·D₈ 会整体偏移。
- 具体代码位置：`src/chain/xmr/subaddress.rs` hash_to_scalar/hash_to_point；`~/.cargo/registry/src/*/monero-ed25519-0.1.0/src/*`（serai Point/H）。
- 排查方法：打印库的 Hp(pub) compressed bytes 前3个 ring member，python 版对照官方 ref10 实现验证点在曲线上且等于官方值。

### S2 D 因子的对称性（历史坑，未完全关闭）
- 官方 CLSAG_Gen: sign 时 wire sig.D = D_raw·INV_EIGHT（rctSigs.cpp:271）；verify 用 scalarmult8(sig.D) 进 precomp，但 c_to_hash 里 c_c 乘的是 **D_8 = scalarmult8(sig.D)**（即 D_raw 原值）。
- serai lib.rs:291-303 sign 端 D = H·mask_delta·inv_eight(wire)；verify 端 D_torsion_free=D·8。
- 我们 pseudo_mask=Σout_masks ⇒ mask_delta = real_mask − pseudo_mask？**这个减法的方向**（real−pseudo 还是 pseudo−real）如果错了，D 点符号反向 → R 全错 → c 链断裂。
- 官方公式：mask_delta_i = mask_pseudo_outs[i] − Σ(mask_others)。单输入时 = a_real − Σa_out？？请重点核对这条！
- 代码位置：`src/chain/xmr/tx_signer.rs` pseudo_mask_bytes 计算；`~/.cargo/registry/src/*/monero-clsag-0.1.0/src/lib.rs` :291-303。

### S3 mu_P/mu_C 输入串接细节
- 官方：`mu_P_to_hash = domain ‖ pub.dest×n ‖ pub.mask×n ‖ I ‖ D ‖ C_offset`，domain 为 `HASH_KEY_CLSAG_AGG_0`(17字节)。
- 风险点：serai 是否完全同序同长度？若 serai 在串接里混入变长编码差异（如 domain 长度 17 vs 18），mu_P 错→L/R 全错。但 serai 有官方测试向量通过，**除非我们喂进去的顺序/内容有出入**。
- 需核对我们在 Rust 侧传给 ctx 的 ring 顺序是否被 sort 过（src.outputs 顺序 vs offs 排序后的顺序——**这两个必须一致**！）。
  - ⚠️ tx_signer.rs:337-341 对 offs 做了 sort_unstable + 差分，而 ring 的构造 (:359-364) 直接按 src.outputs 原始顺序。
  - 若 wallet2 给的 outputs 数组本来就是升序则无害；若不是，key_offsets 与 ring positions 错位，monerod 还原的全局索引就会指到不同 output —— 这是 **目前第二可疑点**（见 S4）。

### S4 offs 排序与 ring 顺序一致性（新发现的结构性风险）
- key_offsets 绝对→相对差分必须基于**升序**索引；ring 数组顺序也决定 verify 时 pubs[i] 位置。
- 如果 src.outputs 原始顺序 ≠ 升序（wallet2 不保证），我们 sort 了 offs 却没同步重排 ring —— ring[i] 与第 i 个 offset 不再对应 → monerod 用链上 outs[offs还原] 对不上的 dest/mask 参与 L/R 计算 → 验签失败而其他一切正常。
- 实证待做：dump src.outputs 的 index 顺序是否单调递增。fixture 打印过 out[0..15] idx 单调升（161457186→162125374），**如果是严格升序则此项排除**——需要确认全部 16 个连续无乱序。

### S5 BP+ 元素进入 msg_hash 的通道
- signature_write Plus 分支产物包含 L/R 的 varint count；get_pre_mlsag_hash 官方代码把 bpp 串接时用的是 `rv.p.bulletproofs_plus[i]` 整体（含其内部 Field 序列化——官方 for loop FIELDS 串接 A,A1,B,r1,s1,d1,L,R，其中 L/R 在 binary_archive 下 begin_array() 无参不写 count? 还是 begin_array(size_t) 写 varint？）
- **矛盾点**：链上 wire 有 count（实测），但 mlsag_prehash 的 kv_hash 计算可能不含 count（因为 get_pre_mlsag_hash 用 ar.begin_object + tag 方案重新序列化）。如果我们把 wire 字节（带count）直接当 kv_hash 输入，msg_hash 就和官方差一个 2 字节 → CLSAG 必挂且其余全过。
- 官方代码：get_pre_mlsag_hash (rctSigs.cpp:602-678) 用自己的 ar 序列化 bulletproofs；**请 GPT 重点检查此函数中 bpp 部分是否含 vector count**。
- 代码位置：`src/chain/xmr/tx_signer.rs:405-415`（signature_write 产物直接进 full_msg_in）。

## 5. 关键文件路径（可按需贴给 GPT 对照）

```
/home/komo/works/shlosilo-poc4/src/chain/xmr/
  ├── tx_signer.rs     (566行) 签名编排、prefix/rct base 组装、wire 序列化 build_official_wire(:505)
  │                           :320 new_tagged(0,…)，:405-415 msg_hash 构造,
  │                           :337-341 offs sort+差分, :359-364 ring 构造, :442-456 clsag::sign 调用
  ├── clsag.rs         (456行) sign 封装 (ring=(dest,C点)), Decoys/ctx 组装 :133-215, wire_body()
  ├── transaction.rs   (770行) TxOutput serialize/deserialize(varint amount), TxExtra, varint 实现
  ├── subaddress.rs    (543行) hash_to_scalar, derive_input_*, calc_subaddress
  ├── rct_sig.rs       (500行) BP+ prove 封装, RctSig base/prunable 结构
  ├── unsigned_txset.rs(497行) fixture 反序列化 (TxConstructionData/TxSourceEntry/OutputEntry)
  └── commitment.rs    (230行) Commitment::new(mask, amount)

deps:
  ~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/monero-clsag-0.1.0/src/lib.rs
      :486-500 Clsag::write(s raw‖c1‖D), :291-303 sign(pseudo_out=Commitment(mask,amount), mask_delta, D=H·delta·inv8)
  ~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/monero-bulletproofs-0.1.0/src/lib.rs
      :272 specific_write_vec, :295-302 signature_write(raw_vec 无count) vs write(vec 带 count)
  ~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/monero-ed25519-0.1.0/src/*
  ~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/monero-io-0.1.0/src/lib.rs
      :21 write_byte/:26 write_raw_vec(无前缀)/:37 write_vec(带 varint len)

官方参照（只读）:
  /home/komo/codebases/monero/src/ringct/rctSigs.cpp   get_pre_mlsag_hash:602-678, CLSAG_Gen:243-321, verRctCLSAGSimple:875-996
  /home/komo/codebases/monero/src/ringct/rctTypes.h    serialize_rctsig_prunable:427-600, ecdhTuple 特化:368-381
  /home/komo/codebases/monero/src/device/device_default.cpp  mlsag_prehash
  /home/komo/codebases/monero/src/cryptonote_basic/cryptonote_boost_serialization.h

测试/工具:
  tests/p63_xmr_sign.rs           端到端签名 (env 注入私钥), 产出 /tmp/signed_tx.hex (1566B)
  /tmp/getouts_all.json           16个 ring output 的链上 key/mask (已与 fixture 全部对齐)
  /tmp/vmeta.json                 wire 解析出的 message/ss/c1/D/po/I
  /tmp/parse_correct.py           正确的 wire parser
  /tmp/clsag_official_verify.py   python 官方 verify 复刻 (卡在 hash_to_p3 移植)
```

## 6. 请 GPT 优先回答的问题清单

1. **S5（最重要）**：官方 get_pre_mlsag_hash 在串接 bulletproofs_plus 时，L/R 向量的 varint count 到底进不进 kv_hash？请从 monero 源码 binary_archive 行为推导确切结论。
2. **S2**：单输入 CLSAG 中 mask_delta 的准确公式（方向、8 因子位置）；若我们 mirror serai 侧 sign 但 pseudo_mask 来源是"Σoutputs"，与 wallet2 实际写入 unsigned_txset 的关系是否等价？
3. **S1**：serai monero-generators 的 hash_to_point 与 ref10 ge_fromfe 的等价性是否有已知例外（如 cofactor 处理、非规范 y 位、odd-x 分支）？
4. **S3/S4**：serai ClsagContext/sign 的 ring 顺序约定与 offsets 差分顺序必须一致的具体约束；给出一个能检测"offsets 排序破坏 ring 对应"的最小测试设计。
5. 其他你注意到的、我们没列出的可能性（直接指出，不要客气）。

## 7. 复现环境摘要

- monerod 主网 log-level 可调至 3-4，RPC 127.0.0.1:18085（digest auth）
- `/tmp/signed_tx.hex` 为最新拒收 blob (1566B)，可直接 send_raw_transaction 复现
- 签名随机性不影响复现（每次重签都同样失败）
- wallet-rpc 18091 可再产 unsigned_txset fixture（用户授权真实资金测试）

---
*文档由 Kleo 生成于 2026-08-27，基于当日全部实证诊断记录。*
