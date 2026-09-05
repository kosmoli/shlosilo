# shlosilo XMR 多输入签名 — 新 Session 交接

## 背景(一个段落)

shlosilo(Rust 硬件钱包签名库,`~/works/shlosilo-poc4`)刚完成 GPT 连续 11 轮对抗性审计的整改,当前 main = `cec9ec6`,745 tests 全绿,审计台账在 Obsidian `shlosilo/GPT审计整改落实.md`。审计发现的最大功能缺口是:**XMR 签名只支持单输入**(`tx_signer.rs:427` 处 `sources.len() != 1` 直接拒绝,标注"P1-06 范围,多输入排期后续")。GPT 暂不可用,新整改暂时无法送审,所以现在开工多输入功能。注意:连续 4 轮审计的规律是"整改一种缺陷时在另一维度引入新缺陷"(封装 vs totality、清零时机 vs 协议语义、Copy 语义),写代码时两面同查。

## 任务:XMR 多输入签名

### 当前实现(单输入假设散布在这些位置)

- `src/chain/xmr/tx_signer.rs:427` — 形状检查 `sources.len() != 1 → Err`
- `:555-558` — CLSAG 伪输出掩码:单输入时 `pseudo_mask = sum_out_masks`(monero-clsag `sum_outputs` 语义);多输入的正确公式是 `pseudo_mask[i] = sum_out_masks − Σ_{j<i} pseudo_mask[j]`(官方 genRctSimple: `a[last] = Σout_masks − Σprev_pseudo`)
- `derive_input_from_source` / `derive_input_spend_key` 已按 source 迭代,owner 容器(`ZeroizingMaskGuard`,带 kind 标签)已支持多元素
- 测试基础设施:`signer_clsag_failure_populates_then_drops_owner`、`multi_input_rejected_before_guard_populated`(2 source 手工构造 TxConstructionData 的模式可直接复用)

### 关键约束(审计红线,违反会被下一轮复审打回)

1. **secret owner 纪律**:所有 Scalar 秘密用 `types/secret_scalar.rs::SecretScalar`(dalek Scalar 是 Copy+无 Drop,禁止普通绑定跨 `?`);字节数组用 `SecretBytes<32>`/`Zeroizing`;"从产生即 owner",不用 `let mut x = x` shadow Copy
2. **API totality**:压缩点解压必须 fallible(`mul_point` 返回 Result),禁止 expect/panic——敌对点编码可从签名请求到达
3. **清零时机**:缓冲清零必须在最后一个消费者之后(`Vec::zeroize` = clear+擦 capacity,清早了破坏协议语义——审计#8 的 P0 就是这么来的)
4. **每项"声称的行为"要有会失败的测试**(连续三轮被 GPT 抓"声称与代码不符")
5. 形状检查位置:多输入放开后,原"任何秘密 owner 建立前拒绝"的断言改为验证 guard 未被填充(静态影子 `SHADOW_POST_DROP` 带 kind 标签可归因)

### 完成定义

- CLSAG 多输入密码学正确(pseudo_mask 链式推导,逐输入 real_mask)
- `multi_input_rejected_before_guard_populated` 测试删除或反转为成功用例
- change/subaddress 分支 KAT(审计 ⬜ 项顺带关闭)
- 真实多输入 signer 成功路径测试 + 失败路径测试(手工构造 TxConstructionData,不用 env)
- 745+ tests 全绿,clippy/fmt/cbindgen exact diff/Miri 双组并行/release 全门禁
- 真机构建(`bash scripts/build_forgebox_bin.sh` → forgebox.bin)与刷机回归另算

### 参考

- 官方语义:monero `genRctSimple`(wallet2)/ keystone transfer.rs;pseudo_mask 链式推导见 `tx_signer.rs:555` 注释
- 单输入 fixture:`tests/fixtures/txset_plain.bin`;端到端(ignored,需 env):`tests/p1_06_xmr_business.rs`
- 审计台账:Obsidian `shlosilo/GPT审计整改落实.md`(审计 #6-#11 的 secret owner 纪律演化全过程)
- **cec9ec6 尚未经 GPT 复审**(GPT 暂不可用),多输入的 diff 会和它一起进入下次复审
