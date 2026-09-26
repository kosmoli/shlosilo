# vendor 基线台账（T-12，2026-09-25 固化）

> Z5 动刀前置。统一规范：**可回放真 diff 为主**（`patches/baseline/*.diff`，`patch -p1` 干净应用、
> 回放 == 树，逐树已验证），in-tree 注释 + 版本锚点为辅。
> 排除项（构建产物/锁文件，非树内容）：`target/`、`Cargo.lock`、`.cargo-checksum.json`、`.cargo-ok`。
> 校验：`bash scripts/vendor_baseline_check.sh`（重放全部 7 树并断言零余量）。

| 树 | Provenance（锚点） | 基线 diff（回放 ✓） | 修改簇 | 退出条件（状态/计划） |
|---|---|---|---|---|
| quircs 0.10.2 | crates.io tarball | `quircs-vs-crates-io-0.10.2.diff` | no_std 化（thiserror→手写 Display、libm::round 等）——`patches/quircs-no-std.patch` 散文档全 | **观察哨**（计划）：dignifiedquire/quircs 出现 no_std feature/PR 即撤 |
| rqrr 0.11.0 | crates.io tarball | `rqrr-vs-crates-io-0.11.0.diff` | no_std 化 + g2p 消费调整——`patches/rqrr-g2p-no-std.patch` 散文档 | **观察哨**（计划）：上游 no_std 化即撤 |
| g2p 1.2.2 | crates.io tarball | `g2p-vs-crates-io-1.2.2.diff` | no_std 化（std-only 面删除、libm）——同上联合 patch 散文档 | 同 rqrr |
| g2poly 1.2.2 | crates.io tarball | `g2poly-vs-crates-io-1.2.2.diff` | no_std 化——同上联合 patch 散文档 | 同 rqrr |
| curve25519-dalek 4.1.3 | crates.io tarball | `curve25519-dalek-vs-crates-io-4.1.3.diff` | ①generator-cache（`patches/curve25519-dalek-generator-cache.patch` 散文档）②perf-bench 入口（src/perf_bench.rs +196，in-tree 标注）③straus-compact-codegen 属性 ×6（in-tree 标注；T-11 A/B）④非源裁剪 benches/CHANGELOG/Makefile 等 | **观察哨**（计划）：上游出等价 generator-cache API 即撤；升级时按 patch 头 reapply 流程 |
| cryptonight 0.1.0 | **git 子树**：Cuprate/cuprate `cryptonight/` @ `cf3137b7579b`（2026-02-10；入树 2026-08-28 前该目录最后上游提交） | `cryptonight-vs-upstream-cf3137b7579b.diff` | 下游特化（深度修改 CryptoNight 共识逻辑——Kosmo 判据允许：协议冻结 + 官方测试向量钉正确性）+ cn_timing_hook（shlosilo 新增） | **观察哨**（T-13 A2 已定）：上游 no_std 化即撤（watch `cryptonight/`） |
| monero-bulletproofs 0.1.0 | **crates.io tarball**（VENDOR.md 为准；入树 2026-09-03。树内 `.cargo_vcs_info.json` 记上游 commit） | `monero-bulletproofs-vs-crates-io-0.1.0.diff` | ①build.rs 去栈大数组（VENDOR.md 文档）②generator_cache_hook（新增）③prove/phase 计时探针（PhaseProbe）④tests 面调整 ⑤**Z5.1 API 边缘借用化**（prove/prove_plus/witness 收 `&[Commitment]`，wipe 责任移交调用方 forms Zeroizing owner——2026-09-25，纯内存管理，BP+ wire 字节钉未动）⑥**Z5.2 生成器表出堆**（`Generators` 借用型 + `provide_generator_table_storage` 调用方点表缓冲 + `init_tables` 就地填充/`leak_vec` 过渡回退 + 生成模板存储分支——2026-09-26，表内容逐点=参考表钉死） | **计划**（无真链接）：上游合等价修复 + 发版（>0.1.0）+ 回归过后撤——见 VENDOR.md |

## 结论

- **7/7 树回放验证通过**：`diff -ruN a b` 产物经 `patch -p1` 应用于干净基准后 == 当前树（零余量）。
- 全部修改簇均有归属：3 份散文 patch 文档 + in-tree 标注 + shlosilo commit 链；**未发现无归属漂移**。
- 曾误用 git 子树做 monero-bulletproofs 基准（差分混入上游发布差异）——按 VENDOR.md 的
  crates.io provenance 重打后归位（教训：**先读树内 provenance 记录再选基准**）。
- 退出条件诚实状态：6 树为「观察哨」（计划性，无 PR/issue 真链接）；monero-bulletproofs 为
  「计划」（VENDOR.md 条件完整但无链接）。按 T-12 规范：无链接 = 计划而非状态，不冒充。

## Z5 手术目标位（供动刀引用）

- monero-bulletproofs：`Vec<Commitment>` 生成器边缘 5 站点（rct_sig prove_plus / clsag ring 组装）——
  patch 不碰密码学语义 + oracle 互验（keystone monero 源）。
- curve25519-dalek：generator-cache 簇升级/撤除随上游；perf-bench/straus 簇随 T-11 裁定。
- cryptonight：深度特化保持（T-13 定案）。
