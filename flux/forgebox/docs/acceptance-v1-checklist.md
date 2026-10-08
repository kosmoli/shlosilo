# 密钥供给 v1 验收清单（设计 §7 三条）

> 操作级（外行照做）。固件、测试钢板、对照工具都在
> `~/works/shlosilo-acceptance-plates/`：
> - `fw/forgebox-product-20261008.bin`（验收①②）sha256 `0817f108b062…`（921,086 B）
> - `fw/forgebox-smoke-20261008.bin`（验收③ SE 面）sha256 `58b545ff91aa…`（892,551 B）
> - `plate_12w_standard.png` / `plate_12w_compact.png` / `plate_24w_*.png`（测试钢板，
>   SeedSigner 真编码器生成，测试熵、无真实资金）
> - `derive_btc_addr.py`（验收② 地址对照）
>
> ⚠️ 刷机纪律：先核对 sha256 再刷；串口调试台 **UART0 512000** 波特率。

---

## 验收①：钢板入 → XMR 真交易签名（Cake 四腿·主网终版）

**目的**：SeedSigner 生态钢板 ⇄ Cake 直配全流程（设备直答配对腿，Cupcake 出局）。

**前提**：盘钱包已充值（2026-10-08 已打入，≥10 确认后 Cake 可用）。
- 盘地址：`49KRWBDNoN6W8V1vMQZcfLFNuVUTTm8rp23NRiULyUbdQ8eWa4kNygGdCMjuTF8yHW7kySrSq7qbQLfkaPAycvEBDb8WRrJ`
- view_priv（Cake watch-only）：`db93ce632d8d31e31bd0b4ecbdbdb833cae813928af402c5b7ffeb85769cf000`
- 固件：`fw-product-pairing.bin`（sha `6962c4f3215c…`，四腿全套 + 槽位显示）

**步骤**：
1. 设备扫 `plate_24w_standard.png` → `standard seed - 24 words` → continue → `key session live`。
2. Cake 侧建 **watch-only 钱包**（restore：address + view key）→ 等余额解锁（≥10 确认）。
3. Cake 发起 Send（金额随意小额）→ 出 **xmr-output** 动画 → 设备扫入（自动进配对腿）→
   设备出 **xmr-keyimage** QR → Cake 点 **"Scan QR Code"** 收。
4. Cake 推进到 **xmr-txunsigned** 动画 → 设备扫入 → 签名（~17s）→ 设备出 **xmr-txsigned** QR
   → Cake 点 **"Scan QR Code"** 收 → Cake 广播。

**验收判据**：四腿全自动走通 + Cake 广播上链（txid 可查）。
**做完**：`se dump`（残余应 0）→ 退到 welcome 自动清。

## 验收②：钢板出 → SeedSigner 扫入 → BTC 地址一致

**目的**：shlosilo 制作的盘与 SeedSigner 互认（方向二）。

1. 刷 `forgebox-smoke-20261008.bin`（或 product 味均可；dev console 在 smoke 味）。
2. 串口（UART0 512000）发：
   ```
   key new
   ```
   屏显**秘密暴露警示**后生成钱包。
3. 发：
   ```
   key plate standard
   ```
   屏显 SeedQR。用手机/SeedSigner（或任何扫码器）**立即扫下内容**（数字串）。
   想验 compact 面再发 `key plate compact`（扫出的十六进制 = 原始熵）。
4. **SeedSigner 扫入**：SeedSigner 的「Load → QR」扫屏上 `key plate standard` 的盘
   → 选 BTC → 显示首个收款地址（默认 BIP-84）。
5. 对照：取 compact 盘的十六进制（= 熵），跑
   ```
   ~/works/ur-anim-acceptance/venv/bin/python ~/works/shlosilo-acceptance-plates/derive_btc_addr.py <熵hex>
   ```
   把输出的 **BIP-84 地址**与 SeedSigner 显示的逐字符对比。

**验收判据**：地址**逐字符一致**（SeedSigner 地址类型须选 BIP-84；其他路径脚本也给了）。
**做完**：`se lock`（清钱包）→ `se dump` 应显 `qr scratch residue: 0 nonzero bytes`。

## 验收③：SE 路径（密码解锁 → 签名 → 零化取证 + 错密码拒）

**目的**：三因素 SE 模型端到端 + 零化主张的真机取证。

⚠️ **阶段 C 是一次性永久操作**（OTP 烧录不可逆）——按
`flux/forgebox/docs/se-keystore-checklist.md` 的警示与二次确认流程执行；
只读检查（`se probe`）随时可跑。

1. 刷 `forgebox-smoke-20261008.bin`；串口 `se probe` 自检（双 SE 识别 OK、4 个 OTP BLANK）。
2. `se provision` → 屏显永久警示 → 确认后 `se provision CONFIRM`（⚠️ 一次性）。
   复验 `se probe` 4 项 `provisioned`。
3. `se slots` → `se slots CONFIRM <口令>`（3 账户密钥分片写入+读回，逐槽 PASS）。
4. **签名**：`se unlock <口令>` → 会话活 → 走验收①的 Cake 四腿签名（或先演练①再回来）。
5. **零化取证**：
   - 签名完成后 `se dump`——ws 窗口可见密钥字节（**拍照留证：close 前**）；
   - `se lock` → 再 `se dump`——**ws 窗口全零 + `qr scratch residue: 0`**（拍照留证：close 后）。
6. **错密码拒**：`se unlock <错误口令>` → 一次即拒（AuthFailed 类报错，无会话）。

**验收判据**：provision 成功 + 签名成功 + close 前后 dump 对比（有钥→全零）+ 错密码一次拒。

---

## 完成后

三条全过 → 回报，Kleo 走 Task 10 收官（`scripts/gates_run.sh` 15 门 + 池/交接/设计文档
状态回填 + `docs: key provisioning v1 implementation record`）。
任何一条不符 → 拍屏幕/串口输出发回，Kleo 排障。
