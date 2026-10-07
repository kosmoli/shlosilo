# SE keystore 真机检查清单（Task 7）

> 面向真机操作（外行照做）：每步一条命令、逐行预期输出。
> 串口调试台：UART0，**512000** 波特率（`src/driver/drv_uart.c` Uart0Init 实测）。
> 固件：smoke 味 `build/forgebox.bin`（SE 冒烟电池挂在 smoke task / dev console）。

---

## ⚠️ 先读：哪些操作是一次性不可逆的

以下 4 项是**一扇单向门**（烧了就永久固化，无法恢复出厂）：

| OTP 区 | 内容 | 后果 |
|---|---|---|
| OTP_ADDR_SALT | HashWithSalt 盐 | 每个 KDF 输出都依赖它 |
| OTP_ADDR_AES_KEY | 内层 AES piece | Save/Load 账户密文的第三因子 |
| OTP_ADDR_ATECC608B | ATECC608B 绑定密钥 | 首次 Init 同时写/锁芯片配置 |
| OTP_ADDR_DS28S60 | DS28S60 绑定密钥 | 同上 |

因此固件的安全门设计是：
- **只读检查自动可跑、可反复**；
- **一切写操作**都要显式命令触发 → 屏幕先弹永久性警示 → 再发一条独立的 `CONFIRM` 命令才执行；
- 自动电池**永远不会**隐式写 SE/OTP（连"懒烧盐"都被门挡住：探测与 KDF 检查先查盐是否已烧，绝不触发隐式烧录）。

---

## 阶段 A：只读自检（安全，任何时候可跑）

```
se probe
```

预期输出（关键行，`== SE probe (read-only) ==` 开头）：

```
atecc608b: OK sn=<18位十六进制序列号>
atecc608b rng: OK
ds28s60: OK romid=<16位十六进制> man=<4位十六进制>
ds28s60 rng: OK
otp salt: provisioned 或 BLANK
otp aes piece: provisioned 或 BLANK
otp atecc keys: provisioned 或 BLANK
otp ds28s60 keys: provisioned 或 BLANK
```

- 全新板子预期 4 个 `BLANK`（尚未 provision）。
- `FAIL comm rc=…`：SE 芯片通信问题——查 I2C 接线/供电，勿继续。
- 最终以失败计数收尾（`62 checks` 层面的 host 对应物；真机上 fail 计数=0 为过）。

## 阶段 B：只读 KDF 检查（安全）

```
se kdf 你的测试口令
```

- 若 `otp salt: BLANK` → 输出 `kdf: SKIP (otp salt blank - run 'se provision' first)`（**这不是失败**，盐未烧时 KDF 无从谈起，跳过是正确行为）。
- 盐已烧时预期：`ds wrong-piece differs: PASS`、`kdf auth gate: PASS (rc=…)`；
  若用 provision 时的同一口令且 slots 已写，还会见 `kdf right-pwd get: PASS`。

## 阶段 C：⚠️ 一次性永久烧录（provision）

**这步烧 4 个 OTP 区 + 写/锁 ATECC608B 芯片配置——不可逆。确认板子就是要长期使用的那块再做。**

1. 先发（只弹警示，不执行）：

```
se provision
```

屏幕应出现永久性警示（`!! EXECUTING PERMANENT OTP WRITES !!` 类警示文案）。

2. 确认要做，再发：

```
se provision CONFIRM
```

预期：逐区 `…: BURNED (n bytes, PERMANENT)`；每个烧录点烧后回读验证。

3. 复验：重跑 `se probe`，4 个 OTP 行全部应显示 `provisioned`。

## 阶段 D：⚠️ 账户密钥槽写/读回（se slots）

SE 数据槽可重写（非一次性），但写的是**密钥分片**，也走双段确认：

1. `se slots` → 弹 SE 写警示。
2. `se slots CONFIRM <口令>` → 3 账户 key-piece 写入 + 读回比对，预期逐槽 `OK`。

## 失败排查速查

| 现象 | 含义 |
|---|---|
| `FAIL comm rc=…` | SE 通信失败（I2C/供电/初始化） |
| `kdf auth gate: FAIL rc=… (want …)` | 错口令未被归一为 ERR_KEYSTORE_AUTH——实现回归，报 Kleo |
| `ds wrong-piece differs: FAIL (collision!)` | 两口令推出同 piece——极严重，停用该板并报告 |
| `atecc piece err,0x14`（host 面） | host shim 的预期错误注入路径，非故障 |

---

维护：本清单随 `src/tasks/se_smoke.c` 的命令面同步更新（命令/输出改了这里必须跟着改）。
