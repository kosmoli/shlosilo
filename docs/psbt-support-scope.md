# PSBT 支持范围(审计 #4 工程项 3)

> 审计要求:"capability/设计文档明确当前只接受的 script type、是否允许
> non-witness UTXO、是否允许多 derivation/multisig、mixed input 的整体拒绝
> 策略。对未支持类型应在解析早期稳定拒绝,不能依赖后续偶然失败。"

## 现状(v0.5.0-poc4,审计 #4 整改后)

### 已支持的输入类型

| Script type | 签名入口 | 状态 |
|---|---|---|
| P2WPKH(native segwit v0) | `sign_psbt_p2wpkh` | ✅ 完整(BIP-174 + BIP-143) |
| P2PKH(legacy) | `sign_psbt_p2pkh` | ✅ 完整 |
| P2SH-P2WPKH(nested segwit) | `sign_psbt_p2sh_p2wpkh` | ✅ 完整 |
| P2TR keypath(BIP-86/341) | `sign_psbt_p2tr_keypath` | ✅ 完整(BIP-371) |
| P2TR scriptpath | `sign_psbt_p2tr_scriptpath` | ✅ 完整(BIP-371) |

### UTXO 来源策略

- **WITNESS_UTXO(0x02)**:首选。CTxOut 格式解析(P0-01 加固后对恶意
  CompactSize 稳定拒绝)。
- **NON_WITNESS_UTXO(0x01)**:当前 `get_utxo_any` 会作为 WITNESS_UTXO
  的 fallback 解析其 CTxOut(keystone taproot fixture 的实际行为)。
  **未做 full tx 哈希校验**——审计建议的 complete-transaction 验证是
  后续加固项,当前依赖上层(L3)确认。
- 两者皆缺 → 签名入口返回 `EncodingInvalidFormat`,稳定拒绝。

### 所有权绑定(P1-B,已关闭)

- P2WPKH:输入的 `BIP32_DERIVATION` pubkey 必须等于本机派生公钥,
  否则 `PsbtOwnershipMismatch` 拒绝签名(P1-B 整改,tests/p63 锁定)。
- fingerprint 比对:`parse_derivation_value` 返回 master fingerprint,
  上层比对本机 fingerprint,防错链签名。

### 明确不支持(解析后稳定拒绝)

- **P2WSH / P2SH-multisig 输入签名**:无对应入口;错误输入在 script
  type 判定/ownership 绑定处稳定报错,不会静默通过。
- **Taproot 多签(MuSig2 PSBT 协作字段 0x16-0x1B)**:MuSig2 密码学层
  已实现(BIP-327),PSBT 协作字段未接。
- **PSBT v2(BIP-370)**:不支持。仅 BIP-174 v0。
- **PSBT_GLOBAL_XPUB(0x01 global)**:忽略(不报错)。
- **PSBT combine / finalize / extract**:未实现(签名器角色只产出
  PARTIAL_SIG / TAP_KEY_SIG,finalizer 是 coordinator 的事)。

### Parser totality(P0-01,已关闭)

- 全部 wire CompactSize 经 `PSBT_WIRE_MAX_LEN`(64 KiB)预算 +
  非规范编码拒绝;字节域经 `take_bytes` checked_add。
- `with_capacity` 前计数钳制——任意恶意字节序列不 panic/OOM
  (tests/p001_psbt_totality.rs 12 个边界测试锁定)。

## 已知限制(非拒绝路径)

- 单 P2TR input 的 scriptpath 依赖 `get_utxo_any` 的 NON_WITNESS_UTXO
  fallback(keystone fixture 兼容行为,见上)。
- 多 derivation per key(BIP-174 允许同一 key 多路径)取第一个;
  不做全路径枚举。
- mixed input 类型(一个 PSBT 里同时有 P2WPKH 和 P2TR 输入):
  每个 input 独立签名,按各自 script type 走对应入口;签名器一次
  调用签一个 input(`input_index`),不隐式批量。
