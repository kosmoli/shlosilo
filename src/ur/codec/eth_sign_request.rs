//! eth-sign-request UR codec（ur-registry 1.0.5 同构）
//!
//! CBOR map（UR 类型 `eth-sign-request`）：
//! ```text
//! 1: request_id      — tag(37 UUID) + 16B
//! 2: sign_data       — bytes（原始 tx / typed-data / message，按 data_type 解释）
//! 3: data_type       — uint 1=Transaction 2=TypedData 3=PersonalMessage 4=TypedTransaction
//! 4: chain_id        — int
//! 5: derivation_path — tag(304 crypto-keypath)
//! 6: address         — bytes
//! 7: origin          — string
//! ```
//!
//! P1-01（2026-08-26）：真实 MetaMask/Keystone UR 的 payload 是 CBOR map，
//! 不是遗留的「首字节 tag + raw」私有封装。sign 路径按 data_type 解释 sign_data。

use crate::encoding::cbor::Cbor;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// UR registry crypto-keypath tag（BCR-2020-006；与 crypto_hd_key.rs 编码侧同源）
const TAG_CRYPTO_KEYPATH: u64 = 304;

extern crate alloc;

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// sign_data 的解释类型（ur-registry DataType 枚举）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EthSignDataType {
    Transaction = 1,
    TypedData = 2,
    PersonalMessage = 3,
    TypedTransaction = 4,
}

impl EthSignDataType {
    pub fn from_u64(v: u64) -> Result<Self> {
        match v {
            1 => Ok(Self::Transaction),
            2 => Ok(Self::TypedData),
            3 => Ok(Self::PersonalMessage),
            4 => Ok(Self::TypedTransaction),
            _ => Err(err()),
        }
    }
}

/// eth-sign-request 解析结果（只取签名需要的字段）
#[derive(Debug)]
pub struct EthSignRequest {
    /// 原始 sign_data（对 Transaction / TypedTransaction = raw tx bytes）
    pub sign_data: alloc::vec::Vec<u8>,
    pub data_type: EthSignDataType,
    pub chain_id: Option<i128>,
    /// derivation_path（key 5，tag 304 crypto-keypath，可选）
    /// P1-02：给定则签名用该路径派生；缺省 fallback m/44'/60'/0'/0/0
    pub derivation_path: Option<crate::derivation::path::DerivationPath>,
}

/// 解析 eth-sign-request CBOR payload → EthSignRequest
pub fn parse_eth_sign_request(payload: &[u8]) -> Result<EthSignRequest> {
    let cbor = crate::encoding::cbor::decode(payload)?;
    let map = match cbor {
        Cbor::Map(_) => &cbor,
        _ => return Err(err()),
    };

    // sign_data（key 2，必填）
    let sign_data = match map.map_get_uint(2)? {
        Some(v) => v.as_bytes()?.to_vec(),
        None => return Err(err()),
    };

    // data_type（key 3，必填）
    let data_type = match map.map_get_uint(3)? {
        Some(v) => EthSignDataType::from_u64(v.as_uint()?)?,
        None => return Err(err()),
    };

    // chain_id（key 4，可选）
    let chain_id = match map.map_get_uint(4)? {
        Some(v) => Some(v.as_int()?),
        None => None,
    };

    // derivation_path（key 5，可选）— tag 304 crypto-keypath 内 map {1: components[(idx u64, hardened bool)...], 2: depth}
    //
    // P1-01 加固（2026-09-01 审计 #4）：
    // 1. tag 白名单——只接受 registry tag 304（crypto-keypath，BCR-2020-006）。
    //    修复前匹配 `Cbor::Tag(_, _)` 任意 tag（tag 999 也被接受）。
    //    注释曾误写 305，正确值见 crypto_hd_key.rs TAG_CRYPTO_KEYPATH=304。
    // 2. idx 高位域收紧——无论 hardened bool 为何，idx ≤ 0x7fff_ffff。
    //    修复前 `(idx=0x8000_0001, hardened=false)` 被接受，wire 表示
    //    "非 hardened 高位 idx" 传入 DerivationPath 后被解释成 hardened 1
    //    ——wire/语义不一致。hardened bit 只由 bool 唯一编码。
    let derivation_path = match map.map_get_uint(5)? {
        Some(v) => {
            let inner = match v {
                Cbor::Tag(TAG_CRYPTO_KEYPATH, boxed) => boxed.as_ref(),
                _ => return Err(err()),
            };
            // components（key 1）：扁平 [idx0, hardened0, idx1, hardened1, ...]
            let comps = inner
                .map_get_uint(1)?
                .ok_or_else(err)?
                .as_array()?;
            // X2: components 必须是偶数长度 (idx, hardened) 对——奇数视为格式错误
            if comps.len() % 2 != 0 {
                return Err(err());
            }
            let mut flat = alloc::vec::Vec::with_capacity(comps.len() / 2);
            let mut i = 0;
            while i + 1 < comps.len() {
                let idx = comps[i].as_uint()?;
                // X2: BIP-32 index 域是 u32——超域拒绝,不静默截断
                if idx > u32::MAX as u64 {
                    return Err(err());
                }
                let idx = idx as u32;
                let hardened = match comps[i + 1] {
                    Cbor::Bool(b) => b,
                    _ => return Err(err()),
                };
                // P1-01: idx 高位域收紧（≤ 0x7fff_ffff）——无论 hardened bool。
                // 修复前仅 hardened=true 时拒绝高位，(0x8000_0001, false) 被静默
                // 当作 hardened 1 解释。
                if idx >= 0x8000_0000 {
                    return Err(err());
                }
                let raw = if hardened { idx | 0x8000_0000 } else { idx };
                flat.push(raw);
                i += 2;
            }
            // Gate4 #5 备注：key 2 (depth) 不校验——ur-registry 官方测试向量
            // （test_encode）的 depth 是占位值 0x12345678，registry 规范与上游
            // 实现（keystone/ur-registry）均未赋予 depth 约束语义，depth 是信息性字段。
            Some(crate::derivation::path::DerivationPath::from_flat(flat)?)
        }
        None => None,
    };

    Ok(EthSignRequest {
        sign_data,
        data_type,
        chain_id,
        derivation_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// ur-registry 1.0.5 test_encode 官方向量（test 里那段 hex）
    /// a6 01 d8 25 50 <request_id> 02 58 4b <sign_data> 03 01 04 01 05 d9 0130 ...
    #[test]
    fn parse_official_ur_registry_vector() {
        let hex_str = "a601d825509b1deb4d3b7d4bad9bdd2b0d7b3dcb6d02584bf849808609184e72a00082271094000000000000000000000000000000000000000080a47f74657374320000000000000000000000000000000000000000000000000000006000578080800301040105d90130a2018a182cf501f501f500f401f4021a1234567807686d6574616d61736b";
        let payload = hex(hex_str);
        let req = parse_eth_sign_request(&payload).unwrap();
        assert_eq!(req.data_type, EthSignDataType::Transaction);
        assert_eq!(req.chain_id, Some(1));
        // sign_data = raw tx（f8 49 80 86 09 18 4e 72 a0 ...）
        assert!(req.sign_data.len() > 40);
        assert_eq!(req.sign_data[0], 0xf8); // legacy tx RLP list
    }

    /// 非 map → 拒绝
    #[test]
    fn reject_non_map() {
        let payload = [0x01u8, 0x02, 0x03]; // 不是 map
        assert!(parse_eth_sign_request(&payload).is_err());
    }

    /// 缺 sign_data → 拒绝
    #[test]
    fn reject_missing_sign_data() {
        // a1 03 01 = {3: 1} 无 sign_data
        let payload = [0xa1u8, 0x03, 0x01];
        assert!(parse_eth_sign_request(&payload).is_err());
    }

    /// 未知 data_type → 拒绝
    #[test]
    fn reject_unknown_data_type() {
        // a2 02 41 61 03 09  = {2: bytes"a", 3: 9}
        let payload = [0xa2u8, 0x02, 0x41, 0x61, 0x03, 0x09];
        assert!(parse_eth_sign_request(&payload).is_err());
    }

    /// P1-01：完整 UR decode → eth-sign-request 解析（byte-exact 互通验证）
    /// payload = ur-registry 1.0.5 test_encode 官方向量（MetaMask 形状）
    #[test]
    fn decode_real_ur_registry_vector() {
        // 用库自身 encode 生成 UR，再 decode 回 payload，确保 round-trip 一致
        let payload = hex(
            "a601d825509b1deb4d3b7d4bad9bdd2b0d7b3dcb6d02584bf849808609184e72a00082271094000000000000000000000000000000000000000080a47f74657374320000000000000000000000000000000000000000000000000000006000578080800301040105d90130a2018a182cf501f501f500f401f4021a1234567807686d6574616d61736b",
        );
        let enc = crate::ur::ur_encode::encode(
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &payload,
        )
        .unwrap();
        let d = crate::ur::ur_decode::decode(enc.as_str()).unwrap();
        // P1-01 关键：type tag 由 UR decode 携带
        assert_eq!(
            d.type_tag(),
            crate::ur::ur_encode::UrTypeTag::EthSignRequest
        );
        assert_eq!(d.as_ref(), payload.as_slice());
        // 解析出 sign_data（真实 tx）
        let req = parse_eth_sign_request(d.as_ref()).unwrap();
        assert_eq!(req.data_type, EthSignDataType::Transaction);
        assert_eq!(req.chain_id, Some(1));
        assert!(req.sign_data.len() > 40);
    }

    /// X2 负例: 奇数长度 components 静默忽略 → 显式拒绝
    #[test]
    fn keypath_odd_components_rejected() {
        // tag 304, map{1: [0, false, 1], 2: 2}  — 3 个 comps(奇数)
        // （P1-01: 原用 tag 305——修复前任意 tag 均被接受，负例并未证明目标分支；
        //   现统一 tag 304，错误确定来自 components 校验）
        let payload: alloc::vec::Vec<u8> = alloc::vec![
            0xA1, 0x05, 0xD9, 0x01, 0x30, 0xA2, 0x01, 0x83, 0x00, 0xF4, 0x01, 0x02, 0x02,
        ];
        assert!(parse_eth_sign_request(&payload).is_err(), "odd keypath must be rejected");
    }

    /// Gate4 #5 负例: hardened=true 且 idx 已带 0x80000000 高位（非规范双表达）→ 拒
    #[test]
    fn keypath_hardened_high_bit_rejected() {
        // tag 304, map{1: [0x80000001, true]}
        let mut p: alloc::vec::Vec<u8> =
            alloc::vec![0xA1, 0x05, 0xD9, 0x01, 0x30, 0xA2, 0x01, 0x82];
        p.push(0x1a); // uint32
        p.extend_from_slice(&0x8000_0001u32.to_be_bytes());
        p.push(0xf5); // hardened=true
        assert!(
            parse_eth_sign_request(&p).is_err(),
            "hardened idx with high bit must be rejected"
        );
    }

    /// X2 负例: index 超出 u32 域拒绝(不截断)
    #[test]
    fn keypath_oversized_index_rejected() {
        // tag 304, map{1: [0x1_0000_0000, false], 2: 1} — 2^32 超 u32
        let payload: alloc::vec::Vec<u8> = alloc::vec![
            0xA1, 0x05, 0xD9, 0x01, 0x30, 0xA2, 0x01, 0x82, 0x1B, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0xF4, 0x02, 0x01,
        ];
        assert!(parse_eth_sign_request(&payload).is_err(), "index > u32::MAX must be rejected");
    }

    // ── P1-01（审计 #4）新增负例：完整有效请求只改一个字段，锁定目标分支 ──

    /// 完整有效请求：{1: request_id, 2: sign_data, 3: data_type, 4: chain_id,
    ///                5: keypath(tag 304)}——作为以下负例的基线
    fn valid_request_with_keypath(comps_cbor: &[u8]) -> alloc::vec::Vec<u8> {
        use crate::encoding::cbor;
        // components 数组的 CBOR 编码由调用方注入（bytes item 内联原始字节）
        let inner_map = cbor::encode_map(&[
            (cbor::encode_uint(2), cbor::encode_uint(1)),
        ]);
        // 手工构造 {1: comps, 2: 1}
        let k1 = cbor::encode_uint(1);
        let mut inner = alloc::vec::Vec::new();
        inner.push(0xa2); // map(2)
        inner.extend_from_slice(&k1);
        inner.extend_from_slice(comps_cbor);
        // 追加 key2:1（inner_map = 0xa1 || k2 || v2,摘除 header 取 body）
        inner.extend_from_slice(&inner_map[1..]);

        let request_id = [0x9bu8; 16];
        let pairs = alloc::vec![
            (cbor::encode_uint(1), cbor::encode_bytes(&request_id)),
            (cbor::encode_uint(2), cbor::encode_bytes(&[0x02u8; 16])),
            (cbor::encode_uint(3), cbor::encode_uint(1)), // data_type = Transaction
            (cbor::encode_uint(4), cbor::encode_uint(1)), // chain_id = 1
            (cbor::encode_uint(5), cbor::encode_tag(TAG_CRYPTO_KEYPATH, &inner)),
        ];
        cbor::encode_map(&pairs)
    }

    /// P1-01 负例 1：tag 999（非 registry crypto-keypath）→ 拒绝
    /// （修复前任意 tag 都被当作 keypath 接受）
    #[test]
    fn keypath_wrong_tag_rejected() {
        use crate::encoding::cbor;
        let inner = cbor::encode_map(&[
            (cbor::encode_uint(1), cbor::encode_array(&[
                cbor::encode_uint(44),
                cbor::encode_bool(true),
            ])),
            (cbor::encode_uint(2), cbor::encode_uint(1)),
        ]);
        let pairs = alloc::vec![
            (cbor::encode_uint(1), cbor::encode_bytes(&[0x9bu8; 16])),
            (cbor::encode_uint(2), cbor::encode_bytes(&[0x02u8; 16])),
            (cbor::encode_uint(3), cbor::encode_uint(1)),
            (cbor::encode_uint(4), cbor::encode_uint(1)),
            (cbor::encode_uint(5), cbor::encode_tag(999, &inner)), // 唯一改动：tag
        ];
        let payload = cbor::encode_map(&pairs);
        assert!(
            parse_eth_sign_request(&payload).is_err(),
            "tag 999 must be rejected (only registry tag 304 accepted)"
        );
    }

    /// P1-01 负例 2：(idx=0x8000_0001, hardened=false) → 拒绝
    /// （修复前被接受，wire 表示与业务解释不一致：idx 高位被静默当 hardened bit）
    #[test]
    fn keypath_high_bit_idx_non_hardened_rejected() {
        use crate::encoding::cbor;
        let comps = cbor::encode_array(&[
            cbor::encode_uint(0x8000_0001), // 高位 idx
            cbor::encode_bool(false),       // 声称非 hardened——歧义组合
        ]);
        let payload = valid_request_with_keypath(&comps);
        assert!(
            parse_eth_sign_request(&payload).is_err(),
            "(high-bit idx, hardened=false) must be rejected regardless of bool"
        );
    }

    /// P1-01 正例：合法 keypath（tag 304, 普通索引）完整请求 → 接受且路径正确
    #[test]
    fn keypath_valid_full_request_accepted() {
        use crate::encoding::cbor;
        let comps = cbor::encode_array(&[
            cbor::encode_uint(44),
            cbor::encode_bool(true),
            cbor::encode_uint(60),
            cbor::encode_bool(true),
            cbor::encode_uint(1),
            cbor::encode_bool(false),
        ]);
        let payload = valid_request_with_keypath(&comps);
        let req = parse_eth_sign_request(&payload)
            .expect("valid full request must parse");
        let path = req.derivation_path.expect("keypath present");
        // m/44'/60'/1 —— value() 是去掉 hardened bit 的纯索引，
        // hardened 位单独断言
        let flat: alloc::vec::Vec<(u32, bool)> = path
            .as_slice()
            .iter()
            .map(|i| (i.value(), i.is_hardened()))
            .collect();
        assert_eq!(
            flat,
            alloc::vec![(44, true), (60, true), (1, false)]
        );
    }
}
