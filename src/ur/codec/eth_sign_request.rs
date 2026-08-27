//! eth-sign-request UR codec（ur-registry 1.0.5 同构）
//!
//! CBOR map（UR 类型 `eth-sign-request`）：
//! ```text
//! 1: request_id      — tag(37 UUID) + 16B
//! 2: sign_data       — bytes（原始 tx / typed-data / message，按 data_type 解释）
//! 3: data_type       — uint 1=Transaction 2=TypedData 3=PersonalMessage 4=TypedTransaction
//! 4: chain_id        — int
//! 5: derivation_path — tag(305 crypto-keypath)
//! 6: address         — bytes
//! 7: origin          — string
//! ```
//!
//! P1-01（2026-08-26）：真实 MetaMask/Keystone UR 的 payload 是 CBOR map，
//! 不是遗留的「首字节 tag + raw」私有封装。sign 路径按 data_type 解释 sign_data。

use crate::encoding::cbor::Cbor;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

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

    Ok(EthSignRequest {
        sign_data,
        data_type,
        chain_id,
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
}
