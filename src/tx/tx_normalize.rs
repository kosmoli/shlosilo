//! TxNormalize：UR payload → TxTemplate
//!
//! **Phase 2.4 假实现**：根据 UR type tag 推断 ChainKind，生成最小 TxTemplate
//! Phase 4 真实实现：完整 UR payload 解析 + ChainKind 推断 + tx 字段提取

use crate::error::Result;
use crate::types::chain_kind::ChainKind;
use crate::ur::ur_encode::UrTypeTag;

extern crate alloc;

/// 交易模板（chain-agnostic）
///
/// 业务模块拿到 TxTemplate 后按 ChainKind dispatch 到对应 chain 处理
#[derive(Clone, Debug)]
pub struct TxTemplate {
    pub chain_kind: ChainKind,
    /// raw payload（业务模块 chain-specific 解析）
    ///
    /// **堆分配**（PSRAM heap_4）：真实 PSBT 常 2-12KB（Sparrow 多输入 fixture 实测 12KB），
    /// 不能放栈上——P6.3 真机回归发现 heapless 内联 16384 容量把 smoke task 32KB 栈
    /// 压爆（HardFault→WDT 复位→sign 卡死重启循环）。栈上只留 Vec 头（24B）。
    /// P6.3 修正（2026-08-26）：原 2048 且 extend 失败被 `let _ =` 吞掉 → 静默截断，
    /// 真实 PSBT 签名必错。现改堆分配 + 显式容量上限（禁止静默截断）。
    pub payload: alloc::vec::Vec<u8>,
    /// 派生路径（业务模块 dispatch 用，区分主网/测试网 + 账户）
    pub derivation_path: crate::derivation::path::DerivationPath,
}

/// payload 显式上限：真实 PSBT 12KB + 余量。超过报 UrPayloadTooLarge（禁止静默截断）。
const PAYLOAD_MAX: usize = 16384;

/// UR payload → TxTemplate
///
/// **P1-01（2026-08-26）**：不再从 payload 首字节推断 ChainKind——type tag
/// 由 UR decode 层携带（`ur:<type>/`），业务层按 type 调对应 codec。
/// 遗留 `UrTypeTag::from_bytes` 首字节私有 tag 协议已废弃。
pub fn to_template(type_tag: UrTypeTag, payload: &[u8]) -> Result<TxTemplate> {
    let chain_kind = match type_tag {
        UrTypeTag::CryptoPsbt => ChainKind::Btc,
        UrTypeTag::EthSignRequest => ChainKind::Eth,
        UrTypeTag::CryptoMoneroTx | UrTypeTag::XmrTxUnsigned | UrTypeTag::XmrTxSigned => {
            ChainKind::Xmr
        }
        UrTypeTag::SolanaSignRequest => ChainKind::Sol,
        UrTypeTag::CardanoSignRequest => ChainKind::Ada,
        UrTypeTag::CosmosSignRequest => ChainKind::Cosmos,
        UrTypeTag::Bytes
        | UrTypeTag::CryptoHdKey
        | UrTypeTag::CryptoAccount
        | UrTypeTag::Unknown => {
            return Err(crate::error::ShlosiloError::new(
                crate::error::ShlosiloErrorKind::UrPayloadUnknownType,
            ));
        }
    };
    let derivation_path = crate::derivation::path::DerivationPath::parse("m/44'/0'/0'/0/0")
        .map_err(|_| {
            crate::error::ShlosiloError::new(
                crate::error::ShlosiloErrorKind::DerivationPathInvalidSyntax,
            )
        })?;
    if payload.len() > PAYLOAD_MAX {
        return Err(crate::error::ShlosiloError::new(
            crate::error::ShlosiloErrorKind::UrPayloadTooLarge,
        ));
    }
    let payload = payload.to_vec();
    Ok(TxTemplate {
        chain_kind,
        payload,
        derivation_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_template_btc() {
        let result = to_template(UrTypeTag::CryptoPsbt, &[0x58, 0x03, 1, 2, 3]);
        assert!(result.is_ok());
        let template = result.unwrap();
        assert_eq!(template.chain_kind, ChainKind::Btc);
    }

    #[test]
    fn to_template_xmr() {
        let result = to_template(UrTypeTag::CryptoMoneroTx, &[1, 2, 3]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().chain_kind, ChainKind::Xmr);
    }

    #[test]
    fn to_template_unknown_rejected() {
        let result = to_template(UrTypeTag::Unknown, &[99, 1, 2, 3]);
        assert!(result.is_err());
    }

    /// P1-01：type 由 tag 决定，payload 首字节不再有特殊含义
    #[test]
    fn to_template_type_tag_not_first_byte() {
        // 同一 payload，不同 tag → 不同链
        let btc = to_template(UrTypeTag::CryptoPsbt, &[0x01, 0x02]).unwrap();
        let eth = to_template(UrTypeTag::EthSignRequest, &[0x01, 0x02]).unwrap();
        assert_eq!(btc.chain_kind, ChainKind::Btc);
        assert_eq!(eth.chain_kind, ChainKind::Eth);
    }

    /// P1-01：payload 完整保留（含 CBOR 包装），不剥首字节
    #[test]
    fn to_template_payload_preserved() {
        let payload = [0xa2u8, 0x01, 0x02, 0x03];
        let t = to_template(UrTypeTag::EthSignRequest, &payload).unwrap();
        assert_eq!(t.payload.as_slice(), &payload[..]);
    }

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("tx_normalize.rs");
        assert!(source.contains("Phase 2.4"));
        assert!(source.contains("ChainKind"));
    }
}
