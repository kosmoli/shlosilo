//! UR 编码（BC-UR 单分片）— Phase 6 P6.0b 真实实现
//!
//! 格式：`ur:<type>/<bytewords-minimal(payload)>`
//!
//! UR 传输层 **不** 再包一层 CBOR。codec（crypto-psbt / crypto-hd-key）产出的
//! CBOR 字节作为 payload 原样进入 bytewords。BCR-2020-05 / keystone-ur 官方向量
//! `ur:bytes/iehsjyhspmwfwfia` 的 body 解出就是原始 `b"data"`，不是 CBOR item。
//!
//! fountain 多分片在 Phase 6 P6.2 补（真机大 PSBT 时）。

use crate::encoding::bytewords;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// 原始 payload 上限（codec 产出的 CBOR）
pub const UR_PAYLOAD_MAX_LEN: usize = 2048;
/// 完整 URI 上限：prefix + bytewords(payload+crc32) ≈ 2×payload + 头
pub const UR_URI_MAX_LEN: usize = 8192;

#[derive(Clone, PartialEq, Eq)]
pub struct UrEncoded {
    uri: heapless::String<UR_URI_MAX_LEN>,
}

impl UrEncoded {
    pub fn as_str(&self) -> &str {
        &self.uri
    }

    pub fn from_string(s: &str) -> Result<Self> {
        let mut uri = heapless::String::new();
        uri.push_str(s)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
        Ok(UrEncoded { uri })
    }
}

impl AsRef<str> for UrEncoded {
    fn as_ref(&self) -> &str {
        &self.uri
    }
}

impl core::fmt::Debug for UrEncoded {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "UrEncoded(<{} bytes redacted>)", self.uri.len())
    }
}

/// UR type tag（BC-UR 顶层 type 字段）
///
/// 用于 v2 §7 ChainKind 推断——业务模块 dispatch 用
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrTypeTag {
    CryptoPsbt,         // BTC
    EthSignRequest,     // ETH
    CryptoMoneroTx,     // XMR（兼容别名，deprecated——官方为 xmr-txunsigned/signed）
    XmrTxUnsigned,      // XMR 官方 registry 8303（payload = 完整加密 unsigned txset blob）
    XmrTxSigned,        // XMR 官方 registry 8304（payload = 完整加密 signed txset blob）
    SolanaSignRequest,  // SOL
    CardanoSignRequest, // ADA
    CosmosSignRequest,  // Cosmos 系
    Bytes,              // opaque bytes（测试 / 透传）
    CryptoHdKey,        // crypto-hdkey
    CryptoAccount,      // crypto-account
    Unknown,
}

impl UrTypeTag {
    pub fn from_name(name: &str) -> Self {
        match name {
            "crypto-psbt" => Self::CryptoPsbt,
            "eth-sign-request" => Self::EthSignRequest,
            "crypto-monero-tx" => Self::CryptoMoneroTx,
            "xmr-txunsigned" => Self::XmrTxUnsigned,
            "xmr-txsigned" => Self::XmrTxSigned,
            "solana-sign-request" => Self::SolanaSignRequest,
            "cardano-sign-request" => Self::CardanoSignRequest,
            "cosmos-sign-request" => Self::CosmosSignRequest,
            "bytes" => Self::Bytes,
            "crypto-hdkey" => Self::CryptoHdKey,
            "crypto-account" => Self::CryptoAccount,
            _ => Self::Unknown,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Self::CryptoPsbt => "crypto-psbt",
            Self::EthSignRequest => "eth-sign-request",
            Self::CryptoMoneroTx => "crypto-monero-tx",
            Self::XmrTxUnsigned => "xmr-txunsigned",
            Self::XmrTxSigned => "xmr-txsigned",
            Self::SolanaSignRequest => "solana-sign-request",
            Self::CardanoSignRequest => "cardano-sign-request",
            Self::CosmosSignRequest => "cosmos-sign-request",
            Self::Bytes => "bytes",
            Self::CryptoHdKey => "crypto-hdkey",
            Self::CryptoAccount => "crypto-account",
            Self::Unknown => "unknown",
        }
    }

    /// 兼容旧接口：从首字节推断（Phase 4 遗留调用方）
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match bytes.first().copied() {
            Some(0) => Self::CryptoPsbt,
            Some(1) => Self::EthSignRequest,
            Some(2) => Self::CryptoMoneroTx,
            Some(3) => Self::SolanaSignRequest,
            Some(4) => Self::CardanoSignRequest,
            Some(5) => Self::CosmosSignRequest,
            _ => Self::Unknown,
        }
    }
}

/// 单分片编码：payload → bytewords-minimal → `ur:<type>/<body>`
pub fn encode(type_tag: UrTypeTag, payload: &[u8]) -> Result<UrEncoded> {
    if payload.len() > UR_PAYLOAD_MAX_LEN {
        return Err(err());
    }
    let mut uri = heapless::String::<UR_URI_MAX_LEN>::new();
    push_str(&mut uri, "ur:")?;
    push_str(&mut uri, type_tag.type_name())?;
    push_str(&mut uri, "/")?;
    for c in bytewords::encode_minimal(payload).chars() {
        uri.push(c)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }
    Ok(UrEncoded { uri })
}

fn push_str(uri: &mut heapless::String<UR_URI_MAX_LEN>, s: &str) -> Result<()> {
    uri.push_str(s)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BCR-2020-05 / keystone-ur doctest：
    /// `ur:bytes/iehsjyhspmwfwfia` ↔ `b"data"`
    #[test]
    fn bcr_official_single_part_round_trip() {
        let d = crate::ur::ur_decode::decode("ur:bytes/iehsjyhspmwfwfia").unwrap();
        assert_eq!(d.type_tag(), UrTypeTag::Bytes);
        assert_eq!(d.as_ref(), b"data");
        let enc = encode(UrTypeTag::Bytes, b"data").unwrap();
        assert_eq!(enc.as_str(), "ur:bytes/iehsjyhspmwfwfia");
    }

    /// Python 独立实现：raw `[0x01, 0x02]` → `ur:bytes/adaorpsffwmo`
    #[test]
    fn independent_oracle_bytes_vector() {
        let enc = encode(UrTypeTag::Bytes, &[0x01, 0x02]).unwrap();
        assert_eq!(enc.as_str(), "ur:bytes/adaorpsffwmo");
        let d = crate::ur::ur_decode::decode(enc.as_str()).unwrap();
        assert_eq!(d.as_ref(), &[0x01, 0x02]);
    }

    /// crypto-psbt round trip：payload 透传（CBOR map 由 codec 层做）
    #[test]
    fn crypto_psbt_round_trip() {
        let payload: alloc::vec::Vec<u8> = b"psbt\xff".iter().copied().chain(0..40u8).collect();
        let enc = encode(UrTypeTag::CryptoPsbt, &payload).unwrap();
        assert!(enc.as_str().starts_with("ur:crypto-psbt/"));
        let d = crate::ur::ur_decode::decode(enc.as_str()).unwrap();
        assert_eq!(d.type_tag(), UrTypeTag::CryptoPsbt);
        assert_eq!(d.as_ref(), &payload[..]);
    }

    /// multi-part 形状显式拒绝（fountain 属 P6.2）；坏 scheme 拒绝
    #[test]
    fn multipart_and_garbage_rejected() {
        assert!(crate::ur::ur_decode::decode(
            "ur:bytes/1-20/lpadbbcsiecyvdidatkpfeghihjtcxiabdfevlms"
        )
        .is_err());
        assert!(crate::ur::ur_decode::decode("http://x/y").is_err());
        assert!(crate::ur::ur_decode::decode("ur:noslash").is_err());
        assert!(crate::ur::ur_decode::decode("ur:bytes/iehsjyhspmwfwfib").is_err());
    }

    #[test]
    fn payload_max_len() {
        assert_eq!(UR_PAYLOAD_MAX_LEN, 2048);
    }
}
// ============================================================================
// §B.5 定案 1 测试（2026-08-28）：官方 XMR UR tag
// ============================================================================
#[cfg(test)]
mod xmr_tag_tests {
    use super::*;

    /// 官方 registry 名称 ↔ tag 双向映射
    #[test]
    fn xmr_official_tags_round_trip() {
        assert_eq!(
            UrTypeTag::from_name("xmr-txunsigned"),
            UrTypeTag::XmrTxUnsigned
        );
        assert_eq!(UrTypeTag::XmrTxUnsigned.type_name(), "xmr-txunsigned");
        assert_eq!(UrTypeTag::from_name("xmr-txsigned"), UrTypeTag::XmrTxSigned);
        assert_eq!(UrTypeTag::XmrTxSigned.type_name(), "xmr-txsigned");
    }

    /// encode/decode round-trip 用官方 tag
    #[test]
    fn xmr_official_tag_encode_decode() {
        let payload = b"Monero unsigned tx set\x05fake";
        let enc = encode(UrTypeTag::XmrTxUnsigned, payload).unwrap();
        assert!(enc.as_str().starts_with("ur:xmr-txunsigned/"));
        let dec = crate::ur::ur_decode::decode(enc.as_str()).unwrap();
        assert_eq!(dec.type_tag(), UrTypeTag::XmrTxUnsigned);
        assert_eq!(dec.as_ref(), payload);
    }

    /// 兼容别名 crypto-monero-tx 仍 dispatch 到 XMR（三个 tag → 同一 ChainKind）
    #[test]
    fn legacy_alias_still_dispatches_xmr() {
        for tag in [
            UrTypeTag::CryptoMoneroTx,
            UrTypeTag::XmrTxUnsigned,
            UrTypeTag::XmrTxSigned,
        ] {
            let t = crate::tx::tx_normalize::to_template(tag, b"x").unwrap();
            assert_eq!(
                t.chain_kind,
                crate::types::chain_kind::ChainKind::Xmr,
                "tag {:?}",
                tag
            );
        }
    }
}
