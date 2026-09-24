//! UR encoding (BC-UR single fragment) — Phase 6 P6.0b real implementation
//!
//! Format: `ur:<type>/<bytewords-minimal(payload)>`
//!
//! The UR transport layer does **not** wrap another CBOR layer. The CBOR bytes produced by codecs
//! (crypto-psbt / crypto-hd-key) enter bytewords verbatim as the payload. The body of the BCR-2020-05 /
//! keystone-ur official vector `ur:bytes/iehsjyhspmwfwfia` decodes to the raw `b"data"`, not a CBOR item.
//!
//! Multi-fragment fountain arrives in Phase 6 P6.2 (for large on-device PSBTs).

use crate::encoding::bytewords;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// Raw payload upper bound (CBOR produced by codecs)
pub const UR_PAYLOAD_MAX_LEN: usize = 2048;
/// Full URI upper bound: prefix + bytewords(payload+crc32) ≈ 2×payload + header
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

/// UR type tag (BC-UR top-level type field)
///
/// Used for v2 §7 ChainKind inference — business module dispatch
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrTypeTag {
    CryptoPsbt,         // BTC
    EthSignRequest,     // ETH
    CryptoMoneroTx,     // XMR (compatibility alias, deprecated — official is xmr-txunsigned/signed)
    XmrTxUnsigned,      // XMR official registry 8303 (payload = full encrypted unsigned txset blob)
    XmrTxSigned,        // XMR official registry 8304 (payload = full encrypted signed txset blob)
    SolanaSignRequest,  // SOL
    CardanoSignRequest, // ADA
    CosmosSignRequest,  // Cosmos family
    Bytes,              // opaque bytes (tests / passthrough)
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

    /// Legacy interface compatibility: infer from the first byte (Phase 4 leftover callers)
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

/// Single-fragment encoding: payload → bytewords-minimal → `ur:<type>/<body>`
pub fn encode(type_tag: UrTypeTag, payload: &[u8]) -> Result<UrEncoded> {
    if payload.len() > UR_PAYLOAD_MAX_LEN {
        return Err(err());
    }
    let mut uri = heapless::String::<UR_URI_MAX_LEN>::new();
    push_str(&mut uri, "ur:")?;
    push_str(&mut uri, type_tag.type_name())?;
    push_str(&mut uri, "/")?;
    bytewords::encode_minimal_into_str(payload, &mut uri)?;
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

    /// Independent Python implementation: raw `[0x01, 0x02]` → `ur:bytes/adaorpsffwmo`
    #[test]
    fn independent_oracle_bytes_vector() {
        let enc = encode(UrTypeTag::Bytes, &[0x01, 0x02]).unwrap();
        assert_eq!(enc.as_str(), "ur:bytes/adaorpsffwmo");
        let d = crate::ur::ur_decode::decode(enc.as_str()).unwrap();
        assert_eq!(d.as_ref(), &[0x01, 0x02]);
    }

    /// crypto-psbt round trip: payload passthrough (the CBOR map is built by the codec layer)
    #[test]
    fn crypto_psbt_round_trip() {
        let payload: alloc::vec::Vec<u8> = b"psbt\xff".iter().copied().chain(0..40u8).collect();
        let enc = encode(UrTypeTag::CryptoPsbt, &payload).unwrap();
        assert!(enc.as_str().starts_with("ur:crypto-psbt/"));
        let d = crate::ur::ur_decode::decode(enc.as_str()).unwrap();
        assert_eq!(d.type_tag(), UrTypeTag::CryptoPsbt);
        assert_eq!(d.as_ref(), &payload[..]);
    }

    /// multi-part shape explicitly rejected (fountain belongs to P6.2); bad scheme rejected
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
// §B.5 decision 1 tests (2026-08-28): official XMR UR tag
// ============================================================================
#[cfg(test)]
mod xmr_tag_tests {
    use super::*;

    /// Official registry name ↔ tag bidirectional mapping
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

    /// encode/decode round-trip with the official tag
    #[test]
    fn xmr_official_tag_encode_decode() {
        let payload = b"Monero unsigned tx set\x05fake";
        let enc = encode(UrTypeTag::XmrTxUnsigned, payload).unwrap();
        assert!(enc.as_str().starts_with("ur:xmr-txunsigned/"));
        let dec = crate::ur::ur_decode::decode(enc.as_str()).unwrap();
        assert_eq!(dec.type_tag(), UrTypeTag::XmrTxUnsigned);
        assert_eq!(dec.as_ref(), payload);
    }

    /// The compatibility alias crypto-monero-tx still dispatches to XMR (three tags → same ChainKind)
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
