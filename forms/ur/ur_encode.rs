//! UR encoding (BC-UR single fragment) — Phase 6 P6.0b real implementation
//!
//! Format: `ur:<type>/<bytewords-minimal(message)>`
//!
//! Message convention (2026-10-12, keystone-ur Bytes / monero_c alignment):
//! the message body is one CBOR byte-string item — short shell (`0x58` +
//! 1-byte length / `0x59` + 2-byte length) wrapping the container — encoded
//! into bytewords verbatim. Peers that decode with `CborLite::decodeBytes`
//! (monero_c importKeyImagesUR / submitTransactionUR, Cupcake exportKeyImagesUR
//! / signUR) expect exactly this shape; the real-capture Cake xmr-output leg
//! reassembles to `58 f0 ...`. On the decode side `ur_message_content`
//! strips the shell and passes bare messages through, so legacy bare senders
//! (Cake's xmr-txunsigned leg) keep working.
//!
//! Multi-fragment fountain arrives in Phase 6 P6.2 (for large on-device PSBTs).

use crate::encoding::bytewords;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::ur::ur_shell::ur_message_shell_len;

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// Raw payload upper bound (CBOR produced by codecs).
///
/// Sizing (2026-10-21, pool §36 fix): 2048 under-budgeted real traffic — a
/// real Cake `xmr-output` message is 2052 B (2026-10-19 inventory). 2176
/// covers that plus ~one export record of headroom (~102 B/record). Beyond
/// this the SINGLE-FRAME path is capped by QR physics anyway (one QR's
/// alphanumeric capacity ≈ 4296 chars ≈ 2145 B of bytewords payload), so
/// larger messages legitimately travel the multipart path (whose caps are
/// the 16 KiB-class `ur_multipart` constants) — raising this constant further
/// would only grow buffers, not capability.
pub const UR_PAYLOAD_MAX_LEN: usize = 2176;
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
    XmrOutput, // Cake direct pairing (monero_c patch name): encrypted output-export container (Monero output export\x04)
    XmrKeyImage, // Cake direct pairing (monero_c patch name): encrypted key-image container (Monero key image export\x03)
    SolanaSignRequest, // SOL
    CardanoSignRequest, // ADA
    CosmosSignRequest, // Cosmos family
    Bytes,       // opaque bytes (tests / passthrough)
    CryptoHdKey, // crypto-hdkey
    CryptoAccount, // crypto-account
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
            "xmr-output" => Self::XmrOutput,
            "xmr-keyimage" => Self::XmrKeyImage,
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
            Self::XmrOutput => "xmr-output",
            Self::XmrKeyImage => "xmr-keyimage",
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

/// Single-fragment encoding: payload → CBOR byte-string shell →
/// bytewords-minimal → `ur:<type>/<body>` (outbound wrap; the delivered
/// payload is what `ur_decode` hands back after stripping).
pub fn encode(type_tag: UrTypeTag, payload: &[u8]) -> Result<UrEncoded> {
    if payload.len() > UR_PAYLOAD_MAX_LEN {
        return Err(err());
    }
    let mut wire = heapless::Vec::<u8, { UR_PAYLOAD_MAX_LEN + 3 }>::new();
    crate::ur::ur_shell::ur_message_wrap_into(payload, &mut wire)?;
    debug_assert_eq!(wire.len(), ur_message_shell_len(payload.len())?);
    let mut uri = heapless::String::<UR_URI_MAX_LEN>::new();
    push_str(&mut uri, "ur:")?;
    push_str(&mut uri, type_tag.type_name())?;
    push_str(&mut uri, "/")?;
    bytewords::encode_minimal_into_str(&wire, &mut uri)?;
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
    /// `ur:bytes/iehsjyhspmwfwfia` ↔ `b"data"` — the legacy vector's message is
    /// bare (`0x64` is CBOR text, not a byte-string head), so the inbound shell
    /// strip passes it through unchanged. Since 2026-10-12 outbound is shelled,
    /// so `encode` produces the wrapped form and still round-trips to `b"data"`.
    #[test]
    fn bcr_official_single_part_round_trip() {
        let d = crate::ur::ur_decode::decode("ur:bytes/iehsjyhspmwfwfia").unwrap();
        assert_eq!(d.type_tag(), UrTypeTag::Bytes);
        assert_eq!(d.as_ref(), b"data");
        // outbound message = CBOR byte-string shell (0x58 0x04) + content
        let enc = encode(UrTypeTag::Bytes, b"data").unwrap();
        assert_eq!(enc.as_str(), "ur:bytes/hdaaiehsjyhsdedeoyln");
        let d = crate::ur::ur_decode::decode(enc.as_str()).unwrap();
        assert_eq!(d.as_ref(), b"data");
    }

    /// Independent Python implementation: raw `[0x01, 0x02]` → shell-wrapped
    /// `ur:bytes/hdaoadaouyjzkegm` (message = `58 02 01 02` + CRC32)
    #[test]
    fn independent_oracle_bytes_vector() {
        let enc = encode(UrTypeTag::Bytes, &[0x01, 0x02]).unwrap();
        assert_eq!(enc.as_str(), "ur:bytes/hdaoadaouyjzkegm");
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
        // Contract reminder: 2176 = the 2052-B real-Cake benchmark (pool §36)
        // + ~one record of headroom, bounded above by single-QR physics
        // (~2145 B bytewords payload ≈ one QR alphanumeric capacity). Larger
        // traffic rides the multipart path.
        assert_eq!(UR_PAYLOAD_MAX_LEN, 2176);
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

// ============================================================================
// T2 tests (2026-10-08): Cake direct pairing UR tags (xmr-output / xmr-keyimage)
// ============================================================================
#[cfg(test)]
mod xmr_pairing_tag_tests {
    use super::*;

    /// Type string ↔ enum bidirectional mapping (the string literal IS the UR
    /// type, identical to the monero_c patch names).
    #[test]
    fn xmr_pairing_tags_round_trip() {
        assert_eq!(UrTypeTag::from_name("xmr-output"), UrTypeTag::XmrOutput);
        assert_eq!(UrTypeTag::XmrOutput.type_name(), "xmr-output");
        assert_eq!(UrTypeTag::from_name("xmr-keyimage"), UrTypeTag::XmrKeyImage);
        assert_eq!(UrTypeTag::XmrKeyImage.type_name(), "xmr-keyimage");
    }

    /// Single-frame encode/decode round trip through the new tags.
    #[test]
    fn xmr_pairing_tag_encode_decode() {
        for (tag, name) in [
            (UrTypeTag::XmrOutput, "ur:xmr-output/"),
            (UrTypeTag::XmrKeyImage, "ur:xmr-keyimage/"),
        ] {
            let payload = b"Monero output export\x04fake";
            let enc = encode(tag, payload).unwrap();
            assert!(enc.as_str().starts_with(name));
            let dec = crate::ur::ur_decode::decode(enc.as_str()).unwrap();
            assert_eq!(dec.type_tag(), tag);
            assert_eq!(dec.as_ref(), payload);
        }
    }

    /// Decode routing: the UR layer must route the container types by their
    /// type strings, not by payload content.
    #[test]
    fn xmr_pairing_decode_routes_type() {
        let out = encode(UrTypeTag::XmrOutput, b"aa").unwrap();
        let ki = encode(UrTypeTag::XmrKeyImage, b"bb").unwrap();
        assert_eq!(
            crate::ur::ur_decode::decode(out.as_str())
                .unwrap()
                .type_tag(),
            UrTypeTag::XmrOutput
        );
        assert_eq!(
            crate::ur::ur_decode::decode(ki.as_str())
                .unwrap()
                .type_tag(),
            UrTypeTag::XmrKeyImage
        );
    }

    /// The pairing containers are not signing requests: `to_template` must
    /// refuse them (they never reach the sign dispatch).
    #[test]
    fn xmr_pairing_tags_not_signable() {
        for tag in [UrTypeTag::XmrOutput, UrTypeTag::XmrKeyImage] {
            let r = crate::tx::tx_normalize::to_template(tag, b"x");
            assert!(r.is_err(), "tag {:?} must not become a TxTemplate", tag);
        }
    }
}
