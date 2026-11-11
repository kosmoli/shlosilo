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
    CryptoPsbt, // BTC (registry name, BCR-2020-006)
    /// BTC PSBT under the short name the Cake family puts on the wire
    /// (`~/codebases/cupcake/lib/coins/bitcoin/wallet.dart`: `UR("psbt", ...)`).
    /// Same payload as `CryptoPsbt`, different name: the reply must carry the
    /// name the request used, so the two are distinct tags, not aliases.
    Psbt,
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
    /// crypto-multi-accounts (tag 1103): the aggregated-wallet account bundle
    CryptoMultiAccounts,
    Unknown,
}

impl UrTypeTag {
    /// Map a UR type string to its tag. **Case-insensitive**: BC-UR encoders are
    /// free to upper-case the whole UR (QR alphanumeric mode has no lowercase —
    /// Sparrow does exactly that), and the spec puts the case-folding burden on
    /// the decoder.
    pub fn from_name(name: &str) -> Self {
        // Fold once into a stack buffer; the longest canonical name is
        // "eth-sign-request" (16 bytes), so anything longer cannot match.
        let mut buf = [0u8; 32];
        if name.len() > buf.len() {
            return Self::Unknown;
        }
        for (i, b) in name.as_bytes().iter().enumerate() {
            buf[i] = b.to_ascii_lowercase();
        }
        let name = match core::str::from_utf8(&buf[..name.len()]) {
            Ok(s) => s,
            Err(_) => return Self::Unknown,
        };
        match name {
            "crypto-psbt" => Self::CryptoPsbt,
            "psbt" => Self::Psbt,
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
            "crypto-multi-accounts" => Self::CryptoMultiAccounts,
            _ => Self::Unknown,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Self::CryptoPsbt => "crypto-psbt",
            Self::Psbt => "psbt",
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
            Self::CryptoMultiAccounts => "crypto-multi-accounts",
            Self::Unknown => "unknown",
        }
    }

    /// The same name as a NUL-terminated C string.
    ///
    /// A `&str` pointer is not a C string (Rust literals carry no terminator), so
    /// the FFI hands out this form. One pin asserts the two agree for every tag.
    pub fn type_name_cstr(self) -> &'static core::ffi::CStr {
        match self {
            Self::CryptoPsbt => c"crypto-psbt",
            Self::Psbt => c"psbt",
            Self::EthSignRequest => c"eth-sign-request",
            Self::CryptoMoneroTx => c"crypto-monero-tx",
            Self::XmrTxUnsigned => c"xmr-txunsigned",
            Self::XmrTxSigned => c"xmr-txsigned",
            Self::XmrOutput => c"xmr-output",
            Self::XmrKeyImage => c"xmr-keyimage",
            Self::SolanaSignRequest => c"solana-sign-request",
            Self::CardanoSignRequest => c"cardano-sign-request",
            Self::CosmosSignRequest => c"cosmos-sign-request",
            Self::Bytes => c"bytes",
            Self::CryptoHdKey => c"crypto-hdkey",
            Self::CryptoAccount => c"crypto-account",
            Self::CryptoMultiAccounts => c"crypto-multi-accounts",
            Self::Unknown => c"unknown",
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

    /// Official BC-UR registry tag (BCR-2020-05 registry extension). Golden
    /// anchor: `ur-registry 1.0.9` `registry_types.rs:251-254`
    /// (xmr-output=8301, xmr-keyimage=8302, xmr-txunsigned=8303,
    /// xmr-txsigned=8304) — the crate keystone3-firmware 3.2.0 links.
    pub fn registry_tag(self) -> Option<u64> {
        match self {
            Self::XmrOutput => Some(8301),
            Self::XmrKeyImage => Some(8302),
            Self::XmrTxUnsigned => Some(8303),
            Self::XmrTxSigned => Some(8304),
            _ => None,
        }
    }
}

/// Whether this type's UR **message** is a CBOR byte-string container or the
/// CBOR item itself.
///
/// The byte-string shell is a transport convention for container-carrying types:
/// BCR-2020-006 (crypto-psbt) and the Monero types put a byte container inside,
/// and the peers (Sparrow, monero_c / Cupcake) decode with `decodeBytes`, so the
/// shell is what they expect.
///
/// The key/path registries are different: BCR-2020-007 defines the crypto-hdkey
/// and crypto-account (and eth-sign-request) message as the **CBOR map itself** -
/// `CryptoHDKey.fromCBOR(ur.cbor)` decodes the message directly. Wrapping those
/// puts a byte string where the registry expects a map, and a strict parser then
/// reads the shell's bytes as map fields (the keystone SDK's `parseHDKey` dies
/// with "getData is not a function" because `map[5]` is a byte). Our own decoder
/// strips the shell, so the defect is invisible to a decode-side shape test -
/// only an external parser caught it (`tools/sdk-gate`).
pub(crate) fn message_is_cbor_item(type_tag: UrTypeTag) -> bool {
    matches!(
        type_tag,
        UrTypeTag::CryptoHdKey
            | UrTypeTag::CryptoAccount
            | UrTypeTag::CryptoMultiAccounts
            | UrTypeTag::EthSignRequest
    )
}

/// Single-fragment encoding: payload → CBOR byte-string shell →
/// bytewords-minimal → `ur:<type>/<body>` (outbound wrap; the delivered
/// payload is what `ur_decode` hands back after stripping).
pub fn encode(type_tag: UrTypeTag, payload: &[u8]) -> Result<UrEncoded> {
    if payload.len() > UR_PAYLOAD_MAX_LEN {
        return Err(err());
    }
    let mut wire = heapless::Vec::<u8, { UR_PAYLOAD_MAX_LEN + 3 }>::new();
    if message_is_cbor_item(type_tag) {
        // The payload already IS the message (a CBOR item): no shell.
        wire.extend_from_slice(payload).map_err(|_| err())?;
    } else {
        crate::ur::ur_shell::ur_message_wrap_into(payload, &mut wire)?;
        debug_assert_eq!(wire.len(), ur_message_shell_len(payload.len())?);
    }
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
        // outbound message = canonical CBOR byte-string shell (0x44, short
        // form since the WP3 registry cross-check) + content
        let enc = encode(UrTypeTag::Bytes, b"data").unwrap();
        assert_eq!(enc.as_str(), "ur:bytes/fyiehsjyhsvdvadawm");
        let d = crate::ur::ur_decode::decode(enc.as_str()).unwrap();
        assert_eq!(d.as_ref(), b"data");
    }

    /// Independent Python implementation: raw `[0x01, 0x02]` → shell-wrapped
    /// (message = `42 01 02` + CRC32). The Python oracle originally emitted
    /// the non-minimal `58 02` head (`hdaoadaouyjzkegm`); the WP3 registry
    /// cross-check (ur-registry `44aabbccdd`, RFC 8949 §4.2) canonicalized
    /// the head to `42` — the payload and CRC semantics are unchanged.
    #[test]
    fn independent_oracle_bytes_vector() {
        let enc = encode(UrTypeTag::Bytes, &[0x01, 0x02]).unwrap();
        assert_eq!(enc.as_str(), "ur:bytes/fwadaokggetitt");
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
mod type_name_tests {
    use super::UrTypeTag;

    /// The C names and the Rust names are one source: the device's frame encoder
    /// is handed the C string, the SDK gate and logs use the Rust one.
    #[test]
    fn cstr_type_names_match() {
        let all = [
            UrTypeTag::CryptoPsbt,
            UrTypeTag::Psbt,
            UrTypeTag::EthSignRequest,
            UrTypeTag::CryptoMoneroTx,
            UrTypeTag::XmrTxUnsigned,
            UrTypeTag::XmrTxSigned,
            UrTypeTag::XmrOutput,
            UrTypeTag::XmrKeyImage,
            UrTypeTag::SolanaSignRequest,
            UrTypeTag::CardanoSignRequest,
            UrTypeTag::CosmosSignRequest,
            UrTypeTag::Bytes,
            UrTypeTag::CryptoHdKey,
            UrTypeTag::CryptoAccount,
            UrTypeTag::CryptoMultiAccounts,
            UrTypeTag::Unknown,
        ];
        for t in all {
            assert_eq!(
                t.type_name_cstr().to_str().expect("ascii"),
                t.type_name(),
                "{t:?} C name differs from the Rust name"
            );
        }
    }
}

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

    /// I9/WP3 registry pin (2026-10-31): the four Monero registry tags match
    /// `ur-registry 1.0.9` `registry_types.rs:251-254` exactly — the crate
    /// keystone3-firmware 3.2.0 links (its monero app encodes via
    /// `XmrKeyImage/XmrTxSigned::get_registry_type().get_type()`).
    #[test]
    fn registry_tags_match_ur_registry_109() {
        assert_eq!(UrTypeTag::XmrOutput.registry_tag(), Some(8301));
        assert_eq!(UrTypeTag::XmrKeyImage.registry_tag(), Some(8302));
        assert_eq!(UrTypeTag::XmrTxUnsigned.registry_tag(), Some(8303));
        assert_eq!(UrTypeTag::XmrTxSigned.registry_tag(), Some(8304));
    }

    /// I9/WP3 registry CBOR pin: our message shell IS the ur-registry
    /// message shape. Official vector (ur-registry 1.0.9
    /// `monero/xmr_txsigned.rs::tests::test_encode`):
    /// `XmrTxSigned::new(0xaabbccdd).try_into()` == `44aabbccdd` — a
    /// definite-length CBOR byte-string head (0x44 = bstr(4)) + payload,
    /// exactly what `ur_message_wrap_into` builds. Byte-for-byte both ways.
    #[test]
    fn xmr_shell_matches_ur_registry_vector() {
        let payload = [0xAAu8, 0xBB, 0xCC, 0xDD];
        let mut wire = heapless::Vec::<u8, 8>::new();
        crate::ur::ur_shell::ur_message_wrap_into(&payload, &mut wire).unwrap();
        assert_eq!(
            wire.as_slice(),
            &[0x44, 0xAA, 0xBB, 0xCC, 0xDD],
            "official ur-registry vector 44aabbccdd"
        );
        assert_eq!(
            crate::ur::ur_shell::ur_message_content(wire.as_slice()),
            &payload[..],
            "strip round-trips the official shape"
        );
    }
}
