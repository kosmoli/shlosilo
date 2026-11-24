//! `ur:eth-signature` UR codec — outbound signature container.
//!
//! Contract: `docs/eth-signature-codec.md`. The wire layout is the
//! `@keystonehq/bc-ur-registry-eth` `ETHSignature` map that the peer decodes as
//! the UR message itself (`ETHSignature.fromCBOR(ur.cbor)`), so this type is a
//! CBOR item on the wire, never a byte-string shell (`message_is_cbor_item`).
//!
//! ```text
//! 1: request_id — tag(37 UUID) + 16 B, echoed from eth-sign-request key 1
//! 2: signature  — bytes(65) = r (32) | s (32) | v (1); v is opaque here
//! 3: origin     — text (optional), echoed from eth-sign-request key 7
//! ```
//!
//! The container never mints a request id and never interprets `v`: chain
//! semantics (yParity vs 27/28 vs EIP-155) belong to the signer.
//!
//! Zero-heap: the production encode writes structurally through
//! [`crate::encoding::cbor::CborWriter`] into the caller's buffer, the decode is
//! a borrowed [`Cbor`] view over the payload, and the only allocating helper
//! (`encode_eth_signature_ur`, a transitional UR-string shell) is behind
//! `alloc-fallback`/`test`.

#[cfg(any(feature = "alloc-fallback", test))]
extern crate alloc;

use crate::encoding::cbor::{Cbor, CborWriter};
use crate::error::{ErrorContext, Result, ShlosiloError, ShlosiloErrorKind};
use crate::types::caps::ETH_UR_ORIGIN_MAX_LEN;
#[cfg(any(feature = "alloc-fallback", test))]
use crate::ur::ur_encode::{self, UrEncoded, UrTypeTag};

/// Upper bound of the CBOR message: 156 B worst case (65-byte signature +
/// origin at [`ETH_UR_ORIGIN_MAX_LEN`]) with margin.
pub const ETH_SIGNATURE_CBOR_MAX_LEN: usize = 160;

const KEY_REQUEST_ID: u64 = 1;
const KEY_SIGNATURE: u64 = 2;
const KEY_ORIGIN: u64 = 3;
/// CBOR tag 37 = UUID (RFC 4122 §3); the ur-registry `requestId` wrapper.
const TAG_UUID: u64 = 37;
const REQUEST_ID_LEN: usize = 16;
const SIGNATURE_LEN: usize = 65;

/// Outbound `ur:eth-signature` container fields.
pub struct EthSignature<'a> {
    /// Echoed from `eth-sign-request` key 1 — never minted here.
    pub request_id: [u8; 16],
    /// `r (32) | s (32) | v (1)`. `v` is opaque: no 27 offset, no range check.
    pub signature: [u8; 65],
    /// Echoed from `eth-sign-request` key 7 (optional).
    pub origin: Option<&'a str>,
}

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

fn too_small(need: usize) -> ShlosiloError {
    ShlosiloError::with_context(
        ShlosiloErrorKind::BufferTooSmall,
        ErrorContext::RequiredLength(need),
    )
}

/// Length of a CBOR head carrying `arg` (RFC 8949 §3: the shortest form wins —
/// same table as `CborWriter::head`).
const fn head_len(arg: u64) -> usize {
    if arg < 24 {
        1
    } else if arg <= u8::MAX as u64 {
        2
    } else if arg <= u16::MAX as u64 {
        3
    } else if arg <= u32::MAX as u64 {
        5
    } else {
        9
    }
}

/// Exact byte length of the message `encode_eth_signature_into` writes.
///
/// Computed up front so an under-capacity buffer reports the true requirement
/// instead of failing halfway through a partial write.
fn encoded_len(sig: &EthSignature<'_>) -> Result<usize> {
    // map head + key 1 (uint + uuid tag + 16-byte string) + key 2 (uint + 65 bytes)
    let entries = if sig.origin.is_some() { 3 } else { 2 };
    let mut need = head_len(entries as u64)
        + head_len(KEY_REQUEST_ID)
        + head_len(TAG_UUID)
        + head_len(REQUEST_ID_LEN as u64)
        + REQUEST_ID_LEN
        + head_len(KEY_SIGNATURE)
        + head_len(SIGNATURE_LEN as u64)
        + SIGNATURE_LEN;
    if let Some(origin) = sig.origin {
        // Over the cap is a format error, never a truncation.
        if origin.len() > ETH_UR_ORIGIN_MAX_LEN {
            return Err(err());
        }
        need += head_len(KEY_ORIGIN) + head_len(origin.len() as u64) + origin.len();
    }
    Ok(need)
}

/// CBOR message only (no UR wrapper), into the caller's buffer.
///
/// Zero-alloc: the map is written structurally through
/// [`CborWriter`], entries in canonical key order 1, 2, 3.
pub fn encode_eth_signature_into(sig: &EthSignature<'_>, out: &mut [u8]) -> Result<usize> {
    let need = encoded_len(sig)?;
    if out.len() < need {
        return Err(too_small(need));
    }
    let mut w = CborWriter::new(out);
    w.map_head(if sig.origin.is_some() { 3 } else { 2 })?;
    w.uint(KEY_REQUEST_ID)?;
    w.tag(TAG_UUID)?;
    w.bytes(&sig.request_id)?;
    w.uint(KEY_SIGNATURE)?;
    w.bytes(&sig.signature)?;
    if let Some(origin) = sig.origin {
        w.uint(KEY_ORIGIN)?;
        w.text(origin)?;
    }
    Ok(w.pos())
}

/// Full `ur:eth-signature/...` string (test/transitional shell only).
///
/// The device hands the message to its frame encoder
/// ([`encode_eth_signature_into`]); this wrapper exists for tests and the
/// host-side single-frame path.
#[cfg(any(feature = "alloc-fallback", test))]
pub fn encode_eth_signature_ur(sig: &EthSignature<'_>) -> Result<UrEncoded> {
    let mut buf = [0u8; ETH_SIGNATURE_CBOR_MAX_LEN];
    let n = encode_eth_signature_into(sig, &mut buf)?;
    ur_encode::encode(UrTypeTag::EthSignature, &buf[..n])
}

/// Borrowed decode of the CBOR message. Fails closed — every listed rule is an
/// error, never a default:
///
/// - non-map payload → error;
/// - key 1 absent, or not `tag(37)` over exactly 16 bytes → error;
/// - key 2 absent, or not exactly 65 bytes → error;
/// - key 3 present but not text, or over [`ETH_UR_ORIGIN_MAX_LEN`] → error;
/// - trailing garbage → error (the shared `encoding::cbor::decode` rejects it).
pub fn parse_eth_signature(payload: &[u8]) -> Result<EthSignature<'_>> {
    let cbor = crate::encoding::cbor::decode(payload)?;
    if !matches!(cbor, Cbor::Map(_)) {
        return Err(err());
    }

    // key 1: uuid tag over exactly 16 bytes (whitelisted tag, not "any tag")
    let request_id_item = cbor.map_get_uint(KEY_REQUEST_ID)?.ok_or_else(err)?;
    if !matches!(request_id_item, Cbor::Tag(TAG_UUID, _)) {
        return Err(err());
    }
    let request_id_bytes = request_id_item.inner()?.as_bytes()?;
    if request_id_bytes.len() != REQUEST_ID_LEN {
        return Err(err());
    }
    let mut request_id = [0u8; REQUEST_ID_LEN];
    request_id.copy_from_slice(request_id_bytes);

    // key 2: exactly 65 bytes (a 64-byte r||s is refused, not short-filled)
    let signature_bytes = cbor
        .map_get_uint(KEY_SIGNATURE)?
        .ok_or_else(err)?
        .as_bytes()?;
    if signature_bytes.len() != SIGNATURE_LEN {
        return Err(err());
    }
    let mut signature = [0u8; SIGNATURE_LEN];
    signature.copy_from_slice(signature_bytes);

    // key 3: optional text, bounded
    let origin = match cbor.map_get_uint(KEY_ORIGIN)? {
        Some(v) => {
            let s = v.as_text()?;
            if s.len() > ETH_UR_ORIGIN_MAX_LEN {
                return Err(err());
            }
            Some(s)
        }
        None => None,
    };

    Ok(EthSignature {
        request_id,
        signature,
        origin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gold vector from `keystone-sdk-web/src/__tests__/ethereum.test.ts`
    /// (`ETHSignature.fromCBOR(ur.cbor)`), 99 B for an 8-char origin.
    const GOLD_HEX: &str = concat!(
        "a301d82550",
        "9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d",
        "025841",
        "d4f0a7bcd95bba1fbb1051885054730e3f47064288575aacc102fbbf6a9a14d",
        "aa066991e360d3e3406c20c00a40973eff37c7d641e5b351ec4a99bfe86f335f713",
        "03686b657973746f6e65",
    );
    const REQUEST_ID_HEX: &str = "9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d";
    const SIGNATURE_HEX: &str = concat!(
        "d4f0a7bcd95bba1fbb1051885054730e3f47064288575aacc102fbbf6a9a14d",
        "aa066991e360d3e3406c20c00a40973eff37c7d641e5b351ec4a99bfe86f335f713",
    );

    fn hex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn fixed<const N: usize>(s: &str) -> [u8; N] {
        let v = hex(s);
        assert_eq!(v.len(), N, "hex length");
        let mut out = [0u8; N];
        out.copy_from_slice(&v);
        out
    }

    fn gold_request_id() -> [u8; 16] {
        fixed::<16>(REQUEST_ID_HEX)
    }

    fn gold_signature() -> [u8; 65] {
        fixed::<65>(SIGNATURE_HEX)
    }

    /// Pin 1: the gold payload decodes to the three fields, byte for byte.
    #[test]
    fn eth_signature_gold_vector_decodes() {
        let payload = hex(GOLD_HEX);
        assert_eq!(payload.len(), 99, "gold vector size");
        let sig = parse_eth_signature(&payload).expect("gold vector must parse");
        assert_eq!(sig.request_id, gold_request_id());
        assert_eq!(sig.signature, gold_signature());
        assert_eq!(sig.origin, Some("keystone"));
    }

    /// Pin 2: our encoder reproduces the gold bytes exactly — no reordering, no
    /// re-tagging, no `v` adjustment.
    #[test]
    fn eth_signature_encode_matches_gold_vector_byte_exact() {
        let sig = EthSignature {
            request_id: gold_request_id(),
            signature: gold_signature(),
            origin: Some("keystone"),
        };
        let mut out = [0u8; ETH_SIGNATURE_CBOR_MAX_LEN];
        let n = encode_eth_signature_into(&sig, &mut out).expect("encode");
        assert_eq!(n, 99);
        assert_eq!(&out[..n], &hex(GOLD_HEX)[..]);
    }

    /// Pin 3: full UR round trip — the type tag survives and the message is the
    /// CBOR map itself (no byte-string shell).
    #[test]
    fn eth_signature_round_trip_through_ur() {
        let sig = EthSignature {
            request_id: gold_request_id(),
            signature: gold_signature(),
            origin: Some("keystone"),
        };
        let enc = encode_eth_signature_ur(&sig).expect("encode ur");
        assert!(
            enc.as_str().starts_with("ur:eth-signature/"),
            "UR name: {}",
            enc.as_str()
        );
        let decoded = crate::ur::ur_decode::decode(enc.as_str()).expect("decode ur");
        assert_eq!(decoded.type_tag(), UrTypeTag::EthSignature);
        // message_is_cbor_item: the payload is the map, verbatim
        assert_eq!(decoded.as_ref(), &hex(GOLD_HEX)[..]);
        let back = parse_eth_signature(decoded.as_ref()).expect("parse");
        assert_eq!(back.request_id, sig.request_id);
        assert_eq!(back.signature, sig.signature);
        assert_eq!(back.origin, sig.origin);
    }

    /// Pin 4: the container echoes the id it is given — two ids, two encodings,
    /// each parsing back to its own id (nothing is regenerated).
    #[test]
    fn eth_signature_echoes_request_id_no_regeneration() {
        let a = EthSignature {
            request_id: [0x11; 16],
            signature: gold_signature(),
            origin: None,
        };
        let b = EthSignature {
            request_id: [0x22; 16],
            signature: gold_signature(),
            origin: None,
        };
        let mut buf_a = [0u8; ETH_SIGNATURE_CBOR_MAX_LEN];
        let mut buf_b = [0u8; ETH_SIGNATURE_CBOR_MAX_LEN];
        let na = encode_eth_signature_into(&a, &mut buf_a).expect("encode a");
        let nb = encode_eth_signature_into(&b, &mut buf_b).expect("encode b");
        assert_ne!(&buf_a[..na], &buf_b[..nb], "ids must reach the wire");
        assert_eq!(
            parse_eth_signature(&buf_a[..na])
                .expect("parse a")
                .request_id,
            [0x11; 16]
        );
        assert_eq!(
            parse_eth_signature(&buf_b[..nb])
                .expect("parse b")
                .request_id,
            [0x22; 16]
        );
    }

    /// Pin 5: a 64-byte `r || s` is not short-filled into a 65-byte signature.
    #[test]
    fn eth_signature_rejects_64_byte_signature() {
        use crate::encoding::cbor;
        let payload = cbor::encode_map(&[
            (
                cbor::encode_uint(1),
                cbor::encode_tag(TAG_UUID, &cbor::encode_bytes(&gold_request_id())),
            ),
            (
                cbor::encode_uint(2),
                cbor::encode_bytes(&gold_signature()[..64]),
            ),
        ]);
        assert!(
            parse_eth_signature(&payload).is_err(),
            "64-byte signature must be rejected"
        );
    }

    /// Pin 6: key 1 must carry the uuid tag — a bare 16-byte string is rejected.
    #[test]
    fn eth_signature_rejects_unwrapped_uuid() {
        use crate::encoding::cbor;
        let payload = cbor::encode_map(&[
            (cbor::encode_uint(1), cbor::encode_bytes(&gold_request_id())),
            (cbor::encode_uint(2), cbor::encode_bytes(&gold_signature())),
        ]);
        assert!(
            parse_eth_signature(&payload).is_err(),
            "untagged request id must be rejected"
        );
    }

    /// Pin 7: the origin cap is an error on both sides — never truncation on
    /// encode, never silent acceptance on parse. The cap is also what bounds the
    /// container at `ETH_SIGNATURE_CBOR_MAX_LEN`.
    #[test]
    fn eth_signature_rejects_oversized_origin() {
        use crate::encoding::cbor;
        // encode: over the cap is refused
        let long = "a".repeat(ETH_UR_ORIGIN_MAX_LEN + 1);
        let sig = EthSignature {
            request_id: gold_request_id(),
            signature: gold_signature(),
            origin: Some(&long),
        };
        let mut out = [0u8; ETH_SIGNATURE_CBOR_MAX_LEN];
        assert!(
            encode_eth_signature_into(&sig, &mut out).is_err(),
            "oversized origin must be refused, not truncated"
        );
        // parse: same cap on the inbound side
        let payload = cbor::encode_map(&[
            (
                cbor::encode_uint(1),
                cbor::encode_tag(TAG_UUID, &cbor::encode_bytes(&gold_request_id())),
            ),
            (cbor::encode_uint(2), cbor::encode_bytes(&gold_signature())),
            (cbor::encode_uint(3), cbor::encode_text(&long)),
        ]);
        assert!(
            parse_eth_signature(&payload).is_err(),
            "oversized inbound origin must be rejected"
        );
        // exactly at the cap: accepted, and the worst case fits the buffer bound
        let cap = "b".repeat(ETH_UR_ORIGIN_MAX_LEN);
        let sig = EthSignature {
            request_id: gold_request_id(),
            signature: gold_signature(),
            origin: Some(&cap),
        };
        let n = encode_eth_signature_into(&sig, &mut out).expect("cap-sized origin encodes");
        assert_eq!(n, 156, "documented worst case for the origin cap");
        assert!(n <= ETH_SIGNATURE_CBOR_MAX_LEN);
        assert_eq!(
            parse_eth_signature(&out[..n])
                .expect("cap-sized origin parses")
                .origin,
            Some(&cap[..])
        );
    }

    /// Pin 8: trailing garbage after the single top-level item is rejected by the
    /// shared decoder (no second parser, no lenient tail).
    #[test]
    fn eth_signature_rejects_trailing_garbage() {
        let mut payload = hex(GOLD_HEX);
        payload.push(0x00);
        assert!(
            parse_eth_signature(&payload).is_err(),
            "trailing garbage must be rejected"
        );
    }

    /// Pin 9: both ETH types travel as the CBOR item itself; `xmr-txsigned`
    /// (byte-string container) does not.
    #[test]
    fn eth_signature_and_eth_sign_request_are_cbor_items() {
        use crate::ur::ur_encode::message_is_cbor_item;
        assert!(message_is_cbor_item(UrTypeTag::EthSignature));
        assert!(message_is_cbor_item(UrTypeTag::EthSignRequest));
        assert!(!message_is_cbor_item(UrTypeTag::XmrTxSigned));
    }

    /// Strictness rule from the contract without a numbered pin: under-capacity
    /// reports the required length instead of a partial write that looks success.
    #[test]
    fn eth_signature_reports_required_length_on_short_buffer() {
        use crate::error::{ErrorContext, ShlosiloErrorKind};
        let sig = EthSignature {
            request_id: gold_request_id(),
            signature: gold_signature(),
            origin: Some("keystone"),
        };
        let mut out = [0u8; 98];
        let e = encode_eth_signature_into(&sig, &mut out).expect_err("98 B is one byte short");
        assert_eq!(e.kind, ShlosiloErrorKind::BufferTooSmall);
        assert_eq!(e.context, ErrorContext::RequiredLength(99));
    }
}
