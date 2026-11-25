//! `ur:eth-signature` UR codec — outbound signature container.
//!
//! Contract: `docs/eth-signature-codec.md`. The wire layout is the
//! `@keystonehq/bc-ur-registry-eth` `ETHSignature` map that the peer decodes as
//! the UR message itself (`ETHSignature.fromCBOR(ur.cbor)`), so this type is a
//! CBOR item on the wire, never a byte-string shell (`message_is_cbor_item`).
//!
//! ```text
//! 1: request_id — tag(37 UUID) + 16 B, echoed from eth-sign-request key 1
//! 2: signature  — bytes(65..=72) = r (32) | s (32) | v (1..=8); v is opaque here
//! 3: origin     — text (optional), echoed from eth-sign-request key 7
//! ```
//!
//! The container never mints a request id and never interprets `v`: chain
//! semantics (yParity vs 27/28 vs EIP-155) belong to the signer.
//!
//! ## Why `v` is 1..=8 bytes (E-1, 2026-11-25)
//!
//! `v` was one byte while the only schemes wired up were EIP-1559 (`0/1`) and
//! EIP-191 (`27/28`). EIP-155 makes `v = chain_id * 2 + 35 + y_parity`, which is a
//! `u64`: `37/38` on mainnet, `309/310` on Polygon (137 — 2 bytes), `22310257…` on
//! Sepolia (11155111 — 4 bytes). A fixed 65-byte signature could not carry a
//! Sepolia `v` at all, so the field is now a `u64` written **big-endian with its
//! leading zero bytes dropped** — byte for byte what keystone's reference
//! implementation does in `EthereumSignature::serialize`
//! (`rust/apps/ethereum/src/structs.rs`), so the same signature reaches a wallet
//! as the same bytes whichever implementation produced it.
//!
//! That rule is also the canonical form: `v = 309` has one encoding (`01 35`), and
//! a reader that also accepted `00 01 35` would give one signature two byte
//! strings. Both sides enforce it ([`check_signature_shape`]).
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

/// Upper bound of the CBOR message: 163 B worst case (a 72-byte signature plus an
/// origin at [`ETH_UR_ORIGIN_MAX_LEN`]) with margin.
///
/// The 65-byte form is 156 B, as before; the 7 extra bytes are the widest `v` an
/// EIP-155 chain id can produce (`u64::MAX` → `ffffffffffffff` and no longer
/// representable as `v`, see `eip155::sign_eip155_parts`).
pub const ETH_SIGNATURE_CBOR_MAX_LEN: usize = 168;

/// Shortest `r ‖ s ‖ v`: 64 bytes of signature plus a one-byte `v`.
pub const SIGNATURE_MIN_LEN: usize = 65;
/// Longest: 64 bytes plus a full-width 8-byte `v` (`chain_id = u64::MAX`).
pub const SIGNATURE_MAX_LEN: usize = 72;
/// `r ‖ s`, the part of the container that never changes width.
const RS_LEN: usize = 64;

const KEY_REQUEST_ID: u64 = 1;
const KEY_SIGNATURE: u64 = 2;
const KEY_ORIGIN: u64 = 3;
/// CBOR tag 37 = UUID (RFC 4122 §3); the ur-registry `requestId` wrapper.
const TAG_UUID: u64 = 37;
const REQUEST_ID_LEN: usize = 16;

/// Outbound `ur:eth-signature` container fields.
pub struct EthSignature<'a> {
    /// Echoed from `eth-sign-request` key 1 — never minted here.
    pub request_id: [u8; 16],
    /// `r (32) | s (32) | v (1..=8)`. `v` is opaque: no 27 offset, no range check.
    ///
    /// Only the first [`Self::signature_len`] bytes are on the wire; the tail is
    /// padding so the field stays a plain array (`forms/` is zero-heap and
    /// panics on nothing, so no slice/Vec would do).
    pub signature: [u8; SIGNATURE_MAX_LEN],
    /// Valid bytes in [`Self::signature`]: 65..=72 (64 + the width of `v`).
    pub signature_len: usize,
    /// Echoed from `eth-sign-request` key 7 (optional).
    pub origin: Option<&'a str>,
}

impl EthSignature<'_> {
    /// The `r ‖ s ‖ v` bytes that go on the wire (65..=72).
    ///
    /// Empty when `signature_len` was set outside the range: reading must not
    /// panic on a hand-built struct, and every encode refuses that shape anyway
    /// (see [`check_signature_shape`]).
    pub fn signature_bytes(&self) -> &[u8] {
        match self.signature.get(..self.signature_len) {
            Some(s) => s,
            None => &[],
        }
    }
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

/// The one shape rule shared by encode and decode.
///
/// - `len` below [`SIGNATURE_MIN_LEN`] → error. A 64-byte `r ‖ s` is **not**
///   short-filled with a `v`: which `v` (yParity? 27/28? EIP-155?) is exactly the
///   fact a signature must not invent.
/// - `len` above [`SIGNATURE_MAX_LEN`] → error (no `v` is wider than 8 bytes).
/// - `len` above [`SIGNATURE_MIN_LEN`] with a leading zero byte in the `v`
///   segment → error. `v` is big-endian minimal, so `00 01 35` and `01 35` would
///   be two encodings of one signature; accepting both makes the container
///   non-canonical and gives a re-encoding peer no way to recompute our bytes.
fn check_signature_shape(bytes: &[u8]) -> Result<()> {
    if bytes.len() < SIGNATURE_MIN_LEN || bytes.len() > SIGNATURE_MAX_LEN {
        return Err(err());
    }
    if bytes.len() > SIGNATURE_MIN_LEN && bytes[RS_LEN] == 0 {
        return Err(err());
    }
    Ok(())
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
    let signature = sig.signature_bytes();
    // Also the only guard that the hand-set `signature_len` is a length we can
    // encode at all; everything below uses `signature.len()`.
    check_signature_shape(signature)?;
    // map head + key 1 (uint + uuid tag + 16-byte string) + key 2 (uint + bytes)
    let entries = if sig.origin.is_some() { 3 } else { 2 };
    let mut need = head_len(entries as u64)
        + head_len(KEY_REQUEST_ID)
        + head_len(TAG_UUID)
        + head_len(REQUEST_ID_LEN as u64)
        + REQUEST_ID_LEN
        + head_len(KEY_SIGNATURE)
        + head_len(signature.len() as u64)
        + signature.len();
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
    // The bstr length follows the actual `v` width: 65..=72 bytes.
    w.bytes(sig.signature_bytes())?;
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
/// - key 2 absent, or not 65..=72 bytes → error (a 64-byte `r ‖ s` is refused,
///   never short-filled; more than 72 bytes has no `v` that wide);
/// - key 2 wider than 65 bytes with a zero leading byte in the `v` segment →
///   error (only the minimal big-endian form is canonical);
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

    // key 2: r ‖ s ‖ v, 65..=72 bytes, minimal `v`
    let signature_bytes = cbor
        .map_get_uint(KEY_SIGNATURE)?
        .ok_or_else(err)?
        .as_bytes()?;
    check_signature_shape(signature_bytes)?;
    let mut signature = [0u8; SIGNATURE_MAX_LEN];
    // `signature_bytes.len()` is <= SIGNATURE_MAX_LEN: check_signature_shape ran.
    match signature.get_mut(..signature_bytes.len()) {
        Some(slot) => slot.copy_from_slice(signature_bytes),
        None => return Err(err()),
    }
    let signature_len = signature_bytes.len();

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
        signature_len,
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

    /// `signature` slot padded to [`SIGNATURE_MAX_LEN`]; only the first
    /// `signature_len` bytes are on the wire.
    fn slot(bytes: &[u8]) -> [u8; SIGNATURE_MAX_LEN] {
        let mut out = [0u8; SIGNATURE_MAX_LEN];
        out[..bytes.len()].copy_from_slice(bytes);
        out
    }

    /// The gold container: a 65-byte signature (v = one byte).
    fn gold_container(origin: Option<&str>) -> EthSignature<'_> {
        EthSignature {
            request_id: gold_request_id(),
            signature: slot(&gold_signature()),
            signature_len: 65,
            origin,
        }
    }

    /// Pin 1: the gold payload decodes to the three fields, byte for byte.
    #[test]
    fn eth_signature_gold_vector_decodes() {
        let payload = hex(GOLD_HEX);
        assert_eq!(payload.len(), 99, "gold vector size");
        let sig = parse_eth_signature(&payload).expect("gold vector must parse");
        assert_eq!(sig.request_id, gold_request_id());
        assert_eq!(sig.signature_len, 65, "the gold signature is 65 bytes");
        assert_eq!(sig.signature_bytes(), &gold_signature()[..]);
        assert_eq!(sig.origin, Some("keystone"));
    }

    /// Pin 2: our encoder reproduces the gold bytes exactly — no reordering, no
    /// re-tagging, no `v` adjustment.
    #[test]
    fn eth_signature_encode_matches_gold_vector_byte_exact() {
        let sig = gold_container(Some("keystone"));
        let mut out = [0u8; ETH_SIGNATURE_CBOR_MAX_LEN];
        let n = encode_eth_signature_into(&sig, &mut out).expect("encode");
        assert_eq!(n, 99);
        assert_eq!(&out[..n], &hex(GOLD_HEX)[..]);
    }

    /// Pin 3: full UR round trip — the type tag survives and the message is the
    /// CBOR map itself (no byte-string shell).
    #[test]
    fn eth_signature_round_trip_through_ur() {
        let sig = gold_container(Some("keystone"));
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
        assert_eq!(back.signature_bytes(), sig.signature_bytes());
        assert_eq!(back.signature_len, sig.signature_len);
        assert_eq!(back.origin, sig.origin);
    }

    /// Pin 4: the container echoes the id it is given — two ids, two encodings,
    /// each parsing back to its own id (nothing is regenerated).
    #[test]
    fn eth_signature_echoes_request_id_no_regeneration() {
        let a = EthSignature {
            request_id: [0x11; 16],
            ..gold_container(None)
        };
        let b = EthSignature {
            request_id: [0x22; 16],
            ..gold_container(None)
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
        let sig = gold_container(Some(&long));
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
        let sig = gold_container(Some(&cap));
        let n = encode_eth_signature_into(&sig, &mut out).expect("cap-sized origin encodes");
        assert_eq!(
            n, 156,
            "documented worst case for the origin cap, 65-byte sig"
        );
        assert!(n <= ETH_SIGNATURE_CBOR_MAX_LEN);
        assert_eq!(
            parse_eth_signature(&out[..n])
                .expect("cap-sized origin parses")
                .origin,
            Some(&cap[..])
        );
        // and with the widest v the container still fits its declared bound
        let widest = EthSignature {
            request_id: gold_request_id(),
            signature: {
                let mut s = slot(&gold_signature());
                // v = 8 bytes of 0xff: the shape a u64::MAX chain id would need.
                s[64..SIGNATURE_MAX_LEN].copy_from_slice(&[0xff; 8]);
                s
            },
            signature_len: SIGNATURE_MAX_LEN,
            origin: Some(&cap),
        };
        let n = encode_eth_signature_into(&widest, &mut out).expect("widest v encodes");
        assert_eq!(n, 163, "documented worst case overall");
        assert!(
            n <= ETH_SIGNATURE_CBOR_MAX_LEN,
            "ETH_SIGNATURE_CBOR_MAX_LEN must cover the widest v"
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
        let sig = gold_container(Some("keystone"));
        let mut out = [0u8; 98];
        let e = encode_eth_signature_into(&sig, &mut out).expect_err("98 B is one byte short");
        assert_eq!(e.kind, ShlosiloErrorKind::BufferTooSmall);
        assert_eq!(e.context, ErrorContext::RequiredLength(99));
    }

    /// Pin 10 (E-1, 2026-11-25): the `v` segment is 1..=8 bytes and the CBOR head
    /// of key 2 follows it, so an EIP-155 `v` is carried instead of being
    /// truncated to a byte.
    ///
    /// Each case names the chain the width comes from and the exact `v` bytes:
    /// the point is not "some length is accepted" but that the *encoding of one
    /// given v* is one specific byte string.
    #[test]
    fn eth_signature_carries_a_variadic_v_byte_exact() {
        // (label, v bytes, total signature length)
        let cases: [(&str, &[u8], usize); 4] = [
            // mainnet EIP-155 v = 37 (0x25): one byte → 65-byte signature
            ("mainnet 37", &[0x25], 65),
            // EIP-1559 yParity 0 / EIP-191 27: still one byte
            ("yparity 0", &[0x00], 65),
            // Polygon (137) → v = 309 (0x0135): 2 bytes → 66
            ("polygon 309", &[0x01, 0x35], 66),
            // Sepolia (11155111) → v = 22310257 (0x01546d71): 4 bytes → 68
            ("sepolia 4-byte v", &[0x01, 0x54, 0x6d, 0x71], 68),
        ];
        for (label, v, want_len) in cases {
            // The gold hex is a whole 65-byte signature; the r ‖ s part is the first 64.
            let mut sig_bytes = hex(SIGNATURE_HEX);
            sig_bytes.truncate(RS_LEN);
            sig_bytes.extend_from_slice(v);
            assert_eq!(sig_bytes.len(), want_len, "{label}: signature length");
            let sig = EthSignature {
                request_id: gold_request_id(),
                signature: slot(&sig_bytes),
                signature_len: want_len,
                origin: None,
            };
            let mut out = [0u8; ETH_SIGNATURE_CBOR_MAX_LEN];
            let n = encode_eth_signature_into(&sig, &mut out).expect("encode");
            // With no origin, key 2 is the last entry: `0x58 <len>` (a bstr of 24+
            // bytes always carries the two-byte head) followed by r ‖ s ‖ v. So the
            // length byte moves with `v` and the container grows by exactly as much.
            let body = &out[..n];
            let head_at = n - 2 - want_len;
            assert_eq!(body[head_at], 0x58, "{label}: key 2 bstr head prefix");
            assert_eq!(
                body[head_at + 1],
                want_len as u8,
                "{label}: key 2 length byte follows the signature width"
            );
            assert_eq!(
                &body[n - v.len()..],
                v,
                "{label}: v is the container's tail, byte for byte"
            );
            let back = parse_eth_signature(body).expect("parse");
            assert_eq!(back.signature_len, want_len, "{label}: length round-trips");
            assert_eq!(
                back.signature_bytes(),
                &sig_bytes[..],
                "{label}: every byte of r ‖ s ‖ v round-trips"
            );
            let v_back = &back.signature_bytes()[RS_LEN..];
            assert_eq!(v_back, v, "{label}: the v segment is carried verbatim");
        }
    }

    /// Pin 11 (E-1): `v` is minimal big-endian, so a padded `v` is a second
    /// encoding of a signature we already accept. Both directions refuse it —
    /// otherwise two different byte strings decode to one signature and a peer
    /// that re-encodes cannot reproduce what we sent.
    #[test]
    fn eth_signature_rejects_leading_zero_v() {
        use crate::encoding::cbor;
        // r ‖ s ‖ 00 01 35 — v = 309 padded to 3 bytes (the canonical form is 66 B)
        let mut padded = hex(SIGNATURE_HEX);
        padded.truncate(RS_LEN);
        padded.extend_from_slice(&[0x00, 0x01, 0x35]);
        assert_eq!(padded.len(), 67);
        let payload = cbor::encode_map(&[
            (
                cbor::encode_uint(1),
                cbor::encode_tag(TAG_UUID, &cbor::encode_bytes(&gold_request_id())),
            ),
            (cbor::encode_uint(2), cbor::encode_bytes(&padded)),
        ]);
        assert!(
            parse_eth_signature(&payload).is_err(),
            "a leading zero in the v segment must be rejected"
        );

        // the encoder refuses to mint it either
        let sig = EthSignature {
            request_id: gold_request_id(),
            signature: slot(&padded),
            signature_len: padded.len(),
            origin: None,
        };
        let mut out = [0u8; ETH_SIGNATURE_CBOR_MAX_LEN];
        assert!(
            encode_eth_signature_into(&sig, &mut out).is_err(),
            "the encoder must never write a padded v"
        );

        // control: the minimal form of the same v is accepted (66 B, v = 01 35)
        let mut minimal = hex(SIGNATURE_HEX);
        minimal.truncate(RS_LEN);
        minimal.extend_from_slice(&[0x01, 0x35]);
        let sig = EthSignature {
            request_id: gold_request_id(),
            signature: slot(&minimal),
            signature_len: minimal.len(),
            origin: None,
        };
        let n = encode_eth_signature_into(&sig, &mut out).expect("minimal v encodes");
        assert_eq!(
            parse_eth_signature(&out[..n])
                .expect("minimal v parses")
                .signature_bytes(),
            &minimal[..]
        );
    }

    /// Pin 12 (E-1): the two ends of the accepted range — 72 bytes is the widest
    /// signature this container carries, 73 has no `v` that wide.
    #[test]
    fn eth_signature_rejects_73_bytes_and_accepts_72() {
        use crate::encoding::cbor;
        let build = |sig: &[u8]| {
            cbor::encode_map(&[
                (
                    cbor::encode_uint(1),
                    cbor::encode_tag(TAG_UUID, &cbor::encode_bytes(&gold_request_id())),
                ),
                (cbor::encode_uint(2), cbor::encode_bytes(sig)),
            ])
        };
        // 72 = r ‖ s ‖ 8-byte v (a chain id near u64::MAX)
        let mut widest = hex(SIGNATURE_HEX);
        widest.truncate(RS_LEN);
        widest.extend_from_slice(&[0xff; 8]);
        assert_eq!(widest.len(), SIGNATURE_MAX_LEN);
        let widest_payload = build(&widest);
        let parsed = parse_eth_signature(&widest_payload).expect("72 bytes is the widest v");
        assert_eq!(parsed.signature_bytes(), &widest[..]);

        // 73 has no representation: v is a u64
        let mut too_wide = hex(SIGNATURE_HEX);
        too_wide.truncate(RS_LEN);
        too_wide.extend_from_slice(&[0xff; 9]);
        assert!(
            parse_eth_signature(&build(&too_wide)).is_err(),
            "73 bytes must be rejected"
        );

        // and an out-of-range signature_len cannot be encoded (or read) by accident
        let sig = EthSignature {
            request_id: gold_request_id(),
            signature: slot(&too_wide[..SIGNATURE_MAX_LEN]),
            signature_len: 73,
            origin: None,
        };
        let mut out = [0u8; ETH_SIGNATURE_CBOR_MAX_LEN];
        assert!(
            encode_eth_signature_into(&sig, &mut out).is_err(),
            "signature_len beyond the slot must be a format error, not a panic"
        );
        assert!(
            sig.signature_bytes().is_empty(),
            "and reading it stays safe"
        );
    }
}
