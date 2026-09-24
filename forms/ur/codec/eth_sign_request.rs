//! eth-sign-request UR codec (isomorphic to ur-registry 1.0.5)
//!
//! CBOR map (UR type `eth-sign-request`):
//! ```text
//! 1: request_id      — tag(37 UUID) + 16B
//! 2: sign_data       — bytes (raw tx / typed-data / message, interpreted per data_type)
//! 3: data_type       — uint 1=Transaction 2=TypedData 3=PersonalMessage 4=TypedTransaction
//! 4: chain_id        — int
//! 5: derivation_path — tag(304 crypto-keypath)
//! 6: address         — bytes
//! 7: origin          — string
//! ```
//!
//! P1-01 (2026-08-26): the payload of real MetaMask/Keystone URs is a CBOR map,
//! not the legacy "first-byte tag + raw" private wrapping. The sign path interprets sign_data per data_type.

use crate::encoding::cbor::Cbor;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// UR registry crypto-keypath tag (BCR-2020-006; same source as the encode side of crypto_hd_key.rs)
const TAG_CRYPTO_KEYPATH: u64 = 304;

extern crate alloc;

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// Interpretation type of sign_data (ur-registry DataType enum)
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

/// eth-sign-request parse result (only the fields needed for signing)
#[derive(Debug)]
pub struct EthSignRequest<'a> {
    /// Raw sign_data (for Transaction / TypedTransaction = raw tx bytes)
    pub sign_data: &'a [u8],
    pub data_type: EthSignDataType,
    pub chain_id: Option<i128>,
    /// derivation_path (key 5, tag 304 crypto-keypath, optional)
    /// P1-02: when given, signing derives with that path; the default fallback is m/44\'/60\'/0\'/0/0
    pub derivation_path: Option<crate::derivation::path::DerivationPath>,
}

/// Parse an eth-sign-request CBOR payload → EthSignRequest
pub fn parse_eth_sign_request<'a>(payload: &'a [u8]) -> Result<EthSignRequest<'a>> {
    let cbor = crate::encoding::cbor::decode(payload)?;
    let map = match cbor {
        Cbor::Map(_) => &cbor,
        _ => return Err(err()),
    };

    // sign_data (key 2, required)
    let sign_data = match map.map_get_uint(2)? {
        Some(v) => v.as_bytes()?,
        None => return Err(err()),
    };

    // data_type (key 3, required)
    let data_type = match map.map_get_uint(3)? {
        Some(v) => EthSignDataType::from_u64(v.as_uint()?)?,
        None => return Err(err()),
    };

    // chain_id (key 4, optional)
    let chain_id = match map.map_get_uint(4)? {
        Some(v) => Some(v.as_int()?),
        None => None,
    };

    // derivation_path (key 5, optional) — tag 304 crypto-keypath inner map {1: components[(idx u64, hardened bool)...], 2: depth}
    //
    // P1-01 hardening (2026-09-01 audit #4):
    // 1. Tag whitelist — only registry tag 304 (crypto-keypath, BCR-2020-006) is accepted.
    //    Before the fix, any `Cbor::Tag(_, _)` tag matched (tag 999 was also accepted).
    //    A comment previously miswrote 305; the correct value is crypto_hd_key.rs TAG_CRYPTO_KEYPATH=304.
    // 2. idx high-bit domain tightened — regardless of the hardened bool, idx ≤ 0x7fff_ffff.
    //    Before the fix `(idx=0x8000_0001, hardened=false)` was accepted; in the wire representation
    //    "a non-hardened high-bit idx" passed into DerivationPath was interpreted as hardened 1
    //    — wire/semantics inconsistency. The hardened bit is encoded solely by the bool.
    let derivation_path = match map.map_get_uint(5)? {
        Some(v) => {
            let inner = match v {
                Cbor::Tag(TAG_CRYPTO_KEYPATH, _) => v.inner()?,
                _ => return Err(err()),
            };
            // components (key 1): flattened [idx0, hardened0, idx1, hardened1, ...]
            let comps = inner.map_get_uint(1)?.ok_or_else(err)?.as_array()?;
            // X2: components must be an even-length (idx, hardened) pair list — odd length is a format error
            if comps.len() % 2 != 0 {
                return Err(err());
            }
            let mut flat = heapless::Vec::<u32, 16>::new(); // Z2.4b-2: bounded component list (BIP-32 paths cap at CAPS_PATH_COMPONENTS=16)
            let mut ci = comps.iter();
            while let Some(idx_item) = ci.next() {
                let idx = idx_item?.as_uint()?;
                // X2: the BIP-32 index domain is u32 — over-domain rejected, no silent truncation
                if idx > u32::MAX as u64 {
                    return Err(err());
                }
                let idx = idx as u32;
                let hardened = match ci.next().ok_or_else(err)?? {
                    Cbor::Bool(b) => b,
                    _ => return Err(err()),
                };
                // P1-01: idx high-bit domain tightened (≤ 0x7fff_ffff) — regardless of the hardened bool.
                // Before the fix the high bit was only rejected when hardened=true, so (0x8000_0001, false) was silently
                // interpreted as hardened 1.
                if idx >= 0x8000_0000 {
                    return Err(err());
                }
                let raw = if hardened { idx | 0x8000_0000 } else { idx };
                flat.push(raw).map_err(|_| err())?;
            }
            // Gate4 #5 note: key 2 (depth) is not validated — in the official ur-registry test vector
            // (test_encode) the depth is a placeholder value 0x12345678; neither the registry spec nor upstream
            // implementations (keystone/ur-registry) give depth constraining semantics; depth is informational.
            Some(crate::derivation::path::DerivationPath::from_flat(
                flat.iter().copied(),
            )?)
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

    /// ur-registry 1.0.5 test_encode official vector (the hex in that test)
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

    /// Non-map → reject
    #[test]
    fn reject_non_map() {
        let payload = [0x01u8, 0x02, 0x03]; // not a map
        assert!(parse_eth_sign_request(&payload).is_err());
    }

    /// Missing sign_data → reject
    #[test]
    fn reject_missing_sign_data() {
        // a1 03 01 = {3: 1} with no sign_data
        let payload = [0xa1u8, 0x03, 0x01];
        assert!(parse_eth_sign_request(&payload).is_err());
    }

    /// Unknown data_type → reject
    #[test]
    fn reject_unknown_data_type() {
        // a2 02 41 61 03 09  = {2: bytes"a", 3: 9}
        let payload = [0xa2u8, 0x02, 0x41, 0x61, 0x03, 0x09];
        assert!(parse_eth_sign_request(&payload).is_err());
    }

    /// P1-01: full UR decode → eth-sign-request parsing (byte-exact interop verification)
    /// payload = ur-registry 1.0.5 test_encode official vector (MetaMask shape)
    #[test]
    fn decode_real_ur_registry_vector() {
        // Generate the UR with the library\'s own encode, then decode back the payload to ensure round-trip consistency
        let payload = hex(
            "a601d825509b1deb4d3b7d4bad9bdd2b0d7b3dcb6d02584bf849808609184e72a00082271094000000000000000000000000000000000000000080a47f74657374320000000000000000000000000000000000000000000000000000006000578080800301040105d90130a2018a182cf501f501f500f401f4021a1234567807686d6574616d61736b",
        );
        let enc =
            crate::ur::ur_encode::encode(crate::ur::ur_encode::UrTypeTag::EthSignRequest, &payload)
                .unwrap();
        let d = crate::ur::ur_decode::decode(enc.as_str()).unwrap();
        // P1-01 key point: the type tag is carried by the UR decode
        assert_eq!(
            d.type_tag(),
            crate::ur::ur_encode::UrTypeTag::EthSignRequest
        );
        assert_eq!(d.as_ref(), payload.as_slice());
        // Parse out the sign_data (real tx)
        let req = parse_eth_sign_request(d.as_ref()).unwrap();
        assert_eq!(req.data_type, EthSignDataType::Transaction);
        assert_eq!(req.chain_id, Some(1));
        assert!(req.sign_data.len() > 40);
    }

    /// X2 negative case: odd-length components silently ignored → explicitly rejected
    #[test]
    fn keypath_odd_components_rejected() {
        // tag 304, map{1: [0, false, 1], 2: 2}  — 3 comps (odd)
        // (P1-01: originally used tag 305 — before the fix any tag was accepted, so the negative case never proved the target branch;
        //   now tag 304 uniformly, so the error definitively comes from components validation)
        let payload: alloc::vec::Vec<u8> = alloc::vec![
            0xA1, 0x05, 0xD9, 0x01, 0x30, 0xA2, 0x01, 0x83, 0x00, 0xF4, 0x01, 0x02, 0x02,
        ];
        assert!(
            parse_eth_sign_request(&payload).is_err(),
            "odd keypath must be rejected"
        );
    }

    /// Gate4 #5 negative case: hardened=true with idx already carrying the 0x80000000 high bit (non-canonical dual expression) → reject
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

    /// X2 negative case: index beyond the u32 domain rejected (no truncation)
    #[test]
    fn keypath_oversized_index_rejected() {
        // tag 304, map{1: [0x1_0000_0000, false], 2: 1} — 2^32 exceeds u32
        let payload: alloc::vec::Vec<u8> = alloc::vec![
            0xA1, 0x05, 0xD9, 0x01, 0x30, 0xA2, 0x01, 0x82, 0x1B, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0xF4, 0x02, 0x01,
        ];
        assert!(
            parse_eth_sign_request(&payload).is_err(),
            "index > u32::MAX must be rejected"
        );
    }

    // ── P1-01 (audit #4) new negative cases: a fully valid request with one field changed, pinning the target branch ──

    /// Fully valid request: {1: request_id, 2: sign_data, 3: data_type, 4: chain_id,
    ///                5: keypath(tag 304)} — the baseline for the negative cases below
    fn valid_request_with_keypath(comps_cbor: &[u8]) -> alloc::vec::Vec<u8> {
        use crate::encoding::cbor;
        // The CBOR encoding of the components array is injected by the caller (bytes item with inline raw bytes)
        let inner_map = cbor::encode_map(&[(cbor::encode_uint(2), cbor::encode_uint(1))]);
        // Hand-build {1: comps, 2: 1}
        let k1 = cbor::encode_uint(1);
        let mut inner = alloc::vec::Vec::new();
        inner.push(0xa2); // map(2)
        inner.extend_from_slice(&k1);
        inner.extend_from_slice(comps_cbor);
        // Append key2:1 (inner_map = 0xa1 || k2 || v2; strip the header to take the body)
        inner.extend_from_slice(&inner_map[1..]);

        let request_id = [0x9bu8; 16];
        let pairs = alloc::vec![
            (cbor::encode_uint(1), cbor::encode_bytes(&request_id)),
            (cbor::encode_uint(2), cbor::encode_bytes(&[0x02u8; 16])),
            (cbor::encode_uint(3), cbor::encode_uint(1)), // data_type = Transaction
            (cbor::encode_uint(4), cbor::encode_uint(1)), // chain_id = 1
            (
                cbor::encode_uint(5),
                cbor::encode_tag(TAG_CRYPTO_KEYPATH, &inner)
            ),
        ];
        cbor::encode_map(&pairs)
    }

    /// P1-01 negative case 1: tag 999 (not the registry crypto-keypath) → reject
    /// (before the fix any tag was accepted as a keypath)
    #[test]
    fn keypath_wrong_tag_rejected() {
        use crate::encoding::cbor;
        let inner = cbor::encode_map(&[
            (
                cbor::encode_uint(1),
                cbor::encode_array(&[cbor::encode_uint(44), cbor::encode_bool(true)]),
            ),
            (cbor::encode_uint(2), cbor::encode_uint(1)),
        ]);
        let pairs = alloc::vec![
            (cbor::encode_uint(1), cbor::encode_bytes(&[0x9bu8; 16])),
            (cbor::encode_uint(2), cbor::encode_bytes(&[0x02u8; 16])),
            (cbor::encode_uint(3), cbor::encode_uint(1)),
            (cbor::encode_uint(4), cbor::encode_uint(1)),
            (cbor::encode_uint(5), cbor::encode_tag(999, &inner)), // the only change: the tag
        ];
        let payload = cbor::encode_map(&pairs);
        assert!(
            parse_eth_sign_request(&payload).is_err(),
            "tag 999 must be rejected (only registry tag 304 accepted)"
        );
    }

    /// P1-01 negative case 2: (idx=0x8000_0001, hardened=false) → reject
    /// (before the fix it was accepted; wire representation diverged from business interpretation: the idx high bit was silently treated as the hardened bit)
    #[test]
    fn keypath_high_bit_idx_non_hardened_rejected() {
        use crate::encoding::cbor;
        let comps = cbor::encode_array(&[
            cbor::encode_uint(0x8000_0001), // high-bit idx
            cbor::encode_bool(false),       // claims non-hardened — ambiguous combination
        ]);
        let payload = valid_request_with_keypath(&comps);
        assert!(
            parse_eth_sign_request(&payload).is_err(),
            "(high-bit idx, hardened=false) must be rejected regardless of bool"
        );
    }

    /// P1-01 positive case: a legal keypath (tag 304, ordinary index) full request → accepted with the correct path
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
        let req = parse_eth_sign_request(&payload).expect("valid full request must parse");
        let path = req.derivation_path.expect("keypath present");
        // m/44\'/60\'/1 — value() is the pure index with the hardened bit stripped,
        // the hardened bit asserted separately
        let flat: alloc::vec::Vec<(u32, bool)> = path
            .as_slice()
            .iter()
            .map(|i| (i.value(), i.is_hardened()))
            .collect();
        assert_eq!(flat, alloc::vec![(44, true), (60, true), (1, false)]);
    }
}
