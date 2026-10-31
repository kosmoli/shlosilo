//! bytes UR codec (opaque payload; the UR message shell is handled by the
//! transport: `ur_encode` wraps outbound, `ur_message_content` strips inbound)

use crate::error::Result;
use crate::ur::ur_encode::{self, UrEncoded, UrTypeTag};

pub fn encode(bytes: &[u8]) -> Result<UrEncoded> {
    ur_encode::encode(UrTypeTag::Bytes, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&[u8]) -> Result<UrEncoded> = encode;

    /// BCR-2020-05 / keystone-ur doctest vector: bare message `b"data"`,
    /// decoded as-is (head `0x64` is CBOR text — no shell to strip).
    #[test]
    fn official_data_vector_decodes_bare() {
        let d = crate::ur::ur_decode::decode("ur:bytes/iehsjyhspmwfwfia").unwrap();
        assert_eq!(d.as_ref(), b"data");
    }

    /// Since 2026-10-12 outbound messages carry the CBOR byte-string shell
    /// (keystone-ur Bytes / monero_c `CborLite::encodeBytes` semantics) —
    /// CANONICAL head since the WP3 registry cross-check (2026-10-31):
    /// `0x44` short form (RFC 8949 §4.2), the `44aabbccdd` ur-registry shape.
    #[test]
    fn official_data_vector_encode_shells() {
        let enc = encode(b"data").unwrap();
        assert_eq!(enc.as_str(), "ur:bytes/fyiehsjyhsvdvadawm");
    }
}
