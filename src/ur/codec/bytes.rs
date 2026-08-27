//! bytes UR codec（opaque payload，不额外包 CBOR）

use crate::error::Result;
use crate::ur::ur_encode::{self, UrEncoded, UrTypeTag};

pub fn encode(bytes: &[u8]) -> Result<UrEncoded> {
    ur_encode::encode(UrTypeTag::Bytes, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&[u8]) -> Result<UrEncoded> = encode;

    #[test]
    fn official_data_vector() {
        let enc = encode(b"data").unwrap();
        assert_eq!(enc.as_str(), "ur:bytes/iehsjyhspmwfwfia");
    }
}
