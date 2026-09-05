//! crypto-psbt UR codec（BCR-2020-006）
//!
//! CBOR shape: a bare `bytes` item (not a map). oracle = the ur-registry 1.0.5 test vector.

extern crate alloc;

use crate::encoding::cbor;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::ur::ur_decode;
use crate::ur::ur_encode::{self, UrEncoded, UrTypeTag};

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// Encode raw PSBT bytes into `ur:crypto-psbt/...`
pub fn encode(psbt: &[u8]) -> Result<UrEncoded> {
    let cbor = cbor::encode_bytes(psbt);
    ur_encode::encode(UrTypeTag::CryptoPsbt, &cbor)
}

/// Parse PSBT raw bytes out of `ur:crypto-psbt/...`
pub fn decode(uri: &str) -> Result<alloc::vec::Vec<u8>> {
    let d = ur_decode::decode(uri)?;
    if d.type_tag() != UrTypeTag::CryptoPsbt {
        return Err(err());
    }
    match cbor::decode(d.as_ref())? {
        cbor::Cbor::Bytes(b) => Ok(b.to_vec()),
        _ => Err(err()),
    }
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

    /// ur-registry 1.0.5 `crypto_psbt::tests::test_encode`
    #[test]
    fn ur_registry_official_vector() {
        let psbt = hex("8c05c4b4f3e88840a4f4b5f155cfd69473ea169f3d0431b7a6787a23777f08aa");
        let enc = encode(&psbt).unwrap();
        assert_eq!(
            enc.as_str(),
            "ur:crypto-psbt/hdcxlkahssqzwfvslofzoxwkrewngotktbmwjkwdcmnefsaaehrlolkskncnktlbaypkvoonhknt"
        );
        assert_eq!(decode(enc.as_str()).unwrap(), psbt);
    }
}
