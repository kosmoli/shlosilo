//! UR decoding (BC-UR single fragment) — Phase 6 P6.0b real implementation
//!
//! Input `ur:<type>/<body>`; body = bytewords-minimal(payload).
//! payload returned as-is (the codec parses the CBOR next). multi-part shapes are
//! explicitly rejected until the fountain lands (P6.2).

use crate::encoding::bytewords;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::ur::ur_encode::{UrTypeTag, UR_PAYLOAD_MAX_LEN};

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// UR decode result (raw payload for the codec / business modules to parse further)
#[derive(Clone, PartialEq, Eq)]
pub struct UrDecoded {
    bytes: heapless::Vec<u8, UR_PAYLOAD_MAX_LEN>,
    type_tag: UrTypeTag,
}

impl UrDecoded {
    pub fn type_tag(&self) -> UrTypeTag {
        self.type_tag
    }
}

impl AsRef<[u8]> for UrDecoded {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl core::fmt::Debug for UrDecoded {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "UrDecoded(<{} bytes redacted>)", self.bytes.len())
    }
}

/// UR decoding (single fragment)
pub fn decode(uri: &str) -> Result<UrDecoded> {
    let rest = uri.strip_prefix("ur:").ok_or_else(err)?;
    let (type_name, body) = rest.split_once('/').ok_or_else(err)?;
    if type_name.is_empty()
        || !type_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(err());
    }
    // multi-part shape ("1-2/") not yet supported → P6.2 fountain
    if body.contains('/') {
        return Err(err());
    }
    let payload = bytewords::decode_minimal(body)?;
    if payload.len() > UR_PAYLOAD_MAX_LEN {
        return Err(ShlosiloError::new(
            ShlosiloErrorKind::EncodingBufferOverflow,
        ));
    }
    let mut bytes = heapless::Vec::new();
    bytes
        .extend_from_slice(&payload)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    Ok(UrDecoded {
        bytes,
        type_tag: UrTypeTag::from_name(type_name),
    })
}
