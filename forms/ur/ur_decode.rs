//! UR decoding (BC-UR single fragment) — Phase 6 P6.0b real implementation
//!
//! Input `ur:<type>/<body>`; body = bytewords-minimal(message).
//! Payload semantics (2026-10-12 CBOR-shell alignment): the returned bytes are
//! the CBOR byte-string shell's **content** when the message is one complete
//! definite byte-string item (keystone-ur Bytes / monero_c
//! `CborLite::encodeBytes` shape), and the bare message itself otherwise
//! (Cake's xmr-txunsigned leg is bare on the wire). multi-part shapes are
//! explicitly rejected until the fountain lands (P6.2).

use crate::encoding::bytewords;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::ur::ur_encode::{UrTypeTag, UR_PAYLOAD_MAX_LEN};
use crate::ur::ur_shell::ur_message_content;

/// Wire budget: payload content (≤ UR_PAYLOAD_MAX_LEN) plus the largest
/// definite byte-string shell head (0x5b + 8-byte length = 9 bytes), so an
/// encoded message of the full payload budget still round-trips.
const UR_WIRE_MAX_LEN: usize = UR_PAYLOAD_MAX_LEN + 9;

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// UR decode result — the message with any complete CBOR byte-string shell
/// stripped (bare messages pass through), for the codec / business modules to
/// parse further.
#[derive(Clone, PartialEq, Eq)]
pub struct UrDecoded {
    bytes: heapless::Vec<u8, UR_WIRE_MAX_LEN>,
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
    // Z2.4c-4: decode straight into the result buffer (was a Vec intermediate + copy);
    // total = body.len()/2 covers message + CRC32, over-capacity rejects explicitly.
    let total = body.len() / 2;
    let mut bytes = heapless::Vec::new();
    for _ in 0..total {
        bytes
            .push(0u8)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }
    let n = bytewords::decode_minimal_into(body, &mut bytes)?;
    bytes.truncate(n);
    // Payload semantics: strip one complete CBOR byte-string shell (bare
    // fallback = Cake's xmr-txunsigned quirk); the budget is on the delivered
    // payload, the wire may carry the extra shell head.
    let content_len = ur_message_content(&bytes).len();
    let head = bytes.len() - content_len;
    if content_len > UR_PAYLOAD_MAX_LEN {
        return Err(ShlosiloError::new(
            ShlosiloErrorKind::EncodingBufferOverflow,
        ));
    }
    if head > 0 {
        bytes.copy_within(head.., 0);
        bytes.truncate(content_len);
    }
    Ok(UrDecoded {
        bytes,
        type_tag: UrTypeTag::from_name(type_name),
    })
}
