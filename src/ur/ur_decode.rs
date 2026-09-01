//! UR 解码（BC-UR 单分片）— Phase 6 P6.0b 真实实现
//!
//! 输入 `ur:<type>/<body>`；body = bytewords-minimal(payload)。
//! payload 原样返回（codec 再解析 CBOR）。multi-part 形状在 fountain
//! 落地（P6.2）前显式拒绝。

use crate::encoding::bytewords;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::ur::ur_encode::{UrTypeTag, UR_PAYLOAD_MAX_LEN};

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// UR 解码结果（原始 payload，让 codec / 业务模块进一步解析）
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

/// UR 解码（单分片）
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
    // multi-part 形状（"1-2/"）暂不支持 → P6.2 fountain
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
