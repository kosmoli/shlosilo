//! XRP address encoding (classic + X-address, base58 + ripple alphabet)

use crate::curve_primitive::secp256k1::Secp256k1Point;
use crate::error::Result;
use crate::network::Network;
use core::fmt;

/// XRP address (classic base58 encoding, up to ~35 chars)
pub const XRP_ADDRESS_MAX_LEN: usize = 64;

#[derive(Clone, PartialEq, Eq)]
pub struct XrpAddress {
    bytes: heapless::String<XRP_ADDRESS_MAX_LEN>,
}

impl AsRef<str> for XrpAddress {
    fn as_ref(&self) -> &str {
        self.bytes.as_str()
    }
}

impl fmt::Display for XrpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.bytes)
    }
}

impl fmt::Debug for XrpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.bytes.as_str();
        if s.len() > 12 {
            write!(f, "XrpAddress({}…{})", &s[..4], &s[s.len() - 4..])
        } else {
            write!(f, "XrpAddress(<redacted>)")
        }
    }
}

/// XRP classic address (`r...` prefix)
///
/// # Phase 4 implementation
/// - base58(0x00 || ripemd160(sha256(pubkey)))
pub fn encode_classic(_pubkey: &Secp256k1Point, _network: Network) -> Result<XrpAddress> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

/// XRP X-address (with destination tag, `X...` prefix)
pub fn encode_x_address(
    _pubkey: &Secp256k1Point,
    _network: Network,
    _tag: u32,
) -> Result<XrpAddress> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&Secp256k1Point, Network) -> Result<XrpAddress> = encode_classic;
    const _: fn(&Secp256k1Point, Network, u32) -> Result<XrpAddress> = encode_x_address;

    #[test]
    fn stub_no_panic_marker() {
        // P2-01: stubs have been changed to stable error codes; panic macros must not regress (skip comment lines)
        for line in include_str!("xrp.rs").lines() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            assert!(
                !t.contains(concat!("unimplemented", "!(")),
                "panic macro regressed: {}",
                line
            );
        }
    }
}
