//! Arweave address encoding (base64url + SHA-256 digest)

use crate::curve_primitive::rsa::RsaPubKey;
use crate::error::Result;
use crate::network::Network;
use core::fmt;

/// Arweave address length (base64url-encoded 512-bit SHA-256 digest = 43 characters)
pub const ARWEAVE_ADDRESS_MAX_LEN: usize = 64;

#[derive(Clone, PartialEq, Eq)]
pub struct ArweaveAddress {
    bytes: heapless::String<ARWEAVE_ADDRESS_MAX_LEN>,
}

impl AsRef<str> for ArweaveAddress {
    fn as_ref(&self) -> &str {
        self.bytes.as_str()
    }
}

impl fmt::Display for ArweaveAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.bytes)
    }
}

impl fmt::Debug for ArweaveAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.bytes.as_str();
        if s.len() > 12 {
            write!(f, "ArweaveAddress({}…{})", &s[..8], &s[s.len() - 6..])
        } else {
            write!(f, "ArweaveAddress(<redacted>)")
        }
    }
}

/// Arweave address encoding
///
/// # Phase 4 implementation
/// - sha256(modulus_bytes) → 32-byte digest → base64url (43 characters)
pub fn encode(_pubkey: &RsaPubKey, _network: Network) -> Result<ArweaveAddress> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&RsaPubKey, Network) -> Result<ArweaveAddress> = encode;

    #[test]
    fn address_length() {
        assert_eq!(ARWEAVE_ADDRESS_MAX_LEN, 64);
    }

    #[test]
    fn stub_no_panic_marker() {
        // P2-01: stubs now return stable error codes; panic macros must not regress (skip comment lines)
        for line in include_str!("arweave.rs").lines() {
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
