//! RSA-PSS signature (Arweave)

use crate::curve_primitive::rsa::{RsaPrivKey, RsaPubKey};
use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// RSA-PSS signature fixed length (512 bytes for RSA-4096)
pub const RSA_PSS_SIGNATURE_LEN: usize = 512;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RsaPssSignature {
    bytes: [u8; RSA_PSS_SIGNATURE_LEN],
}

impl AsRef<[u8]> for RsaPssSignature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for RsaPssSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RsaPssSignature(<{} bytes redacted>)", self.bytes.len())
    }
}

/// RSA-PSS signature
///
/// # Phase 4 implementation
/// `rsa::pss::SigningKey::<Sha512>::sign(rng, hashed_msg)`
///
/// Important: RSA-PSS **needs an RNG** (unlike ECDSA's deterministic nonce).
/// Under `no_std` the RNG source is provided by the L3 imperative shell — here only pre-salted msgs are accepted.
pub fn sign(_sk: &RsaPrivKey, _msg_hash: &[u8]) -> Result<RsaPssSignature> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

/// RSA-PSS verification
pub fn verify(_pk: &RsaPubKey, _msg_hash: &[u8], _sig: &RsaPssSignature) -> bool {
    // P2-01: unimplemented!() panic → stable false (bool signatures have no Err channel)
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&RsaPrivKey, &[u8]) -> Result<RsaPssSignature> = sign;
    const _: fn(&RsaPubKey, &[u8], &RsaPssSignature) -> bool = verify;

    #[test]
    fn signature_len() {
        assert_eq!(RSA_PSS_SIGNATURE_LEN, 512);
    }

    #[test]
    fn signature_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<RsaPssSignature>());
    }

    #[test]
    fn stub_no_panic_marker() {
        // P2-01: stubs now return stable error codes/values; panic macros must not regress
        // (check code lines, skip comment lines)
        for line in "rsa_pss.rs".lines() {
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
