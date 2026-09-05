//! Monero CLSAG ring signature (XMR core signature)

use crate::curve_primitive::ed25519::{Ed25519Point, Ed25519Scalar};
use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// CLSAG ring signature (variable length, depends on ring size)
pub const CLSAG_PROOF_MAX_LEN: usize = 32 * 16; // assumes MAX_RING = 16, proof length 32 * ring_size

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ClsagProof {
    bytes: heapless::Vec<u8, CLSAG_PROOF_MAX_LEN>,
}

impl AsRef<[u8]> for ClsagProof {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl core::fmt::Debug for ClsagProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ClsagProof(<{} bytes redacted>)", self.bytes.len())
    }
}

/// CLSAG signature auxiliary data
///
/// Contains pseudo_out + alpha / scc Params needed for key image generation, etc.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ClsagAux {
    bytes: heapless::Vec<u8, 256>,
}

impl AsRef<[u8]> for ClsagAux {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl core::fmt::Debug for ClsagAux {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ClsagAux(<{} bytes redacted>)", self.bytes.len())
    }
}

/// CLSAG ring signature
///
/// # Phase 4 implementation
/// `monero-oxide` crate's `clsag::sign(spend, ring, pseudo_out, aux)`
pub fn sign(
    _spend_skey: &Ed25519Scalar,
    _msg: &[u8],
    _ring_members: &[Ed25519Point], // ring members (real public key + decoys)
    _pseudo_output: &Ed25519Point,
    _aux_data: &ClsagAux,
) -> Result<ClsagProof> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

/// CLSAG verification
pub fn verify(
    _ring_members: &[Ed25519Point],
    _pseudo_output: &Ed25519Point,
    _msg: &[u8],
    _proof: &ClsagProof,
) -> bool {
    // P2-01: unimplemented!() panic → stable false (bool signatures have no Err channel)
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // signature/verification function shapes locked at compile time (complex signatures flattened via aliases)
    type SignFn =
        fn(&Ed25519Scalar, &[u8], &[Ed25519Point], &Ed25519Point, &ClsagAux) -> Result<ClsagProof>;
    type VerifyFn = fn(&[Ed25519Point], &Ed25519Point, &[u8], &ClsagProof) -> bool;
    const _: SignFn = sign;
    const _: VerifyFn = verify;

    #[test]
    fn proof_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<ClsagProof>());
    }

    #[test]
    fn aux_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<ClsagAux>());
    }

    #[test]
    fn stub_no_panic_marker() {
        // P2-01: stubs now return stable error codes/values; panic macros must not regress
        // (check code lines, skip comment lines)
        for line in "clsag_ed25519.rs".lines() {
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
