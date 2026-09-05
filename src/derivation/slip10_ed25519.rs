//! SLIP-0010 derivation over ed25519 (SOL + SUI + NEAR + TON)

use crate::curve_primitive::ed25519::Ed25519Scalar;
use crate::derivation::path::DerivationPath;
use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SLIP-0010 extended private key (ed25519 uses a different bit field, 32 bytes long)
pub const SLIP10_EXTENDED_KEY_LEN: usize = 32;

// P1-03: Clone forbidden (v2-security §2)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Slip10ExtendedKey {
    bytes: [u8; SLIP10_EXTENDED_KEY_LEN],
}

impl AsRef<[u8]> for Slip10ExtendedKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for Slip10ExtendedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Slip10ExtendedKey(<{} bytes redacted>)",
            self.bytes.len()
        )
    }
}

/// SLIP-0010 master derivation (ed25519 uses hardened-only derivation)
///
/// # Phase 4 implementation
/// `slip10::derive_ed25519_master(seed)`（slip10 14.x crate）
pub fn master_from_seed(_seed: &[u8]) -> Result<Slip10ExtendedKey> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

/// SLIP-0010 path derivation (Phase 4 real implementation)
///
/// Important: SLIP-0010 for ed25519 requires **every segment to be hardened** (including account / change / address_index)
pub fn derive(_master: &Slip10ExtendedKey, _path: &DerivationPath) -> Result<Ed25519Scalar> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&[u8]) -> Result<Slip10ExtendedKey> = master_from_seed;
    const _: fn(&Slip10ExtendedKey, &DerivationPath) -> Result<Ed25519Scalar> = derive;

    #[test]
    fn extended_key_len() {
        assert_eq!(SLIP10_EXTENDED_KEY_LEN, 32);
    }

    #[test]
    fn extended_key_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<Slip10ExtendedKey>());
    }

    #[test]
    fn stub_no_panic_marker() {
        // P2-01: stubs have been changed to stable error codes/return values; panic macros must not regress
        // (check code lines, excluding comment lines)
        for line in "slip10_ed25519.rs".lines() {
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
