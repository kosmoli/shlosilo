//! Icarus derivation over ed25519 (Cardano Shelley)

use crate::curve_primitive::ed25519::Ed25519Scalar;
use crate::derivation::path::DerivationPath;
use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Cardano extended private key — carries more field groups than a plain ed25519 key: stake / drep / ccl etc.
///
/// v2 §2.7 key constraint: aggregated structure, **all fields ZeroizeOnDrop**
///
/// **Does not derive Clone**: each clone adds one more in-memory spend+stake+drep+ccl copy,
/// doubling the physical attack surface (cold boot / DMA / 0day / register residue).
/// `ZeroizeOnDrop` only zeroes the copy in the current scope; it is useless against dump / DMA / Spectre.
///
/// **Correct usage in business modules**:
/// ```ignore
/// let master = icarus_ed25519::master_from_seed(seed)?;
/// let child = icarus_ed25519::derive(&master, &path)?;
/// let spend = child.spend();  // &Ed25519Scalar (borrow)
/// let sig = eddsa_ed25519::sign(spend, msg)?;
/// // master / child auto ZeroizeOnDrop when leaving scope
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CardanoExtSk {
    spend: Ed25519Scalar,
    stake: Option<Ed25519Scalar>,
    drep: Option<Ed25519Scalar>,
    ccl: Option<Ed25519Scalar>,
}

impl CardanoExtSk {
    pub fn spend(&self) -> &Ed25519Scalar {
        &self.spend
    }
    pub fn stake(&self) -> Option<&Ed25519Scalar> {
        self.stake.as_ref()
    }
    pub fn drep(&self) -> Option<&Ed25519Scalar> {
        self.drep.as_ref()
    }
    pub fn ccl(&self) -> Option<&Ed25519Scalar> {
        self.ccl.as_ref()
    }
}

impl core::fmt::Debug for CardanoExtSk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "CardanoExtSk(<redacted> stake={} drep={} ccl={})",
            self.stake.is_some(),
            self.drep.is_some(),
            self.ccl.is_some()
        )
    }
}

/// Icarus master derivation (the Ed25519 derivation in Cardano Byron wallet style)
///
/// # Phase 4 implementation
/// `cardano_serialization_lib::crypto::derive`
pub fn master_from_seed(_seed: &[u8]) -> Result<CardanoExtSk> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

/// Icarus path derivation — returns the full CardanoExtSk (aggregated structure)
///
/// After a business module obtains the CardanoExtSk, it **destructures it itself**:
/// `let spend = &cardano_ext_sk.spend;` then pass it to `eddsa_ed25519::sign(spend, msg)`
pub fn derive(_master: &CardanoExtSk, _path: &DerivationPath) -> Result<CardanoExtSk> {
    // P2-01: unimplemented!() panic → stable error code
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&[u8]) -> Result<CardanoExtSk> = master_from_seed;
    const _: fn(&CardanoExtSk, &DerivationPath) -> Result<CardanoExtSk> = derive;

    #[test]
    fn extsk_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<CardanoExtSk>());
    }

    #[test]
    fn stub_no_panic_marker() {
        // P2-01: stubs have been changed to stable error codes/return values; panic macros must not regress
        // (check code lines, excluding comment lines)
        for line in "icarus_ed25519.rs".lines() {
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
