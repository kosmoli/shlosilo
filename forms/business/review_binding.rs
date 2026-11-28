//! Review/sign binding: the bytes you signed are the bytes that were reviewed.
//!
//! # Why this module exists (chain-axis design §5, S11a)
//!
//! The review face and the signing face take the same payload **twice**: a carrier reviews a
//! request, the operator confirms, and the carrier signs. Nothing in the type system said those
//! two payloads were the same buffer — the invariant rested on the carrier's discipline, which is
//! exactly the kind of guarantee that survives until someone refactors a buffer.
//!
//! This module gives the invariant a shape that can be checked: the review step hands back a
//! [`ReviewedDigest`] of the exact bytes it rendered, and [`sign_reviewed`] refuses to sign unless
//! the payload it was given hashes to that digest. A mismatch is `InvariantViolation` — the
//! pre-existing kind for "the library's own contract was broken", not a new error code.
//!
//! # What this deliberately does NOT do (Kosmo's ruling, 2026-11-26)
//!
//! It does not authorize anything. `forms` holds no flow state: there is no `approved: bool`, no
//! latch, no session. Whether the operator actually pressed confirm is the product flow's
//! business, and that lives in `flux/shell` — the shell is what calls review, waits for the
//! confirmation action, and only then calls sign. Two separate invariants:
//!
//!   * **所审即所签** (this module): the bytes signed are the bytes reviewed. Data identity.
//!   * **未授权不得签** (`flux/shell`): nothing is signed without the operator's confirmation.
//!     Flow obbligation.
//!
//! Keeping them apart is what lets a carrier compose them differently (a session-based flow, a
//! single-shot flow) without `forms` learning about either.
//!
//! # What it cannot promise
//!
//! A digest proves the bytes match; it does not prove the operator read them. That is a UI
//! question and is pinned by the review-face tests, not here.

use crate::encoding::sha256;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// SHA-256 of exactly the request bytes the review face rendered.
///
/// Deliberately opaque and `Copy`: it is data about the request, not a capability. Carrying it
/// costs 32 bytes and no allocation, and it crosses an FFI boundary as a plain `[u8; 32]`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReviewedDigest([u8; 32]);

impl ReviewedDigest {
    /// Digest the request bytes that were just rendered for review.
    ///
    /// # Errors
    /// Only if the hash itself fails (it cannot for SHA-256 over a slice), so callers treat the
    /// result as infallible in practice.
    pub fn of(payload: &[u8]) -> Result<Self> {
        let digest = sha256::hash(payload)?;
        Ok(Self(digest))
    }

    /// Wrap a digest that arrived from outside (a carrier that stored it across a reboot, a C
    /// host that kept it in `.bss`).
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl core::fmt::Debug for ReviewedDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A digest is not secret, but printing it in full makes log lines long and is never what
        // a reader wants; the first four bytes identify it well enough for forensics.
        write!(
            f,
            "ReviewedDigest({:02x}{:02x}{:02x}{:02x}…)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// Check that `payload` is byte-for-byte the request `reviewed` was taken from.
///
/// Split out from [`sign_reviewed`] so a carrier can fail fast — before it stages entropy, opens a
/// workspace or touches the key material — and so the check itself is testable without a signer.
///
/// # Errors
/// `InvariantViolation` when the digests differ.
pub fn verify_reviewed(payload: &[u8], reviewed: ReviewedDigest) -> Result<()> {
    let actual = ReviewedDigest::of(payload)?;
    if actual != reviewed {
        return Err(ShlosiloError::new(
            ShlosiloErrorKind::ReviewedPayloadMismatch,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST: &[u8] = b"\x01\x02\x03 a request the operator reviewed";

    #[test]
    fn digest_is_of_the_exact_bytes() {
        let a = ReviewedDigest::of(REQUEST).unwrap();
        let b = ReviewedDigest::of(REQUEST).unwrap();
        assert_eq!(a, b, "the same bytes must digest the same way");
        assert_eq!(a.to_bytes().len(), 32);
    }

    #[test]
    fn a_single_changed_byte_changes_the_digest() {
        let mut other = REQUEST.to_vec();
        other[0] ^= 0x01;
        assert_ne!(
            ReviewedDigest::of(REQUEST).unwrap(),
            ReviewedDigest::of(&other).unwrap(),
            "one flipped bit must not digest equal — otherwise the binding is decoration"
        );
    }

    #[test]
    fn verify_accepts_the_reviewed_bytes() {
        let reviewed = ReviewedDigest::of(REQUEST).unwrap();
        verify_reviewed(REQUEST, reviewed).expect("the reviewed bytes must verify");
    }

    #[test]
    fn verify_refuses_bytes_that_were_not_reviewed() {
        let reviewed = ReviewedDigest::of(REQUEST).unwrap();
        let mut tampered = REQUEST.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x80;
        let err = verify_reviewed(&tampered, reviewed).expect_err("must refuse");
        assert_eq!(err.kind, ShlosiloErrorKind::ReviewedPayloadMismatch);
    }

    #[test]
    fn verify_refuses_a_digest_from_another_request() {
        // The interesting case for a carrier: right payload, digest kept from a previous request.
        let elsewhere = ReviewedDigest::of(b"a different request").unwrap();
        let err = verify_reviewed(REQUEST, elsewhere).expect_err("must refuse");
        assert_eq!(err.kind, ShlosiloErrorKind::ReviewedPayloadMismatch);
    }

    /// The gate must fire **before** the signer looks at keys, entropy or the payload: a bogus
    /// mnemonic and an empty output buffer are enough to prove nothing downstream ran.
    #[test]
    fn sign_reviewed_refuses_before_touching_the_signer() {
        use crate::business::sign::{sign_reviewed, SignInput};
        use crate::ur::ur_encode::UrTypeTag;

        let reviewed = ReviewedDigest::of(REQUEST).unwrap();
        let mut other = REQUEST.to_vec();
        other[0] ^= 0xFF;

        // A deliberately unusable mnemonic/seed: if the digest gate did not run first, this would
        // answer a mnemonic or key error instead of the invariant violation.
        let seed = [0u8; 64];
        let mut out = [0u8; 0]; // also too small for any signature
        let err = sign_reviewed(
            SignInput::Seed { seed: &seed },
            UrTypeTag::CryptoPsbt,
            &other,
            reviewed,
            &[],
            &mut out,
        )
        .expect_err("signing bytes that were not reviewed must be refused");
        assert_eq!(
            err.kind,
            ShlosiloErrorKind::ReviewedPayloadMismatch,
            "the refusal must be the binding, not a downstream key/buffer error"
        );
    }

    #[test]
    fn an_empty_request_is_reviewable_and_binds() {
        // Degenerate but reachable: an empty payload must not become a wildcard that anything
        // verifies against.
        let empty = ReviewedDigest::of(b"").unwrap();
        verify_reviewed(b"", empty).expect("empty binds to empty");
        assert!(verify_reviewed(b"x", empty).is_err());
    }
}
