//! SecretScalar: a non-Copy dalek Scalar secret owner (audits #9-#10 P1)
//!
//! Design (audit #10 P1-01/P1-02 refactor):
//! - **Whitelisted operations**: never expose `&Scalar` to callers — `Scalar: Copy`, so any callback
//!   returning a generic `R` or `&Scalar` lets the value escape (reproduced by the 10th re-review
//!   with a minimal out-of-repo program). All consumption goes through this module's whitelist: point mul / scalar add / write_bytes.
//! - **Internal Zeroizing<Scalar>**: construction never establishes a plain `let s: Scalar` intermediate binding
//!   (last round's `let s = ...; Self { scalar: s }` source binding was not covered by any wrapper's Drop —
//!   for a Copy type, copying into the owner after construction cannot prove the source stack slot was erased).
//! - If arithmetic results need continued protection, this module returns a new SecretScalar; public point results
//!   (EdwardsPoint/compressed bytes) are not secrets and are returned directly.

use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

pub struct SecretScalar {
    scalar: Zeroizing<Scalar>,
}

// Zeroizing<Scalar> provides Deref<Target=Scalar> and Drop zeroization
use zeroize::Zeroizing;

impl SecretScalar {
    /// Construct from bytes. raw is the caller's buffer — this function builds the Scalar directly
    /// inside a Zeroizing; no plain `let s: Scalar` intermediate binding ever lands.
    pub fn from_bytes_mod_order(raw: [u8; 32]) -> Self {
        Self {
            scalar: Zeroizing::new(Scalar::from_bytes_mod_order(raw)),
        }
    }

    /// Construct from a byte slice (e.g. the expose() result of an existing owner like view_sec).
    pub fn from_slice(bytes: &[u8; 32]) -> Self {
        Self::from_bytes_mod_order(*bytes)
    }

    /// Whitelist: scalar addition (bytes form, monero key_offset derivation).
    /// Returns a new owner. Audit #11 P1-01: expressions go straight into the owner — the previous
    /// version's three plain bindings `let o = ...; let sum = ...; let out = ...;`
    /// (whose comment claimed "temporary o is taken over by Zeroizing", contradicting the code) are all eliminated
    pub fn add_bytes(&self, other: &[u8; 32]) -> Self {
        Self {
            scalar: Zeroizing::new(*self.scalar + Scalar::from_bytes_mod_order(*other)),
        }
    }

    /// Whitelist: basepoint multiplication (r·G) → compressed point (public value).
    pub fn mul_basepoint(&self) -> [u8; 32] {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        self.with(|v| (ED25519_BASEPOINT_TABLE * v).compress().to_bytes())
    }

    /// Whitelist: arbitrary point multiplication (point * scalar) → compressed point (public value).
    /// Accepts compressed point bytes (decompressed internally). Audit #11 P0-01: decompression failure returns Err
    /// (untrusted point encodings can arrive from hostile signing requests — an expect panic on device
    /// with panic=abort is a full-device DoS; restores the pre-refactor totality)
    pub fn mul_point(
        &self,
        point_bytes: &[u8; 32],
    ) -> Result<[u8; 32], crate::error::ShlosiloError> {
        let point: curve25519_dalek::EdwardsPoint =
            curve25519_dalek::edwards::CompressedEdwardsY(*point_bytes)
                .decompress()
                .ok_or_else(|| {
                    crate::error::ShlosiloError::new(
                        crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
                    )
                })?;
        Ok(self.with(|v| (point * v).compress().to_bytes()))
    }

    /// Whitelist: point multiplication + cofactor (8Ra = (A_v·r)·8 variant, compressed point input).
    pub fn mul_point_cofactor(
        &self,
        point_bytes: &[u8; 32],
    ) -> Result<[u8; 32], crate::error::ShlosiloError> {
        let point: curve25519_dalek::EdwardsPoint =
            curve25519_dalek::edwards::CompressedEdwardsY(*point_bytes)
                .decompress()
                .ok_or_else(|| {
                    crate::error::ShlosiloError::new(
                        crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
                    )
                })?;
        Ok(self.with(|v| (point * v).mul_by_cofactor().compress().to_bytes()))
    }

    /// Whitelist: multi-scalar multiplication (monero stealth = B_dest + Hs·G).
    /// Returns a compressed point (public value).
    pub fn mul_basepoint_add_point(&self, point: &curve25519_dalek::EdwardsPoint) -> [u8; 32] {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        self.with(|v| (point + ED25519_BASEPOINT_TABLE * v).compress().to_bytes())
    }

    /// Whitelist: field addition, in-place accumulation (blinding mask accumulation).
    /// Audit #12 P1-01: takes an owner input — the old signature add_assign(&Scalar) made a plain Scalar
    /// held by callers (a secret not managed by any owner) a legitimate input;
    /// now only another SecretScalar is accepted.
    pub fn add_assign(&mut self, other: &SecretScalar) {
        *self.scalar += *other.scalar;
    }

    /// Whitelist: explicit immediate zeroization (normal-path cleanup; error paths covered by Drop).
    pub fn zeroize_now(&mut self) {
        self.scalar.zeroize();
    }

    /// Whitelist: add another SecretScalar → new SecretScalar.
    /// Audit #11 P1-01: expressions go straight into the owner (last version built a plain sum first, then copied)
    pub fn add_secret(&self, other: &SecretScalar) -> SecretScalar {
        Self {
            scalar: Zeroizing::new(self.with(|a| other.with(|b| a + b))),
        }
    }

    /// Whitelist: subtract another SecretScalar → new SecretScalar.
    /// genRctSimple's last input `a[last] = Σout_masks − Σprev_pseudo`.
    pub fn sub_secret(&self, other: &SecretScalar) -> SecretScalar {
        Self {
            scalar: Zeroizing::new(self.with(|a| other.with(|b| a - b))),
        }
    }

    /// Whitelist: write out bytes (public consumption such as wire serialization).
    pub fn write_bytes(&self, out: &mut [u8; 32]) {
        *out = self.scalar.to_bytes();
    }

    /// Read a copy of the bytes (audit #12 P1-01: narrowed to crate-private — the public API must not let
    /// secrets Copy-escape; consumers could only rely on the convention "go straight into the next owner/hash",
    /// which the type system cannot enforce; legitimate in-crate uses: wire serialization before push_take, test assertions).
    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }

    /// Internal: controlled borrow (only for this module's whitelist implementations)
    fn with<R>(&self, f: impl FnOnce(&Scalar) -> R) -> R {
        f(&self.scalar)
    }
}

impl core::fmt::Debug for SecretScalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretScalar([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static_assertions::assert_not_impl_any!(SecretScalar: Clone, Copy);

    /// Audit #10 P1-01: the whitelisted API no longer exposes &Scalar — point mul/addition returns a public point
    /// or a new owner; there is no generic callback that could copy the underlying Scalar out.
    /// (The old API `with_scalar<R>(&self, f: impl FnOnce(&Scalar) -> R)` was removed:
    ///  with Scalar: Copy, `|s| *s` could legally escape — re-review judged it an owner-escape vulnerability)
    #[test]
    fn whitelist_ops_return_public_or_owner() {
        let owner = SecretScalar::from_bytes_mod_order([0x77u8; 32]);
        // point mul: returns a compressed point (public value) — no Scalar escape path
        let pub_point = owner.mul_basepoint();
        assert_ne!(pub_point, [0u8; 32]);
        // scalar add: returns a new owner
        let sum = owner.add_bytes(&[0x11u8; 32]);
        let mut expect = [0u8; 32];
        expect.copy_from_slice(
            &(Scalar::from_bytes_mod_order([0x77u8; 32])
                + Scalar::from_bytes_mod_order([0x11u8; 32]))
            .to_bytes(),
        );
        assert_eq!(sum.to_bytes(), expect);
    }

    /// Audit #10 P1-02: construction establishes no plain let s intermediate binding (a Zeroizing<Scalar>
    /// internally); this test locks the API surface against regression.
    #[test]
    fn construction_contract() {
        // Note: from_bytes_mod_order reduces mod l — non-canonical encodings (e.g. all bytes 0x42)
        // change their byte representation; tests use canonical small scalars (0x42 only in the lowest byte)
        let mut raw = [0u8; 32];
        raw[0] = 0x42;
        let owner = SecretScalar::from_bytes_mod_order(raw);
        let mut out = [0u8; 32];
        owner.write_bytes(&mut out);
        assert_eq!(out, raw);
        // mul_basepoint (BP+ scenario)
        let p = owner.mul_basepoint();
        assert_ne!(p, [0u8; 32]);
    }

    /// Audit #11 P0-01: untrusted compressed point decompression failure → Err (no panic).
    /// The re-review reproduced the panic with an out-of-repo PoC using [0x02;32] (on device = abort/DoS).
    /// Totality is a hard gate for this type's API — any regression fails.
    #[test]
    fn invalid_point_encoding_returns_err_not_panic() {
        let owner = SecretScalar::from_bytes_mod_order([0x42u8; 32]);
        // [0x02;32] is not a valid compressed point (the re-review PoC's encoding)
        assert!(owner.mul_point(&[0x02u8; 32]).is_err());
        assert!(owner.mul_point_cofactor(&[0x02u8; 32]).is_err());
        // valid points still work (no false positives)
        let pt = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
            * &curve25519_dalek::Scalar::from(1u8);
        let pt_bytes = pt.compress().to_bytes();
        assert!(owner.mul_point(&pt_bytes).is_ok());
        assert!(owner.mul_point_cofactor(&pt_bytes).is_ok());
    }

    /// add_secret: owner + owner → owner (field arithmetic fully closed)
    #[test]
    fn add_secret_returns_owner() {
        let a = SecretScalar::from_bytes_mod_order([1u8; 32]);
        let b = SecretScalar::from_bytes_mod_order([2u8; 32]);
        let c = a.add_secret(&b);
        let mut out = [0u8; 32];
        c.write_bytes(&mut out);
        let expect =
            Scalar::from_bytes_mod_order([1u8; 32]) + Scalar::from_bytes_mod_order([2u8; 32]);
        assert_eq!(out, expect.to_bytes());
    }

    /// sub_secret: owner − owner → owner (used for genRctSimple's last mask)
    #[test]
    fn sub_secret_returns_owner() {
        let a = SecretScalar::from_bytes_mod_order([7u8; 32]);
        let b = SecretScalar::from_bytes_mod_order([3u8; 32]);
        let c = a.sub_secret(&b);
        let mut out = [0u8; 32];
        c.write_bytes(&mut out);
        let expect =
            Scalar::from_bytes_mod_order([7u8; 32]) - Scalar::from_bytes_mod_order([3u8; 32]);
        assert_eq!(out, expect.to_bytes());
    }

    /// Audit #12 P1-01 API gate: whitelisted inputs/outputs create no plain Scalar channels —
    /// add_assign only accepts owners; to_bytes exits the public surface (pub(crate), integration tests
    /// are rejected at compile time); public outputs are only compressed points (public values) and write_bytes (into the caller's buffer).
    #[test]
    fn add_assign_owner_only_api_gate() {
        assert!(core::mem::needs_drop::<SecretScalar>());
        static_assertions::assert_not_impl_any!(SecretScalar: Clone, Copy);
        let mut acc = SecretScalar::from_bytes_mod_order([1u8; 32]);
        let b = SecretScalar::from_bytes_mod_order([2u8; 32]);
        acc.add_assign(&b);
        let mut out = [0u8; 32];
        acc.write_bytes(&mut out);
        let expect =
            Scalar::from_bytes_mod_order([1u8; 32]) + Scalar::from_bytes_mod_order([2u8; 32]);
        assert_eq!(out, expect.to_bytes());
    }
}
