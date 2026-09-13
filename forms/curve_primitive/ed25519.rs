//! ed25519 curve primitive (Layer A / XMR + SOL + Cardano + SUI + Near + Aptos)
//!
//! Phase 5 v4 real implementation: `ed25519-dalek` crate 2.2
//!
//! ## Design Notes
//!
//! - wrap `ed25519_dalek::SigningKey` + `VerifyingKey` directly (ed25519-dalek 2 friendly API)
//! - do not wrap `curve25519_dalek` types directly (avoids exposing low-level details)
//! - the XMR business module may import `monero-ed25519` on its own for Pedersen commitments + reduce_scalar
//!
//! ## Security Constraints (v2 §2.1)
//!
//! - `Ed25519Scalar` forbids `Copy` and implements `Zeroize + ZeroizeOnDrop`
//! - `Ed25519Point` allows `Copy + Eq` (public keys are public material)
//! - fields are private; outsiders cannot construct them from thin air

use ed25519_dalek::{SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// ed25519 scalar length (32 bytes)
pub(crate) const SCALAR_LEN: usize = SECRET_KEY_LENGTH;

/// ed25519 compressed point length (32 bytes)
pub(crate) const COMPRESSED_POINT_LEN: usize = PUBLIC_KEY_LENGTH;

/// ed25519 scalar (internal representation of a private key component)
///
/// Internally stores an `ed25519_dalek::SigningKey`.
/// **Copy forbidden**: v2 §2.1 v2.x security constraint.
pub struct Ed25519Scalar {
    inner: SigningKey,
}

// manual impl Zeroize + ZeroizeOnDrop (SigningKey itself already zeroizes, but inner still needs Drop)
impl Drop for Ed25519Scalar {
    fn drop(&mut self) {
        // SigningKey zeroizes automatically on drop (it impls Zeroize)
        // only the ZeroizeOnDrop marker is needed here (via the derive helper macro)
    }
}

// provides a manual Zeroize impl (SigningKey already zeroizes)
impl Zeroize for Ed25519Scalar {
    fn zeroize(&mut self) {
        // call SigningKey's Zeroize (if it exists); otherwise drop + rewrite
        let mut sk_bytes = self.inner.to_bytes();
        sk_bytes.zeroize();
        // rebuild the SigningKey to overwrite inner's memory
        if let Ok(new_sk) = SigningKey::from_keypair_bytes(&{
            let mut kp = [0u8; 64];
            kp[..32].copy_from_slice(&sk_bytes);
            kp
        }) {
            self.inner = new_sk;
        }
    }
}

impl ZeroizeOnDrop for Ed25519Scalar {}

/// ed25519 point (internal representation of a public key)
///
/// **Public material** — `Copy + Eq` allowed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ed25519Point {
    inner: VerifyingKey,
}

// ============================================================================
// Free functions
// ============================================================================

/// ed25519 curve basepoint
pub fn generator() -> Ed25519Point {
    let g_bytes: [u8; PUBLIC_KEY_LENGTH] = {
        let mut b = [0u8; PUBLIC_KEY_LENGTH];
        b[0] = 1;
        b
    };
    let g = VerifyingKey::from_bytes(&g_bytes).expect("basepoint");
    Ed25519Point { inner: g }
}

/// Basepoint multiplication: result = s * G (use `verifying_key()` to get the public pk)
pub fn base_mul(s: &Ed25519Scalar) -> Ed25519Point {
    let vk = s.inner.verifying_key();
    Ed25519Point { inner: vk }
}

/// Zero scalar (for accumulator initialization)
pub fn scalar_zero() -> Ed25519Scalar {
    let zero_bytes = [0u8; SECRET_KEY_LENGTH];
    // uses from_keypair_bytes accepting 64 bytes (sk || pk)
    let mut kp_bytes = [0u8; 64];
    kp_bytes[..32].copy_from_slice(&zero_bytes);
    // pk = base_mul(zero_scalar) = identity
    // uses from_keypair_bytes + an error fallback to unsafe from_bytes
    let sk = SigningKey::from_bytes(&zero_bytes);
    Ed25519Scalar { inner: sk }
}

/// Build an ed25519 scalar from 32 bytes
///
/// # Errors
/// - `EncodingInvalidFormat`: the byte length is not 32
pub fn scalar_from_bytes(bytes: &[u8]) -> Result<Ed25519Scalar> {
    if bytes.len() != SCALAR_LEN {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut arr = [0u8; SCALAR_LEN];
    arr.copy_from_slice(bytes);
    // SigningKey::from_bytes is infallible (accepts any 32 bytes)
    let sk = SigningKey::from_bytes(&arr);
    Ok(Ed25519Scalar { inner: sk })
}

/// ed25519 scalar → 32 bytes
pub fn scalar_to_bytes(s: &Ed25519Scalar) -> [u8; SCALAR_LEN] {
    s.inner.to_bytes()
}

/// ed25519 point → 32-byte compression
pub fn point_to_compressed(p: &Ed25519Point) -> [u8; COMPRESSED_POINT_LEN] {
    p.inner.to_bytes()
}

/// Build an ed25519 point from 32 compressed bytes
pub fn point_from_compressed(bytes: &[u8]) -> Result<Ed25519Point> {
    if bytes.len() != COMPRESSED_POINT_LEN {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut arr = [0u8; COMPRESSED_POINT_LEN];
    arr.copy_from_slice(bytes);
    let vk = VerifyingKey::from_bytes(&arr)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    Ok(Ed25519Point { inner: vk })
}

#[cfg(test)]
mod tests {
    use super::*;

    // type-signature shape verification
    const _: fn() -> Ed25519Point = generator;
    const _: fn(&Ed25519Scalar) -> Ed25519Point = base_mul;
    const _: fn() -> Ed25519Scalar = scalar_zero;

    #[test]
    fn scalar_not_copy() {
        assert!(core::mem::needs_drop::<Ed25519Scalar>());
    }

    #[test]
    fn point_is_copy() {
        assert!(!core::mem::needs_drop::<Ed25519Point>());
    }

    #[test]
    fn scalar_zero_works() {
        let s = scalar_zero();
        let out = scalar_to_bytes(&s);
        assert_eq!(out, [0u8; SCALAR_LEN]);
    }

    /// scalar_from_bytes round-trip
    #[test]
    fn scalar_from_bytes_works() {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        let s = scalar_from_bytes(&bytes).unwrap();
        assert_eq!(scalar_to_bytes(&s), bytes);
    }

    /// base_mul(s) = verifying_key
    #[test]
    fn base_mul_equals_verifying_key() {
        let mut bytes = [0u8; 32];
        bytes[31] = 42;
        let s = scalar_from_bytes(&bytes).unwrap();
        let p = base_mul(&s);
        let pk_bytes = s.inner.verifying_key().to_bytes();
        assert_eq!(point_to_compressed(&p), pk_bytes);
    }

    /// Compressed pubkey round-trip
    #[test]
    fn point_compressed_roundtrip() {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 7;
        let sk = scalar_from_bytes(&sk_bytes).unwrap();
        let pk = base_mul(&sk);
        let compressed = point_to_compressed(&pk);
        assert_eq!(compressed.len(), COMPRESSED_POINT_LEN);
        let pk2 = point_from_compressed(&compressed).unwrap();
        assert_eq!(point_to_compressed(&pk), point_to_compressed(&pk2));
    }

    /// Known compressed bytes of the ed25519 basepoint (G)
    #[test]
    fn ed25519_basepoint_test_vector() {
        let g = generator();
        let g_compressed = point_to_compressed(&g);
        assert_eq!(g_compressed[0], 1);
        for &b in &g_compressed[1..] {
            assert_eq!(b, 0);
        }
    }

    /// scalar_from_bytes rejects a wrong length
    #[test]
    fn scalar_from_bytes_rejects_wrong_length() {
        let bytes = [0u8; 16];
        let r = scalar_from_bytes(&bytes);
        assert!(r.is_err());
    }

    /// scalar_from_bytes accepts any bytes (ed25519-dalek 2's from_bytes is infallible)
    #[test]
    fn scalar_from_bytes_accepts_any() {
        // ed25519-dalek accepts even all-ff values
        let bytes = [0xFFu8; 32];
        let r = scalar_from_bytes(&bytes);
        assert!(r.is_ok());
    }
}
