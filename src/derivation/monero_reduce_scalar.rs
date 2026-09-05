//! Monero reduce_scalar derivation (XMR core derivation)

use crate::curve_primitive::ed25519::Ed25519Scalar;
use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Monero derivation path (v2 §2.7 key point: MoneroPath is not DerivationPath)
///
/// Monero paths use the account / subaddress index structure, not BIP-32 strings
#[derive(Clone, Debug)]
pub struct MoneroPath {
    pub account: u32,
    pub subaddress_major: u32,
    pub subaddress_minor: u32,
}

impl MoneroPath {
    pub fn mainnet(account: u32) -> Self {
        Self {
            account,
            subaddress_major: 0,
            subaddress_minor: 0,
        }
    }
}

/// Monero key pair (the key aggregation structure of v2 §2.7)
///
/// **Does not derive Clone**: each clone adds one more in-memory spend/view copy,
/// doubling the physical attack surface (cold boot / DMA / 0day / register residue).
/// `ZeroizeOnDrop` only zeroes the copy in the current scope; it is useless against dump / DMA / Spectre.
///
/// **Correct usage in business modules**:
/// ```ignore
/// let kp = monero_reduce_scalar::derive(seed, &path)?;
/// let spend = kp.spend_priv();  // &Ed25519Scalar (borrow)
/// let sig = clsag_ed25519::sign(spend, msg, ring, pseudo_out, aux)?;
/// // kp auto ZeroizeOnDrop when leaving scope, signing done
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MoneroKeyPair {
    spend_priv: Ed25519Scalar,
    view_priv: Ed25519Scalar,
}

impl MoneroKeyPair {
    /// Lend the spend private key (borrow, not clone)
    pub fn spend_priv(&self) -> &Ed25519Scalar {
        &self.spend_priv
    }
    /// Lend the view private key (borrow, not clone)
    pub fn view_priv(&self) -> &Ed25519Scalar {
        &self.view_priv
    }
}

impl core::fmt::Debug for MoneroKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MoneroKeyPair(<spend+view priv redacted>)")
    }
}

/// Monero reduce_scalar derivation (the key formula of v2 §2.7)
///
/// # P1-06 (2026-08-26) real implementation (aligned with keystone apps/monero/src/key.rs)
///
/// 1. BIP-32 secp256k1 derive `m/44\'/128\'/{account}\'/0/0` → 32B raw private key
/// 2. spend = Hs(raw) = reduce_scalar(keccak256(raw))     （monero hash_to_scalar）
/// 3. view  = Hs(spend_bytes)                              （monero generate_keys）
///
/// This is keystone\'s standard path for generating a Monero keypair from a BIP-39 seed (P6.3 already
/// cross-verified with base58-monero address encoding: DEST1 matches meta.json).
pub fn derive(seed: &[u8], path: &MoneroPath) -> Result<MoneroKeyPair> {
    extern crate alloc;
    use alloc::format;

    // 1. BIP-32 secp256k1 m/44'/128'/{account}'/0/0
    let path_str = format!("m/44'/128'/{}'/0/0", path.account);
    let dp = crate::derivation::path::DerivationPath::parse(&path_str)?;
    let sk = crate::derivation::bip32_secp256k1::derive_from_seed(seed, &dp)?;
    let raw = crate::curve_primitive::secp256k1::scalar_to_bytes(&sk);

    // 2. spend = Hs(raw)
    let spend_hash = crate::encoding::keccak256::hash(&raw)?;
    let spend_priv = crate::chain::xmr::reduce_scalar::reduce_scalar(&spend_hash)?;

    // 3. view = Hs(spend)
    let spend_bytes = crate::curve_primitive::ed25519::scalar_to_bytes(&spend_priv);
    let view_hash = crate::encoding::keccak256::hash(&spend_bytes)?;
    let view_priv = crate::chain::xmr::reduce_scalar::reduce_scalar(&view_hash)?;

    Ok(MoneroKeyPair {
        spend_priv,
        view_priv,
    })
}

/// View key derivation (for exporting view-only credentials)
///
/// view = Hs(spend_private) (the second step of monero generate_keys)
pub fn derive_view_key(spend_private: &Ed25519Scalar) -> Result<Ed25519Scalar> {
    let spend_bytes = crate::curve_primitive::ed25519::scalar_to_bytes(spend_private);
    let view_hash = crate::encoding::keccak256::hash(&spend_bytes)?;
    crate::chain::xmr::reduce_scalar::reduce_scalar(&view_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&[u8], &MoneroPath) -> Result<MoneroKeyPair> = derive;
    const _: fn(&Ed25519Scalar) -> Result<Ed25519Scalar> = derive_view_key;

    #[test]
    fn keypair_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<MoneroKeyPair>());
    }

    #[test]
    fn path_mainnet() {
        let path = MoneroPath::mainnet(0);
        assert_eq!(path.account, 0);
        assert_eq!(path.subaddress_major, 0);
        assert_eq!(path.subaddress_minor, 0);
    }

    /// P1-06: derivation determinism — same seed same path → same spend/view
    #[test]
    fn derive_deterministic() {
        let seed = [0x42u8; 64];
        let path = MoneroPath::mainnet(0);
        let kp1 = derive(&seed, &path).unwrap();
        let kp2 = derive(&seed, &path).unwrap();
        assert_eq!(
            crate::curve_primitive::ed25519::scalar_to_bytes(kp1.spend_priv()),
            crate::curve_primitive::ed25519::scalar_to_bytes(kp2.spend_priv())
        );
        assert_eq!(
            crate::curve_primitive::ed25519::scalar_to_bytes(kp1.view_priv()),
            crate::curve_primitive::ed25519::scalar_to_bytes(kp2.view_priv())
        );
    }

    /// P1-06: derive_view_key matches derive\'s view (Hs(spend))
    #[test]
    fn derive_view_key_matches_derive() {
        let seed = [0x24u8; 64];
        let path = MoneroPath::mainnet(0);
        let kp = derive(&seed, &path).unwrap();
        let view = derive_view_key(kp.spend_priv()).unwrap();
        assert_eq!(
            crate::curve_primitive::ed25519::scalar_to_bytes(&view),
            crate::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv())
        );
    }

    /// P1-06: different account → different keys (the path participates in derivation)
    #[test]
    fn derive_differs_by_account() {
        let seed = [0x11u8; 64];
        let kp0 = derive(&seed, &MoneroPath::mainnet(0)).unwrap();
        let kp1 = derive(&seed, &MoneroPath::mainnet(1)).unwrap();
        assert_ne!(
            crate::curve_primitive::ed25519::scalar_to_bytes(kp0.spend_priv()),
            crate::curve_primitive::ed25519::scalar_to_bytes(kp1.spend_priv())
        );
    }

    #[test]
    fn spend_and_view_differ() {
        let seed = [0x77u8; 64];
        let kp = derive(&seed, &MoneroPath::mainnet(0)).unwrap();
        assert_ne!(
            crate::curve_primitive::ed25519::scalar_to_bytes(kp.spend_priv()),
            crate::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv())
        );
    }
}
