//! BIP-67 多签（v1 不支持，Phase 8+ 真实实现）

use crate::curve_primitive::secp256k1::{Secp256k1Point, Secp256k1Scalar};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// BIP-67 排序的公钥列表（用于 P2SH multisig redeem script）
pub const MAX_MULTISIG_SIGNERS: usize = 15;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MultisigScript {
    bytes: heapless::Vec<u8, 256>,
}

impl AsRef<[u8]> for MultisigScript {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl core::fmt::Debug for MultisigScript {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MultisigScript(<{} bytes redacted>)", self.bytes.len())
    }
}

/// Multisig 聚合公钥（Phase 8+ 真实实现）
pub fn aggregate_pubkey(_pubkeys: &[Secp256k1Point]) -> Result<Secp256k1Point> {
    Err(ShlosiloError::new(ShlosiloErrorKind::MultisigNotSupported))
}

/// 构造 m-of-n P2SH redeem script（Phase 8+ 真实实现）
pub fn redeem_script(_m: u8, _sorted_pubkeys: &[Secp256k1Point]) -> Result<MultisigScript> {
    Err(ShlosiloError::new(ShlosiloErrorKind::MultisigNotSupported))
}

/// Multisig 签名（Phase 8+ 真实实现）
pub fn sign_multisig(
    _sk: &Secp256k1Scalar,
    _msg_hash: &[u8; 32],
    _redeem_script: &MultisigScript,
) -> Result<heapless::Vec<u8, 128>> {
    Err(ShlosiloError::new(ShlosiloErrorKind::MultisigNotSupported))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&[Secp256k1Point]) -> Result<Secp256k1Point> = aggregate_pubkey;
    const _: fn(u8, &[Secp256k1Point]) -> Result<MultisigScript> = redeem_script;
    const _: fn(&Secp256k1Scalar, &[u8; 32], &MultisigScript) -> Result<heapless::Vec<u8, 128>> =
        sign_multisig;

    #[test]
    fn max_signers_constant() {
        assert_eq!(MAX_MULTISIG_SIGNERS, 15);
    }

    #[test]
    fn script_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<MultisigScript>());
    }

    #[test]
    fn v1_returns_multisig_not_supported() {
        let result = aggregate_pubkey(&[]);
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::MultisigNotSupported
        );
    }

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("bip32_secp256k1_multisig.rs");
        // v1 不支持，所以错误码是 MultisigNotSupported（不是 unimplemented!）
        assert!(source.contains("MultisigNotSupported"));
        assert!(source.contains("Phase 8+"));
    }
}
