//! RSA-PSS 签名（Arweave）

use crate::curve_primitive::rsa::{RsaPrivKey, RsaPubKey};
use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// RSA-PSS 签名固定长度（512 bytes for RSA-4096）
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

/// RSA-PSS 签名
///
/// # Phase 4 实现
/// `rsa::pss::SigningKey::<Sha512>::sign(rng, hashed_msg)`
///
/// 重要：RSA-PSS **需要 RNG**（与 ECDSA 的 deterministic nonce 不同）。
/// 在 `no_std` 环境下 RNG 来源由 L3 imperative shell 提供——这里只接受 pre-salted msg。
pub fn sign(_sk: &RsaPrivKey, _msg_hash: &[u8]) -> Result<RsaPssSignature> {
    unimplemented!("Phase 2.2 stub: rsa_pss::sign 将在 Phase 4 接入 rsa crate")
}

/// RSA-PSS 验签
pub fn verify(_pk: &RsaPubKey, _msg_hash: &[u8], _sig: &RsaPssSignature) -> bool {
    unimplemented!("Phase 2.2 stub: rsa_pss::verify 将在 Phase 4 接入 rsa crate")
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
    fn stub_phase_documented() {
        let source = include_str!("rsa_pss.rs");
        assert!(source.contains("unimplemented!"));
        assert!(source.contains("Phase 4"));
    }
}