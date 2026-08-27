//! Monero CLSAG 环签名（XMR 核心签名）

use crate::curve_primitive::ed25519::{Ed25519Point, Ed25519Scalar};
use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// CLSAG 环签名（可变长度，取决于环大小）
pub const CLSAG_PROOF_MAX_LEN: usize = 32 * 16; // 假设 MAX_RING = 16，proof 长度 32 * ring_size

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

/// CLSAG 签名 auxiliary data
///
/// 包含 key image 生成所需的 pseudo_out + alpha / scc Params 等
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

/// CLSAG 环签名
///
/// # Phase 4 实现
/// `monero-oxide` crate 的 `clsag::sign(spend, ring, pseudo_out, aux)`
pub fn sign(
    _spend_skey: &Ed25519Scalar,
    _msg: &[u8],
    _ring_members: &[Ed25519Point],  // 环成员（含真实公钥 + 诱饵）
    _pseudo_output: &Ed25519Point,
    _aux_data: &ClsagAux,
) -> Result<ClsagProof> {
    unimplemented!("Phase 2.2 stub: clsag_ed25519::sign 将在 Phase 4 接入 monero-oxide")
}

/// CLSAG 验签
pub fn verify(
    _ring_members: &[Ed25519Point],
    _pseudo_output: &Ed25519Point,
    _msg: &[u8],
    _proof: &ClsagProof,
) -> bool {
    unimplemented!("Phase 2.2 stub: clsag_ed25519::verify 将在 Phase 4 接入 monero-oxide")
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&Ed25519Scalar, &[u8], &[Ed25519Point], &Ed25519Point, &ClsagAux) -> Result<ClsagProof> = sign;
    const _: fn(&[Ed25519Point], &Ed25519Point, &[u8], &ClsagProof) -> bool = verify;

    #[test]
    fn proof_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<ClsagProof>());
    }

    #[test]
    fn aux_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<ClsagAux>());
    }

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("clsag_ed25519.rs");
        assert!(source.contains("unimplemented!"));
        assert!(source.contains("Phase 4"));
        assert!(source.contains("monero-oxide"));
    }
}