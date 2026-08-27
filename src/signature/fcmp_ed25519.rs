//! Monero FCMP++ 证明（XMR 升级，Phase 7 占位）

use crate::curve_primitive::ed25519::{Ed25519Point, Ed25519Scalar};
use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// FCMP++ 证明长度（待 Phase 7 实际确定）
pub const FCMP_PROOF_MAX_LEN: usize = 1024;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct FcmpProof {
    bytes: heapless::Vec<u8, FCMP_PROOF_MAX_LEN>,
}

impl AsRef<[u8]> for FcmpProof {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl core::fmt::Debug for FcmpProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FcmpProof(<{} bytes redacted>)", self.bytes.len())
    }
}

/// FCMP++ 证明生成（Phase 7 占位）
pub fn sign(_spend_skey: &Ed25519Scalar, _msg: &[u8]) -> Result<FcmpProof> {
    unimplemented!("Phase 2.2 stub: fcmp_ed25519::sign 将在 Phase 7 接入真实 FCMP++ 算法")
}

/// FCMP++ 验证
pub fn verify(_ring_output: &Ed25519Point, _msg: &[u8], _proof: &FcmpProof) -> bool {
    unimplemented!("Phase 2.2 stub: fcmp_ed25519::verify 将在 Phase 7 接入真实 FCMP++ 算法")
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&Ed25519Scalar, &[u8]) -> Result<FcmpProof> = sign;
    const _: fn(&Ed25519Point, &[u8], &FcmpProof) -> bool = verify;

    #[test]
    fn proof_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<FcmpProof>());
    }

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("fcmp_ed25519.rs");
        assert!(source.contains("unimplemented!"));
        assert!(source.contains("Phase 7"));
    }
}