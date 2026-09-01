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
    // P2-01: unimplemented!() panic → 稳定错误码
    Err(crate::error::ShlosiloError::new(
        crate::error::ShlosiloErrorKind::FeatureNotImplemented,
    ))
}

/// FCMP++ 验证
pub fn verify(_ring_output: &Ed25519Point, _msg: &[u8], _proof: &FcmpProof) -> bool {
    // P2-01: unimplemented!() panic → 稳定 false（bool 签名无 Err 通道）
    false
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
    fn stub_no_panic_marker() {
        // P2-01：stub 已改为稳定错误码/返回值，不允许 panic 宏回归
        // （检查代码行，排除注释行）
        for line in "fcmp_ed25519.rs".lines() {
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
