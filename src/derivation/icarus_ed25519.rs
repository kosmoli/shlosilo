//! Icarus 派生 over ed25519（Cardano Shelley）

use crate::curve_primitive::ed25519::Ed25519Scalar;
use crate::derivation::path::DerivationPath;
use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Cardano 扩展私钥——比普通 ed25519 多 stake / drep / ccl 等多组字段
///
/// v2 §2.7 关键约束：聚合结构，**字段全 ZeroizeOnDrop**
///
/// **不 derive Clone**：每 clone 一次内存里多 1 份 spend+stake+drep+ccl 副本，
/// 物理攻击面放大一倍（cold boot / DMA / 0day / 寄存器残留）。
/// `ZeroizeOnDrop` 只清零当前 scope 的副本，对 dump / DMA / Spectre 无效。
///
/// **业务模块正确用法**：
/// ```ignore
/// let master = icarus_ed25519::master_from_seed(seed)?;
/// let child = icarus_ed25519::derive(&master, &path)?;
/// let spend = child.spend();  // &Ed25519Scalar (borrow)
/// let sig = eddsa_ed25519::sign(spend, msg)?;
/// // master / child 出 scope 自动 ZeroizeOnDrop
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CardanoExtSk {
    spend: Ed25519Scalar,
    stake: Option<Ed25519Scalar>,
    drep: Option<Ed25519Scalar>,
    ccl: Option<Ed25519Scalar>,
}

impl CardanoExtSk {
    pub fn spend(&self) -> &Ed25519Scalar { &self.spend }
    pub fn stake(&self) -> Option<&Ed25519Scalar> { self.stake.as_ref() }
    pub fn drep(&self) -> Option<&Ed25519Scalar> { self.drep.as_ref() }
    pub fn ccl(&self) -> Option<&Ed25519Scalar> { self.ccl.as_ref() }
}

impl core::fmt::Debug for CardanoExtSk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CardanoExtSk(<redacted> stake={} drep={} ccl={})",
            self.stake.is_some(), self.drep.is_some(), self.ccl.is_some())
    }
}

/// Icarus master 派生（Cardano Byron 钱包风格的 Ed25519 派生）
///
/// # Phase 4 实现
/// `cardano_serialization_lib::crypto::derive`
pub fn master_from_seed(_seed: &[u8]) -> Result<CardanoExtSk> {
    unimplemented!("Phase 2.2 stub: icarus_ed25519::master_from_seed 将在 Phase 4 接入 cardano crate")
}

/// Icarus 路径派生——返回完整 CardanoExtSk（聚合结构）
///
/// 业务模块拿到 CardanoExtSk 后，**自己解构**：
/// `let spend = &cardano_ext_sk.spend;` 然后传给 `eddsa_ed25519::sign(spend, msg)`
pub fn derive(_master: &CardanoExtSk, _path: &DerivationPath) -> Result<CardanoExtSk> {
    unimplemented!("Phase 2.2 stub: icarus_ed25519::derive 将在 Phase 4 接入 cardano crate")
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
    fn stub_phase_documented() {
        let source = include_str!("icarus_ed25519.rs");
        assert!(source.contains("unimplemented!"));
        assert!(source.contains("Phase 4"));
    }
}