//! Monero reduce_scalar 派生（XMR 核心派生）

use crate::curve_primitive::ed25519::Ed25519Scalar;
use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Monero 派生路径（v2 §2.7 关键：MoneroPath 不是 DerivationPath）
///
/// Monero 路径用 account / subaddress index 结构，不用 BIP-32 字符串
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

/// Monero 密钥对（v2 §2.7 关键聚合结构）
///
/// **不 derive Clone**：每 clone 一次，内存里多一份 spend/view 副本，
/// 物理攻击面放大一倍（cold boot / DMA / 0day / 寄存器残留）。
/// `ZeroizeOnDrop` 只清零当前 scope 的副本，对 dump / DMA / Spectre 无效。
///
/// **业务模块正确用法**：
/// ```ignore
/// let kp = monero_reduce_scalar::derive(seed, &path)?;
/// let spend = kp.spend_priv();  // &Ed25519Scalar (borrow)
/// let sig = clsag_ed25519::sign(spend, msg, ring, pseudo_out, aux)?;
/// // kp 出 scope 自动 ZeroizeOnDrop，签名完成
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MoneroKeyPair {
    spend_priv: Ed25519Scalar,
    view_priv: Ed25519Scalar,
}

impl MoneroKeyPair {
    /// 借出 spend 私钥（borrow，不 clone）
    pub fn spend_priv(&self) -> &Ed25519Scalar {
        &self.spend_priv
    }
    /// 借出 view 私钥（borrow，不 clone）
    pub fn view_priv(&self) -> &Ed25519Scalar {
        &self.view_priv
    }
}

impl core::fmt::Debug for MoneroKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MoneroKeyPair(<spend+view priv redacted>)")
    }
}

/// Monero reduce_scalar 派生（v2 §2.7 关键公式）
///
/// # P1-06（2026-08-26）真实实现（对齐 keystone apps/monero/src/key.rs）
///
/// 1. BIP-32 secp256k1 派生 `m/44'/128'/{account}'/0/0` → 32B raw private key
/// 2. spend = Hs(raw) = reduce_scalar(keccak256(raw))     （monero hash_to_scalar）
/// 3. view  = Hs(spend_bytes)                              （monero generate_keys）
///
/// 这是 keystone 从 BIP-39 seed 生成 Monero keypair 的标准路径（P6.3 已用
/// base58-monero 地址编码互验：DEST1 与 meta.json MATCH）。
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

/// View key 派生（用于导出 view-only 凭证）
///
/// view = Hs(spend_private)（monero generate_keys 第二步）
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

    /// P1-06：派生确定性——同 seed 同路径 → 同 spend/view
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

    /// P1-06：derive_view_key 与 derive 的 view 一致（Hs(spend)）
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

    /// P1-06：account 不同 → key 不同（路径参与派生）
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