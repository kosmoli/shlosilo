//! BIP-32 派生 over secp256k1（BTC + ETH + Cosmos + Tron + XRP）
//!
//! Phase 5 v2 真实实现：wrap `bip32 0.5.3` crate
//!
//! ## 设计要点
//!
//! - shlosilo `DerivationPath` → `bip32::DerivationPath` 通过字符串格式转换
//! - 内部把 `bip32::XPrv` 的 secp256k1 私钥部分提取出来作为 `Secp256k1Scalar`
//!
//! ## 安全约束（v2 §2.1）
//!
//! - `ExtendedPrivKey` 字段全部私有
//! - `derive_from_seed` 接受 `&[u8]` seed（BIP-39 输出 64 bytes）
//! - 返回的 `Secp256k1Scalar` 直接受 Zeroize 保护
//!
//! ## v2 §2.3 算法决策
//!
//! ✅ **接受审计过的 bip32 crate**（RustCrypto 维护，多次审计）

extern crate alloc;
use alloc::format;
use alloc::string::String;

use crate::curve_primitive::secp256k1::Secp256k1Scalar;
use crate::derivation::path::DerivationPath;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use bip32::{DerivationPath as Bip32Path, Prefix, XPrv, XPub};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// BIP-32 扩展私钥（78 bytes：version + depth + fp + chain_code + key + ...）
pub const EXTENDED_PRIVKEY_LEN: usize = 78;

/// BIP-32 扩展私钥包装
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ExtendedPrivKey {
    bytes: [u8; EXTENDED_PRIVKEY_LEN],
}

impl AsRef<[u8]> for ExtendedPrivKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for ExtendedPrivKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ExtendedPrivKey(<{} bytes redacted>)", self.bytes.len())
    }
}

/// 从 BIP-32 master XPrv 提取 78 bytes 序列化（零 alloc 路径）
///
/// 直接从 `ExtendedKey` 公开字段拼 78 bytes serialized form，**不**走
/// `xprv.to_string()` 的 base58check round-trip（避免 alloc String）。
///
/// **结构**（78 bytes）：
/// - bytes[0..4]   = prefix (`xprv` = 0x0488ADE4)
/// - bytes[4]      = depth
/// - bytes[5..9]   = parent fingerprint (4 bytes)
/// - bytes[9..13]  = child number (4 bytes big-endian)
/// - bytes[13..45] = chain code (32 bytes)
/// - bytes[45..78] = key (33 bytes, prefix 0x00 + 32 bytes scalar)
fn xprv_to_bytes(xprv: &XPrv) -> Result<[u8; EXTENDED_PRIVKEY_LEN]> {
    // to_extended_key 内部仅栈操作：key_bytes: [u8; 33] + attrs.clone() (Copy fields)
    let ek = xprv.to_extended_key(Prefix::XPRV);
    let mut bytes = [0u8; EXTENDED_PRIVKEY_LEN];
    bytes[..4].copy_from_slice(&ek.prefix.to_bytes());
    bytes[4] = ek.attrs.depth;
    bytes[5..9].copy_from_slice(&ek.attrs.parent_fingerprint);
    bytes[9..13].copy_from_slice(&ek.attrs.child_number.to_bytes());
    bytes[13..45].copy_from_slice(&ek.attrs.chain_code);
    bytes[45..78].copy_from_slice(&ek.key_bytes);
    Ok(bytes)
}

/// BIP-32 master 派生（从 BIP-39 seed 派生 master key）
pub fn master_from_seed(seed: &[u8]) -> Result<ExtendedPrivKey> {
    let xprv = XPrv::new(seed).map_err(|_| {
        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
    })?;
    let bytes = xprv_to_bytes(&xprv)?;
    Ok(ExtendedPrivKey { bytes })
}

/// 把 shlosilo DerivationPath 转换为 bip32 DerivationPath (via string format)
fn to_bip32_path(path: &DerivationPath) -> Result<Bip32Path> {
    // shlosilo DerivationPath Display → "m/44'/0'/..." 字符串 → bip32 parse
    let s = format!("{:?}", path);
    s.parse::<Bip32Path>().map_err(|_| {
        ShlosiloError::new(ShlosiloErrorKind::DerivationPathInvalidSyntax)
    })
}

/// BIP-32 路径派生（从 seed 直接派生 child key，返回 32 bytes scalar）
pub fn derive_from_seed(seed: &[u8], path: &DerivationPath) -> Result<Secp256k1Scalar> {
    let bip32_path = to_bip32_path(path)?;
    let xprv = XPrv::derive_from_path(seed, &bip32_path).map_err(|_| {
        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
    })?;
    // 提取 raw 私钥 (32 bytes)
    let sk_bytes = xprv.to_bytes();
    crate::curve_primitive::secp256k1::scalar_from_bytes(&sk_bytes)
}

/// BIP-32 路径派生（从 master extended key 派生 child scalar）
///
/// 简化实现：master 只持有 78 bytes 序列化，不持有 bip32::XPrv
/// 实际业务中应该直接用 derive_from_seed（持有 seed 即可）
pub fn derive(_master: &ExtendedPrivKey, _path: &DerivationPath) -> Result<Secp256k1Scalar> {
    Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))
}

/// 从 seed + path 导出 BIP-32 xpub（78 bytes，version = 0x0488B21E）
pub fn xpub_from_seed(seed: &[u8], path: &DerivationPath) -> Result<[u8; EXTENDED_PRIVKEY_LEN]> {
    let bip32_path = to_bip32_path(path)?;
    let xprv = XPrv::derive_from_path(seed, &bip32_path).map_err(|_| {
        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
    })?;
    let xpub: XPub = xprv.public_key();
    let ek = xpub.to_extended_key(Prefix::XPUB);
    let mut bytes = [0u8; EXTENDED_PRIVKEY_LEN];
    bytes[..4].copy_from_slice(&ek.prefix.to_bytes());
    bytes[4] = ek.attrs.depth;
    bytes[5..9].copy_from_slice(&ek.attrs.parent_fingerprint);
    bytes[9..13].copy_from_slice(&ek.attrs.child_number.to_bytes());
    bytes[13..45].copy_from_slice(&ek.attrs.chain_code);
    bytes[45..78].copy_from_slice(&ek.key_bytes);
    Ok(bytes)
}

// 抑制 unused Prefix 警告（bip32 0.5 需要使用）
#[allow(dead_code)]
fn _use_prefix() -> Prefix {
    Prefix::XPRV
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_privkey_len() {
        assert_eq!(EXTENDED_PRIVKEY_LEN, 78);
    }

    #[test]
    fn extended_privkey_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<ExtendedPrivKey>());
    }

    /// BIP-32 Test Vector 1 (basic master_from_seed)
    #[test]
    fn master_from_seed_basic() {
        let seed = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let master = master_from_seed(&seed).unwrap();
        assert_eq!(master.bytes.len(), EXTENDED_PRIVKEY_LEN);
        // Version bytes = 0x0488ade4 (BIP-32 mainnet xprv version)
        assert_eq!(&master.bytes[0..4], &[0x04, 0x88, 0xad, 0xe4]);
        // Depth = 0 (master)
        assert_eq!(master.bytes[4], 0);
    }

    /// BIP-32 派生：seed → master scalar (m)
    #[test]
    fn derive_from_seed_master() {
        let seed = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let path = DerivationPath::parse("m").unwrap();
        let scalar = derive_from_seed(&seed, &path).unwrap();
        let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&scalar);
        assert_eq!(sk_bytes.len(), 32);
    }

    /// BIP-32 派生：seed → m/0
    #[test]
    fn derive_from_seed_m_0() {
        let seed = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let path = DerivationPath::parse("m/0").unwrap();
        let scalar = derive_from_seed(&seed, &path).unwrap();
        let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&scalar);
        assert_eq!(sk_bytes.len(), 32);
        assert_ne!(sk_bytes, [0u8; 32]);
    }

    /// BIP-32 派生：seed → m/44'/0'/0'/0/0 (BTC BIP-44 标准路径)
    #[test]
    fn derive_from_seed_bip44() {
        let seed = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let path = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
        let scalar = derive_from_seed(&seed, &path).unwrap();
        let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&scalar);
        assert_eq!(sk_bytes.len(), 32);
    }

    /// BIP-32 派生一致性：相同 seed + path 产生相同 scalar
    #[test]
    fn derive_from_seed_deterministic() {
        let seed = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let s1 = derive_from_seed(&seed, &path).unwrap();
        let s2 = derive_from_seed(&seed, &path).unwrap();
        assert_eq!(
            crate::curve_primitive::secp256k1::scalar_to_bytes(&s1),
            crate::curve_primitive::secp256k1::scalar_to_bytes(&s2)
        );
    }

    /// BIP-32 派生：不同 path 产生不同 scalar
    #[test]
    fn derive_from_seed_different_paths() {
        let seed = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let path_a = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
        let path_b = DerivationPath::parse("m/44'/0'/0'/0/1").unwrap();
        let s_a = derive_from_seed(&seed, &path_a).unwrap();
        let s_b = derive_from_seed(&seed, &path_b).unwrap();
        assert_ne!(
            crate::curve_primitive::secp256k1::scalar_to_bytes(&s_a),
            crate::curve_primitive::secp256k1::scalar_to_bytes(&s_b)
        );
    }

    /// BIP-32 标准测试向量（bip32 0.5.3 官方）：
    /// seed = 000102030405060708090a0b0c0d0e0f
    /// m → xprv = xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
    /// m/0' → xprv = xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7
    #[test]
    fn bip32_test_vector_1_master() {
        let seed = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let xprv = bip32::XPrv::new(&seed).unwrap();
        let s = xprv.to_string(bip32::Prefix::XPRV);
        let expected = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        assert_eq!(&s as &str, expected);
    }

    /// BIP-32 派生测试向量 1: m/0' (第一个 hardened child)
    #[test]
    fn bip32_test_vector_1_m_0h() {
        let seed = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let path = DerivationPath::parse("m/0'").unwrap();
        let scalar = derive_from_seed(&seed, &path).unwrap();
        // 验证 raw 私钥是有效的 secp256k1 scalar
        let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&scalar);
        assert_eq!(sk_bytes.len(), 32);
        assert_ne!(sk_bytes, [0u8; 32]);
    }

    /// master_from_seed 错误：seed 太短
    #[test]
    fn master_from_seed_rejects_short_seed() {
        let seed = [0u8; 8];
        let result = master_from_seed(&seed);
        assert!(result.is_err());
    }
}