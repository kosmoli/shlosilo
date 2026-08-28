//! §B.5 RNG 注入定案（2026-08-28）：entropy-injection + 成熟 CSPRNG。
//!
//! 分层契约：
//! - L3 负责 entropy 获取（TRNG / getrandom() / 掷骰子 / 拍照），承诺来源与最低
//!   min-entropy（建议 ≥128 bit）。本模块不验证熵质量，长度检查仅为 misuse guard。
//! - L2 用 HKDF-SHA256 按 [`RngPurpose`] 子域派生独立 RNG seed。
//! - L1 链层只消费 `RngCore + CryptoRng`，不感知 entropy 来源。
//!
//! 安全角色（§B.5 加粗定案）：
//! - **entropy 提供不可预测性**（安全性的根）；
//! - **tx digest = context/domain separation，不计入 entropy bits**——攻击者知道
//!   construction data，低熵 entropy 仍可被枚举，hash 混入不增熵。
//!
//! construction 全部用成熟审计 crate，零自制 DRBG：
//! `HKDF-SHA256(ikm=entropy, info=label‖context) → 32B seed → ChaCha20Rng`。
//!
//! 同 entropy + 同 construction → 同签名流：**feature**（deterministic retry
//! property），r 只服务本交易 outputs，无跨交易碰撞。

use rand_chacha::rand_core::{CryptoRng, RngCore};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use zeroize::Zeroize;

use hkdf::Hkdf;

/// entropy 长度下限（misuse guard，非熵质量验证——见模块文档）。
pub const ENTROPY_MIN_LEN: usize = 16;

/// 随机数用途子域。各 purpose 独立 KDF 派生，互不共享字节流——
/// 重构 sign 内部随机数消费顺序不再碎 deterministic vector。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RngPurpose {
    /// 交易临时密钥 r（tx public key R = rG，标准记号；subaddress 特例另注）
    TxKey,
    /// Bulletproof+ blinding
    BulletproofPlus,
    /// CLSAG 签名，按输入索引隔离
    Clsag(usize),
}

impl RngPurpose {
    /// info 域标签（label ‖ 32B context 拼接前半段）
    fn label(&self) -> &'static str {
        match self {
            RngPurpose::TxKey => "shlosilo/xmr/tx-key",
            RngPurpose::BulletproofPlus => "shlosilo/xmr/bulletproof+",
            // clsag 索引编码进 info 后半段，见 purpose_rng
            RngPurpose::Clsag(_) => "shlosilo/xmr/clsag",
        }
    }
}

/// entropy 注入错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RngSeedError {
    /// entropy 为空或短于 [`ENTROPY_MIN_LEN`]（API misuse guard）
    EntropyTooShort(usize),
}

impl From<RngSeedError> for crate::error::ShlosiloError {
    fn from(e: RngSeedError) -> Self {
        match e {
            RngSeedError::EntropyTooShort(n) => crate::error::ShlosiloError::with_context(
                crate::error::ShlosiloErrorKind::EntropyInjectionInvalid,
                crate::error::ErrorContext::ActualLength(n),
            ),
        }
    }
}

/// 派生指定 purpose 的确定性 RNG。
///
/// `context` = tx construction data 的摘要（domain separation，不计熵）。
/// 同一 (entropy, purpose, context) 三元组永远产生相同随机流——测试模型
/// `F(keys, tx, entropy) → signed_tx` 的纯函数性由本函数保证。
///
/// info = label ‖ context ‖ purpose_index（u32 LE，clsag 的输入索引也在此段），
/// 各 purpose 语义互不重叠。
pub fn purpose_rng(
    entropy: &[u8],
    purpose: RngPurpose,
    context: &[u8; 32],
) -> Result<ChaCha20Rng, RngSeedError> {
    if entropy.len() < ENTROPY_MIN_LEN {
        return Err(RngSeedError::EntropyTooShort(entropy.len()));
    }
    // purpose_index：TxKey=0, BulletproofPlus=1, Clsag(i)=2（i 编码进后续 4B）
    let (purpose_index, sub_index): (u32, u32) = match purpose {
        RngPurpose::TxKey => (0, 0),
        RngPurpose::BulletproofPlus => (1, 0),
        RngPurpose::Clsag(i) => (2, i as u32),
    };
    // info = label ‖ context(32) ‖ purpose_index(4 LE) ‖ sub_index(4 LE)
    let mut info = [0u8; 80];
    let label = purpose.label();
    let mut off = 0usize;
    info[..label.len()].copy_from_slice(label.as_bytes());
    off += label.len();
    info[off..off + 32].copy_from_slice(context);
    off += 32;
    info[off..off + 4].copy_from_slice(&purpose_index.to_le_bytes());
    off += 4;
    info[off..off + 4].copy_from_slice(&sub_index.to_le_bytes());
    off += 4;

    let hk = Hkdf::<Sha256>::new(None, entropy);
    let mut seed = [0u8; 32];
    // 32B OKM 对 HKDF-SHA256 恒成功；unwrap 安全
    hk.expand(&info[..off], &mut seed).unwrap();
    let rng = ChaCha20Rng::from_seed(seed); // from_seed 拷贝进内部状态
    seed.zeroize(); // 中间 seed 用后即清
    Ok(rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX_A: [u8; 32] = [1u8; 32];
    const CTX_B: [u8; 32] = [2u8; 32];

    fn entropy() -> [u8; 32] {
        let mut e = [0u8; 32];
        for (i, b) in e.iter_mut().enumerate() {
            *b = i as u8;
        }
        e
    }

    fn stream(rng: &mut ChaCha20Rng) -> [u8; 64] {
        let mut out = [0u8; 64];
        rng.fill_bytes(&mut out);
        out
    }

    /// 固定 (entropy, purpose, context) → 确定性输出（deterministic retry property）
    #[test]
    fn deterministic_same_inputs_same_stream() {
        let e = entropy();
        let x = stream(&mut purpose_rng(&e, RngPurpose::TxKey, &CTX_A).unwrap());
        let y = stream(&mut purpose_rng(&e, RngPurpose::TxKey, &CTX_A).unwrap());
        assert_eq!(x, y);
    }

    /// 不同 context（= 不同 tx construction data）→ 不同流（domain separation）
    #[test]
    fn different_context_different_stream() {
        let e = entropy();
        let x = stream(&mut purpose_rng(&e, RngPurpose::TxKey, &CTX_A).unwrap());
        let y = stream(&mut purpose_rng(&e, RngPurpose::TxKey, &CTX_B).unwrap());
        assert_ne!(x, y);
    }

    /// 不同 entropy → 不同流（不可预测性的根）
    #[test]
    fn different_entropy_different_stream() {
        let mut e = entropy();
        e[0] ^= 1;
        let x = stream(&mut purpose_rng(&entropy(), RngPurpose::TxKey, &CTX_A).unwrap());
        let y = stream(&mut purpose_rng(&e, RngPurpose::TxKey, &CTX_A).unwrap());
        assert_ne!(x, y);
    }

    /// purpose 子域相互独立（tx-key ≠ bp+ ≠ clsag(i)，含 clsag 索引区分）
    #[test]
    fn purposes_are_domain_separated() {
        let e = entropy();
        let mut streams = [
            stream(&mut purpose_rng(&e, RngPurpose::TxKey, &CTX_A).unwrap()),
            stream(&mut purpose_rng(&e, RngPurpose::BulletproofPlus, &CTX_A).unwrap()),
            stream(&mut purpose_rng(&e, RngPurpose::Clsag(0), &CTX_A).unwrap()),
            stream(&mut purpose_rng(&e, RngPurpose::Clsag(1), &CTX_A).unwrap()),
        ];
        for i in 0..4 {
            for j in i + 1..4 {
                assert_ne!(streams[i], streams[j], "purpose {} == purpose {}", i, j);
            }
        }
        let _ = &mut streams; // silence unused assign in release
    }

    /// misuse guard：<16B entropy 拒绝；16B 恰好通过
    #[test]
    fn short_entropy_rejected() {
        let e = [0u8; 15];
        assert_eq!(
            purpose_rng(&e, RngPurpose::TxKey, &CTX_A).unwrap_err(),
            RngSeedError::EntropyTooShort(15)
        );
        let e16 = [0u8; 16];
        assert!(purpose_rng(&e16, RngPurpose::TxKey, &CTX_A).is_ok());
    }

    /// RFC 5869 官方 Test Case 1 交叉验证 HKDF-SHA256 正确性
    /// （IKM=0x0b×22, salt=0x000102..., info=0xf0f1..., L=42）
    #[test]
    fn hkdf_rfc5869_test_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        let expect: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        assert_eq!(okm, expect);
    }
}
