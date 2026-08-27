//! 业务 3：账户创建（v2 §1.3 + v2.1.1 接口笔记 §5）
//!
//! **Phase 2.4 假实现**：调用 entropy 子模块（dice_rolls::dice_rolls_to_entropy + bip39 stub）
//! 生成 stub mnemonic + stub seed 写入 output buffer

use crate::entropy::dice_rolls;
use crate::entropy::mnemonic::WordCount;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// 账户创建业务入口
///
/// **Phase 2.4 假实现流程**：
/// 1. `dice_rolls_to_entropy(sides, rolls, required_bytes)` → entropy bytes
/// 2. stub: 生成 stub mnemonic（u16 索引都是 0）
/// 3. stub: bip39_passphrase::mnemonic_to_seed 不实际调用（避免 panic）
/// 4. 写 stub entropy 到 mnemonic_buf + stub seed 到 seed_out
///
/// **v2.4 安全**：`passphrase: &[u8]` borrow。
pub fn create_account(
    word_count: WordCount,
    entropy_source_sides: u8,
    entropy_source_rolls: &[u8],
    passphrase: &[u8],
    mnemonic_buf: &mut [u8],
    seed_out: &mut [u8; 64],
) -> Result<()> {
    let required_entropy_bytes = word_count.entropy_bytes() as usize;
    // P0-01 审计整改：入口强制最少骰子次数（12 次 d6 只有 ~31 bit，不可穷举下限 128 bit）
    if entropy_source_sides < 2 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::InvalidDiceConfig));
    }
    let required_bits = (required_entropy_bytes * 8) as u16;
    let min_rolls = dice_rolls::minimum_rolls(entropy_source_sides, required_bits) as usize;
    if entropy_source_rolls.len() < min_rolls {
        return Err(ShlosiloError::with_context(
            ShlosiloErrorKind::DiceRollsInvalidCount,
            crate::error::ErrorContext::RequiredLength(min_rolls),
        ));
    }

    // Step 1: dice rolls → entropy
    let entropy = dice_rolls::dice_rolls_to_entropy(
        entropy_source_sides,
        entropy_source_rolls,
        required_entropy_bytes,
    )?;

    let mnemonic = crate::entropy::mnemonic::Mnemonic::from_entropy(entropy.as_slice())?;
    let indices = mnemonic.indices();
    let needed = indices.len() * 2;
    if mnemonic_buf.len() < needed {
        return Err(ShlosiloError::with_context(
            ShlosiloErrorKind::BufferTooSmall,
            crate::error::ErrorContext::RequiredLength(needed),
        ));
    }
    for (i, &idx) in indices.iter().enumerate() {
        let b = idx.to_le_bytes();
        mnemonic_buf[i * 2] = b[0];
        mnemonic_buf[i * 2 + 1] = b[1];
    }
    for i in needed..mnemonic_buf.len() {
        mnemonic_buf[i] = 0;
    }

    let seed = crate::entropy::bip39_passphrase::mnemonic_to_seed(&mnemonic, passphrase)?;
    seed_out.copy_from_slice(seed.as_ref());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P0-01 审计整改：12 次 d6（~31 bit）必须被拒绝——原测试断言成功，方向反了
    #[test]
    fn create_account_rejects_insufficient_rolls_12_d6() {
        let rolls = [3u8, 5, 1, 6, 2, 4, 3, 5, 1, 6, 2, 4];
        let mut mnemonic_buf = [0u8; 64];
        let mut seed_out = [0u8; 64];
        let result = create_account(
            WordCount::Words12,
            6,
            &rolls,
            b"",
            &mut mnemonic_buf,
            &mut seed_out,
        );
        let err = result.expect_err("12 d6 = ~31 bit < 128 bit required");
        assert!(matches!(err.kind, ShlosiloErrorKind::DiceRollsInvalidCount));
    }

    #[test]
    fn create_account_invalid_sides() {
        let rolls = [1u8; 12];
        let mut mnemonic_buf = [0u8; 64];
        let mut seed_out = [0u8; 64];
        let result = create_account(
            WordCount::Words12,
            1,  // sides < 2
            &rolls,
            b"",
            &mut mnemonic_buf,
            &mut seed_out,
        );
        assert!(result.is_err());
    }

    #[test]
    fn create_account_buffer_too_small() {
        let rolls = [3u8, 5, 1, 6];
        let mut mnemonic_buf = [0u8; 8];  // 太小
        let mut seed_out = [0u8; 64];
        let result = create_account(
            WordCount::Words24,  // 需要 32 bytes entropy
            6,
            &rolls,
            b"",
            &mut mnemonic_buf,
            &mut seed_out,
        );
        assert!(result.is_err());
    }
}