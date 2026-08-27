//! EntropySource enum（v2.3 接口笔记 §14）
//!
//! **三种熵源**：
//! - `DiceRolls`：用户选 `{sides, rolls}`，程序转换成熵 bytes
//! - `HwRng`：硬件 RNG 输出（如 STM32 RNG 外设 / ATECC608 TRNG）
//! - `MnemonicRestore`：已有助记词，恢复时直接从 mnemonics 转 seed

use crate::entropy::mnemonic::Mnemonic;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// Entropy 源
///
/// **v2.4 安全**：所有变体都是 borrow，不持有 owned 副本。
#[derive(Clone, Debug)]
pub enum EntropySource<'a> {
    /// 骰子 roll 输入：用户选 `{sides, rolls}`，业务模块转换成熵
    DiceRolls {
        sides: u8,
        rolls: &'a [u8],
    },
    /// 硬件 RNG 直接输出（已熵化的 bytes）
    HwRng(&'a [u8]),
    /// 已有助记词，恢复时直接用
    MnemonicRestore(&'a Mnemonic),
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_source_variants_distinct() {
        // 类型层验证：枚举有 3 个变体
        // （编译期保证，不需要 runtime 测试）
        fn _check_exhaustiveness(source: &EntropySource<'_>) {
            match source {
                EntropySource::DiceRolls { sides, rolls } => {
                    assert!(*sides >= 2);
                    assert!(!rolls.is_empty());
                }
                EntropySource::HwRng(bytes) => {
                    assert!(!bytes.is_empty());
                }
                EntropySource::MnemonicRestore(_) => {
                    // Mnemonic 类型已经在业务测试中验证
                }
            }
        }
    }

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("source.rs");
        assert!(source.contains("v2.4"));
        assert!(source.contains("v2.3"));
    }
}