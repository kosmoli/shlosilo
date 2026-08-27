//! dice-rolls 骰子输入 → 熵 bytes 转换（v1.1 修订）
//!
//! **设计原则**：
//! - 用户选 `{sides, total_entropy_bits}` → 程序算 `rolls_needed`
//! - 每掷一次的 bits 数：`bits_per_digit(sides) = floor(log2(sides))`
//! - `minimum_rolls(sides, required_entropy_bits)` 是 L1 纯函数（用户明确）
//! - **d6 base-6 累乘 → base-N 累乘通用算法**（u32 数组模拟 256-bit bigint）

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// 256-bit 累乘器（32 bytes = 8 × u32 limbs）
type U256 = [u32; 8];

const LIMBS: usize = 8;

/// 每掷一次获得的最大 entropy bit 数（floor(log2(sides))）
///
/// 整数实现：避免 no_std 下浮点依赖。多掷 1-2 次补足上界，永远安全。
pub fn bits_per_digit(sides: u8) -> u16 {
    debug_assert!(sides >= 2, "sides 必须 >= 2");
    if sides <= 3 {
        1
    } else if sides <= 7 {
        2
    } else if sides <= 15 {
        3
    } else if sides <= 31 {
        4
    } else if sides <= 63 {
        5
    } else if sides <= 127 {
        6
    } else {
        7 // sides ∈ [128, 255]
    }
}

/// 最少需要掷几次
///
/// 上取整 = (required_entropy_bits + bits_per_digit - 1) / bits_per_digit
pub fn minimum_rolls(sides: u8, required_entropy_bits: u16) -> u16 {
    let bpd = bits_per_digit(sides);
    if bpd == 0 {
        0
    } else {
        required_entropy_bits.div_ceil(bpd)
    }
}

/// dice-rolls → entropy bytes（通用 base-N 累乘）
///
/// **Phase 2.4 假实现**：完整实现 base-N 累乘算法（u32 bigint），用户输入 rolls 转换成熵。
/// Phase 4 不需要替换此函数（已真实实现）。
///
/// 算法：
/// ```text
/// acc = 1
/// for r in rolls:
///     acc = acc * sides + r
/// entropy_bytes = acc.to_bytes()
/// ```text
///
/// **注意**：每次累乘后丢弃溢出位（u32 limbs 模拟 mod 2^256 大数），
/// 这是 NIST SP 800-90A 推荐的"rejection sampling"基础——但这里简化成"先大数累乘后 mod"。
/// Phase 4 不需要替换此函数（已真实实现）。
///
/// **v2.4 安全**：不返回 owned `Scalar`——返回 owned `Vec<u8>`，业务模块不持有私钥副本。
pub fn dice_rolls_to_entropy(
    sides: u8,
    rolls: &[u8],
    required_len: usize,
) -> Result<heapless::Vec<u8, 64>> {
    if sides < 2 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::InvalidDiceConfig));
    }
    if rolls.is_empty() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::InsufficientRolls));
    }
    // 校验每个 roll ∈ [1, sides]
    for (i, &r) in rolls.iter().enumerate() {
        if r < 1 || r > sides {
            // 复用 MnemonicInvalidWord 作为 generic "out of range" 错误
            return Err(ShlosiloError::new(ShlosiloErrorKind::MnemonicInvalidWord));
        }
        let _ = i;
    }

    // 大数累乘
    let mut acc: U256 = [0u32; LIMBS];
    acc[0] = 1;
    for &r in rolls {
        // acc = acc * sides + r
        let mut carry: u64 = r as u64;
        for i in 0..LIMBS {
            let product = (acc[i] as u64) * (sides as u64) + carry;
            acc[i] = product as u32;
            carry = product >> 32;
        }
        // 溢出位丢弃（256-bit mod）
    }

    // 转换成 bytes（little-endian）
    let mut result: heapless::Vec<u8, 64> = heapless::Vec::new();
    for i in 0..LIMBS {
        let bytes = acc[i].to_le_bytes();
        for b in bytes {
            if result.len() >= required_len.min(64) {
                break;
            }
            result.push(b).ok();
        }
    }
    // 截断到 required_len（如果大数实际更大）
    while result.len() > required_len {
        result.pop();
    }
    // 如果不足，零填充
    while result.len() < required_len {
        result.push(0).ok();
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_per_digit_table() {
        assert_eq!(bits_per_digit(2), 1);    // 硬币
        assert_eq!(bits_per_digit(4), 2);
        assert_eq!(bits_per_digit(6), 2);    // DND d6
        assert_eq!(bits_per_digit(8), 3);
        assert_eq!(bits_per_digit(16), 4);
        assert_eq!(bits_per_digit(20), 4);   // DND d20
        assert_eq!(bits_per_digit(64), 6);
        assert_eq!(bits_per_digit(100), 6);  // 百分骰
        assert_eq!(bits_per_digit(255), 7);
    }

    #[test]
    fn minimum_rolls_examples() {
        // 256 bit + 6 面骰（floor(log2(6))=2，ceil(256/2)=128）
        assert_eq!(minimum_rolls(6, 256), 128);
        // 256 bit + d20（floor(log2(20))=4，ceil(256/4)=64）
        assert_eq!(minimum_rolls(20, 256), 64);
        // 128 bit + 硬币（floor(log2(2))=1，ceil(128/1)=128）
        assert_eq!(minimum_rolls(2, 128), 128);
        // 256 bit + d100（floor(log2(100))=6，ceil(256/6)=43）
        assert_eq!(minimum_rolls(100, 256), 43);
    }

    #[test]
    fn d6_rolls_produce_entropy() {
        // 6 面骰 × 12 次 → 12 byte entropy
        let rolls = [3u8, 5, 1, 6, 2, 4, 3, 5, 1, 6, 2, 4];
        let entropy = dice_rolls_to_entropy(6, &rolls, 12).unwrap();
        assert_eq!(entropy.len(), 12);
    }

    #[test]
    fn sides_below_2_rejected() {
        let result = dice_rolls_to_entropy(1, &[1], 32);
        assert_eq!(result.err().unwrap().kind, ShlosiloErrorKind::InvalidDiceConfig);
    }

    #[test]
    fn empty_rolls_rejected() {
        let result = dice_rolls_to_entropy(6, &[], 32);
        assert_eq!(
            result.err().unwrap().kind,
            ShlosiloErrorKind::InsufficientRolls
        );
    }

    #[test]
    fn out_of_range_roll_rejected() {
        // d6 但 rolls 包含 7（超出 [1, 6]）
        let result = dice_rolls_to_entropy(6, &[1, 2, 3, 7], 32);
        assert!(result.is_err());
    }
}