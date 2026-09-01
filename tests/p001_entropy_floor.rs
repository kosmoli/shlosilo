//! P0-01 审计整改（2026-08-25）：骰子熵下限必须在 create_account 业务入口强制执行
//!
//! 审计发现：12 次 d6（~31 bit）可成功创建 12 词助记词，远低于 128 bit 要求。
//! 修复：入口比较 rolls.len() 与 minimum_rolls(sides, entropy_bits)。

use shlosilo::business::create_account::create_account;
use shlosilo::entropy::dice_rolls::minimum_rolls;
use shlosilo::entropy::mnemonic::WordCount;
use shlosilo::error::ShlosiloErrorKind;

/// 12 次 d6 必须被拒绝（审计 P0-01 核心回归）
#[test]
fn p0_01_reject_12_d6_for_12_words() {
    let rolls = [3u8; 12];
    let mut mbuf = [0u8; 24];
    let result = create_account(WordCount::Words12, 6, &rolls, b"", &mut mbuf);
    let err = result.expect_err("31-bit entropy must be rejected");
    assert!(matches!(err.kind, ShlosiloErrorKind::DiceRollsInvalidCount));
}

/// 恰好 minimum_rolls 次必须成功（边界：64 次 d6 → 128 bit → 12 词）
#[test]
fn p0_01_accept_minimum_boundary() {
    let n = minimum_rolls(6, 128) as usize; // = 99? no: ceil(128/2)=64
    assert_eq!(n, 64);
    // 64 rolls ∈ [1,6]：用确定性序列
    let rolls: heapless::Vec<u8, 128> = (0..n).map(|i| (i % 6) as u8 + 1).collect();
    let mut mbuf = [0u8; 24];
    let result = create_account(WordCount::Words12, 6, &rolls, b"", &mut mbuf);
    assert!(result.is_ok(), "exactly minimum_rolls must succeed");
}

/// 差一次也必须拒绝（63 次 d6）
#[test]
fn p0_01_reject_below_minimum_by_one() {
    let n = minimum_rolls(6, 128) as usize - 1; // 63
    let rolls: heapless::Vec<u8, 128> = (0..n).map(|i| (i % 6) as u8 + 1).collect();
    let mut mbuf = [0u8; 24];
    let result = create_account(WordCount::Words12, 6, &rolls, b"", &mut mbuf);
    assert!(result.is_err());
}

/// 24 词需要 256 bit → minimum_rolls(6,256)=128
#[test]
fn p0_01_24_words_requires_128_d6() {
    assert_eq!(minimum_rolls(6, 256), 128);
    // 127 次拒绝
    let rolls: heapless::Vec<u8, 128> = (0..127).map(|i| (i % 6) as u8 + 1).collect();
    let mut mbuf = [0u8; 48];
    let result = create_account(WordCount::Words24, 6, &rolls, b"", &mut mbuf);
    assert!(result.is_err());
}
