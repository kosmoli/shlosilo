//! P0-01 audit remediation (2026-08-25): the dice entropy floor must be enforced at the create_account business entry point
//!
//! Audit finding: 12 d6 rolls (~31 bits) could successfully create a 12-word mnemonic, far below the 128-bit requirement.
//! Fix: the entry point compares rolls.len() against minimum_rolls(sides, entropy_bits).

use shlosilo::business::create_account::create_account;
use shlosilo::entropy::dice_rolls::minimum_rolls;
use shlosilo::entropy::mnemonic::WordCount;
use shlosilo::error::ShlosiloErrorKind;

/// 12 d6 rolls must be rejected (core regression for audit P0-01)
#[test]
fn p0_01_reject_12_d6_for_12_words() {
    let rolls = [3u8; 12];
    let mut mbuf = [0u8; 24];
    let result = create_account(WordCount::Words12, 6, &rolls, b"", &mut mbuf);
    let err = result.expect_err("31-bit entropy must be rejected");
    assert!(matches!(err.kind, ShlosiloErrorKind::DiceRollsInvalidCount));
}

/// Exactly minimum_rolls must succeed (boundary: 64 d6 rolls → 128 bits → 12 words)
#[test]
fn p0_01_accept_minimum_boundary() {
    let n = minimum_rolls(6, 128) as usize; // = 99? no: ceil(128/2)=64
    assert_eq!(n, 64);
    // 64 rolls ∈ [1,6]: use a deterministic sequence
    let rolls: heapless::Vec<u8, 128> = (0..n).map(|i| (i % 6) as u8 + 1).collect();
    let mut mbuf = [0u8; 24];
    let result = create_account(WordCount::Words12, 6, &rolls, b"", &mut mbuf);
    assert!(result.is_ok(), "exactly minimum_rolls must succeed");
}

/// One roll short must also be rejected (63 d6 rolls)
#[test]
fn p0_01_reject_below_minimum_by_one() {
    let n = minimum_rolls(6, 128) as usize - 1; // 63
    let rolls: heapless::Vec<u8, 128> = (0..n).map(|i| (i % 6) as u8 + 1).collect();
    let mut mbuf = [0u8; 24];
    let result = create_account(WordCount::Words12, 6, &rolls, b"", &mut mbuf);
    assert!(result.is_err());
}

/// 24 words need 256 bits → minimum_rolls(6,256)=128
#[test]
fn p0_01_24_words_requires_128_d6() {
    assert_eq!(minimum_rolls(6, 256), 128);
    // 127 rolls rejected
    let rolls: heapless::Vec<u8, 128> = (0..127).map(|i| (i % 6) as u8 + 1).collect();
    let mut mbuf = [0u8; 48];
    let result = create_account(WordCount::Words24, 6, &rolls, b"", &mut mbuf);
    assert!(result.is_err());
}
