//! Business 3: account creation (v2 §1.3 + v2.1.1 interface notes §5)
//!
//! **Phase 2.4 fake implementation**: calls the entropy submodule (dice_rolls::dice_rolls_to_entropy + bip39 stub)
//! to generate a stub mnemonic + stub seed written into the output buffer

use crate::entropy::dice_rolls;
use crate::entropy::mnemonic::WordCount;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// Account creation business entry point
///
/// **Phase 2.4 fake implementation flow**:
/// 1. `dice_rolls_to_entropy(sides, rolls, required_bytes)` → entropy bytes
/// 2. stub: generate a stub mnemonic (all u16 indices are 0)
/// 3. stub: bip39_passphrase::mnemonic_to_seed is not actually called (avoids panic)
/// 4. Write stub entropy to mnemonic_buf + stub seed to seed_out
///
/// **v2.4 security**: `passphrase: &[u8]` borrow.
pub fn create_account(
    word_count: WordCount,
    entropy_source_sides: u8,
    entropy_source_rolls: &[u8],
    _passphrase: &[u8], // P1-04: contract slot only (upper-bound validation at the FFI layer); no seed is produced so it is not consumed here
    mnemonic_buf: &mut [u8],
) -> Result<()> {
    let required_entropy_bytes = word_count.entropy_bytes();
    // P0-01 audit remediation: enforce a minimum dice-roll count at entry (12× d6 is only ~31 bits; the non-exhaustible floor is 128 bits)
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
    // X5 v2 (rejection sampling): no uniformity upper bound anymore — the more entropy above the minimum,
    // the lower the rejection probability and uniformity is strictly preserved. N < T (insufficient entropy) is decided by dice_rolls_to_entropy.

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
    for slot in &mut mnemonic_buf[needed..] {
        *slot = 0;
    }

    // P1-04: no seed output anymore (nothing crosses the FFI). The passphrase is kept as wallet metadata;
    // signing/export paths receive the mnemonic from the caller and restore it in the library on the spot.

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P0-01 audit remediation: 12× d6 (~31 bits) must be rejected — the original test asserted success, direction inverted
    #[test]
    fn create_account_rejects_insufficient_rolls_12_d6() {
        let rolls = [3u8, 5, 1, 6, 2, 4, 3, 5, 1, 6, 2, 4];
        let mut mnemonic_buf = [0u8; 64];
        let result = create_account(WordCount::Words12, 6, &rolls, b"", &mut mnemonic_buf);
        let err = result.expect_err("12 d6 = ~31 bit < 128 bit required");
        assert!(matches!(err.kind, ShlosiloErrorKind::DiceRollsInvalidCount));
    }

    #[test]
    fn create_account_invalid_sides() {
        let rolls = [1u8; 12];
        let mut mnemonic_buf = [0u8; 64];
        let result = create_account(
            WordCount::Words12,
            1, // sides < 2
            &rolls,
            b"",
            &mut mnemonic_buf,
        );
        assert!(result.is_err());
    }

    #[test]
    fn create_account_buffer_too_small() {
        let rolls = [3u8, 5, 1, 6];
        let mut mnemonic_buf = [0u8; 8]; // too small
        let result = create_account(
            WordCount::Words24, // needs 32 bytes of entropy
            6,
            &rolls,
            b"",
            &mut mnemonic_buf,
        );
        assert!(result.is_err());
    }
}
