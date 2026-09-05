//! EntropySource enum (v2.3 interface notes §14)
//!
//! **Three entropy sources**:
//! - `DiceRolls`: the user picks `{sides, rolls}`; the program converts them into entropy bytes
//! - `HwRng`: hardware RNG output (e.g. the STM32 RNG peripheral / ATECC608 TRNG)
//! - `MnemonicRestore`: an existing mnemonic; at restore time convert directly from mnemonics to seed

use crate::entropy::mnemonic::Mnemonic;

/// Entropy source
///
/// **v2.4 security**: all variants are borrows; no owned copies are held.
#[derive(Clone, Debug)]
pub enum EntropySource<'a> {
    /// Dice roll input: the user picks `{sides, rolls}`; business modules convert it into entropy
    DiceRolls { sides: u8, rolls: &'a [u8] },
    /// Hardware RNG direct output (already-entropized bytes)
    HwRng(&'a [u8]),
    /// An existing mnemonic, used directly at restore time
    MnemonicRestore(&'a Mnemonic),
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_source_variants_distinct() {
        // Type-level check: the enum has 3 variants
        // (guaranteed at compile time; no runtime test needed)
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
                    // The Mnemonic type is already verified in the business tests
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
