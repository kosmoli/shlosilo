//! shlosilo L1 entropy module (v2 §2.x leaf node)
//!
//! **Phase 2.0**：mnemonic.rs（Mnemonic struct + WordCount enum）
//! **Phase 2.4 increments**:
//!   - source.rs（EntropySource enum，DiceRolls / HwRng / MnemonicRestore）
//!   - dice_rolls.rs (base-N accumulation + minimum_rolls pure function + bits_per_digit)
//!   - bip39_words.rs (2048-word table stub)
//!   - bip39_passphrase.rs（mnemonic + passphrase → 64-byte seed）
//!
//! **v2.4 security fix**: all functions take borrowed inputs, **business modules hold no owned copies**.

pub mod bip39_passphrase;
pub mod bip39_words;
pub mod dice_rolls;
pub mod mnemonic;
pub mod source;
