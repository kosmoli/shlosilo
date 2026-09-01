//! shlosilo L1 entropy 模块（v2 §2.x 叶子节点）
//!
//! **Phase 2.0**：mnemonic.rs（Mnemonic struct + WordCount enum）
//! **Phase 2.4 增量**：
//!   - source.rs（EntropySource enum，DiceRolls / HwRng / MnemonicRestore）
//!   - dice_rolls.rs（base-N 累乘 + minimum_rolls 纯函数 + bits_per_digit）
//!   - bip39_words.rs（2048 单词表 stub）
//!   - bip39_passphrase.rs（mnemonic + passphrase → 64-byte seed）
//!
//! **v2.4 安全修正**：所有函数接受 borrow 输入，**业务模块不持有 owned 副本**。

pub mod bip39_passphrase;
pub mod bip39_words;
pub mod dice_rolls;
pub mod mnemonic;
pub mod source;
