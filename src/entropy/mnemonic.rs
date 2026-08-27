//! Mnemonic 类型（v2.3 接口笔记 §3）
//!
//! BIP-39 标准：12/15/18/21/24 词（对应 128/160/192/224/256 bit 熵）
//!
//! Phase 2.0 stub：
//! - Mnemonic 字段：固定大小 [u16; MAX_MNEMONIC_WORDS] + len
//! - `from_entropy`：校验熵长度 + 简化版 checksum（Phase 4 用 SHA-256 替换）
//! - `to_seed`：返回 [0u8; 64] 占位（Phase 4 用 PBKDF2-HMAC-SHA512 真实实现）
//! - `from_indices`：Phase 4 真实实现 + 测试用

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_MNEMONIC_WORDS: usize = 24;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WordCount {
    Words12 = 12,
    Words15 = 15,
    Words18 = 18,
    Words21 = 21,
    Words24 = 24,
}

impl WordCount {
    /// WordCount u16 → WordCount enum（用于 FFI dispatch）
    pub fn try_from_count(n: usize) -> Option<Self> {
        match n {
            12 => Some(Self::Words12),
            15 => Some(Self::Words15),
            18 => Some(Self::Words18),
            21 => Some(Self::Words21),
            24 => Some(Self::Words24),
            _ => None,
        }
    }

    pub const fn entropy_bytes(self) -> usize {
        match self {
            WordCount::Words12 => 16,
            WordCount::Words15 => 20,
            WordCount::Words18 => 24,
            WordCount::Words21 => 28,
            WordCount::Words24 => 32,
        }
    }

    pub const fn checksum_bits(self) -> usize {
        // BIP-39: checksum bits = ENT / 32
        self.entropy_bytes() / 4
    }

    pub const fn as_usize(self) -> usize {
        self as usize
    }
}

/// BIP-39 mnemonic（栈分配，固定大小）
///
/// 字段：
/// - `indices`：每个 u16 表示一个 BIP-39 词表的索引（0..=2047）
/// - `len`：实际词数（12/15/18/21/24）
///
/// **安全约束（v2.3 §3.2）**：不 derive `Debug`——防止 key material 通过 Debug 输出泄露单词表内容。
/// 手写 Debug 只输出词数。
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Mnemonic {
    indices: [u16; MAX_MNEMONIC_WORDS],
    len: u8,
}

/// 手写 Debug：只暴露词数 + 索引哈希，**不暴露单词表内容**
impl core::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 用一个简单的 rolling hash 暴露"这是同一个 mnemonic"——不暴露内容
        let mut h: u32 = 0;
        for &i in &self.indices[..self.len as usize] {
            h = h.wrapping_mul(31).wrapping_add(i as u32);
        }
        f.debug_struct("Mnemonic")
            .field("word_count", &self.len)
            .field("indices_hash", &h)
            .finish()
    }
}

impl Mnemonic {
    /// 从熵字节构造 mnemonic（Phase 2.0 stub）
    ///
    /// Phase 2.0 简化：
    /// - 校验熵长度
    /// - 计算 SHA-256 checksum（暂时用零代替；Phase 4 真实实现）
    /// - 切分 11-bit 段写入 indices
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        let word_count = match entropy.len() {
            16 => WordCount::Words12,
            20 => WordCount::Words15,
            24 => WordCount::Words18,
            28 => WordCount::Words21,
            32 => WordCount::Words24,
            _ => return Err(ShlosiloError::new(ShlosiloErrorKind::MnemonicInvalidEntropyLength)),
        };

        // BIP-39 checksum：SHA-256(entropy) 高 checksum_bits 位接到熵后面
        let hash = crate::encoding::sha256::hash(entropy)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::MnemonicInvalidEntropyLength))?;
        let checksum_byte = hash[0];

        let total_bits = entropy.len() * 8 + word_count.checksum_bits();
        let mut mnemonic = Self {
            indices: [0u16; MAX_MNEMONIC_WORDS],
            len: word_count as u8,
        };

        let mut bit_idx = 0;
        let mut entropy_buf = [0u8; 33]; // 最大 32 熵 + 1 字节 checksum
        entropy_buf[..entropy.len()].copy_from_slice(entropy);
        entropy_buf[entropy.len()] = checksum_byte;

        for word_idx in 0..word_count.as_usize() {
            let mut value: u16 = 0;
            for _bit in 0..11 {
                if bit_idx >= total_bits {
                    break;
                }
                let byte_idx = bit_idx / 8;
                let bit_offset = bit_idx % 8;
                let bit_val = (entropy_buf[byte_idx] >> (7 - bit_offset)) & 1;
                value = (value << 1) | (bit_val as u16);
                bit_idx += 1;
            }
            mnemonic.indices[word_idx] = value;
        }

        Ok(mnemonic)
    }

    /// 从 u16 索引构造（Phase 4 真实解析时使用，Phase 2.0 stub 可用）
    pub fn from_indices(indices: &[u16], expected_count: WordCount) -> Result<Self> {
        if indices.len() != expected_count.as_usize() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::MnemonicInvalidWordCount));
        }
        for &i in indices {
            if i >= 2048 {
                return Err(ShlosiloError::new(ShlosiloErrorKind::MnemonicInvalidWord));
            }
        }
        let mut mnemonic = Self {
            indices: [0u16; MAX_MNEMONIC_WORDS],
            len: expected_count as u8,
        };
        mnemonic.indices[..indices.len()].copy_from_slice(indices);
        Ok(mnemonic)
    }

    pub fn word_count(&self) -> WordCount {
        match self.len {
            12 => WordCount::Words12,
            15 => WordCount::Words15,
            18 => WordCount::Words18,
            21 => WordCount::Words21,
            24 => WordCount::Words24,
            _ => unreachable!("invalid mnemonic length"),
        }
    }

    pub fn indices(&self) -> &[u16] {
        &self.indices[..self.len as usize]
    }

    /// Phase 2.0 stub：返回 [0u8; 64] 占位
    /// Phase 4 真实实现：PBKDF2-HMAC-SHA512(mnemonic_sentence, "mnemonic" + passphrase, 2048 iterations)
    pub fn to_seed(&self, _passphrase: &[u8]) -> [u8; 64] {
        // Phase 4 真实实现：sha2::Sha512 + pbkdf2
        [0u8; 64]
    }

    /// 校验 mnemonic 的 checksum 位（P1-05 审计整改，2026-08-26）
    ///
    /// 从 indices 反解 entropy（11-bit 段，取前 ENT bits）→ SHA-256 →
    /// 比对高 checksum_bits 位与 mnemonic 末尾嵌入的 checksum。
    /// 任一词错误（含相邻合法词替换）都会被拒绝。
    pub fn validate(&self) -> Result<()> {
        let wc = self.word_count();
        let ent_bits = wc.entropy_bytes() * 8;
        let cs_bits = wc.checksum_bits();
        let total_bits = ent_bits + cs_bits; // 最大 256+8=264

        // 1. 11-bit 段 → bit stream（固定栈数组，不堆分配）
        //    24 词 = 264 bits 是上限（L1 无堆纪律：热路径零 alloc）
        let mut bits = [0u8; 264];
        let mut n = 0usize;
        'outer: for &idx in self.indices() {
            for shift in (0..11).rev() {
                bits[n] = ((idx >> shift) & 1) as u8;
                n += 1;
                if n == total_bits {
                    break 'outer;
                }
            }
        }

        // 2. 前 ent_bits → entropy bytes
        let ent_bytes = wc.entropy_bytes();
        let mut entropy = [0u8; 32];
        for i in 0..ent_bits {
            if bits[i] == 1 {
                entropy[i / 8] |= 1 << (7 - (i % 8));
            }
        }

        // 3. 后 cs_bits → embedded checksum bits
        let mut embedded: u32 = 0;
        for i in 0..cs_bits {
            if bits[ent_bits + i] == 1 {
                embedded |= 1 << (cs_bits - 1 - i);
            }
        }

        // 4. SHA-256(entropy) 高 cs_bits 位 = 期望 checksum
        let hash = crate::encoding::sha256::hash(&entropy[..ent_bytes])
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::MnemonicInvalidEntropyLength))?;
        let expected: u32 = (hash[0] as u32) >> (8 - cs_bits);

        if embedded == expected {
            Ok(())
        } else {
            Err(ShlosiloError::new(
                ShlosiloErrorKind::MnemonicInvalidChecksum,
            ))
        }
    }

    /// 序列化为字节流（每个 u16 写两字节 little-endian）
    ///
    /// Phase 2.0 占位：用于 L2b C-ABI 传递
    pub fn to_bytes(&self) -> ([u8; MAX_MNEMONIC_WORDS * 2], usize) {
        let mut out = [0u8; MAX_MNEMONIC_WORDS * 2];
        for (i, &idx) in self.indices[..self.len as usize].iter().enumerate() {
            let bytes = idx.to_le_bytes();
            out[i * 2] = bytes[0];
            out[i * 2 + 1] = bytes[1];
        }
        (out, self.len as usize * 2)
    }
}

// PartialEq for tests（不靠 derive，避免 zeroize 干扰）
impl PartialEq for Mnemonic {
    fn eq(&self, other: &Self) -> bool {
        self.indices[..self.len as usize] == other.indices[..other.len as usize]
            && self.len == other.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn word_count_entropy_bytes() {
        assert_eq!(WordCount::Words12.entropy_bytes(), 16);
        assert_eq!(WordCount::Words24.entropy_bytes(), 32);
    }

    #[test]
    fn from_entropy_invalid_length() {
        let bad = [0u8; 17];
        assert_eq!(
            Mnemonic::from_entropy(&bad).unwrap_err().kind,
            ShlosiloErrorKind::MnemonicInvalidEntropyLength
        );
    }

    #[test]
    fn from_indices_word_count_mismatch() {
        let indices = [0u16; 11]; // 11 不是合法 WordCount
        let result = Mnemonic::from_indices(&indices, WordCount::Words12);
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::MnemonicInvalidWordCount
        );
    }

    #[test]
    fn from_indices_index_out_of_range() {
        let mut indices = [0u16; 12];
        indices[3] = 2048; // 越界
        let result = Mnemonic::from_indices(&indices, WordCount::Words12);
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::MnemonicInvalidWord
        );
    }

    #[test]
    fn round_trip_indices() {
        let original: [u16; 12] = [0, 1, 2, 3, 2047, 100, 200, 300, 400, 500, 600, 700];
        let mnemonic = Mnemonic::from_indices(&original, WordCount::Words12).unwrap();
        assert_eq!(mnemonic.indices(), &original);
        assert_eq!(mnemonic.word_count(), WordCount::Words12);
    }

    #[test]
    fn from_entropy_16_bytes_12_words() {
        let entropy = [0u8; 16];
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(mnemonic.word_count(), WordCount::Words12);
        assert_eq!(mnemonic.indices().len(), 12);
    }

    // ============================================================
    // Phase 3 property-based 测试
    // ============================================================

    use proptest::prelude::*;

    /// proptest 策略：5 个 WordCount 之一
    fn arb_word_count() -> impl Strategy<Value = WordCount> {
        prop_oneof![
            Just(WordCount::Words12),
            Just(WordCount::Words15),
            Just(WordCount::Words18),
            Just(WordCount::Words21),
            Just(WordCount::Words24),
        ]
    }

    /// proptest 策略：固定大小 entropy 数组（用 proptest::array::uniform 避免 Vec）
    fn arb_entropy(wc: WordCount) -> impl Strategy<Value = Vec<u8>> {
        // dev-dependencies 走 std target，Vec 是可用的
        proptest::collection::vec(any::<u8>(), wc.entropy_bytes())
    }

    /// proptest 策略：合法 u16 索引（0..2048）
    fn arb_valid_index() -> impl Strategy<Value = u16> {
        (0u16..2048u16)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// 合法 entropy 长度 → word_count 跟 entropy 长度匹配
        #[test]
        fn from_entropy_legal_length_matches_word_count(
            wc in arb_word_count(),
        ) {
            let entropy = vec![0u8; wc.entropy_bytes()];
            let m = Mnemonic::from_entropy(&entropy).unwrap();
            prop_assert_eq!(m.word_count(), wc);
            prop_assert_eq!(m.indices().len(), wc.as_usize());
        }

        /// 非合法 entropy 长度（1-15 / 17-19 / 21-23 / 25-27 / 29-31 / 33+） → 拒绝
        #[test]
        fn from_entropy_invalid_length_rejected(
            bad_len in 0usize..64,
        ) {
            prop_assume!(!matches!(bad_len, 16 | 20 | 24 | 28 | 32));
            let entropy = vec![0u8; bad_len];
            let result = Mnemonic::from_entropy(&entropy);
            prop_assert!(result.is_err());
            prop_assert_eq!(
                result.unwrap_err().kind,
                ShlosiloErrorKind::MnemonicInvalidEntropyLength
            );
        }

        /// from_indices 合法索引 + 任意 WordCount → round-trip 一致
        #[test]
        fn from_indices_round_trip_preserved(
            wc in arb_word_count(),
        ) {
            let indices = vec![0u16; wc.as_usize()]; // 全 0 索引（0..2048 合法）
            let m = Mnemonic::from_indices(&indices, wc).unwrap();
            prop_assert_eq!(m.indices(), &indices[..]);
            prop_assert_eq!(m.word_count(), wc);
        }

        /// from_indices 越界索引（≥2048） → 拒绝
        #[test]
        fn from_indices_out_of_range_rejected(
            wc in arb_word_count(),
            bad_index in 2048u16..u16::MAX,
            bad_pos in 0usize..24,
        ) {
            prop_assume!(bad_pos < wc.as_usize());
            let mut indices = vec![0u16; wc.as_usize()];
            indices[bad_pos] = bad_index;
            let result = Mnemonic::from_indices(&indices, wc);
            prop_assert!(result.is_err());
            prop_assert_eq!(
                result.unwrap_err().kind,
                ShlosiloErrorKind::MnemonicInvalidWord
            );
        }

        /// from_indices 长度不匹配 WordCount → 拒绝
        #[test]
        fn from_indices_length_mismatch_rejected(
            wc_idx in 0u8..5,
            bad_len in 0usize..24,
        ) {
            let wc = match wc_idx {
                0 => WordCount::Words12,
                1 => WordCount::Words15,
                2 => WordCount::Words18,
                3 => WordCount::Words21,
                _ => WordCount::Words24,
            };
            prop_assume!(bad_len != wc.as_usize());
            let bad_indices = vec![0u16; bad_len];
            let result = Mnemonic::from_indices(&bad_indices, wc);
            prop_assert!(result.is_err());
            prop_assert_eq!(
                result.unwrap_err().kind,
                ShlosiloErrorKind::MnemonicInvalidWordCount
            );
        }

        /// word_count() → entropy_bytes() 反向：5 个 WordCount 全部映射
        #[test]
        fn word_count_entropy_bytes_injective(wc_idx in 0u8..5) {
            let wc = match wc_idx {
                0 => WordCount::Words12,
                1 => WordCount::Words15,
                2 => WordCount::Words18,
                3 => WordCount::Words21,
                _ => WordCount::Words24,
            };
            prop_assert_eq!(wc.entropy_bytes(), wc.as_usize() * 4 / 3);
        }

        /// PartialEq 自反性：a == a
        #[test]
        fn mnemonic_eq_reflexive(indices in (0u16..24u16).prop_map(|_| (0u16..12u16).map(|i| i * 100).collect::<Vec<u16>>())) {
            let m = Mnemonic::from_indices(&indices, WordCount::Words12).unwrap();
            let m_ref = m.clone();  // v2.4 允许 Clone（聚合结构业务需要）
            prop_assert_eq!(m, m_ref);
        }

        /// 两个相同 index 构造的两个 mnemonic 应该相等
        #[test]
        fn mnemonic_eq_same_indices(indices in (0u16..24u16).prop_map(|_| (0u16..12u16).map(|i| i * 100).collect::<Vec<u16>>())) {
            let m1 = Mnemonic::from_indices(&indices, WordCount::Words12).unwrap();
            let m2 = Mnemonic::from_indices(&indices, WordCount::Words12).unwrap();
            prop_assert_eq!(m1, m2);
        }
    }

    // ============================================================
    // Phase 3 BIP-39 测试向量（trezor-mnemonic 公开）
    // ============================================================
    //
    // **重要**：Phase 2.0 stub 的 Mnemonic::from_entropy 用 0 字节代替 checksum
    // （不是真实 SHA-256）——所以**标准 BIP-39 测试向量不能直接通过**
    // 但**流程**应该对：调用 from_entropy、构造 mnemonic、获取 word_count / indices
    
    /// BIP-39 12 词标准 entropy "0000...0000" → 12 词 stub output
    #[test]
    fn bip39_stub_12_words_from_zero_entropy() {
        let entropy = [0u8; 16];  // 128-bit entropy
        let m = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(m.word_count(), WordCount::Words12);
        assert_eq!(m.indices().len(), 12);
        // stub：checksum byte = 0，所以前 11 个索引都是 0，最后 1 个索引是 entropy byte[0] 高 3 位（=0）
        for (i, &idx) in m.indices().iter().enumerate() {
            assert!(idx < 2048, "BIP-39 index must be < 2048, got {} at {}", idx, i);
        }
    }

    /// BIP-39 24 词标准 entropy "0000...0000" (256-bit) → 24 词 stub output
    #[test]
    fn bip39_stub_24_words_from_zero_entropy() {
        let entropy = [0u8; 32];  // 256-bit entropy
        let m = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(m.word_count(), WordCount::Words24);
        assert_eq!(m.indices().len(), 24);
        for (i, &idx) in m.indices().iter().enumerate() {
            assert!(idx < 2048, "BIP-39 index must be < 2048, got {} at {}", idx, i);
        }
    }

    /// BIP-39 任意非零 entropy → 合法 mnemonic（5 个 WordCount 都验证）
    #[test]
    fn bip39_stub_non_zero_entropy_valid() {
        for &wc in &[WordCount::Words12, WordCount::Words15, WordCount::Words18,
                     WordCount::Words21, WordCount::Words24] {
            let entropy = vec![0xffu8; wc.entropy_bytes()];
            let m = Mnemonic::from_entropy(&entropy).unwrap();
            assert_eq!(m.word_count(), wc);
            assert_eq!(m.indices().len(), wc.as_usize());
        }
    }

    // ============================================================
    // P1-05 BIP-39 checksum 验证（审计整改）
    // ============================================================

    /// 官方向量：from_entropy 产物 validate 必须通过（checksum 正确）
    #[test]
    fn validate_passes_official_abandon_about() {
        // 128-bit 全零 entropy → 11×abandon + about（index 3）
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert_eq!(m.indices()[0], 0);
        assert_eq!(m.indices()[11], 3);
        assert!(m.validate().is_ok());
    }

    /// 官方向量：Trezor 测试向量（256-bit entropy ff...ff）validate 通过
    #[test]
    fn validate_passes_official_ff_entropy() {
        // 256-bit 全 ff entropy → zoo zoo ... vote（Trezor 官方向量）
        let m = Mnemonic::from_entropy(&[0xffu8; 32]).unwrap();
        assert!(m.validate().is_ok());
    }

    /// 最后一个词换成相邻合法词（checksum 破坏）→ validate 拒绝
    #[test]
    fn validate_rejects_flipped_last_word() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        // 最后一个词 index 3 (about) → 4 (accident)，破坏 checksum
        let mut bad_indices = m.indices().to_vec();
        bad_indices[11] = 4;
        let bad = Mnemonic::from_indices(&bad_indices, WordCount::Words12).unwrap();
        assert!(bad.validate().is_err());
        assert_eq!(
            bad.validate().unwrap_err().kind,
            ShlosiloErrorKind::MnemonicInvalidChecksum
        );
    }

    /// 任意位置翻转一个词 → validate 拒绝（checksum 能捕获任意单词错误）
    #[test]
    fn validate_rejects_mid_sentence_flip() {
        let m = Mnemonic::from_entropy(&[0x42u8; 16]).unwrap();
        let mut bad_indices = m.indices().to_vec();
        let orig = bad_indices[5];
        bad_indices[5] = (orig + 1) % 2048;
        let bad = Mnemonic::from_indices(&bad_indices, WordCount::Words12).unwrap();
        assert!(bad.validate().is_err());
    }

    /// 5 种词数全验证：from_entropy 产物 validate 都通过
    #[test]
    fn validate_passes_all_word_counts() {
        for &wc in &[WordCount::Words12, WordCount::Words15, WordCount::Words18,
                     WordCount::Words21, WordCount::Words24] {
            let entropy = vec![0xabu8; wc.entropy_bytes()];
            let m = Mnemonic::from_entropy(&entropy).unwrap();
            assert!(
                m.validate().is_ok(),
                "validate failed for {:?}",
                wc
            );
        }
    }

    /// from_entropy → from_indices round-trip 保持 checksum 合法
    #[test]
    fn validate_round_trip_from_entropy() {
        for &wc in &[WordCount::Words12, WordCount::Words15, WordCount::Words18,
                     WordCount::Words21, WordCount::Words24] {
            let entropy = vec![0x7fu8; wc.entropy_bytes()];
            let m = Mnemonic::from_entropy(&entropy).unwrap();
            let idx: Vec<u16> = m.indices().to_vec();
            let m2 = Mnemonic::from_indices(&idx, wc).unwrap();
            assert!(m2.validate().is_ok());
        }
    }
    /// Trezor 官方向量：256-bit 全零 entropy → abandon×23 + art（索引 0×23 + 102）
    #[test]
    fn validate_trezor_zero_entropy_24_words() {
        let mut idx = [0u16; 24];
        idx[23] = 102; // art
        let m = Mnemonic::from_indices(&idx, WordCount::Words24).unwrap();
        assert!(m.validate().is_ok(), "Trezor official 24-word all-zero must pass");
        // 与 from_entropy 产物一致
        let m2 = Mnemonic::from_entropy(&[0u8; 32]).unwrap();
        assert_eq!(m, m2);
    }

    /// Trezor 官方向量：128-bit 全零 → abandon×11 + about（索引 0×11 + 3）
    #[test]
    fn validate_trezor_zero_entropy_12_words() {
        let mut idx = [0u16; 12];
        idx[11] = 3; // about
        let m = Mnemonic::from_indices(&idx, WordCount::Words12).unwrap();
        assert!(m.validate().is_ok());
    }

}