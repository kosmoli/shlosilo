//! DerivationPath 类型（v2.3 接口笔记 §2）
//!
//! BIP-32 派生路径内部表示：
//! - 每个 component 是 32-bit unsigned integer，高位 0x80000000 表示 hardened
//! - 不可变，构造后只读；修改通过创建新 `DerivationPath`
//! - 栈分配，固定 [DerivationIndex; MAX_DEPTH]
//! - parse API：从 `&str`（"m/44'/0'/0'/0/0"）解析

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

pub const MAX_DEPTH: usize = 16; // BIP-44 通常 ≤ 5；预留到 16（兼容 Cardano Shelley 等多段路径）

/// BIP-32 hardened bit（最高位）
pub const HARDENED_BIT: u32 = 0x8000_0000;

/// Soft index 上限（无符号 31-bit）
pub const MAX_SOFT_INDEX: u32 = 0x7FFF_FFFF;

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DerivationIndex(pub u32);

impl DerivationIndex {
    pub const fn hardened(value: u32) -> Self {
        debug_assert!(value <= MAX_SOFT_INDEX, "hardened value out of range");
        Self(value | HARDENED_BIT)
    }

    pub const fn soft(value: u32) -> Self {
        debug_assert!(value <= MAX_SOFT_INDEX, "soft value out of range");
        Self(value)
    }

    pub const fn is_hardened(self) -> bool {
        (self.0 & HARDENED_BIT) != 0
    }

    pub const fn value(self) -> u32 {
        self.0 & !HARDENED_BIT
    }

    pub fn fmt_append(self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_hardened() {
            write!(f, "{}'", self.value())
        } else {
            write!(f, "{}", self.value())
        }
    }
}

impl core::fmt::Debug for DerivationIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.fmt_append(f)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DerivationPath {
    indices: [DerivationIndex; MAX_DEPTH],
    len: u8,
}

impl DerivationPath {
    pub const fn empty() -> Self {
        Self {
            indices: [DerivationIndex(0); MAX_DEPTH],
            len: 0,
        }
    }

    /// 从 `&[DerivationIndex]` 切片构造
    /// 从 `&[u32]` flat 数组构造（hardened bit 由最高位 0x80000000 表示）
    pub fn from_flat<I>(iter: I) -> Result<Self>
    where
        I: IntoIterator<Item = u32>,
    {
        let mut indices = [DerivationIndex(0); MAX_DEPTH];
        let mut len: u8 = 0;
        for n in iter.into_iter() {
            if (len as usize) >= MAX_DEPTH {
                return Err(ShlosiloError::new(ShlosiloErrorKind::DerivationPathInvalidSyntax));
            }
            indices[len as usize] = DerivationIndex(n);
            len += 1;
        }
        Ok(Self { indices, len })
    }

pub fn from_indices(indices: &[DerivationIndex]) -> Result<Self> {
        if indices.len() > MAX_DEPTH {
            return Err(ShlosiloError::new(ShlosiloErrorKind::DerivationPathInvalidSyntax));
        }
        let mut path = Self::empty();
        let mut i = 0;
        while i < indices.len() {
            path.indices[i] = indices[i];
            i += 1;
        }
        path.len = indices.len() as u8;
        Ok(path)
    }

    /// 从字符串解析（支持 m/M 前缀 + / 分隔 + ' 或 h/H hardened 后缀）
    ///
    /// 接受格式：
    /// - `"m"` / `"M"`（空路径）
    /// - `"m/44'/0'/0'/0/0"` / `"M/44H/0H/0H/0/0"`
    /// - `"m/44h/0h/0h/0/0"`
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let rest = if s.starts_with("m/") || s.starts_with("M/") {
            &s[2..]
        } else if s == "m" || s == "M" {
            return Ok(Self::empty());
        } else {
            return Err(ShlosiloError::new(ShlosiloErrorKind::DerivationPathInvalidSyntax));
        };

        if rest.is_empty() {
            return Ok(Self::empty());
        }

        let mut indices = [DerivationIndex(0); MAX_DEPTH];
        let mut len: usize = 0;

        for component in rest.split('/') {
            if len >= MAX_DEPTH {
                return Err(ShlosiloError::new(ShlosiloErrorKind::DerivationPathInvalidSyntax));
            }

            let (num_str, hardened) = if let Some(stripped) = component.strip_suffix('\'') {
                (stripped, true)
            } else if let Some(stripped) = component.strip_suffix('h') {
                (stripped, true)
            } else if let Some(stripped) = component.strip_suffix('H') {
                (stripped, true)
            } else {
                (component, false)
            };

            let value = parse_u32_decimal(num_str).ok_or_else(|| {
                ShlosiloError::new(ShlosiloErrorKind::DerivationPathInvalidSyntax)
            })?;
            if value > MAX_SOFT_INDEX {
                return Err(ShlosiloError::new(ShlosiloErrorKind::DerivationPathIndexOutOfRange));
            }

            indices[len] = if hardened {
                DerivationIndex::hardened(value)
            } else {
                DerivationIndex::soft(value)
            };
            len += 1;
        }

        let mut path = Self::empty();
        path.indices[..len].copy_from_slice(&indices[..len]);
        path.len = len as u8;
        Ok(path)
    }

    pub fn as_slice(&self) -> &[DerivationIndex] {
        &self.indices[..self.len as usize]
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 用于 ChainKind 推断（链类型 → coin_type）
    pub fn coin_type(&self) -> Option<u32> {
        self.as_slice().get(1).map(|i| i.value()) // m/<coin_type>/...
    }
}

/// 解析十进制 u32（不接受负号、十六进制、八进制）
fn parse_u32_decimal(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let mut result: u32 = 0;
    for c in s.chars() {
        if !c.is_ascii_digit() {
            return None;
        }
        let digit = c as u32 - '0' as u32;
        // 检查溢出
        match result.checked_mul(10).and_then(|v| v.checked_add(digit)) {
            Some(v) => result = v,
            None => return None,
        }
    }
    Some(result)
}

impl core::fmt::Debug for DerivationPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "m")?;
        for i in self.as_slice() {
            write!(f, "/")?;
            i.fmt_append(f)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    extern crate alloc;
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec::Vec;

    #[test]
    fn parse_simple_path() {
        let path = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(path.len(), 5);
        assert_eq!(path.as_slice()[0], DerivationIndex::hardened(44));
        assert_eq!(path.as_slice()[1], DerivationIndex::hardened(0));
        assert_eq!(path.as_slice()[2], DerivationIndex::hardened(0));
        assert_eq!(path.as_slice()[3], DerivationIndex::soft(0));
        assert_eq!(path.as_slice()[4], DerivationIndex::soft(0));
    }

    #[test]
    fn parse_h_suffix() {
        let path = DerivationPath::parse("M/44h/0h/0h/0/0").unwrap();
        assert_eq!(path.len(), 5);
        assert!(path.as_slice()[0].is_hardened());
    }

    #[test]
    fn parse_empty() {
        let path = DerivationPath::parse("m").unwrap();
        assert_eq!(path.len(), 0);
        assert!(path.is_empty());
    }

    #[test]
    fn parse_no_prefix_error() {
        let path = DerivationPath::parse("44'/0'/0'/0/0");
        assert!(path.is_err());
    }

    #[test]
    fn parse_negative_error() {
        let path = DerivationPath::parse("m/-1/0");
        assert!(path.is_err());
    }

    #[test]
    fn parse_overflow_error() {
        // 2^31 越界（soft index 上限是 2^31-1）
        let path = DerivationPath::parse("m/2147483648");
        assert_eq!(
            path.unwrap_err().kind,
            ShlosiloErrorKind::DerivationPathIndexOutOfRange
        );
    }

    #[test]
    fn coin_type_extraction() {
        let path = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(path.coin_type(), Some(0)); // BTC coin_type = 0

        let eth_path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(eth_path.coin_type(), Some(60)); // ETH coin_type = 60
    }

    #[test]
    fn depth_limit() {
        // MAX_DEPTH = 16，超过 16 层应报错
        let s = "m/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0"; // 17 个 component
        let path = DerivationPath::parse(s);
        assert!(path.is_err());
    }

    #[test]
    fn display_round_trip() {
        use core::fmt::Write;
        let original = "m/44'/0'/0'/0/0";
        let path = DerivationPath::parse(original).unwrap();
        let mut s = heapless::String::<64>::new();
        write!(s, "{:?}", path).unwrap();
        assert_eq!(s.as_str(), original);
    }

    // ============================================================
    // Phase 3 property-based 测试
    // ============================================================

    proptest! {
    /// 任意 dummy 参数（proptest! 要求所有 fn 都有 in 模式）
    #[test]
    fn parse_empty_path_is_valid(_dummy in 0u8..1) {
        let path = DerivationPath::parse("m").unwrap();
        prop_assert_eq!(path.len(), 0);
    }

    /// hardened index "i'" → 高位 0x80000000
    #[test]
    fn parse_hardened_sets_high_bit(idx in 0u32..16) {
        let path_str = format!("m/{}'", idx);
        let path = DerivationPath::parse(&path_str).unwrap();
        prop_assert_eq!(path.len(), 1);
        let first = &path.as_slice()[0];
        prop_assert_eq!(first.0 & 0x80000000, 0x80000000);
        prop_assert_eq!(first.0 & 0x7FFFFFFF, idx);
    }

    /// 正常 index "i" → 高位 0
    #[test]
    fn parse_normal_no_high_bit(idx in 0u32..16) {
        let path_str = format!("m/{}", idx);
        let path = DerivationPath::parse(&path_str).unwrap();
        prop_assert_eq!(path.len(), 1);
        prop_assert_eq!(path.as_slice()[0].0 & 0x80000000, 0);
        prop_assert_eq!(path.as_slice()[0].0, idx);
    }

    /// parse → render → 字符串一致（Phase 3 v2 补全）
    #[test]
    fn parse_display_round_trip(components in proptest::collection::vec(0u32..32u32, 1..8)) {
        let path_str = format!(
            "m/{}",
            components
                .iter()
                .map(|&i| {
                    if i & 0x80000000 != 0 {
                        format!("{}'", i & 0x7FFFFFFF)
                    } else {
                        i.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("/")
        );

        let path = DerivationPath::parse(&path_str).unwrap();
        prop_assert_eq!(path.len() as usize, components.len());

        let mut rendered = heapless::String::<128>::new();
        use core::fmt::Write;
        write!(rendered, "{:?}", path).unwrap();
        prop_assert_eq!(rendered.as_str(), path_str);
    }
    fn from_flat_round_trip(components in proptest::collection::vec(0u32..32u32, 1..8)) {
        let path = DerivationPath::from_flat(components.iter().copied()).unwrap();
        prop_assert_eq!(path.len(), components.len());
        for (i, &c) in components.iter().enumerate() {
            prop_assert_eq!(path.as_slice()[i].0, c);
        }
    }

    /// 全 0 索引路径 → 渲染成 "m/0/0/.../0" 一致（v3 边界）
    #[test]
    fn all_zero_indices_round_trip(_dummy in 0u8..1) {
        let path_str = format!("m/{}", (0..5).map(|_| "0").collect::<Vec<_>>().join("/"));

        let path = DerivationPath::parse(&path_str).unwrap();
        prop_assert_eq!(path.len(), 5);
        for i in 0..5 {
            prop_assert_eq!(path.as_slice()[i].0, 0);
            prop_assert_eq!(path.as_slice()[i].is_hardened(), false);
        }

        let mut rendered = heapless::String::<128>::new();
        use core::fmt::Write;
        write!(rendered, "{:?}", path).unwrap();
        prop_assert_eq!(rendered.as_str(), path_str);
    }

    /// MAX_DEPTH=16 路径 → 恰好能 parse + render（v3 边界）
    #[test]
    fn max_depth_path_round_trip(_dummy in 0u8..1) {
        let path_str = format!("m/{}", (0..16).map(|_| "0").collect::<Vec<_>>().join("/"));

        let path = DerivationPath::parse(&path_str).unwrap();
        prop_assert_eq!(path.len(), 16);

        let mut rendered = heapless::String::<256>::new();
        use core::fmt::Write;
        write!(rendered, "{:?}", path).unwrap();
        prop_assert_eq!(rendered.as_str(), path_str);
    }

    /// MAX_DEPTH+1=17 路径 → 应该 parse 失败（v3 边界）
    #[test]
    fn over_max_depth_path_rejected(_dummy in 0u8..1) {
        let path_str = format!("m/{}", (0..17).map(|_| "0").collect::<Vec<_>>().join("/"));
        let result = DerivationPath::parse(&path_str);
        prop_assert!(result.is_err());
    }
}
}