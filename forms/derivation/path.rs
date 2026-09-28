//! DerivationPath type (v2.3 interface notes §2)
//!
//! Internal representation of BIP-32 derivation paths:
//! - each component is a 32-bit unsigned integer; the high bit 0x80000000 marks hardened
//! - immutable, read-only after construction; modification creates a new `DerivationPath`
//! - stack-allocated, fixed [DerivationIndex; MAX_DEPTH]
//! - parse API: parse from `&str` ("m/44'/0'/0'/0/0")

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

pub const MAX_DEPTH: usize = 16; // BIP-44 usually ≤ 5; reserved up to 16 (compatible with multi-segment paths like Cardano Shelley)

/// BIP-32 hardened bit (highest bit)
pub const HARDENED_BIT: u32 = 0x8000_0000;

/// Soft index upper bound (unsigned 31-bit)
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

    /// Construct from a `&[DerivationIndex]` slice
    /// Construct from a flat `&[u32]` array (hardened bit represented by the high bit 0x80000000)
    pub fn from_flat<I>(iter: I) -> Result<Self>
    where
        I: IntoIterator<Item = u32>,
    {
        let mut indices = [DerivationIndex(0); MAX_DEPTH];
        let mut len: u8 = 0;
        for n in iter.into_iter() {
            if (len as usize) >= MAX_DEPTH {
                return Err(ShlosiloError::new(
                    ShlosiloErrorKind::DerivationPathInvalidSyntax,
                ));
            }
            indices[len as usize] = DerivationIndex(n);
            len += 1;
        }
        Ok(Self { indices, len })
    }

    pub fn from_indices(indices: &[DerivationIndex]) -> Result<Self> {
        if indices.len() > MAX_DEPTH {
            return Err(ShlosiloError::new(
                ShlosiloErrorKind::DerivationPathInvalidSyntax,
            ));
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

    /// Parse from a string (supports m/M prefix + / separator + ' or h/H hardened suffix)
    ///
    /// Accepted formats:
    /// - `"m"` / `"M"` (empty path)
    /// - `"m/44'/0'/0'/0/0"` / `"M/44H/0H/0H/0/0"`
    /// - `"m/44h/0h/0h/0/0"`
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let rest = if s.starts_with("m/") || s.starts_with("M/") {
            &s[2..]
        } else if s == "m" || s == "M" {
            return Ok(Self::empty());
        } else {
            return Err(ShlosiloError::new(
                ShlosiloErrorKind::DerivationPathInvalidSyntax,
            ));
        };

        if rest.is_empty() {
            return Ok(Self::empty());
        }

        let mut indices = [DerivationIndex(0); MAX_DEPTH];
        let mut len: usize = 0;

        for component in rest.split('/') {
            if len >= MAX_DEPTH {
                return Err(ShlosiloError::new(
                    ShlosiloErrorKind::DerivationPathInvalidSyntax,
                ));
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
                return Err(ShlosiloError::new(
                    ShlosiloErrorKind::DerivationPathIndexOutOfRange,
                ));
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

    /// Used for ChainKind inference (chain type → coin_type)
    pub fn coin_type(&self) -> Option<u32> {
        self.as_slice().get(1).map(|i| i.value()) // m/<coin_type>/...
    }
}

/// Parse a decimal u32 (no negative signs, hex, or octal)
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
        // check overflow
        let v = result.checked_mul(10).and_then(|v| v.checked_add(digit))?;
        result = v;
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
    #[cfg(feature = "alloc-fallback")]
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
        // 2^31 out of bounds (soft index upper bound is 2^31-1)
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
        // MAX_DEPTH = 16; more than 16 levels should error
        let s = "m/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0"; // 17 components
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
    // Phase 3 property-based tests
    // ============================================================

    proptest! {
        /// Arbitrary dummy parameters (proptest! requires every fn to have `in` patterns)
        #[test]
        fn parse_empty_path_is_valid(_dummy in 0u8..1) {
            let path = DerivationPath::parse("m").unwrap();
            prop_assert_eq!(path.len(), 0);
        }

        /// hardened index "i'" → high bit 0x80000000
        #[test]
        fn parse_hardened_sets_high_bit(idx in 0u32..16) {
            let path_str = format!("m/{}'", idx);
            let path = DerivationPath::parse(&path_str).unwrap();
            prop_assert_eq!(path.len(), 1);
            let first = &path.as_slice()[0];
            prop_assert_eq!(first.0 & 0x80000000, 0x80000000);
            prop_assert_eq!(first.0 & 0x7FFFFFFF, idx);
        }

        /// normal index "i" → high bit 0
        #[test]
        fn parse_normal_no_high_bit(idx in 0u32..16) {
            let path_str = format!("m/{}", idx);
            let path = DerivationPath::parse(&path_str).unwrap();
            prop_assert_eq!(path.len(), 1);
            prop_assert_eq!(path.as_slice()[0].0 & 0x80000000, 0);
            prop_assert_eq!(path.as_slice()[0].0, idx);
        }

        /// parse → render → string identity (Phase 3 v2 completion)
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

        /// all-zero index path → renders as "m/0/0/.../0" consistently (v3 boundary)
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

        /// MAX_DEPTH=16 path → parses + renders exactly (v3 boundary)
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

        /// MAX_DEPTH+1=17 path → should fail to parse (v3 boundary)
        #[test]
        fn over_max_depth_path_rejected(_dummy in 0u8..1) {
            let path_str = format!("m/{}", (0..17).map(|_| "0").collect::<Vec<_>>().join("/"));
            let result = DerivationPath::parse(&path_str);
            prop_assert!(result.is_err());
        }
    }
}
