//! shlosilo vendor patch (Z5.3 D-cut, 2026-09-26): caller-provided scratch
//! for the large-term Straus multi-exponentiations.
//!
//! Design contract (agreed with Kosmo + GPT review):
//! - The scratch is a RESOURCE, not global state: the caller owns the storage
//!   (static/PSRAM/heap — the L3 decides placement) and passes `&mut`
//!   explicitly. No `thread_local`, no bare `static mut` — the borrow itself
//!   is the single-consumer proof.
//! - Secrecy trichotomy: lookup tables are built from PUBLIC points (no
//!   wipe); constant-time radix-16 digits are derived from SECRET scalars and
//!   are zeroized on every path (success or error); vartime NAF digits derive
//!   from public challenges (no wipe).
//! - The ct and vartime views OVERLAY the same two regions (their working
//!   sets are never simultaneously alive — each multiexp completes before
//!   the next starts), halving the footprint; `&mut` prevents overlap in use.
//! - Everything is explicit: `storage_bytes(n)` is the single size source of
//!   truth; too-small/misaligned storage is a loud `ScratchError`; the
//!   trait-based allocating path remains as the fallback.

use core::mem::align_of;

/// Error returned when the provided storage cannot hold the requested
/// working set (explicit failure; no silent truncation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScratchError {
    /// Storage is smaller than `storage_bytes(n)` for the requested term
    /// count, or misaligned.
    TooSmall,
    /// The selected backend has no scratch path (the nightly AVX-512 straus
    /// is not wired; reported loudly rather than silently allocating).
    UnsupportedBackend,
}

/// Caller-owned Straus scratch storage: two overlaid regions —
/// `tables` (sized for the widest table type) and `digits` (sized for the
/// widest digit array), each sized from the term capacity.
pub struct StrausScratch<'a> {
    tables: &'a mut [u8],
    digits: &'a mut [u8],
    terms_cap: usize,
}

impl<'a> StrausScratch<'a> {
    /// The single sizing source of truth for `terms` concurrent terms.
    /// Widest element assumptions (both backends are within these bounds):
    /// table element = 16 * 160 B (NafLookupTable5 over a 160 B point),
    /// digits = 256 B per term (NAF5). 64 B of alignment slack is included.
    pub const fn storage_bytes(terms: usize) -> usize {
        const WIDEST_POINT: usize = 160;
        let tables = terms * (16 * WIDEST_POINT);
        let digits = terms * 256;
        tables + digits + 64
    }

    /// Wrap caller storage for up to `terms_cap` concurrent terms. The buffer
    /// must be at least `storage_bytes(terms_cap)` bytes and 8-aligned.
    pub fn new(storage: &'a mut [u8], terms_cap: usize) -> Result<Self, ScratchError> {
        if storage.len() < Self::storage_bytes(terms_cap) {
            return Err(ScratchError::TooSmall);
        }
        // AVX2 table types are 32-byte aligned; the tables region is aligned
        // internally (the storage_bytes slack covers the padding). The digits
        // region needs byte alignment only.
        let base = storage.as_ptr() as usize;
        let pad = (32 - (base % 32)) % 32;
        if storage.len() < pad + Self::storage_bytes(terms_cap) - 64 {
            return Err(ScratchError::TooSmall);
        }
        let storage = &mut storage[pad..];
        const WIDEST_POINT: usize = 160;
        let tables_len = terms_cap * (16 * WIDEST_POINT);
        let digits_len = terms_cap * 256;
        let (tables, rest) = storage.split_at_mut(tables_len);
        let (digits, _slack) = rest.split_at_mut(digits_len);
        Ok(StrausScratch { tables, digits, terms_cap })
    }

    /// The term capacity this scratch was sized for.
    pub fn terms_cap(&self) -> usize {
        self.terms_cap
    }

    /// Borrow both regions at once (disjoint fields — one `&mut self` split).
    /// Slices are exactly the requested lengths; too-small storage is a loud
    /// `ScratchError`.
    pub(crate) fn split(
        &mut self,
        tables_need: usize,
        digits_need: usize,
    ) -> Result<(&mut [u8], &mut [u8]), ScratchError> {
        if tables_need > self.tables.len() || digits_need > self.digits.len() {
            return Err(ScratchError::TooSmall);
        }
        Ok((&mut self.tables[..tables_need], &mut self.digits[..digits_need]))
    }

    /// Typed view helper: reinterpret a byte region as `&mut [T]`.
    ///
    /// # Safety
    /// `bytes` must be aligned for `T` and sized in whole `T`s; the caller
    /// initializes every element before reading it.
    pub(crate) unsafe fn cast<T>(bytes: &mut [u8]) -> &mut [T] {
        debug_assert_eq!(bytes.as_ptr() as usize % align_of::<T>(), 0);
        debug_assert_eq!(bytes.len() % core::mem::size_of::<T>(), 0);
        core::slice::from_raw_parts_mut(bytes.as_mut_ptr() as *mut T, bytes.len() / core::mem::size_of::<T>())
    }
}

// Re-exports so callers name the scratch path through one module.
pub use crate::backend::{
    straus_multiscalar_mul_scratch, straus_optional_multiscalar_mul_scratch,
};
