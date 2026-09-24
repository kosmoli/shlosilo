//! SliceVec: caller-storage bounded vector (Z2.3, 2026-09-24, decision "选项2").
//!
//! Aggregate lists (sources / txes / ptx / dests / output details) live in
//! **caller-provided slices** instead of heap or inline-max storage:
//! - zero heap (Z6-compatible), zero inline-size multiplication — the caller
//!   (flux appearance) sizes each buffer once for its deployment;
//! - capacity is a runtime property of the caller's buffer (no compile-time
//!   semantic limit on wire counts);
//! - overflow raises an explicit error (silent truncation forbidden).
//!
//! Safe-Rust construction: slots are `T::default()` placeholders (documented
//! "zero/empty" values for secret-bearing types); `push` overwrites a slot and
//! `clear`/drop semantics are ordinary assignments, so no `unsafe` is needed.

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// Z2.3 C3b-1 (2026-09-24): Debug shows the live elements only.
impl<T: core::fmt::Debug> core::fmt::Debug for SliceVec<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries((**self).iter()).finish()
    }
}

pub struct SliceVec<'a, T> {
    buf: &'a mut [T],
    len: usize,
}

impl<'a, T: Default> SliceVec<'a, T> {
    /// Wrap a caller buffer. All slots are reset to `T::default()` placeholders.
    pub fn new(buf: &'a mut [T]) -> Self {
        for slot in buf.iter_mut() {
            let _ = core::mem::take(slot);
        }
        Self { buf, len: 0 }
    }

    /// Append one element. Over-capacity is an explicit error (never truncates).
    pub fn push(&mut self, value: T) -> Result<()> {
        if self.len >= self.buf.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall));
        }
        self.buf[self.len] = value;
        self.len += 1;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Drop all elements (secrets zeroize on drop) and reset slots to placeholders.
    pub fn clear(&mut self) {
        for slot in self.buf.iter_mut() {
            let _ = core::mem::take(slot);
        }
        self.len = 0;
    }
}

impl<T> core::ops::Deref for SliceVec<'_, T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.buf[..self.len]
    }
}

impl<T> core::ops::DerefMut for SliceVec<'_, T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.buf[..self.len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_deref() {
        let mut backing = [0u8; 4];
        let mut v = SliceVec::new(&mut backing);
        assert!(v.is_empty());
        v.push(1).unwrap();
        v.push(2).unwrap();
        assert_eq!(&*v, &[1, 2]);
        assert_eq!(v.capacity(), 4);
    }

    #[test]
    fn overflow_is_explicit_error() {
        let mut backing = [0u8; 2];
        let mut v = SliceVec::new(&mut backing);
        v.push(1).unwrap();
        v.push(2).unwrap();
        assert!(v.push(3).is_err()); // BufferTooSmall, never truncated
        assert_eq!(&*v, &[1, 2]); // state unchanged
    }

    #[test]
    fn clear_resets_and_reuses() {
        let mut backing = [0u8; 2];
        let mut v = SliceVec::new(&mut backing);
        v.push(9).unwrap();
        v.clear();
        assert!(v.is_empty());
        v.push(7).unwrap();
        assert_eq!(&*v, &[7]);
    }

    #[test]
    fn new_resets_stale_slots() {
        let mut backing = [5u8; 3]; // caller's dirty memory
        {
            let v = SliceVec::new(&mut backing);
            assert_eq!(&*v, &[] as &[u8]); // placeholders not exposed
        }
        assert_eq!(backing, [0u8, 0, 0]); // placeholders are zero/empty
    }
}
