//! Zero-heap cursor writes into caller byte buffers (Z2.4a, 2026-09-24).
//!
//! The shared "push into `[u8]` with a cursor" primitive family — replaces the
//! `String`/`Vec` + `format!` building pattern in the signing path. Overflow is
//! an explicit error (silent truncation forbidden).

extern crate alloc;

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// Append bytes at `*n`; over-capacity raises BufferTooSmall.
pub fn push_slice(buf: &mut [u8], n: &mut usize, bytes: &[u8]) -> Result<()> {
    let end = (*n)
        .checked_add(bytes.len())
        .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
    if end > buf.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall));
    }
    buf[*n..end].copy_from_slice(bytes);
    *n = end;
    Ok(())
}

/// Append one byte at `*n`.
pub fn push_byte(buf: &mut [u8], n: &mut usize, b: u8) -> Result<()> {
    push_slice(buf, n, &[b])
}

/// Append `value` in decimal ASCII at `*n` (no allocation, no formatting machinery).
pub fn push_dec(buf: &mut [u8], n: &mut usize, value: u64) -> Result<()> {
    let mut digits = [0u8; 20];
    let mut d = 0usize;
    let mut v = value;
    loop {
        digits[d] = b'0' + (v % 10) as u8;
        v /= 10;
        d += 1;
        if v == 0 {
            break;
        }
    }
    for i in (0..d).rev() {
        push_byte(buf, n, digits[i])?;
    }
    Ok(())
}

// ─── Sink (Z2.4d-2) ───────────────────────────────────────────────────

/// Byte sink for wire writers: one writer implementation feeds either a caller
/// buffer (zero-heap, fallible on overflow) or a `Vec` (staging/test convenience,
/// infallible by construction).
pub trait Sink {
    fn put(&mut self, bytes: &[u8]) -> Result<()>;

    fn put_u8(&mut self, b: u8) -> Result<()> {
        self.put(&[b])
    }
}

/// Cursor sink over a caller buffer (the zero-heap backend).
pub struct SinkCursor<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> SinkCursor<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        SinkCursor { buf, pos: 0 }
    }

    /// Bytes written so far.
    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn written(&self) -> &[u8] {
        &self.buf[..self.pos]
    }
}

impl Sink for SinkCursor<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        push_slice(self.buf, &mut self.pos, bytes)
    }
}

/// Byte-counting sink (Z2.4d-3 length pre-pass): counts without storing,
/// infallible. Lets callers size buffers exactly without materializing the stream.
pub struct CountSink(pub usize);

impl Sink for CountSink {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.0 += bytes.len();
        Ok(())
    }
}

/// Staging backend (documented convenience; infallible by construction).
impl Sink for alloc::vec::Vec<u8> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_overflow() {
        let mut buf = [0u8; 4];
        let mut n = 0;
        push_slice(&mut buf, &mut n, b"ab").unwrap();
        push_byte(&mut buf, &mut n, b'c').unwrap();
        assert_eq!(&buf[..n], b"abc");
        assert!(push_slice(&mut buf, &mut n, b"deee").is_err()); // explicit Err
        assert_eq!(n, 3); // state unchanged on error
    }

    #[test]
    fn decimal_round_trip() {
        let mut buf = [0u8; 20];
        for (v, want) in [
            (0u64, "0"),
            (7, "7"),
            (10, "10"),
            (u32::MAX as u64, "4294967295"),
            (u64::MAX, "18446744073709551615"),
        ] {
            let mut n = 0;
            push_dec(&mut buf, &mut n, v).unwrap();
            assert_eq!(core::str::from_utf8(&buf[..n]).unwrap(), want, "v={v}");
        }
    }
}
