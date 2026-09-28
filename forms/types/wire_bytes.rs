//! Wire-slice bytes: `alloc::borrow::Cow` on the alloc face, plain `&[u8]`
//! on the no-alloc face. Construction sites use `.into()` (works for both);
//! consumers use `.as_ref()` (works for both).

#[cfg(feature = "alloc-fallback")]
extern crate alloc;
#[cfg(feature = "alloc-fallback")]
pub type WireBytes<'a> = alloc::borrow::Cow<'a, [u8]>;

#[cfg(not(feature = "alloc-fallback"))]
pub type WireBytes<'a> = &'a [u8];

/// TxIn witness emptier: `Vec::new()` on the alloc face, `&[]` on the
/// no-alloc face — the TxIn.witness field is cfg-double-defined to match.
#[cfg(feature = "alloc-fallback")]
pub fn witness_empty() -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
    alloc::vec::Vec::new()
}
#[cfg(not(feature = "alloc-fallback"))]
pub fn witness_empty<'a>() -> &'a [&'a [u8]] {
    &[]
}

/// Two-face byte access without lint whiplash: `&[u8]` from either face,
/// carrying the data lifetime (not the borrow of the handle).
#[cfg(feature = "alloc-fallback")]
pub fn wire_slice<'a>(b: &'a WireBytes<'a>) -> &'a [u8] {
    b.as_ref()
}
#[cfg(not(feature = "alloc-fallback"))]
pub fn wire_slice<'a>(b: &'a WireBytes<'a>) -> &'a [u8] {
    b
}

/// Two-face constructor: borrow a wire slice on either face.
#[cfg(feature = "alloc-fallback")]
pub fn wire_from<'a>(b: &'a [u8]) -> WireBytes<'a> {
    alloc::borrow::Cow::Borrowed(b)
}
#[cfg(not(feature = "alloc-fallback"))]
pub fn wire_from<'a>(b: &'a [u8]) -> WireBytes<'a> {
    b
}
