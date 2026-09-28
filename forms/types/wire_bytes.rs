//! Wire-slice bytes: `alloc::borrow::Cow` on the alloc face, plain `&[u8]`
//! on the no-alloc face. Construction sites use `.into()` (works for both);
//! consumers use `.as_ref()` (works for both).

#[cfg(feature = "alloc-fallback")]
extern crate alloc;
#[cfg(feature = "alloc-fallback")]
pub type WireBytes<'a> = alloc::borrow::Cow<'a, [u8]>;

#[cfg(not(feature = "alloc-fallback"))]
pub type WireBytes<'a> = &'a [u8];
