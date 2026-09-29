#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

// shlosilo vendor patch (lang-item campaign): the alloc re-export root is
// feature-gated. `alloc` (default) keeps the historical surface; without
// it the crate is a pure `core` shim and the graph carries no allocator.
#[cfg(feature = "alloc")]
pub extern crate alloc;

pub mod sync;
pub mod collections;
pub mod io;

#[cfg(feature = "alloc")]
pub use alloc::vec;
#[cfg(feature = "alloc")]
pub use alloc::str;
#[cfg(feature = "alloc")]
pub use alloc::string;

#[cfg(feature = "alloc")]
pub mod prelude {
  pub use alloc::{
    format, vec,
    boxed::Box,
    borrow::ToOwned,
    vec::Vec,
    string::{String, ToString},
  };

  #[rustversion::before(1.73)]
  #[doc(hidden)]
  pub trait StdShimsDivCeil {
    fn div_ceil(self, rhs: Self) -> Self;
  }
  #[rustversion::before(1.73)]
  mod impl_divceil {
    use super::StdShimsDivCeil;
    impl StdShimsDivCeil for u8 {
      fn div_ceil(self, rhs: Self) -> Self {
        (self + (rhs - 1)) / rhs
      }
    }
    impl StdShimsDivCeil for u16 {
      fn div_ceil(self, rhs: Self) -> Self {
        (self + (rhs - 1)) / rhs
      }
    }
    impl StdShimsDivCeil for u32 {
      fn div_ceil(self, rhs: Self) -> Self {
        (self + (rhs - 1)) / rhs
      }
    }
    impl StdShimsDivCeil for u64 {
      fn div_ceil(self, rhs: Self) -> Self {
        (self + (rhs - 1)) / rhs
      }
    }
    impl StdShimsDivCeil for u128 {
      fn div_ceil(self, rhs: Self) -> Self {
        (self + (rhs - 1)) / rhs
      }
    }
    impl StdShimsDivCeil for usize {
      fn div_ceil(self, rhs: Self) -> Self {
        (self + (rhs - 1)) / rhs
      }
    }
  }

  #[cfg(feature = "std")]
  #[rustversion::before(1.74)]
  #[doc(hidden)]
  pub trait StdShimsIoErrorOther {
    fn other<E>(error: E) -> Self
    where
      E: Into<Box<dyn std::error::Error + Send + Sync>>;
  }
  #[cfg(feature = "std")]
  #[rustversion::before(1.74)]
  impl StdShimsIoErrorOther for std::io::Error {
    fn other<E>(error: E) -> Self
    where
      E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
      std::io::Error::new(std::io::ErrorKind::Other, error)
    }
  }
}

/// No-alloc shell: glob imports (`use std_shims::prelude::*`) keep resolving.
#[cfg(not(feature = "alloc"))]
pub mod prelude {}
