#[cfg(feature = "std")]
pub use std::collections::*;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
pub use alloc::collections::*;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
pub use hashbrown::{HashSet, HashMap};
