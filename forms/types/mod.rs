//! shlosilo L1 shared types
//!
//! Phase 2.0 contains only chain_kind.rs; later Phase 2.1+ adds:
//!   - curve.rs (Curve enum: identifies the curve family)
//!   - other shared types

pub mod caps;
pub mod chain_kind;
pub mod push;
pub mod secret_bytes;
pub mod secret_scalar;
pub mod slice_vec;

pub use secret_bytes::SecretBytes;
pub use slice_vec::SliceVec;
pub mod wire_bytes;
