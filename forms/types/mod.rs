//! shlosilo L1 shared types
//!
//! Phase 2.0 contains only chain_kind.rs; later Phase 2.1+ adds:
//!   - curve.rs (Curve enum: identifies the curve family)
//!   - other shared types

pub mod caps;
pub mod chain_kind;
pub mod key_session;
pub mod phase_trace;
pub mod push;
pub mod secret_bytes;
/// Primitive axis (S9 batch B): `SecretScalar` is a `curve25519_dalek::Scalar` owner, so it
/// follows `prim-ed25519`. Only the XMR signing path (`chain/xmr/*`, `business/sign.rs`'s
/// XMR arm) names it; a build without the primitive cannot see the type at all.
#[cfg(feature = "prim-ed25519")]
pub mod secret_scalar;
pub mod slice_vec;

pub use secret_bytes::SecretBytes;
pub use slice_vec::SliceVec;
pub mod wire_bytes;
