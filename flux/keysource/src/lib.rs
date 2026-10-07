//! Flux-side key acquisition face: [`KeySource`] + [`QrKeySource`].
//!
//! This crate is flux infrastructure (appearance side), deliberately NOT part
//! of the `forms` core: `forms` stays pure functions over key material, while
//! the appearances own how key material is *acquired* — scanned from a steel
//! plate QR (this crate), or read from a secure element (future `SeKeySource`,
//! same trait).
//!
//! # Threat model: no persistence
//!
//! Seed material is staged and consumed **in RAM only**. Nothing here touches
//! flash, a filesystem, or any other persistent store — a powered-down device
//! must come up with zero key material (`tests/no_persistence.rs` pins the
//! code face with a source-level grep).
//!
//! # Caller-storage slot contract (R3 / Z3.3c, same as the session FFI)
//!
//! A live [`shlosilo::types::key_session::KeySession`] is constructed IN PLACE
//! in caller-owned storage — a [`KeySessionSlot`] placed in a `static` or a
//! task workspace — never `Box`ed (the handle lifecycle must stay off the
//! allocator, Z6). [`KeySessionHandle`] borrows that slot for the handle's
//! lifetime, so safe code cannot move or drop the slot while a session is
//! open; dropping the handle closes the session (`KeySession: ZeroizeOnDrop`
//! wipes the key bytes), and the explicit [`KeySource::close_session`] is the
//! early-teardown form for error paths.

#![no_std]

pub mod keysource;

pub use keysource::qr::QrKeySource;
pub use keysource::{
    KeySessionHandle, KeySessionSlot, KeySource, KeySourceError, KeySourceErrorKind,
};
