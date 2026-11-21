//! A4-07 / A4-08 pin (2026-11-22): the raw-address slice builders are `unsafe fn`
//! and say so.
//!
//! Both helpers take a bare address plus a length and hand back a borrowed slice.
//! The length budget bounds the *claim*, never the address: no length can make an
//! arbitrary pointer readable for that many bytes. A safe signature therefore lets
//! safe code obtain a reference it cannot possibly have proven valid — the
//! obligation belongs to the `unsafe` FFI entry that received the pointer from C,
//! which is the only place that can carry it.
//!
//! This is a source-level tripwire because the property is a signature, not a
//! runtime behaviour: there is no call to make fail. Same discipline as
//! `no_persistence.rs` (scan the code face, leave the assertion strings out of it).

const FFI_RS: &str = include_str!("../src/keysource/ffi.rs");
const SE_FFI_RS: &str = include_str!("../src/keysource/se_ffi.rs");

#[test]
fn scan_payload_is_an_unsafe_helper_over_a_caller_lifetime() {
    assert!(
        FFI_RS.contains("unsafe fn scan_payload<'a>(data: *const u8, data_len: c_uint)"),
        "A4-08: scan_payload must stay an `unsafe fn` — a safe signature over a raw \
         address promises readability nobody checked"
    );
    assert!(
        !FFI_RS.contains("-> Option<&'static [u8]>"),
        "A4-08: no helper may fabricate a `'static` borrow out of a raw pointer"
    );
}

#[test]
fn bounded_password_is_an_unsafe_helper_over_a_caller_lifetime() {
    assert!(
        SE_FFI_RS.contains("unsafe fn bounded_password<'a>(p: *const u8, len: usize)"),
        "A4-07: bounded_password must stay an `unsafe fn` — the ceiling bounds the \
         length claim, not the address"
    );
    assert!(
        !SE_FFI_RS.contains("-> Option<&'static [u8]>"),
        "A4-07: no helper may fabricate a `'static` borrow out of a raw pointer"
    );
}
