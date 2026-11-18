//! UR type-classification FFI — the four questions the product flow asks about an
//! inbound type, answered by `crate::ur::type_table` instead of four `strcmp`
//! chains in C.
//!
//! All four entries take `(ptr, len)` rather than a NUL-terminated string: the type
//! comes straight out of the decoder's fixed buffer, which is NUL-terminated in
//! practice but not by contract, and length-passing keeps the FFI boundary honest
//! about who owns bounds.
//!
//! **NULL / empty means "no type recorded yet"**: every entry answers the
//! fall-through classification (phrase `unknown code`, not a sign request, not
//! review-gated, reply name `bytes`) instead of reading the pointer.

use core::ffi::{c_char, c_int, c_uint};

/// Borrow the caller's bytes as a `&str`, or `None` for NULL/empty. Non-UTF-8 input
/// cannot match a registry name, so it classifies as unknown rather than failing.
///
/// # Safety
/// When `ptr` is non-NULL it must point to `len` readable bytes for the duration of
/// the call.
unsafe fn type_str<'a>(ptr: *const u8, len: c_uint) -> Option<&'a str> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len as usize) };
    core::str::from_utf8(bytes).ok()
}

/// Non-zero when `type` reaches the sign dispatcher.
///
/// # Safety
/// See [`type_str`].
#[no_mangle]
pub unsafe extern "C" fn shlosilo_ur_type_is_sign_ffi(ptr: *const u8, len: c_uint) -> c_int {
    match unsafe { type_str(ptr, len) } {
        Some(t) => crate::ur::type_table::is_sign(t) as c_int,
        None => 0,
    }
}

/// Non-zero when `type` goes through the operator review gate.
///
/// # Safety
/// See [`type_str`].
#[no_mangle]
pub unsafe extern "C" fn shlosilo_ur_type_review_gated_ffi(ptr: *const u8, len: c_uint) -> c_int {
    match unsafe { type_str(ptr, len) } {
        Some(t) => crate::ur::type_table::review_gated(t) as c_int,
        None => 0,
    }
}

/// The fixed on-screen phrase for `type` (a NUL-terminated static string; the
/// caller must NOT free it).
///
/// # Safety
/// See [`type_str`].
#[no_mangle]
pub unsafe extern "C" fn shlosilo_ur_type_display_ffi(
    ptr: *const u8,
    len: c_uint,
) -> *const c_char {
    let phrase = crate::ur::type_table::display(unsafe { type_str(ptr, len) });
    crate::ur::type_table::static_cstr(phrase).as_ptr()
}

/// The UR type the device answers under, given the inbound type (a NUL-terminated
/// static string; the caller must NOT free it).
///
/// # Safety
/// See [`type_str`].
#[no_mangle]
pub unsafe extern "C" fn shlosilo_ur_type_reply_ffi(ptr: *const u8, len: c_uint) -> *const c_char {
    let reply = match unsafe { type_str(ptr, len) } {
        Some(t) => crate::ur::type_table::reply_type(t),
        None => "bytes",
    };
    crate::ur::type_table::static_cstr(reply).as_ptr()
}
