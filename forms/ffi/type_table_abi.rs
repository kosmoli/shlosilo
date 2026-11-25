//! UR type-classification FFI — the questions the product flow asks about an
//! inbound type, answered by `crate::ur::type_table` instead of `strcmp` chains in
//! C.
//!
//! All entries take `(ptr, len)` rather than a NUL-terminated string: the type
//! comes straight out of the decoder's fixed buffer, which is NUL-terminated in
//! practice but not by contract, and length-passing keeps the FFI boundary honest
//! about who owns bounds.
//!
//! The first five are the classify questions: *is it a sign request*, *does it go
//! through the review gate*, *is it a type we know and deliberately do not support*
//! (E-6 — the request is understood and refused by policy, so the screen must say so
//! instead of `unknown code`), *which fixed phrase do we show*, and *which name do we
//! answer under*. The sixth, [`shlosilo_ur_type_goes_to_qr_ffi`], answers where a
//! *reply* payload goes.
//!
//! **NULL / empty means "no type recorded yet"**: every entry answers the
//! fall-through classification (phrase `unknown code`, not a sign request, not
//! review-gated, not a known-unsupported type, reply name `bytes`) instead of
//! reading the pointer.

use core::ffi::{c_char, c_int, c_uint};

/// Longest UR type name the classifier will look at. Registry names are far
/// shorter; this is the same cap the rest of the FFI surface uses for a type
/// name, and it is what keeps a bogus length claim out of the slice below.
const TYPE_NAME_MAX: usize = 64;

/// Borrow the caller's bytes as a `&str`, or `None` for NULL/empty/over-long.
/// Non-UTF-8 input cannot match a registry name, so it classifies as unknown
/// rather than failing.
///
/// # Safety
/// When `ptr` is non-NULL it must point to `len` readable bytes for the duration of
/// the call. `len` above [`TYPE_NAME_MAX`] is not read at all (it answers "unknown
/// type"), so the caller only has to keep the documented name-length window valid.
unsafe fn type_str<'a>(ptr: *const u8, len: c_uint) -> Option<&'a str> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    // F-1 (2026-11-19 graded audit): the claim is bounded BEFORE the slice exists.
    // A `c_uint` length is greater than `isize::MAX` on a 32-bit target, which
    // would make `from_raw_parts` a violated precondition (UB) instead of a miss.
    let len = usize::try_from(len).ok().filter(|&l| l <= TYPE_NAME_MAX)?;
    // SAFETY: non-null (checked above), non-zero and now within `TYPE_NAME_MAX`;
    // validity of those bytes is the caller's `# Safety` obligation.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
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

/// Non-zero when `type` is **known and deliberately unsupported** by this device
/// (E-6: batch signing, `eth-batch-sign-request` 40404).
///
/// Distinct from "not a sign request": the product flow keeps scanning in both
/// cases, but this one must say *not supported* — the request is understood, so a
/// retry will not help. Answers 0 for NULL/empty (no type recorded = unknown).
///
/// # Safety
/// See [`type_str`].
#[no_mangle]
pub unsafe extern "C" fn shlosilo_ur_type_unsupported_ffi(ptr: *const u8, len: c_uint) -> c_int {
    match unsafe { type_str(ptr, len) } {
        Some(t) => crate::ur::type_table::unsupported(t) as c_int,
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

/// Non-zero when a successful sign under `reply` should go straight to the QR
/// carousel instead of the result page.
///
/// The set lives in `ur::type_table::reply_goes_to_qr` (one row per reply type). It
/// used to be a hardcoded `strcmp` chain in the C product task, which silently missed
/// `eth-signature` and left the ETH exit parked on the result page.
///
/// # Safety
/// See [`type_str`].
#[no_mangle]
pub unsafe extern "C" fn shlosilo_ur_type_goes_to_qr_ffi(ptr: *const u8, len: c_uint) -> c_int {
    match unsafe { type_str(ptr, len) } {
        Some(t) => crate::ur::type_table::reply_goes_to_qr(t) as c_int,
        None => 0,
    }
}
