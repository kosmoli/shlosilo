//! ShlosiloError → i32 C-ABI error code conversion (v2 §3.5)
//!
//! C-ABI functions return `i32`: 0 = Ok, negative = error code
//!
//! numeric layout **identical** to ShlosiloErrorKind — L3 gets an i32 and dispatches straight to error handling
//!
//! **Phase 2.5 stub**: converts ShlosiloErrorKind 1:1
//! Phase 5 real implementation: adds the C-ABI-specific wrapping error code (-1 = Unknown)

use crate::error::{ShlosiloError, ShlosiloErrorCode};

/// ShlosiloError → i32 C-ABI error code (stable negative layout, see `ShlosiloErrorCode`)
///
/// **R2 remediation (2026-08-31)**: the original implementation returned a positive number directly via `err.kind as i32` (e.g. 0x0201_0003),
/// contradicting the C-ABI contract of "0 = Ok, negative = error". Now goes through `ShlosiloErrorCode::from_shlosilo_error`
/// stable negative-code mapping (error.rs L2b classification). The raw kind value is still available via Debug logs.
pub fn to_ffi_code(err: &ShlosiloError) -> i32 {
    ShlosiloErrorCode::from_shlosilo_error(*err)
}

/// Generic error (catch-all): a caller receiving this i32 should fall back to the generic error UI
///
/// **Error code alignment (2026-08-31, prerequisite for C host integration)**: after the R2 remediation, `to_ffi_code` goes through
/// `ShlosiloErrorCode` stable negative codes, but these four FFI early-return constants are still independent legacy values
/// (ERR_BUFFER_TOO_SMALL=-3 conflicted with the mapped code BufferTooSmall=-20). Now all folded into
/// `ShlosiloErrorCode` enum as the single source of truth:
/// - ERR_UNKNOWN = UnknownError = -1
/// - ERR_NULL_POINTER = InvalidArgument = -2 (a null argument is an invalid argument)
/// - ERR_BUFFER_TOO_SMALL = BufferTooSmall = **-20** (the old -3 is retired; shlosilo.h updated accordingly)
/// - ERR_PANIC = FfiPanic = -4 (FFI-specific; newly added to the enum)
pub const ERR_UNKNOWN: i32 = ShlosiloErrorCode::UnknownError as i32;
pub const ERR_NULL_POINTER: i32 = ShlosiloErrorCode::InvalidArgument as i32;
pub const ERR_BUFFER_TOO_SMALL: i32 = ShlosiloErrorCode::BufferTooSmall as i32;
pub const ERR_PANIC: i32 = ShlosiloErrorCode::FfiPanic as i32;

/// Success
pub const OK: i32 = ShlosiloErrorCode::Ok as i32;

/// i32 → &'static str (error description for the L3 UI to display)
///
/// For debugging — the L3 production UI should dispatch on integers, not strings
pub fn describe(code: i32) -> &'static str {
    match code {
        OK => "OK",
        ERR_UNKNOWN => "Unknown error",
        ERR_NULL_POINTER => "Null pointer passed to FFI",
        ERR_BUFFER_TOO_SMALL => "Output buffer too small",
        ERR_PANIC => "Rust panic caught at FFI boundary",
        -10 => "Unsupported chain kind",
        -11 => "Unsupported export protocol",
        -12 => "Unsupported network",
        -13 => "Multisig not supported",
        -14 => "Feature not implemented",
        -15 => "PSBT ownership rejected",
        -21 => "Encoding error",
        -30 => "Invalid UR payload",
        -31 => "Invalid mnemonic",
        -32 => "Invalid derivation path",
        -33 => "Invalid dice rolls",
        -40 => "Crypto error",
        -99 => "Invariant violation",
        _ => "Error code from Rust FFI",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ShlosiloError, ShlosiloErrorKind};

    #[test]
    fn ok_is_zero() {
        assert_eq!(OK, 0);
    }

    #[test]
    fn ffi_code_is_negative_stable() {
        // R2: FFI error codes must be negative (0=Ok contract); go through the stable ShlosiloErrorCode mapping
        let err = ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall);
        assert_eq!(to_ffi_code(&err), -20);
        assert!(to_ffi_code(&err) < 0);
        let ur_err = ShlosiloError::new(ShlosiloErrorKind::UrPayloadInvalidCbor);
        assert_eq!(to_ffi_code(&ur_err), -30);
        assert_eq!(to_ffi_code(&ShlosiloError::ok()), 0);
    }

    #[test]
    fn describe_known_codes() {
        assert_eq!(describe(OK), "OK");
        assert_eq!(describe(ERR_NULL_POINTER), "Null pointer passed to FFI");
    }
}
