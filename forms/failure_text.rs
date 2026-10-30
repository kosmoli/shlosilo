//! Fixed user-facing failure vocabulary (拆码 red line, Kosmo 2026-10-12/13).
//!
//! Every failure the user can see maps through a fixed word table: one
//! ambiguous phrase per failure class, no rc codes, no QR-derived strings, no
//! internal detail on screen. The 2026-10-29 KI-cap case proved why the
//! mapping needs its own test face: a `-20` (buffer/cap) failure was wearing
//! the `-34` ("key images out of date") wording on the only diagnostic
//! channel we have — the screen.
//!
//! Single source of truth: the table lives HERE as `CStr` literals (one
//! representation, no str/c-str drift); the forgebox UI renders these through
//! the FFI lookups (`shlosilo_sign_failure_text` /
//! `shlosilo_pairing_failure_reason` / `shlosilo_pairing_failure_hint`) and
//! keeps only glue (ki_store precedent). Pinned byte-exactly by
//! `tests/pin_failure_text.rs`.
//!
//! Scope note: the QR-type vocabulary (`ur`-derived strings -> "unknown code"
//! class words, product_task.c) is the same red line family but an input-side
//! table; it stays on the C side for now (pool #57 附注).

use core::ffi::CStr;

use crate::error::ShlosiloErrorCode;

/// Sign-page failure text: the complete fixed three-line template for a C-ABI
/// error code. Unmapped codes collapse to the generic "unknown code" entry
/// (class only — the split-code rule keeps diagnostics out of user text).
pub fn sign_failure_text(code: i32) -> &'static CStr {
    match code {
        // KeyImageRecordsMissing / KeyImageRecordsMismatch: the wallet's key
        // image picture is out of step with the device's retention (fix37 fp
        // binding refuses / v2 gap policy refuses / mismatch guard refuses).
        x if x == ShlosiloErrorCode::KeyImageRecordsMissing as i32
            || x == ShlosiloErrorCode::KeyImageRecordsMismatch as i32 =>
        {
            c"sign failed
wallet key images out of date
re-run the wallet key image sync, then retry"
        }
        // BufferTooSmall: signed output or request exceeded a fixed buffer
        // (too many inputs / outputs for one transaction).
        x if x == ShlosiloErrorCode::BufferTooSmall as i32 => {
            c"sign failed
request too large
pay with fewer inputs, or split the payment"
        }
        // EncodingError: the scanned request could not be decoded or parsed.
        x if x == ShlosiloErrorCode::EncodingError as i32 => {
            c"sign failed
request data not recognized
re-create the payment and retry"
        }
        // InvalidArgument: the request was parsed but rejected by the
        // signer's input contract.
        x if x == ShlosiloErrorCode::InvalidArgument as i32 => {
            c"sign failed
request not accepted
re-create the payment and retry"
        }
        // Unmapped code -- fixed "unknown code" entry, class only.
        _ => {
            c"sign failed
internal error (unknown code)
reboot the device and retry"
        }
    }
}

/// Pairing (scan-page) failure reason line: one fixed phrase per diagnostic
/// class (2026-10-11 split + 2026-10-29 record-cap class).
pub fn pairing_failure_reason(code: i32) -> &'static CStr {
    match code {
        // -20: wallet too large for pairing (record/details cap).
        x if x == ShlosiloErrorCode::BufferTooSmall as i32 => c"too many outputs for this device",
        // -21: container shape.
        x if x == ShlosiloErrorCode::EncodingError as i32 => c"output format not recognized",
        // -40: envelope signature.
        x if x == ShlosiloErrorCode::CryptoError as i32 => c"output signature check failed",
        // -15: pk1/pk2 ownership binding.
        x if x == ShlosiloErrorCode::PsbtOwnershipRejected as i32 => c"output not from this wallet",
        // -2: data error.
        x if x == ShlosiloErrorCode::InvalidArgument as i32 => c"data error",
        _ => c"unrecognized output",
    }
}

/// Pairing failure hint line: the per-class next-step hint (the -20 class
/// must NOT suggest retrying — the cap does not clear on retry).
pub fn pairing_failure_hint(code: i32) -> &'static CStr {
    if code == ShlosiloErrorCode::BufferTooSmall as i32 {
        c"device limit reached"
    } else {
        c"move camera away, retry"
    }
}
