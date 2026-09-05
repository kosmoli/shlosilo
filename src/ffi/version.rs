//! Version strings + version numbers (validated at Phase 5 L3 startup)

/// Full shlosilo version (cabi + runtime)
pub const SHLOSILO_VERSION_MAJOR: u16 = 0;
pub const SHLOSILO_VERSION_MINOR: u16 = 5;
pub const SHLOSILO_VERSION_PATCH: u16 = 0;

/// Version string ("v0.5.0-poc4"; NUL-terminated — safe for C-side printf/strlen)
pub const SHLOSILO_VERSION_STRING: &str = "v0.5.0-poc4\0";

/// C ABI version (**independent of the runtime version** — L3 must validate the ABI version matches)
///
/// ABI version incompatibility rules (`shlosilo_cabi_check` implements **strict equality**):
/// - major differs → -1 (ABI incompatible; signature/error-code layout changed)
/// - minor differs → -2 (exported function set or semantics changed; L3 must recompile against the new shlosilo.h)
/// - patch differs → -3 (minor behavior tweaks; L3 should re-smoke; the check rejects it too, for determinism)
///
/// Note: unlike traditional semver where "minor bump = backward compatible", this project's C ABI is in
/// its 0.x stage, where minor is the breaking component (consistent with 0.x semver convention). After entering 1.x it should relax to
/// a major-only check.
pub const SHLOSILO_CABI_VERSION_MAJOR: u16 = 0;
pub const SHLOSILO_CABI_VERSION_MINOR: u16 = 3;
pub const SHLOSILO_CABI_VERSION_PATCH: u16 = 0;

/// C ABI version string (NUL-terminated)
///
/// **R2 remediation (2026-08-31)**: 0.1.0 → 0.2.0 — the error-code layout changed from a direct mapping of positive kinds
/// to stable negative ShlosiloErrorCode codes (an ABI behavior change), and the capability query gained a null guard.
///
/// **Audit #4 remediation (2026-09-01)**: 0.2.0 → 0.3.0 — R3 added exports
/// shlosilo_sign_typed_ffi / shlosilo_ur_decode_type (exported function set changed);
/// the P0-02 entry prologue discipline changed ((NULL,len>0) went from a silent empty slice to stable rejection = a semantics change).
pub const SHLOSILO_CABI_VERSION_STRING: &str = "v0.3.0\0";

/// extern "C" returning the version string (C side strdups it before use)
#[no_mangle]
pub extern "C" fn shlosilo_version() -> *const u8 {
    SHLOSILO_VERSION_STRING.as_ptr()
}

/// extern "C" returning the C ABI version string
#[no_mangle]
pub extern "C" fn shlosilo_cabi_version() -> *const u8 {
    SHLOSILO_CABI_VERSION_STRING.as_ptr()
}

/// Validate ABI compatibility at L3 startup (major must match)
///
/// Returns 0 = ABI compatible, non-zero = incompatible
#[no_mangle]
pub extern "C" fn shlosilo_cabi_check(
    l3_expected_major: u16,
    l3_expected_minor: u16,
    l3_expected_patch: u16,
) -> i32 {
    if l3_expected_major != SHLOSILO_CABI_VERSION_MAJOR {
        return -1; // major mismatch → ABI incompatible
    }
    if l3_expected_minor != SHLOSILO_CABI_VERSION_MINOR {
        return -2; // minor mismatch → ABI incompatible (cabi changed exported function signatures)
    }
    if l3_expected_patch != SHLOSILO_CABI_VERSION_PATCH {
        return -3; // patch mismatch → minor behavior tweaks possible
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_constants() {
        assert_eq!(SHLOSILO_VERSION_MAJOR, 0);
        assert_eq!(SHLOSILO_VERSION_MINOR, 5);
        assert_eq!(SHLOSILO_VERSION_PATCH, 0);
    }

    #[test]
    fn cabi_version_constants() {
        // Audit #4 (2026-09-01): 0.2.0 → 0.3.0 (R3 new exports + P0-02 semantics change)
        assert_eq!(SHLOSILO_CABI_VERSION_MAJOR, 0);
        assert_eq!(SHLOSILO_CABI_VERSION_MINOR, 3);
        assert_eq!(SHLOSILO_CABI_VERSION_PATCH, 0);
    }

    #[test]
    fn cabi_check_matches() {
        let result = shlosilo_cabi_check(
            SHLOSILO_CABI_VERSION_MAJOR,
            SHLOSILO_CABI_VERSION_MINOR,
            SHLOSILO_CABI_VERSION_PATCH,
        );
        assert_eq!(result, 0);
    }

    #[test]
    fn cabi_check_major_mismatch() {
        let result = shlosilo_cabi_check(99, 1, 0);
        assert_eq!(result, -1);
    }

    #[test]
    fn version_string_not_null() {
        let p = shlosilo_version();
        assert!(!p.is_null());
    }
}
