//! Version strings + version numbers (validated at Phase 5 L3 startup)

/// Full shlosilo version (cabi + runtime)
pub const SHLOSILO_VERSION_MAJOR: u16 = 0;
pub const SHLOSILO_VERSION_MINOR: u16 = 5;
pub const SHLOSILO_VERSION_PATCH: u16 = 0;

/// Version string ("v0.5.0-poc4+b571508"; NUL-terminated — safe for C-side printf/strlen).
///
/// The `+<git7>` build suffix is injected by build.rs (SHLOSILO_BUILD_GIT) and changes
/// with every commit, so on-device smoke output identifies the exact firmware build.
pub const SHLOSILO_VERSION_STRING: &str = concat!("v0.5.0-poc4+", env!("SHLOSILO_BUILD_GIT"), "\0");

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
/// External audit 2026-11-19 A2-01: 3 -> 4. The version string had stayed at 0.3.0
/// (Audit #4, 2026-09-01) while `shlosilo_sign_ffi` grew from 10 to 12 parameters (the
/// caller workspace `ws`/`ws_len`) — a breaking prototype change that the strict-equality
/// `shlosilo_cabi_check` could not see, so an old host would pass the check and then call
/// the entry with the wrong argument list. 0.x semver: the minor is the breaking bit.
///
/// 2026-11-23 (memory contract, v2-安全 §6): 4 -> 5. The signing entries
/// (`shlosilo_sign_ffi` / `shlosilo_sign_ur_ffi` / `shlosilo_sign_typed_ffi` /
/// `shlosilo_sign_session_view_ffi`) each gained `scratch`/`scratch_len`, and two
/// exports were added (`shlosilo_sign_scratch_len` + `SHLOSILO_SIGN_SCRATCH_ALIGN`)
/// — a parameter shape change, so the minor must move under strict equality.
/// The view entry joined the same unreleased 0.5.0 batch (no host was ever built
/// against a 0.5.0 header without it), so one bump covers the batch.
///
/// 2026-11-27 (chain axis batch 2, L5): 5 -> 6. Two exports were added —
/// `shlosilo_build_fingerprint_ffi` (`uint64_t`) and `shlosilo_build_chain_mask_ffi`
/// (`unsigned int`) — so the library can be asked which chains and which build it
/// carries, and the C carrier compares the answer with the generated
/// `shlosilo_build_identity.h` it compiled against. Adding exports IS a change of the
/// exported function set under this ABI's rule (no host built against a 0.5.0 header
/// has these declarations, and the C side's identity assertion keys on the ABI check
/// passing first), so the minor moves.
///
/// 2026-11-28 (S11a binding through the C ABI): 6 -> 7. Parameter SHAPE change on two
/// existing exports — `shlosilo_review_ffi` gained a trailing out-param
/// (`out_reviewed_digest`, 32 writable bytes) and `shlosilo_sign_session_view_ffi`
/// gained a trailing in-param (`reviewed_digest`, 32 readable bytes or NULL). A host
/// built against the 0.6.0 header would call both with the old argument list, so under
/// strict equality the minor must move.
pub const SHLOSILO_CABI_VERSION_MINOR: u16 = 7;
pub const SHLOSILO_CABI_VERSION_PATCH: u16 = 0;

/// C ABI version string (NUL-terminated)
///
/// **R2 remediation (2026-08-31)**: 0.1.0 → 0.2.0 — the error-code layout changed from a direct mapping of positive kinds
/// to stable negative ShlosiloErrorCode codes (an ABI behavior change), and the capability query gained a null guard.
///
/// **Audit #4 remediation (2026-09-01)**: 0.2.0 → 0.3.0 — R3 added exports
/// shlosilo_sign_typed_ffi / shlosilo_ur_decode_type (exported function set changed);
/// the P0-02 entry prologue discipline changed ((NULL,len>0) went from a silent empty slice to stable rejection = a semantics change).
///
/// **Memory contract (2026-11-23)**: 0.4.0 → 0.5.0 — the three signing entries gained
/// `scratch`/`scratch_len` (caller-provided BP multiexp scratch) and the export set grew
/// by `shlosilo_sign_scratch_len` + `SHLOSILO_SIGN_SCRATCH_ALIGN`.
///
/// **Chain axis batch 2 (2026-11-27)**: 0.5.0 → 0.6.0 — the export set grew by
/// `shlosilo_build_fingerprint_ffi` and `shlosilo_build_chain_mask_ffi` (the C side can
/// now verify the chain set and BUILD_FINGERPRINT of the library it linked).
///
/// **S11a binding through the C ABI (2026-11-28)**: 0.6.0 → 0.7.0 — `shlosilo_review_ffi`
/// gained `out_reviewed_digest` and `shlosilo_sign_session_view_ffi` gained
/// `reviewed_digest` (the review/sign byte binding crosses the C ABI).
pub const SHLOSILO_CABI_VERSION_STRING: &str = "v0.7.0\0";

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
        // External audit 2026-11-19 A2-01: 0.3.0 → 0.4.0 (`shlosilo_sign_ffi` 10 → 12 params)
        // Memory contract (2026-11-23): 0.4.0 → 0.5.0 (three sign entries gained scratch/scratch_len)
        // Chain axis batch 2 (2026-11-27): 0.5.0 → 0.6.0 (build fingerprint + chain mask exports)
        // S11a binding (2026-11-28): 0.6.0 → 0.7.0 (review out_reviewed_digest + sign reviewed_digest)
        assert_eq!(SHLOSILO_CABI_VERSION_MAJOR, 0);
        assert_eq!(SHLOSILO_CABI_VERSION_MINOR, 7);
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
