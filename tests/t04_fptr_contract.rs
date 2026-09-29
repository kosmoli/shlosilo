//! T-04 contract pins — inv1: the generated C header carries typed nullable
//! function pointers on every callback-registration entry point, never integer
//! addresses. The u32-era contract truncated pointers on 64-bit hosts (UB) and
//! let mismatched signatures compile silently at the C call site.
//!
//! Run in the default test face (no features needed): the header is generated
//! from the always-compiled entry points. Enforced by the gate batch (TEST and
//! TESTALL) and CI.

/// Normalize all whitespace runs to single spaces so multi-line cbindgen
/// declarations can be pinned as one string.
fn normalized_header() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/shlosilo.h");
    let header =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    header.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// inv1: every registration entry point takes a C function pointer type.
#[test]
fn inv1_header_carries_typed_fn_pointers() {
    let h = normalized_header();
    let typed = [
        "void shlosilo_timing_set_clock_fn(uint32_t (*fptr)(void));",
        "void shlosilo_cn_timing_set_clock(uint32_t (*clock_fptr)(void));",
        "void shlosilo_bp_timing_set_clock(uint32_t (*clock_fptr)(void));",
        "void shlosilo_tx_phase_set_clock(uint32_t (*clock_fptr)(void));",
        "void shlosilo_gen_cache_set_hooks(const uint8_t *(*load_fptr)(const uint8_t*, uint32_t), uint32_t (*store_fptr)(const uint8_t*, uint32_t, const uint8_t*, uint32_t));",
    ];
    for decl in typed {
        assert!(
            h.contains(decl),
            "inv1: missing typed declaration in shlosilo.h: {decl}"
        );
    }
}

/// inv1: the integer-address contract must not come back.
#[test]
fn inv1_header_has_no_integer_fn_addresses() {
    let h = normalized_header();
    let legacy = [
        "void shlosilo_timing_set_clock_fn(uint32_t fptr);",
        "void shlosilo_cn_timing_set_clock(uint32_t clock_fptr);",
        "void shlosilo_bp_timing_set_clock(uint32_t clock_fptr);",
        "void shlosilo_tx_phase_set_clock(uint32_t clock_fptr);",
        "void shlosilo_gen_cache_set_hooks(uint32_t load_fptr, uint32_t store_fptr);",
    ];
    for decl in legacy {
        assert!(
            !h.contains(decl),
            "inv1: integer-address form regressed in shlosilo.h: {decl}"
        );
    }
}
