//! P0-02 remediation landing tests (2026-09-01 third review #4) — C ABI boundary contract tests
//!
//! Audit requirements:
//! 1. A negative mnemonic_count is rejected before any unsafe construction (the old `as usize` zero-extension = UB)
//! 2. The `(NULL, len>0)` combination is stably rejected (previously bytes_in silently became an empty slice — a wrong passphrase
//!    pointer would derive a completely different wallet)
//! 3. `network as u8` / `sides as u8` narrowing wraparound replaced by full-value validation
//! 4. All out-params are zeroed before any validation (also covering the null early-return)
//!
//! Covered entries: sign / sign_ur / export_readonly / create_account / sign_typed (9-entry family)

use shlosilo::error::ShlosiloErrorCode;
use shlosilo::ffi::c_abi::r3::shlosilo_sign_typed_ffi;
use shlosilo::ffi::c_abi::{
    shlosilo_create_account_ffi, shlosilo_export_readonly_ffi, shlosilo_sign_ffi,
    shlosilo_sign_ur_ffi,
};

const INVALID_MNEMONIC: i32 = ShlosiloErrorCode::InvalidMnemonic as i32;
const INVALID_ARG: i32 = ShlosiloErrorCode::InvalidArgument as i32;

fn valid_indices() -> [u16; 12] {
    // abandon×11 + about (official vector, valid checksum)
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]
}

//-- 1. Negative count rejected on every entry (pre-fix = from_raw_parts UB; aborts under debug UB-check) --

#[test]
fn p002_negative_count_rejected_sign() {
    let idx = valid_indices();
    let mut out = [0u8; 64];
    let mut actual: u32 = 0;
    for bad in [-1i32, i32::MIN, -12, 0, 11, 13, 14, 16, 25, i32::MAX] {
        let rc = shlosilo_sign_ffi(
            idx.as_ptr(),
            bad,
            core::ptr::null(),
            0,
            b"x".as_ptr(),
            1,
            0,
            out.as_mut_ptr(),
            out.len() as u32,
            &mut actual,
        );
        assert_eq!(rc, INVALID_MNEMONIC, "count={bad}");
        assert_eq!(actual, 0, "failure path must zero actual_len (count={bad})");
    }
}

#[test]
fn p002_negative_count_rejected_sign_ur() {
    let idx = valid_indices();
    let mut out = [0u8; 64];
    let mut actual: u32 = 0;
    let uri =
        shlosilo::ur::ur_encode::encode(shlosilo::ur::ur_encode::UrTypeTag::CryptoPsbt, &[0u8; 8])
            .unwrap();
    let uri_c = alloc_cstring(uri.as_str());
    for bad in [-1i32, i32::MIN, 13, 0] {
        let rc = shlosilo_sign_ur_ffi(
            uri_c.as_ptr(),
            idx.as_ptr(),
            bad,
            core::ptr::null(),
            0,
            0,
            core::ptr::null(),
            0,
            out.as_mut_ptr(),
            out.len() as u32,
            &mut actual,
        );
        assert_eq!(rc, INVALID_MNEMONIC, "count={bad}");
        assert_eq!(actual, 0);
    }
}

#[test]
fn p002_negative_count_rejected_export() {
    let idx = valid_indices();
    let elems: [u32; 1] = [44 | 0x8000_0000];
    let mut buf = [0u8; 64];
    let mut actual: u32 = 0;
    for bad in [-1i32, i32::MIN, 13, 0] {
        let rc = shlosilo_export_readonly_ffi(
            idx.as_ptr(),
            bad,
            core::ptr::null(),
            0,
            0,
            elems.as_ptr(),
            elems.len() as u32,
            0,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut actual,
        );
        assert_eq!(rc, INVALID_MNEMONIC, "count={bad}");
        assert_eq!(actual, 0);
    }
}

#[test]
fn p002_negative_count_rejected_sign_typed() {
    let idx = valid_indices();
    let mut out = [0u8; 64];
    let mut actual: u32 = 0;
    let tname = c"crypto-psbt";
    for bad in [-1i32, i32::MIN, 13, 0] {
        let rc = shlosilo_sign_typed_ffi(
            tname.as_ptr(),
            [0u8; 8].as_ptr(),
            8,
            idx.as_ptr(),
            bad,
            core::ptr::null(),
            0,
            0,
            core::ptr::null(),
            0,
            out.as_mut_ptr(),
            out.len() as u32,
            &mut actual,
        );
        assert_eq!(rc, INVALID_MNEMONIC, "count={bad}");
        assert_eq!(actual, 0);
    }
}

//-- 2. (NULL, len>0) combination rejected — a wrong passphrase pointer must not silently become empty --

#[test]
fn p002_null_with_nonzero_len_rejected() {
    let idx = valid_indices();
    let elems: [u32; 1] = [44 | 0x8000_0000];
    let mut buf = [0u8; 64];
    let mut actual: u32 = 0;

    // export: passphrase = (NULL, 1) → rejected (pre-fix = silent empty passphrase → wrong wallet derived)
    let rc = shlosilo_export_readonly_ffi(
        idx.as_ptr(),
        12,
        core::ptr::null(),
        1, // len>0 + NULL = illegal combination
        0,
        elems.as_ptr(),
        elems.len() as u32,
        0,
        buf.as_mut_ptr(),
        buf.len() as u32,
        &mut actual,
    );
    assert_eq!(
        rc, INVALID_ARG,
        "(NULL, len=1) passphrase must be stably rejected"
    );
    assert_eq!(actual, 0);

    // (NULL, 0) still allowed (semantics: no passphrase) — run a full export with a large-enough buffer
    let mut big = [0u8; 1024];
    let mut actual_big: u32 = 0;
    let rc = shlosilo_export_readonly_ffi(
        idx.as_ptr(),
        12,
        core::ptr::null(),
        0,
        0,
        elems.as_ptr(),
        elems.len() as u32,
        0,
        big.as_mut_ptr(),
        big.len() as u32,
        &mut actual_big,
    );
    assert_eq!(
        rc,
        shlosilo::ffi::error_code::OK,
        "(NULL, 0) is a legal combination"
    );
    assert!(core::str::from_utf8(&big[..actual_big as usize])
        .unwrap()
        .starts_with("ur:crypto-hdkey/"));
}

//-- 3. Narrowing wraparound rejected --

#[test]
fn p002_network_wraparound_rejected() {
    let idx = valid_indices();
    let mut out = [0u8; 64];
    let mut actual: u32 = 0;
    // network = 256 → `as u8` wraps to 0 (BitcoinMainnet); must be rejected after the fix
    let big_nets = [256u64, 512, u64::from(u32::MAX), 0x1_0000_0000];
    for &bad_net_u64 in &big_nets {
        // The FFI parameter is c_uint (32-bit); narrowing wraparound is reproducible within the 32-bit range (256 → 0)
        let bad_net = bad_net_u64 as u32;
        let rc = shlosilo_sign_ffi(
            idx.as_ptr(),
            12,
            core::ptr::null(),
            0,
            b"x".as_ptr(),
            1,
            bad_net,
            out.as_mut_ptr(),
            out.len() as u32,
            &mut actual,
        );
        assert_ne!(
            rc,
            shlosilo::ffi::error_code::OK,
            "network={bad_net} must not wrap into a legal value"
        );
    }
}

#[test]
fn p002_sides_wraparound_rejected() {
    // sides = 262 → `as u8` wraps to 6; must be rejected after the fix (InvalidDiceConfig domain)
    let rolls = [1u8; 128];
    let mut mnemonic_buf = [0u8; 24];
    let rc = shlosilo_create_account_ffi(
        12,
        262, // > u8::MAX
        rolls.as_ptr(),
        rolls.len() as u32,
        core::ptr::null(),
        0,
        mnemonic_buf.as_mut_ptr(),
        mnemonic_buf.len() as u32,
    );
    assert_ne!(
        rc,
        shlosilo::ffi::error_code::OK,
        "sides=262 must not wrap to 6"
    );
}

//-- 4. out-param prologue zeroing (null early-return path) --

#[test]
fn p002_outparam_zeroed_on_null_early_return() {
    let _idx = valid_indices(); // semantic placeholder: even valid idx must not rescue a null pointer
    let mut out = [0u8; 64];
    // Pre-fill with garbage to simulate stale C-side stack data
    let mut actual: u32 = 0xDEAD_BEEF;

    // mnemonic_indices = NULL → ERR_NULL_POINTER, but actual_len must already be zeroed
    let rc = shlosilo_sign_ffi(
        core::ptr::null(),
        12,
        core::ptr::null(),
        0,
        b"x".as_ptr(),
        1,
        0,
        out.as_mut_ptr(),
        out.len() as u32,
        &mut actual,
    );
    assert_eq!(rc, INVALID_ARG);
    assert_eq!(
        actual, 0,
        "out-param must be zeroed before the null early-return (pre-fix it kept 0xDEADBEEF)"
    );

    // export, same path
    let mut actual2: u32 = 0xDEAD_BEEF;
    let elems: [u32; 1] = [44 | 0x8000_0000];
    let rc = shlosilo_export_readonly_ffi(
        core::ptr::null(),
        12,
        core::ptr::null(),
        0,
        0,
        elems.as_ptr(),
        elems.len() as u32,
        0,
        out.as_mut_ptr(),
        out.len() as u32,
        &mut actual2,
    );
    assert_eq!(rc, INVALID_ARG);
    assert_eq!(actual2, 0);
}

//-- 5. Smoke: legal paths unaffected --

#[test]
fn p002_valid_path_still_works() {
    let idx = valid_indices();
    let elems: [u32; 5] = [44 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 0];
    let mut buf = [0u8; 1024];
    let mut actual: u32 = 0;
    let rc = shlosilo_export_readonly_ffi(
        idx.as_ptr(),
        12,
        core::ptr::null(),
        0,
        0,
        elems.as_ptr(),
        elems.len() as u32,
        0,
        buf.as_mut_ptr(),
        buf.len() as u32,
        &mut actual,
    );
    assert_eq!(rc, shlosilo::ffi::error_code::OK);
    let uri = core::str::from_utf8(&buf[..actual as usize]).unwrap();
    assert!(uri.starts_with("ur:crypto-hdkey/"));
}

//-- 6. Audit #5 P0-03: UINT_MAX full-range boundary (a 64-bit host cannot trigger isize overflow,
//    but business budget caps reject before unsafe construction — on 32-bit Thumb the isize check is the backstop of the same line) --

#[test]
fn p003_uintmax_lengths_rejected() {
    use shlosilo::error::ShlosiloErrorCode;
    let idx = valid_indices();
    let mut out = [0u8; 64];
    let mut actual: u32 = 0;
    let elems: [u32; 1] = [44 | 0x8000_0000];
    let umax = u32::MAX;

    // passphrase len = UINT_MAX → rejected at the helper layer (over PASSPHRASE_MAX_LEN)
    let rc = shlosilo_export_readonly_ffi(
        idx.as_ptr(),
        12,
        core::ptr::null(),
        umax,
        0,
        elems.as_ptr(),
        elems.len() as u32,
        0,
        out.as_mut_ptr(),
        out.len() as u32,
        &mut actual,
    );
    assert_eq!(rc, INVALID_ARG, "UINT_MAX passphrase must be rejected");
    assert_eq!(actual, 0);

    // path_elem_count = UINT_MAX → rejected at the helper layer (over MAX_DEPTH)
    let rc = shlosilo_export_readonly_ffi(
        idx.as_ptr(),
        12,
        core::ptr::null(),
        0,
        0,
        elems.as_ptr(),
        umax,
        0,
        out.as_mut_ptr(),
        out.len() as u32,
        &mut actual,
    );
    assert_eq!(
        rc,
        ShlosiloErrorCode::InvalidDerivationPath as i32,
        "UINT_MAX path elems must be rejected"
    );
    assert_eq!(actual, 0);

    // output_buf_len = UINT_MAX (over-declared capacity) → checked_slice_mut rejects, preventing an out-of-bounds write
    let rc = shlosilo_export_readonly_ffi(
        idx.as_ptr(),
        12,
        core::ptr::null(),
        0,
        0,
        elems.as_ptr(),
        elems.len() as u32,
        0,
        out.as_mut_ptr(),
        umax,
        &mut actual,
    );
    assert_eq!(
        rc,
        ShlosiloErrorCode::BufferTooSmall as i32,
        "UINT_MAX output capacity must be rejected (prevents OOB write)"
    );
    assert_eq!(actual, 0);

    // rolls_count = UINT_MAX → rejected
    let mut mbuf = [0u8; 24];
    let rc = shlosilo_create_account_ffi(
        12,
        6,
        idx.as_ptr() as *const u8,
        umax,
        core::ptr::null(),
        0,
        mbuf.as_mut_ptr(),
        mbuf.len() as u32,
    );
    assert_eq!(
        rc,
        ShlosiloErrorCode::InvalidDiceRolls as i32,
        "UINT_MAX rolls must be rejected"
    );
}

#[test]
fn p003_null_zero_len_semantics() {
    // (NULL,0) optional = allowed; required = rejected — fixed semantics
    let idx = valid_indices();
    let elems: [u32; 1] = [44 | 0x8000_0000];
    let mut buf = [0u8; 1024];
    let mut actual: u32 = 0;
    let rc = shlosilo_export_readonly_ffi(
        idx.as_ptr(),
        12,
        core::ptr::null(),
        0,
        0,
        elems.as_ptr(),
        elems.len() as u32,
        0,
        buf.as_mut_ptr(),
        buf.len() as u32,
        &mut actual,
    );
    assert_eq!(
        rc,
        shlosilo::ffi::error_code::OK,
        "(NULL,0) passphrase = no passphrase"
    );
}

fn alloc_cstring(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).unwrap()
}
