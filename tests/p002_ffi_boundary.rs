//! P0-02 整改落地测试（2026-09-01 第三次复审 #4）——C ABI boundary contract tests
//!
//! 审计要求：
//! 1. 负 mnemonic_count 在任何 unsafe 构造前被拒绝（原 `as usize` 零扩展 = UB）
//! 2. `(NULL, len>0)` 组合稳定拒绝（原 bytes_in 静默当空 slice——错误 passphrase
//!    指针会派生完全不同的钱包）
//! 3. `network as u8` / `sides as u8` 窄化回绕改为全值校验
//! 4. 所有 out-param 在任何校验前先清零（null early-return 也覆盖）
//!
//! 覆盖入口：sign / sign_ur / export_readonly / create_account / sign_typed（9 入口族）

use shlosilo::error::ShlosiloErrorCode;
use shlosilo::ffi::c_abi::r3::shlosilo_sign_typed_ffi;
use shlosilo::ffi::c_abi::{
    shlosilo_create_account_ffi, shlosilo_export_readonly_ffi, shlosilo_sign_ffi,
    shlosilo_sign_ur_ffi,
};

const INVALID_MNEMONIC: i32 = ShlosiloErrorCode::InvalidMnemonic as i32;
const INVALID_ARG: i32 = ShlosiloErrorCode::InvalidArgument as i32;

fn valid_indices() -> [u16; 12] {
    // abandon×11 + about（官方向量，checksum 合法）
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]
}

// ── 1. 负 count 全入口拒绝（修复前 = from_raw_parts UB，debug 下 UB-check abort）──

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
        assert_eq!(actual, 0, "失败路径 actual_len 必须清零 (count={bad})");
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

// ── 2. (NULL, len>0) 组合拒绝——错误 passphrase 指针不得静默变空 ──

#[test]
fn p002_null_with_nonzero_len_rejected() {
    let idx = valid_indices();
    let elems: [u32; 1] = [44 | 0x8000_0000];
    let mut buf = [0u8; 64];
    let mut actual: u32 = 0;

    // export: passphrase = (NULL, 1) → 拒绝（修复前 = 静默空 passphrase → 派生错钱包）
    let rc = shlosilo_export_readonly_ffi(
        idx.as_ptr(),
        12,
        core::ptr::null(),
        1, // len>0 + NULL = 非法组合
        0,
        elems.as_ptr(),
        elems.len() as u32,
        0,
        buf.as_mut_ptr(),
        buf.len() as u32,
        &mut actual,
    );
    assert_eq!(rc, INVALID_ARG, "(NULL, len=1) passphrase 必须稳定拒绝");
    assert_eq!(actual, 0);

    // (NULL, 0) 仍允许（语义：无 passphrase）——用足够大的 buffer 走完整导出
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
    assert_eq!(rc, shlosilo::ffi::error_code::OK, "(NULL, 0) 是合法组合");
    assert!(core::str::from_utf8(&big[..actual_big as usize])
        .unwrap()
        .starts_with("ur:crypto-hdkey/"));
}

// ── 3. 窄化回绕拒绝 ──

#[test]
fn p002_network_wraparound_rejected() {
    let idx = valid_indices();
    let mut out = [0u8; 64];
    let mut actual: u32 = 0;
    // network = 256 → `as u8` 回绕成 0（BitcoinMainnet）；修复后必须拒绝
    let big_nets = [256u64, 512, u64::from(u32::MAX), 0x1_0000_0000];
    for &bad_net_u64 in &big_nets {
        // FFI 参数是 c_uint(32bit)；窄化回绕在 32bit 值域内已可复现（256 → 0）
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
            "network={bad_net} 不得回绕成合法值"
        );
    }
}

#[test]
fn p002_sides_wraparound_rejected() {
    // sides = 262 → `as u8` 回绕成 6；修复后必须拒绝（InvalidDiceConfig 域）
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
    assert_ne!(rc, shlosilo::ffi::error_code::OK, "sides=262 不得回绕成 6");
}

// ── 4. out-param 序言清零（null early-return 路径）──

#[test]
fn p002_outparam_zeroed_on_null_early_return() {
    let _idx = valid_indices(); // 语义占位：合法 idx 也不该救 null 指针
    let mut out = [0u8; 64];
    // 预填垃圾值，模拟 C 侧栈残留
    let mut actual: u32 = 0xDEAD_BEEF;

    // mnemonic_indices = NULL → ERR_NULL_POINTER，但 actual_len 必须已被清零
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
        "null early-return 前必须清零 out-param（修复前残留 0xDEADBEEF）"
    );

    // export 同路径
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

// ── 5. 冒烟：合法路径不受影响 ──

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

fn alloc_cstring(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).unwrap()
}
