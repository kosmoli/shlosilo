//! C-ABI shim functions for L3 imperative shell (v2 §3.5 + §7.3)
//!
//! **P6.0e 定型**：
//! - 长度类函数带 `actual_len: *mut c_uint` out-param（返回值只作状态码）
//! - null 指针 → ERR_NULL_POINTER（不再是 BufferTooSmall）
//! - catch_unwind 保留（release profile panic = abort 后是零成本兜底）
//!
//! **v2 §4.1 不变量**：
//! - ❌ seed 不跨 FFI——sign 只收 mnemonic indices
//! - ✅ FFI 接受公开材料，返回公开输出

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

/// catch_unwind shim：std 下真正捕获 panic；no_std（panic=abort）下直调
#[cfg(feature = "std")]
macro_rules! ffi_catch_unwind {
    ($body:expr) => {
        std::panic::catch_unwind($body)
    };
}
#[cfg(not(feature = "std"))]
macro_rules! ffi_catch_unwind {
    ($body:expr) => {{
        let r: ::core::result::Result<_, ::core::convert::Infallible> =
            ::core::result::Result::Ok($body());
        r
    }};
}

use core::ffi::{c_char, c_int, c_uint};
use core::slice;

#[cfg(feature = "std")]
use alloc::vec::Vec;

use crate::business;
use crate::derivation::path::DerivationPath;
use crate::entropy::mnemonic::{Mnemonic, WordCount};
use crate::error::{ShlosiloError, ShlosiloErrorKind};
use crate::ffi::error_code::{
    to_ffi_code, ERR_BUFFER_TOO_SMALL, ERR_NULL_POINTER, ERR_PANIC, OK,
};
use crate::network::Network;

fn err(kind: ShlosiloErrorKind) -> ShlosiloError {
    ShlosiloError::new(kind)
}

// ─── P2-03：FFI 入口资源上限（外部 payload 预算）───
/// passphrase 上限：BIP-39 无协议上限，BIP-32 实践 ≤ 256B；超长视为非法输入
const PASSPHRASE_MAX_LEN: usize = 256;
/// dice rolls 上限：24 词 = 256 bit 熵，6 面骰需 ≥ 99 rolls；1024 已超裕量
const ROLLS_MAX_COUNT: usize = 1024;
/// 遗留 sign_ffi payload 上限（与 UR_PAYLOAD_MAX_LEN 对齐）
const LEGACY_PAYLOAD_MAX_LEN: usize = 2048;

/// 把实际长度写回 out-param；null 指针允许（调用方可以只查状态）
fn write_actual_len(ptr: *mut c_uint, len: usize) {
    if !ptr.is_null() {
        unsafe {
            *ptr = len as c_uint;
        }
    }
}

unsafe fn bytes_in<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if p.is_null() {
        &[]
    } else {
        slice::from_raw_parts(p, len)
    }
}

/// shlosilo_sign_ffi — mnemonic + UR payload → 签名
///
/// 返回 0 = Ok（长度写 *actual_len），负数 = 错误码。
#[no_mangle]
pub extern "C" fn shlosilo_sign_ffi(
    mnemonic_indices: *const u16,
    mnemonic_count: c_int, // 12 / 15 / 18 / 21 / 24
    passphrase: *const u8,
    passphrase_len: c_uint,
    ur_payload: *const u8,
    ur_payload_len: c_uint,
    network: c_uint,
    output_buf: *mut u8,
    output_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    if mnemonic_indices.is_null() || ur_payload.is_null() || output_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        if !(12..=24).contains(&mnemonic_count) {
            return Err(err(ShlosiloErrorKind::MnemonicInvalidWordCount));
        }

        let mnem_slice =
            unsafe { slice::from_raw_parts(mnemonic_indices, mnemonic_count as usize) };
        if ur_payload_len as usize > LEGACY_PAYLOAD_MAX_LEN {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let payload_slice = unsafe { slice::from_raw_parts(ur_payload, ur_payload_len as usize) };
        let out_slice = unsafe { slice::from_raw_parts_mut(output_buf, output_buf_len as usize) };
        let pass_slice = unsafe { bytes_in(passphrase, passphrase_len as usize) };
        if pass_slice.len() > PASSPHRASE_MAX_LEN {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }

        let word_count = WordCount::try_from_count(mnemonic_count as usize)
            .ok_or_else(|| err(ShlosiloErrorKind::MnemonicInvalidWordCount))?;
        let mnemonic = Mnemonic::from_indices(mnem_slice, word_count)
            .map_err(|_| err(ShlosiloErrorKind::MnemonicInvalidWord))?;

        let _network = Network::try_from_u8(network as u8)
            .ok_or_else(|| err(ShlosiloErrorKind::NetworkUnrecognized))?;

        let input = business::sign::SignInput::Mnemonic {
            mnemonic,
            passphrase: pass_slice,
        };
        // 遗留接口（无 type tag）：首字节推断仅此 FFI 保留，新调用方用 shlosilo_sign_ur_ffi
        let legacy_tag = crate::ur::ur_encode::UrTypeTag::from_bytes(payload_slice);
        business::sign::sign(input, legacy_tag, payload_slice, out_slice)
    });

    match result {
        Ok(Ok(length)) => {
            write_actual_len(actual_len, length);
            OK
        }
        Ok(Err(e)) => to_ffi_code(&e),
        Err(_) => ERR_PANIC,
    }
}

/// shlosilo_sign_ur_ffi — 完整 UR 字符串 + mnemonic → 签名（P6.1d）
///
/// L3 直接喂 `ur:crypto-psbt/...` / `ur:eth-sign-request/...` / `ur:xmr-txunsigned/...`，
/// UR 解码 + type tag 校验都在库内做（L3 薄、L1 厚）。
///
/// **§B.5 RNG 注入扩展（2026-08-28）**：新增 entropy_ptr / entropy_len 参数——
/// XMR 签名 REQUIRED（≥16B，L3 承诺来源与 min-entropy）；BTC/ETH deterministic
/// backend 传 NULL/0 即可。同一 (keys, tx, entropy) → 同一签名（deterministic retry）。
///
/// 返回 0 = Ok，负数 = 错误码；签名 bytes 写 output_buf。
#[no_mangle]
pub extern "C" fn shlosilo_sign_ur_ffi(
    uri: *const c_char, // null-terminated C string
    mnemonic_indices: *const u16,
    mnemonic_count: c_int,
    passphrase: *const u8,
    passphrase_len: c_uint,
    network: c_uint,
    entropy_ptr: *const u8, // §B.5：可 NULL（BTC/ETH 不需要）
    entropy_len: c_uint,
    output_buf: *mut u8,
    output_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    if uri.is_null() || mnemonic_indices.is_null() || output_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        if !(12..=24).contains(&mnemonic_count) {
            return Err(err(ShlosiloErrorKind::MnemonicInvalidWordCount));
        }

        // C string → &str（无 alloc：直接扫到 \0）
        let mut len = 0usize;
        unsafe {
            while *uri.add(len) != 0 {
                len += 1;
                if len > 4096 {
                    return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
                }
            }
        }
        let uri_slice = unsafe { slice::from_raw_parts(uri as *const u8, len) };
        let uri_str = core::str::from_utf8(uri_slice)
            .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))?;

        // UR 解码
        let decoded = crate::ur::ur_decode::decode(uri_str)?;

        // §B.5 entropy 注入（NULL → 空切片；XMR 分支内部做 ≥16B misuse guard）
        let entropy_slice = unsafe { bytes_in(entropy_ptr, entropy_len as usize) };

        let mnem_slice =
            unsafe { slice::from_raw_parts(mnemonic_indices, mnemonic_count as usize) };
        let out_slice = unsafe { slice::from_raw_parts_mut(output_buf, output_buf_len as usize) };
        let pass_slice = unsafe { bytes_in(passphrase, passphrase_len as usize) };
        if pass_slice.len() > PASSPHRASE_MAX_LEN {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }

        let word_count = WordCount::try_from_count(mnemonic_count as usize)
            .ok_or_else(|| err(ShlosiloErrorKind::MnemonicInvalidWordCount))?;
        let mnemonic = Mnemonic::from_indices(mnem_slice, word_count)
            .map_err(|_| err(ShlosiloErrorKind::MnemonicInvalidWord))?;

        let _network = Network::try_from_u8(network as u8)
            .ok_or_else(|| err(ShlosiloErrorKind::NetworkUnrecognized))?;

        let input = business::sign::SignInput::Mnemonic {
            mnemonic,
            passphrase: pass_slice,
        };
        // P1-01：UR type tag 贯通到业务层（不再靠 payload 首字节推断）
        // §B.5：entropy 透传（XMR REQUIRED / BTC-ETH NOT REQUIRED）
        business::sign::sign_with_entropy(
            input,
            decoded.type_tag(),
            decoded.as_ref(),
            entropy_slice,
            out_slice,
        )
    });

    match result {
        Ok(Ok(length)) => {
            write_actual_len(actual_len, length);
            OK
        }
        Ok(Err(e)) => to_ffi_code(&e),
        Err(_) => ERR_PANIC,
    }
}

/// shlosilo_export_readonly_ffi — seed + path → 只读凭证 UR
///
/// paths 为 flat u32 数组（hardened bit = 0x8000_0000），
/// `path_elem_count` 是这一个 path 的元素数（v1 单 path）。
#[no_mangle]
pub extern "C" fn shlosilo_export_readonly_ffi(
    seed: *const u8, // [u8; 64]
    network: c_uint,
    path_elems: *const u32,
    path_elem_count: c_uint,
    protocol: c_uint, // ExportProtocol as u32
    output_buf: *mut u8,
    output_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    if seed.is_null() || path_elems.is_null() || output_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {

        let seed_slice = unsafe { slice::from_raw_parts(seed, 64) };
        let out_slice = unsafe { slice::from_raw_parts_mut(output_buf, output_buf_len as usize) };
        let elem_slice = unsafe { slice::from_raw_parts(path_elems, path_elem_count as usize) };
        let path = DerivationPath::from_flat(elem_slice.iter().copied())
            .map_err(|_| err(ShlosiloErrorKind::DerivationPathInvalidSyntax))?;

        let network = Network::try_from_u8(network as u8)
            .ok_or_else(|| err(ShlosiloErrorKind::NetworkUnrecognized))?;

        let protocol = match protocol {
            0 => business::export_readonly::ExportProtocol::CryptoHdKey,
            1 => business::export_readonly::ExportProtocol::CryptoAccount,
            2 => business::export_readonly::ExportProtocol::CryptoMultiAccounts,
            3 => business::export_readonly::ExportProtocol::JsonMoneroViewkey,
            4 => business::export_readonly::ExportProtocol::ArweaveCryptoAccount,
            _ => return Err(err(ShlosiloErrorKind::ExportProtocolUnimplemented)),
        };

        business::export_readonly::export_readonly(protocol, seed_slice, network, &[path], out_slice)
    });

    match result {
        Ok(Ok(length)) => {
            write_actual_len(actual_len, length);
            OK
        }
        Ok(Err(e)) => to_ffi_code(&e),
        Err(_) => ERR_PANIC,
    }
}

/// shlosilo_create_account_ffi — dice entropy → mnemonic(u16 LE 索引对) + seed
#[no_mangle]
pub extern "C" fn shlosilo_create_account_ffi(
    word_count: c_uint, // 12 / 15 / 18 / 21 / 24
    sides: c_uint,
    rolls: *const u8,
    rolls_count: c_uint,
    passphrase: *const u8,
    passphrase_len: c_uint,
    mnemonic_buf: *mut u8, // word_count × 2 bytes（u16 LE 索引）
    mnemonic_buf_len: c_uint,
    seed_out: *mut u8, // [u8; 64]
) -> c_int {
    if rolls.is_null() || mnemonic_buf.is_null() || seed_out.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> Result<(), ShlosiloError> {

        if rolls_count as usize > ROLLS_MAX_COUNT {
            return Err(err(ShlosiloErrorKind::DiceRollsInvalidCount));
        }
        let rolls_slice = unsafe { slice::from_raw_parts(rolls, rolls_count as usize) };
        let mnemonic_slice =
            unsafe { slice::from_raw_parts_mut(mnemonic_buf, mnemonic_buf_len as usize) };
        let seed_slice = unsafe { slice::from_raw_parts_mut(seed_out, 64) };
        let pass_slice = unsafe { bytes_in(passphrase, passphrase_len as usize) };
        if pass_slice.len() > PASSPHRASE_MAX_LEN {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }

        let wc = WordCount::try_from_count(word_count as usize)
            .ok_or_else(|| err(ShlosiloErrorKind::MnemonicInvalidWordCount))?;

        business::create_account::create_account(
            wc,
            sides as u8,
            rolls_slice,
            pass_slice,
            mnemonic_slice,
            // safe: len == 64 由 from_raw_parts_mut(…, 64) 保证
            unsafe { &mut *(seed_slice.as_mut_ptr() as *mut [u8; 64]) },
        )
    });

    match result {
        Ok(Ok(())) => OK,
        Ok(Err(e)) => to_ffi_code(&e),
        Err(_) => ERR_PANIC,
    }
}

/// shlosilo_restore_seed_ffi — mnemonic indices + passphrase → BIP-39 seed
#[no_mangle]
pub extern "C" fn shlosilo_restore_seed_ffi(
    mnemonic_indices: *const u16,
    mnemonic_count: c_int,
    passphrase: *const u8,
    passphrase_len: c_uint,
    seed_out: *mut u8, // [u8; 64]
) -> c_int {
    if mnemonic_indices.is_null() || seed_out.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> Result<(), ShlosiloError> {

        let mnem_slice =
            unsafe { slice::from_raw_parts(mnemonic_indices, mnemonic_count as usize) };
        let seed_slice = unsafe { slice::from_raw_parts_mut(seed_out, 64) };
        let pass_slice = unsafe { bytes_in(passphrase, passphrase_len as usize) };
        if pass_slice.len() > PASSPHRASE_MAX_LEN {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }

        let wc = WordCount::try_from_count(mnemonic_count as usize)
            .ok_or_else(|| err(ShlosiloErrorKind::MnemonicInvalidWordCount))?;
        let mnemonic = Mnemonic::from_indices(mnem_slice, wc)
            .map_err(|_| err(ShlosiloErrorKind::MnemonicInvalidWord))?;

        business::restore_seed::restore_seed(
            &mnemonic,
            pass_slice,
            // safe: len == 64
            unsafe { &mut *(seed_slice.as_mut_ptr() as *mut [u8; 64]) },
        )
    });

    match result {
        Ok(Ok(())) => OK,
        Ok(Err(e)) => to_ffi_code(&e),
        Err(_) => ERR_PANIC,
    }
}

/// 支持的 Network u8 列表（L3 启动时 UI dispatch 用）
#[no_mangle]
pub extern "C" fn shlosilo_supported_networks_ffi(
    output_buf: *mut u8,
    output_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        let out_slice = unsafe { slice::from_raw_parts_mut(output_buf, output_buf_len as usize) };
        let mut written = 0usize;
        for i in 0..=143u8 {
            if Network::try_from_u8(i).is_some() {
                if written >= out_slice.len() {
                    return Err(err(ShlosiloErrorKind::BufferTooSmall));
                }
                out_slice[written] = i;
                written += 1;
            }
        }
        Ok(written)
    });

    match result {
        Ok(Ok(n)) => {
            write_actual_len(actual_len, n);
            OK
        }
        Ok(Err(e)) => to_ffi_code(&e),
        Err(_) => ERR_PANIC,
    }
}

/// 支持的 ExportProtocol u8 列表
#[no_mangle]
pub extern "C" fn shlosilo_supported_protocols_ffi(
    output_buf: *mut u8,
    output_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        let out_slice = unsafe { slice::from_raw_parts_mut(output_buf, output_buf_len as usize) };
        let protocols = [
            0u8, // CryptoHdKey
            1,   // CryptoAccount
            2,   // CryptoMultiAccounts
            3,   // JsonMoneroViewkey
            4,   // ArweaveCryptoAccount
        ];
        if out_slice.len() < protocols.len() {
            return Err(err(ShlosiloErrorKind::BufferTooSmall));
        }
        out_slice[..protocols.len()].copy_from_slice(&protocols);
        Ok(protocols.len())
    });

    match result {
        Ok(Ok(n)) => {
            write_actual_len(actual_len, n);
            OK
        }
        Ok(Err(e)) => to_ffi_code(&e),
        Err(_) => ERR_PANIC,
    }
}

// 保留常量引用避免 unused warning
const _: c_int = ERR_NULL_POINTER;
const _: c_int = ERR_BUFFER_TOO_SMALL;
#[allow(unused_imports)]
use alloc::vec::Vec as _VecUnused;

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{null, null_mut};

    #[test]
    fn ffi_sign_signature_exists() {
        const _: extern "C" fn(
            *const u16,
            c_int,
            *const u8,
            c_uint,
            *const u8,
            c_uint,
            c_uint,
            *mut u8,
            c_uint,
            *mut c_uint,
        ) -> c_int = shlosilo_sign_ffi;
    }

    #[test]
    fn ffi_export_signature_exists() {
        const _: extern "C" fn(
            *const u8,
            c_uint,
            *const u32,
            c_uint,
            c_uint,
            *mut u8,
            c_uint,
            *mut c_uint,
        ) -> c_int = shlosilo_export_readonly_ffi;
    }

    #[test]
    fn ffi_create_signature_exists() {
        const _: extern "C" fn(
            c_uint,
            c_uint,
            *const u8,
            c_uint,
            *const u8,
            c_uint,
            *mut u8,
            c_uint,
            *mut u8,
        ) -> c_int = shlosilo_create_account_ffi;
    }

    #[test]
    fn ffi_restore_seed_signature_exists() {
        const _: extern "C" fn(*const u16, c_int, *const u8, c_uint, *mut u8) -> c_int =
            shlosilo_restore_seed_ffi;
    }

    /// 真实调用：官方 BIP-39 向量经 FFI restore_seed 得到正确 seed
    #[test]
    fn ffi_restore_seed_official_vector() {
        let idx: [u16; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        let mut seed_out = [0xFFu8; 64];
        let rc = shlosilo_restore_seed_ffi(idx.as_ptr(), 12, null(), 0, seed_out.as_mut_ptr());
        assert_eq!(rc, OK, "rc={rc}");
        assert_ne!(seed_out, [0u8; 64]);

        // 与 L1 直调一致
        let m = Mnemonic::from_indices(&idx, WordCount::Words12).unwrap();
        let direct = crate::entropy::bip39_passphrase::mnemonic_to_seed(&m, b"").unwrap();
        assert_eq!(seed_out, direct.as_ref());
    }

    /// 真实调用：错误词数 → MnemonicInvalidWordCount 错误码
    #[test]
    fn ffi_restore_seed_bad_word_count() {
        let idx: [u16; 11] = [0; 11];
        let mut seed_out = [0u8; 64];
        let rc = shlosilo_restore_seed_ffi(idx.as_ptr(), 11, null(), 0, seed_out.as_mut_ptr());
        assert_eq!(rc, ShlosiloErrorKind::MnemonicInvalidWordCount as i32);
    }

    /// null 指针拒绝（不崩）
    #[test]
    /// P2-02 审计整改：null 指针 → ERR_NULL_POINTER（文档契约，不再是 BufferTooSmall）
    #[test]
    fn ffi_restore_seed_null_rejected() {
        let rc = shlosilo_restore_seed_ffi(null(), 12, null(), 0, null_mut());
        assert_eq!(rc, ERR_NULL_POINTER);
    }

    /// 真实调用：create_account 经 FFI 出 mnemonic + seed
    #[test]
    fn ffi_create_account_smoke() {
        let rolls: [u8; 64] = {
            let mut r = [0u8; 64];
            for (i, v) in r.iter_mut().enumerate() {
                *v = (i % 6) as u8 + 1;
            }
            r
        };
        let mut mnemonic_buf = [0u8; 24];
        let mut seed_out = [0u8; 64];
        let rc = shlosilo_create_account_ffi(
            12,
            6,
            rolls.as_ptr(),
            rolls.len() as c_uint,
            null(),
            0,
            mnemonic_buf.as_mut_ptr(),
            mnemonic_buf.len() as c_uint,
            seed_out.as_mut_ptr(),
        );
        assert_eq!(rc, OK, "rc={rc}");
        assert_ne!(seed_out, [0u8; 64]);
        // 第一个词索引应为合法 BIP-39 index
        let first = u16::from_le_bytes([mnemonic_buf[0], mnemonic_buf[1]]);
        assert!(first < 2048);
    }

    /// 真实调用：export_readonly(CryptoHdKey) 出 ur:crypto-hdkey/
    #[test]
    fn ffi_export_hdkey_smoke() {
        let seed = [7u8; 64];
        // m/44'/0'/0'/0/0 flat: hardened bit 0x80000000
        let elems: [u32; 5] = [
            44 | 0x8000_0000,
            0 | 0x8000_0000,
            0 | 0x8000_0000,
            0,
            0,
        ];
        let mut buf = [0u8; 1024];
        let mut actual: c_uint = 0;
        let rc = shlosilo_export_readonly_ffi(
            seed.as_ptr(),
            0, // BitcoinMainnet
            elems.as_ptr(),
            elems.len() as c_uint,
            0, // CryptoHdKey
            buf.as_mut_ptr(),
            buf.len() as c_uint,
            &mut actual,
        );
        assert_eq!(rc, OK, "rc={rc}");
        let uri = core::str::from_utf8(&buf[..actual as usize]).unwrap();
        assert!(uri.starts_with("ur:crypto-hdkey/"));
    }

    /// supported_networks / supported_protocols out-param
    #[test]
    fn ffi_supported_lists() {
        let mut net_buf = [0u8; 200];
        let mut n: c_uint = 0;
        let rc = shlosilo_supported_networks_ffi(
            net_buf.as_mut_ptr(),
            net_buf.len() as c_uint,
            &mut n,
        );
        assert_eq!(rc, OK);
        assert!(n > 0);

        let mut proto_buf = [0u8; 16];
        let mut p: c_uint = 0;
        let rc = shlosilo_supported_protocols_ffi(
            proto_buf.as_mut_ptr(),
            proto_buf.len() as c_uint,
            &mut p,
        );
        assert_eq!(rc, OK);
        assert_eq!(p, 5);
    }

    // ── P2-03：FFI 入口资源上限 ──

    /// passphrase 超上限（>256B）→ EncodingInvalidFormat
    #[test]
    fn ffi_passphrase_over_limit_rejected() {
        let idx: [u16; 12] = [0; 12];
        let long_pass = [0x41u8; 257]; // 257 > 256
        let mut seed_out = [0u8; 64];
        let rc = shlosilo_restore_seed_ffi(
            idx.as_ptr(),
            12,
            long_pass.as_ptr(),
            long_pass.len() as c_uint,
            seed_out.as_mut_ptr(),
        );
        assert_eq!(rc, ShlosiloErrorKind::EncodingInvalidFormat as i32);
        // 256 = 上限内 → 通过（合法 checksum 向量：abandon×11 + about）
        let ok_pass = [0x41u8; 256];
        let idx_ok: [u16; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        let rc = shlosilo_restore_seed_ffi(
            idx_ok.as_ptr(),
            12,
            ok_pass.as_ptr(),
            ok_pass.len() as c_uint,
            seed_out.as_mut_ptr(),
        );
        assert_eq!(rc, OK, "256B passphrase should pass, rc={rc}");
    }

    /// dice rolls 超上限（>1024）→ DiceRollsInvalidCount
    #[test]
    fn ffi_rolls_over_limit_rejected() {
        let rolls = [1u8; 1025];
        let mut mnemonic_buf = [0u8; 24];
        let mut seed_out = [0u8; 64];
        let rc = shlosilo_create_account_ffi(
            12,
            6,
            rolls.as_ptr(),
            rolls.len() as c_uint,
            null(),
            0,
            mnemonic_buf.as_mut_ptr(),
            mnemonic_buf.len() as c_uint,
            seed_out.as_mut_ptr(),
        );
        assert_eq!(rc, ShlosiloErrorKind::DiceRollsInvalidCount as i32);
    }

    /// 遗留 sign_ffi payload 超上限（>2048B）→ EncodingInvalidFormat
    #[test]
    fn ffi_legacy_payload_over_limit_rejected() {
        let idx: [u16; 12] = [0; 12];
        let big_payload = [0u8; 2049];
        let mut out = [0u8; 4096];
        let mut actual: c_uint = 0;
        let rc = shlosilo_sign_ffi(
            idx.as_ptr(),
            12,
            null(),
            0,
            big_payload.as_ptr(),
            big_payload.len() as c_uint,
            0, // network
            out.as_mut_ptr(),
            out.len() as c_uint,
            &mut actual,
        );
        assert_eq!(rc, ShlosiloErrorKind::EncodingInvalidFormat as i32);
    }

    #[test]
    fn ffi_version_strings_not_null() {
        use super::super::version::*;
        assert!(!shlosilo_version().is_null());
        assert!(!shlosilo_cabi_version().is_null());
    }

    // ── P6.1d: shlosilo_sign_ur_ffi（收完整 UR 字符串）──

    #[test]
    fn ffi_sign_ur_signature_exists() {
        const _: extern "C" fn(
            *const c_char, // uri (null-terminated)
            *const u16,
            c_int,
            *const u8,
            c_uint,
            c_uint,
            *const u8, // entropy_ptr (§B.5)
            c_uint,    // entropy_len
            *mut u8,
            c_uint,
            *mut c_uint,
        ) -> c_int = shlosilo_sign_ur_ffi;
    }

    /// 端到端：ETH raw tx → ur:eth-sign-request/... → FFI 签名 = 直签
    #[test]
    fn ffi_sign_ur_eth_end_to_end() {
        use crate::chain::eth::{eip1559, rlp};

        let tx = eip1559::Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x22u8; 20]),
            amount: 999,
            data: Vec::new(),
            access_list: Vec::new(),
        };
        let list = rlp::encode_list(&[
            rlp::encode_uint(tx.chain_id as u128),
            rlp::encode_uint(tx.nonce as u128),
            rlp::encode_uint(tx.max_priority_fee_per_gas),
            rlp::encode_uint(tx.max_fee_per_gas),
            rlp::encode_uint(tx.gas_limit as u128),
            rlp::encode_bytes(&tx.destination.unwrap()),
            rlp::encode_uint(tx.amount),
            rlp::encode_bytes(&tx.data),
            rlp::encode_list(&[]),
            rlp::encode_bytes(b""),
            rlp::encode_bytes(b""),
            rlp::encode_bytes(b""),
        ]);
        let mut raw = Vec::new();
        raw.push(0x02u8);
        raw.extend_from_slice(&list);

        // P1-01：payload = 真实 eth-sign-request CBOR map（ur-registry 形状）
        // {2: sign_data, 3: data_type=1, 4: chain_id=1}
        let pairs = alloc::vec![
            (crate::encoding::cbor::encode_uint(2), crate::encoding::cbor::encode_bytes(&raw)),
            (crate::encoding::cbor::encode_uint(3), crate::encoding::cbor::encode_uint(1)),
            (crate::encoding::cbor::encode_uint(4), crate::encoding::cbor::encode_uint(1)),
        ];
        let payload = crate::encoding::cbor::encode_map(&pairs);
        let enc = crate::ur::ur_encode::encode(
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &payload,
        )
        .unwrap();
        let uri = enc.as_str();

        let seed = [7u8; 64];
        // 用 Seed 路径对照：mnemonic indices 全 0 的 seed ≠ [7;64]，
        // 所以这里用 restore_seed 先把 mnemonic→seed，再直签对照
        // P1-05：mnemonic 必须 checksum 合法——全 0 (abandon×12) 校验和不合法，
        // 改用官方向量 abandon×11 + about (idx[11]=3)
        let mut idx: [u16; 12] = [0; 12];
        idx[11] = 3;
        let mut ff_seed = [0u8; 64];
        assert_eq!(
            shlosilo_restore_seed_ffi(idx.as_ptr(), 12, null(), 0, ff_seed.as_mut_ptr()),
            OK
        );
        let path = crate::derivation::path::DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let sk =
            crate::derivation::bip32_secp256k1::derive_from_seed(&ff_seed, &path).unwrap();
        let expected = eip1559::sign_eip1559(&eip1559::Eip1559SignInput {
            tx,
            private_key: crate::curve_primitive::secp256k1::scalar_to_bytes(&sk),
        })
        .unwrap();
        drop(seed);

        let uri_c = alloc::ffi::CString::new(uri).unwrap();
        let mut out = [0u8; 512];
        let mut actual: c_uint = 0;
        let rc = shlosilo_sign_ur_ffi(
            uri_c.as_ptr(),
            idx.as_ptr(),
            12,
            null(),
            0,
            0, // network
            null(), // entropy (§B.5)
            0,
            out.as_mut_ptr(),
            out.len() as c_uint,
            &mut actual,
        );
        assert_eq!(rc, OK, "rc={rc}");
        assert_eq!(actual as usize, expected.tx_bytes.len());
        assert_eq!(&out[..actual as usize], &expected.tx_bytes[..]);
    }

    /// 非 UR 字符串 → 错误码，不崩
    #[test]
    fn ffi_sign_ur_invalid_uri_rejected() {
        let uri_c = alloc::ffi::CString::new("not-a-ur").unwrap();
        let idx: [u16; 12] = [0; 12];
        let mut out = [0u8; 64];
        let mut actual: c_uint = 0;
        let rc = shlosilo_sign_ur_ffi(
            uri_c.as_ptr(),
            idx.as_ptr(),
            12,
            null(),
            0,
            0,
            null(), // entropy (§B.5)
            0,
            out.as_mut_ptr(),
            out.len() as c_uint,
            &mut actual,
        );
        assert_ne!(rc, OK);
    }

    /// null URI 指针拒绝
    #[test]
    fn ffi_sign_ur_null_rejected() {
        let idx: [u16; 12] = [0; 12];
        let mut out = [0u8; 64];
        let rc = shlosilo_sign_ur_ffi(
            null(),
            idx.as_ptr(),
            12,
            null(),
            0,
            0,
            null(), // entropy (§B.5)
            0,
            out.as_mut_ptr(),
            out.len() as c_uint,
            null_mut(),
        );
        assert_eq!(rc, ERR_NULL_POINTER);
    }
}
