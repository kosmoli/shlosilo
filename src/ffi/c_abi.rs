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
use crate::business;
use crate::derivation::path::DerivationPath;
use crate::entropy::mnemonic::{Mnemonic, WordCount};
use crate::error::{ShlosiloError, ShlosiloErrorKind};
use crate::ffi::error_code::{
    to_ffi_code, ERR_BUFFER_TOO_SMALL, ERR_NULL_POINTER, ERR_PANIC, OK,
};
use crate::network::Network;
use crate::types::SecretBytes;

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
#[allow(clippy::not_unsafe_ptr_arg_deref)] // 契约：入口先 null-check 再 from_raw_parts；C 侧保证指针有效性或接受 NULL 错误码
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
        Ok(Err(e)) => {
            // R2：失败路径 actual_len 清零——调用方不得读到残留值
            write_actual_len(actual_len, 0);
            to_ffi_code(&e)
        }
        Err(_) => {
            write_actual_len(actual_len, 0);
            ERR_PANIC
        }
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
#[allow(clippy::not_unsafe_ptr_arg_deref)] // 契约：入口先 null-check 再 from_raw_parts；C 侧保证指针有效性或接受 NULL 错误码
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

        let network_parsed = Network::try_from_u8(network as u8)
            .ok_or_else(|| err(ShlosiloErrorKind::NetworkUnrecognized))?;

        let input = business::sign::SignInput::Mnemonic {
            mnemonic,
            passphrase: pass_slice,
        };
        // P1-02：network 进决策（BTC mainnet-only / ETH chain_id 映射校验）
        business::sign::check_network(decoded.type_tag(), decoded.as_ref(), network_parsed)?;
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
        Ok(Err(e)) => {
            // R2：失败路径 actual_len 清零——调用方不得读到残留值
            write_actual_len(actual_len, 0);
            to_ffi_code(&e)
        }
        Err(_) => {
            write_actual_len(actual_len, 0);
            ERR_PANIC
        }
    }
}

/// shlosilo_export_readonly_ffi — mnemonic + path → 只读凭证 UR
///
/// **P1-04（2026-08-29）**：seed 不再跨 FFI。入口收 mnemonic indices + passphrase，
/// 库内现场恢复 BIP-39 seed（栈 buffer，`SecretBytes::take` 接管清零），导出完成即弃。
///
/// paths 为 flat u32 数组（hardened bit = 0x8000_0000），
/// `path_elem_count` 是这一个 path 的元素数（v1 单 path）。
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // 契约：入口先 null-check 再 from_raw_parts；C 侧保证指针有效性或接受 NULL 错误码
pub extern "C" fn shlosilo_export_readonly_ffi(
    mnemonic_indices: *const u16,
    mnemonic_count: c_int,
    passphrase: *const u8,
    passphrase_len: c_uint,
    network: c_uint,
    path_elems: *const u32,
    path_elem_count: c_uint,
    protocol: c_uint, // ExportProtocol as u32
    output_buf: *mut u8,
    output_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    if mnemonic_indices.is_null() || path_elems.is_null() || output_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {

        let mnem_slice =
            unsafe { slice::from_raw_parts(mnemonic_indices, mnemonic_count as usize) };
        let out_slice = unsafe { slice::from_raw_parts_mut(output_buf, output_buf_len as usize) };
        let elem_slice = unsafe { slice::from_raw_parts(path_elems, path_elem_count as usize) };
        let path = DerivationPath::from_flat(elem_slice.iter().copied())
            .map_err(|_| err(ShlosiloErrorKind::DerivationPathInvalidSyntax))?;

        let pass_slice = unsafe { bytes_in(passphrase, passphrase_len as usize) };
        if pass_slice.len() > PASSPHRASE_MAX_LEN {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }

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

        // seed 现场恢复：栈 buffer → SecretBytes 接管（原副本清零）→ 导出 → scope 末 ZeroizeOnDrop
        let wc = WordCount::try_from_count(mnemonic_count as usize)
            .ok_or_else(|| err(ShlosiloErrorKind::MnemonicInvalidWordCount))?;
        let mnemonic = Mnemonic::from_indices(mnem_slice, wc)
            .map_err(|_| err(ShlosiloErrorKind::MnemonicInvalidWord))?;
        let mut seed_buf = [0u8; 64];
        business::restore_seed::restore_seed(&mnemonic, pass_slice, &mut seed_buf)?;
        let seed = SecretBytes::take(&mut seed_buf);

        business::export_readonly::export_readonly(protocol, seed.expose(), network, &[path], out_slice)
    });

    match result {
        Ok(Ok(length)) => {
            write_actual_len(actual_len, length);
            OK
        }
        Ok(Err(e)) => {
            // R2：失败路径 actual_len 清零——调用方不得读到残留值
            write_actual_len(actual_len, 0);
            to_ffi_code(&e)
        }
        Err(_) => {
            write_actual_len(actual_len, 0);
            ERR_PANIC
        }
    }
}

/// shlosilo_create_account_ffi — dice entropy → mnemonic(u16 LE 索引对)
///
/// **P1-04（2026-08-29）**：`seed_out` 删除——seed 不跨 FFI（v2 安全模型）。
/// dice → mnemonic 是唯一产出；后续签名/导出直接收 mnemonic（库内现场恢复 seed）。
/// passphrase 保留（未来离线 create 时写进设备存储的元数据），当前仅做上限校验。
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // 契约：入口先 null-check 再 from_raw_parts；C 侧保证指针有效性或接受 NULL 错误码
pub extern "C" fn shlosilo_create_account_ffi(
    word_count: c_uint, // 12 / 15 / 18 / 21 / 24
    sides: c_uint,
    rolls: *const u8,
    rolls_count: c_uint,
    passphrase: *const u8,
    passphrase_len: c_uint,
    mnemonic_buf: *mut u8, // word_count × 2 bytes（u16 LE 索引）
    mnemonic_buf_len: c_uint,
) -> c_int {
    if rolls.is_null() || mnemonic_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> Result<(), ShlosiloError> {

        if rolls_count as usize > ROLLS_MAX_COUNT {
            return Err(err(ShlosiloErrorKind::DiceRollsInvalidCount));
        }
        let rolls_slice = unsafe { slice::from_raw_parts(rolls, rolls_count as usize) };
        let mnemonic_slice =
            unsafe { slice::from_raw_parts_mut(mnemonic_buf, mnemonic_buf_len as usize) };
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
        )
    });

    match result {
        Ok(Ok(())) => OK,
        Ok(Err(e)) => to_ffi_code(&e), // create_account 无 actual_len out-param
        Err(_) => ERR_PANIC,
    }
}

// P1-04（2026-08-29）：shlosilo_restore_seed_ffi 已删除——seed 不跨 FFI 后该入口
// 无存在价值（Kosmo 拍板）。mnemonic 合法性校验在 sign/export 入口内联完成。

/// 支持的 Network u8 列表（L3 启动时 UI dispatch 用）
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // 契约：入口先 null-check 再 from_raw_parts；C 侧保证指针有效性或接受 NULL 错误码
pub extern "C" fn shlosilo_supported_networks_ffi(
    output_buf: *mut u8,
    output_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    write_actual_len(actual_len, 0); // Gate4 #2: out-param 前置清零
    if output_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        let out_slice = unsafe { slice::from_raw_parts_mut(output_buf, output_buf_len as usize) };
        // Gate4 #1：真实矩阵——只列业务入口可成功完成的 network：
        // BTC crypto-psbt 仅 mainnet（check_network 拒其余）；ETH mainnet/sepolia/goerli；
        // XMR 固定 MoneroPath::mainnet。testnet/signet/stagenet 未支持，不宣称。
        const SUPPORTED: [u8; 5] = [
            0,  // BitcoinMainnet
            10, // EthereumMainnet
            11, // EthereumSepolia
            12, // EthereumGoerli
            90, // MoneroMainnet
        ];
        if out_slice.len() < SUPPORTED.len() {
            return Err(err(ShlosiloErrorKind::BufferTooSmall));
        }
        out_slice[..SUPPORTED.len()].copy_from_slice(&SUPPORTED);
        Ok(SUPPORTED.len())
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
#[allow(clippy::not_unsafe_ptr_arg_deref)] // 契约：入口先 null-check 再 from_raw_parts；C 侧保证指针有效性或接受 NULL 错误码
pub extern "C" fn shlosilo_supported_protocols_ffi(
    output_buf: *mut u8,
    output_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    write_actual_len(actual_len, 0); // Gate4 #2: out-param 前置清零
    if output_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        let out_slice = unsafe { slice::from_raw_parts_mut(output_buf, output_buf_len as usize) };
        // Gate4 #1（2026-09-01 再复审）：capability 只能宣称业务入口可成功完成的项。
        // export_readonly 实际只实现 CryptoHdKey（且仅 mainnet），
        // 其余 arm 全部返回 ExportProtocolUnimplemented——不得进入 capability 列表。
        let protocols = [0u8]; // CryptoHdKey
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

// ─── R3 typed 多分片 FFI（2026-08-31）─────────────────────────────
mod r3 {
    use super::*;
    use crate::ur::ur_multipart::{UrMultipartDecoder, UrMultipartEncoder, MULTIPART_FRAME_MAX_LEN};
    use alloc::boxed::Box;


// ─── R3: typed 多分片 FFI（2026-08-31 定稿——替代 legacy 首字节猜 type）───
//
// 双通道架构（对齐 keystone gui_model.c 模式）：
//   单帧大 QR  = 已有 shlosilo_sign_ur_ffi / ur_encode::encode（payload ≤ UR_PAYLOAD_MAX_LEN）
//   多分片动画 = 本组三个函数（payload ≤ 16 KiB，帧流 `ur:<type>/<seq>-<count>/<bw>`）
//
// 句柄契约：
//   - encode_begin / decode_new 返回句柄（Box::into_raw 裸指针，非 null = 成功）
//   - 同一句柄重复使用/重复 free 是 L3 bug——debug_assert + 返回错误码兜底
//   - encode_free / decode_free 释放；其余函数对 null 句柄返回 ERR_NULL_POINTER

/// 单帧字符串写出上限（L3 缓冲区；200B 分片 → 帧 ≈ 420 字符，1024 足够）
const FRAME_BUF_MAX_LEN: usize = 1024;

/// R3: 创建多分片编码器。成功返回句柄（非 null），失败返回 null。
/// type_name: ASCII 字母数字 + '-'（如 "xmr-txunsigned"）
/// L3 完成后必须调用 shlosilo_ur_encode_free。
#[no_mangle]
pub extern "C" fn shlosilo_ur_encode_begin(
    type_name: *const c_char,
    payload: *const u8,
    payload_len: c_uint,
    max_fragment_len: c_uint,
) -> *mut UrMultipartEncoder {
    let result = ffi_catch_unwind!(|| -> Option<*mut UrMultipartEncoder> {
        if type_name.is_null() || payload.is_null() {
            return None;
        }
        // type_name: C string → &str（扫到 \0，上限 64）
        let mut tlen = 0usize;
        unsafe {
            while *type_name.add(tlen) != 0 {
                tlen += 1;
                if tlen > 64 {
                    return None;
                }
            }
        }
        let tslice = unsafe { slice::from_raw_parts(type_name as *const u8, tlen) };
        let tname = core::str::from_utf8(tslice).ok()?;
        let pslice = unsafe { slice::from_raw_parts(payload, payload_len as usize) };
        let enc = UrMultipartEncoder::new(tname, pslice, max_fragment_len as usize).ok()?;
        Some(Box::into_raw(Box::new(enc)))
    });
    match result {
        Ok(Some(h)) => h,
        _ => core::ptr::null_mut(),
    }
}

/// R3: 取下一帧 URI 字符串（写 frame_buf，NUL 结尾）。
/// 返回 0 = Ok；负数 = 错误码。重复调用产出 fountain 冗余帧流。
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn shlosilo_ur_encode_next(
    handle: *mut UrMultipartEncoder,
    frame_buf: *mut u8,
    frame_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    write_actual_len(actual_len, 0); // Gate4 #2: out-param 前置清零

    if handle.is_null() || frame_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    if frame_buf_len < FRAME_BUF_MAX_LEN as c_uint {
        // L3 必须给足缓冲
        write_actual_len(actual_len, 0);
        return ERR_BUFFER_TOO_SMALL;
    }
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        let enc = unsafe { &mut *handle };
        let frame = enc.next_frame()?;
        let bytes = frame.as_bytes();
        if bytes.len() + 1 > frame_buf_len as usize {
            return Err(err(ShlosiloErrorKind::EncodingBufferOverflow));
        }
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), frame_buf, bytes.len());
            *frame_buf.add(bytes.len()) = 0;
        }
        Ok(bytes.len())
    });
    match result {
        Ok(Ok(n)) => {
            write_actual_len(actual_len, n);
            OK
        }
        Ok(Err(e)) => {
            write_actual_len(actual_len, 0);
            to_ffi_code(&e)
        }
        Err(_) => {
            write_actual_len(actual_len, 0);
            ERR_PANIC
        }
    }
}

/// R3: XMR cyclic 补扫帧（seq 到顶回 1，无限循环供软件钱包补扫）
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn shlosilo_ur_encode_next_cyclic(
    handle: *mut UrMultipartEncoder,
    frame_buf: *mut u8,
    frame_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    write_actual_len(actual_len, 0); // Gate4 #2: out-param 前置清零

    if handle.is_null() || frame_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    if frame_buf_len < FRAME_BUF_MAX_LEN as c_uint {
        write_actual_len(actual_len, 0);
        return ERR_BUFFER_TOO_SMALL;
    }
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        let enc = unsafe { &mut *handle };
        let frame = enc.next_cyclic_frame()?;
        let bytes = frame.as_bytes();
        if bytes.len() + 1 > frame_buf_len as usize {
            return Err(err(ShlosiloErrorKind::EncodingBufferOverflow));
        }
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), frame_buf, bytes.len());
            *frame_buf.add(bytes.len()) = 0;
        }
        Ok(bytes.len())
    });
    match result {
        Ok(Ok(n)) => {
            write_actual_len(actual_len, n);
            OK
        }
        Ok(Err(e)) => {
            write_actual_len(actual_len, 0);
            to_ffi_code(&e)
        }
        Err(_) => {
            write_actual_len(actual_len, 0);
            ERR_PANIC
        }
    }
}

/// R3: 释放编码器句柄。null 安全（幂等）。
#[no_mangle]
pub extern "C" fn shlosilo_ur_encode_free(handle: *mut UrMultipartEncoder) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle)) };
    }
}

/// R3: 创建多分片解码器。成功返回句柄，失败返回 null。
#[no_mangle]
pub extern "C" fn shlosilo_ur_decode_new() -> *mut UrMultipartDecoder {
    let result = ffi_catch_unwind!(|| -> *mut UrMultipartDecoder {
        Box::into_raw(Box::new(UrMultipartDecoder::new()))
    });
    match result {
        Ok(h) => h,
        Err(_) => core::ptr::null_mut(),
    }
}

/// R3: 喂一帧 URI（NUL 结尾 C string）。
/// 返回 0 = Ok（accepted 状态写 *accepted_out：1=有新信息，0=重复帧）
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn shlosilo_ur_decode_feed(
    handle: *mut UrMultipartDecoder,
    frame: *const c_char,
    accepted_out: *mut c_uint,
) -> c_int {
    if handle.is_null() || frame.is_null() {
        return ERR_NULL_POINTER;
    }
    // Gate4 #2：out-param 前置清零——任何后续失败路径下 C 侧都读到确定值 0
    if !accepted_out.is_null() {
        unsafe { *accepted_out = 0 };
    }
    let result = ffi_catch_unwind!(|| -> Result<bool, ShlosiloError> {
        let mut flen = 0usize;
        unsafe {
            while *frame.add(flen) != 0 {
                flen += 1;
                if flen > MULTIPART_FRAME_MAX_LEN {
                    return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
                }
            }
        }
        let fslice = unsafe { slice::from_raw_parts(frame as *const u8, flen) };
        let fstr = core::str::from_utf8(fslice)
            .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
        let dec = unsafe { &mut *handle };
        dec.receive_frame(fstr)
    });
    match result {
        Ok(Ok(accepted)) => {
            if !accepted_out.is_null() {
                unsafe { *accepted_out = accepted as c_uint };
            }
            OK
        }
        Ok(Err(e)) => to_ffi_code(&e),
        Err(_) => ERR_PANIC,
    }
}

/// R3: 解码进度 0..=99（100 用 complete 表达）
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn shlosilo_ur_decode_progress(handle: *mut UrMultipartDecoder) -> c_int {
    if handle.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> u8 { unsafe { &*handle }.progress() });
    match result {
        Ok(p) => p as c_int,
        Err(_) => ERR_PANIC,
    }
}

/// R3: 是否完成
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn shlosilo_ur_decode_complete(handle: *mut UrMultipartDecoder) -> c_int {
    if handle.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> bool { unsafe { &*handle }.complete() });
    match result {
        Ok(c) => c as c_int,
        Err(_) => ERR_PANIC,
    }
}

/// R3: 取完整 payload（写 payload_buf；实际长度写 actual_len）。
/// 完成前调用 → ERR_UNKNOWN；payload 超过 buf → ERR_BUFFER_TOO_SMALL（actual_len 写需求值）。
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn shlosilo_ur_decode_payload(
    handle: *mut UrMultipartDecoder,
    payload_buf: *mut u8,
    payload_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    write_actual_len(actual_len, 0); // Gate4 #2: out-param 前置清零

    if handle.is_null() || payload_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        let dec = unsafe { &*handle };
        let payload = dec
            .payload()?
            .ok_or_else(err_unknown)?;
        if payload.len() > payload_buf_len as usize {
            return Err(err(ShlosiloErrorKind::BufferTooSmall));
        }
        unsafe {
            core::ptr::copy_nonoverlapping(payload.as_ptr(), payload_buf, payload.len());
        }
        Ok(payload.len())
    });
    // BufferTooSmall 特例：actual_len 写**需求值**（L3 据此重试分配），
    // 其余失败路径保持 R2 清零纪律。
    let required: usize = match &result {
        Ok(Err(e)) if e.kind == ShlosiloErrorKind::BufferTooSmall => {
            ffi_catch_unwind!(|| -> Option<usize> {
                unsafe { &*handle }.payload().ok()?.map(|p| p.len())
            })
            .ok()
            .flatten()
            .unwrap_or(0)
        }
        _ => 0,
    };
    match result {
        Ok(Ok(n)) => {
            write_actual_len(actual_len, n);
            OK
        }
        Ok(Err(e)) => {
            write_actual_len(actual_len, required);
            to_ffi_code(&e)
        }
        Err(_) => {
            write_actual_len(actual_len, 0);
            ERR_PANIC
        }
    }
}

fn err_unknown() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// R3/P0-C（2026-09-01）：取解码后的 UR type（写 type_buf 为 NUL 结尾 ASCII）。
/// 完成前或无帧 → EncodingInvalidFormat；缓冲不足 → BufferTooSmall（actual_len 写需求值，含 NUL）。
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn shlosilo_ur_decode_type(
    handle: *mut UrMultipartDecoder,
    type_buf: *mut u8,
    type_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    write_actual_len(actual_len, 0); // Gate4 #2: out-param 前置清零

    if handle.is_null() || type_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        let dec = unsafe { &*handle };
        let t = dec.ur_type().ok_or_else(err_unknown)?;
        // +1 for NUL
        if t.len() + 1 > type_buf_len as usize {
            return Err(err(ShlosiloErrorKind::BufferTooSmall));
        }
        unsafe {
            core::ptr::copy_nonoverlapping(t.as_ptr(), type_buf, t.len());
            *type_buf.add(t.len()) = 0;
        }
        Ok(t.len() + 1)
    });
    // BufferTooSmall 特例：actual_len 写需求值（含 NUL），其余失败清零
    let required: usize = match &result {
        Ok(Err(e)) if e.kind == ShlosiloErrorKind::BufferTooSmall => {
            ffi_catch_unwind!(|| -> Option<usize> {
                Some(unsafe { &*handle }.ur_type()?.len() + 1)
            })
            .ok()
            .flatten()
            .unwrap_or(0)
        }
        _ => 0,
    };
    match result {
        Ok(Ok(n)) => {
            write_actual_len(actual_len, n);
            OK
        }
        Ok(Err(e)) => {
            write_actual_len(actual_len, required);
            to_ffi_code(&e)
        }
        Err(_) => {
            write_actual_len(actual_len, 0);
            ERR_PANIC
        }
    }
}

/// R3/P0-C（2026-09-01）：typed sign——multipart 重组后的 (type, payload) 垂直贯通签名。
/// type_name 必须是已知可签名的 UrTypeTag（拒绝 Unknown/任意字符串）；
/// payload 预算 = MULTIPART_PAYLOAD_MAX_LEN（16 KiB，对齐 multipart 重组上限）。
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn shlosilo_sign_typed_ffi(
    type_name: *const c_char,
    payload: *const u8,
    payload_len: c_uint,
    mnemonic_indices: *const u16,
    mnemonic_count: c_int,
    passphrase: *const u8,
    passphrase_len: c_uint,
    network: c_uint,
    entropy_ptr: *const u8,
    entropy_len: c_uint,
    output_buf: *mut u8,
    output_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    write_actual_len(actual_len, 0); // Gate4 #2: out-param 前置清零

    if type_name.is_null() || payload.is_null() || mnemonic_indices.is_null() || output_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        if !(12..=24).contains(&mnemonic_count) {
            return Err(err(ShlosiloErrorKind::MnemonicInvalidWordCount));
        }
        // C string → &str（type 名 ≤ 64 字符足够）
        let mut tlen = 0usize;
        unsafe {
            while *type_name.add(tlen) != 0 {
                tlen += 1;
                if tlen > 64 {
                    return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
                }
            }
        }
        let t_slice = unsafe { slice::from_raw_parts(type_name as *const u8, tlen) };
        let t_str = core::str::from_utf8(t_slice)
            .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
        let tag = crate::ur::ur_encode::UrTypeTag::from_name(t_str);
        if matches!(tag, crate::ur::ur_encode::UrTypeTag::Unknown) {
            return Err(err(ShlosiloErrorKind::UrPayloadUnknownType));
        }
        if payload_len as usize > crate::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN {
            return Err(err(ShlosiloErrorKind::UrPayloadTooLarge));
        }
        let payload_slice = unsafe { slice::from_raw_parts(payload, payload_len as usize) };
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
        let network_parsed = Network::try_from_u8(network as u8)
            .ok_or_else(|| err(ShlosiloErrorKind::NetworkUnrecognized))?;
        let input = business::sign::SignInput::Mnemonic {
            mnemonic,
            passphrase: pass_slice,
        };
        business::sign::check_network(tag, payload_slice, network_parsed)?;
        business::sign::sign_with_entropy(input, tag, payload_slice, entropy_slice, out_slice)
    });
    match result {
        Ok(Ok(length)) => {
            write_actual_len(actual_len, length);
            OK
        }
        Ok(Err(e)) => {
            write_actual_len(actual_len, 0);
            to_ffi_code(&e)
        }
        Err(_) => {
            write_actual_len(actual_len, 0);
            ERR_PANIC
        }
    }
}

/// R3: 释放解码器句柄。null 安全（幂等）。
#[no_mangle]
pub extern "C" fn shlosilo_ur_decode_free(handle: *mut UrMultipartDecoder) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle)) };
    }
}

#[cfg(test)]
mod r3_tests {
    use alloc::vec::Vec;
    use super::*;
    use alloc::string::String;

    /// R3 FFI 端到端：encode_begin → next ×N → decode_new → feed → payload 一致
    #[test]
    fn ffi_multipart_roundtrip() {
        let payload: alloc::vec::Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
        let tname = c"xmr-txunsigned".as_ptr();

        let enc = shlosilo_ur_encode_begin(
            tname,
            payload.as_ptr(),
            payload.len() as c_uint,
            200,
        );
        assert!(!enc.is_null());

        let mut frame_buf = [0u8; FRAME_BUF_MAX_LEN];
        let mut actual: c_uint = 0;
        let mut frames: Vec<String> = Vec::new();
        loop {
            let rc = shlosilo_ur_encode_next(enc, frame_buf.as_mut_ptr(), frame_buf.len() as c_uint, &mut actual);
            assert_eq!(rc, OK, "rc={rc}");
            let f = core::str::from_utf8(&frame_buf[..actual as usize]).unwrap();
            let done = f.contains("/11-"); // 1024/200 → 6 fragments; guard below
            frames.push(String::from(f));
            if frames.len() >= 6 {
                break;
            }
            let _ = done;
        }
        // 分片数 = div_ceil(1024,200)=6, fragment_len=171 (fragment_length 公式)
        assert_eq!(frames.len(), 6);
        assert!(frames[0].starts_with("ur:xmr-txunsigned/1-6/"));

        let dec = shlosilo_ur_decode_new();
        assert!(!dec.is_null());
        for f in &frames {
            let cf = alloc::ffi::CString::new(f.as_str()).unwrap();
            let mut accepted: c_uint = 0;
            let rc = shlosilo_ur_decode_feed(dec, cf.as_ptr(), &mut accepted);
            assert_eq!(rc, OK);
        }
        assert_eq!(shlosilo_ur_decode_complete(dec), 1);

        let mut out = [0u8; 2048];
        let rc = shlosilo_ur_decode_payload(dec, out.as_mut_ptr(), out.len() as c_uint, &mut actual);
        assert_eq!(rc, OK);
        assert_eq!(actual as usize, payload.len());
        assert_eq!(&out[..payload.len()], &payload[..]);

        // cyclic 帧：seq 回 1
        let rc = shlosilo_ur_encode_next_cyclic(enc, frame_buf.as_mut_ptr(), frame_buf.len() as c_uint, &mut actual);
        assert_eq!(rc, OK);
        let f = core::str::from_utf8(&frame_buf[..actual as usize]).unwrap();
        assert!(f.starts_with("ur:xmr-txunsigned/1-6/"), "cyclic={f}");

        shlosilo_ur_encode_free(enc);
        shlosilo_ur_decode_free(dec);
        // free 后 double free 防护由 L3 契约保证（C 侧置空）；Rust 侧 null 安全
        shlosilo_ur_encode_free(core::ptr::null_mut());
        shlosilo_ur_decode_free(core::ptr::null_mut());
    }


    /// P0-C E2E（2026-09-01）: multipart(真实 Sparrow signet PSBT ~12KB) → decode_type
    /// → shlosilo_sign_typed_ffi 全链路。payload = CBOR bytes item（与单帧 UR 语义一致）。
    #[test]
    fn p0c_typed_sign_vertical_slice() {
        use alloc::ffi::CString;
        const PSBT: &[u8] = include_bytes!("/home/komo/testTX/test.psbt");
        let ur_payload = crate::encoding::cbor::encode_bytes(PSBT);
        assert!(ur_payload.len() > 4096, "fixture must exceed single-frame legacy budget");

        // mnemonic indices（p63 同源: entropy f284fb... → 12 词）
        let ent: [u8; 16] = [
            0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2,
            0x29, 0x16,
        ];
        let mnem = crate::entropy::mnemonic::Mnemonic::from_entropy(&ent).unwrap();
        let idx: Vec<u16> = mnem.indices().to_vec();

        // multipart encode
        let tname = c"crypto-psbt".as_ptr();
        let enc = shlosilo_ur_encode_begin(
            tname,
            ur_payload.as_ptr(),
            ur_payload.len() as c_uint,
            200,
        );
        assert!(!enc.is_null());
        let frag_count = ur_payload.len().div_ceil(200);
        let mut frame_buf = [0u8; FRAME_BUF_MAX_LEN];
        let mut flen: c_uint = 0;
        let dec = shlosilo_ur_decode_new();
        for _ in 0..frag_count {
            let rc = shlosilo_ur_encode_next(enc, frame_buf.as_mut_ptr(), frame_buf.len() as c_uint, &mut flen);
            assert_eq!(rc, OK);
            let cf = CString::new(&frame_buf[..flen as usize]).unwrap();
            let mut accepted: c_uint = 0;
            let rc = shlosilo_ur_decode_feed(dec, cf.as_ptr(), &mut accepted);
            assert_eq!(rc, OK, "feed rc={rc}");
        }
        assert_eq!(shlosilo_ur_decode_complete(dec), 1);

        // type 提取
        let mut tbuf = [0u8; 64];
        let mut tlen: c_uint = 0;
        let rc = shlosilo_ur_decode_type(dec, tbuf.as_mut_ptr(), tbuf.len() as c_uint, &mut tlen);
        assert_eq!(rc, OK);
        assert_eq!(&tbuf[..tlen as usize - 1], b"crypto-psbt");

        // payload 提取
        let mut pbuf = [0u8; 16384];
        let mut plen: c_uint = 0;
        let rc = shlosilo_ur_decode_payload(dec, pbuf.as_mut_ptr(), pbuf.len() as c_uint, &mut plen);
        assert_eq!(rc, OK);
        assert_eq!(plen as usize, ur_payload.len());
        assert_eq!(&pbuf[..plen as usize], &ur_payload[..]);

        // typed sign: check_network requires BitcoinMainnet(u8=0) for crypto-psbt
        let tname_c = CString::new("crypto-psbt").unwrap();
        let mut out = [0u8; 16384 + 512];
        let mut olen: c_uint = 0;
        let rc = shlosilo_sign_typed_ffi(
            tname_c.as_ptr(),
            pbuf.as_ptr(),
            plen,
            idx.as_ptr(),
            idx.len() as c_int,
            core::ptr::null(), // passphrase
            0,
            0, // network: mainnet(PSBT fixture 是 signet——check_network 对 crypto-psbt 要求 mainnet?)
            core::ptr::null(),
            0, // entropy
            out.as_mut_ptr(),
            out.len() as c_uint,
            &mut olen,
        );
        assert_eq!(rc, OK, "typed sign rc={rc}");
        assert!(olen as usize > PSBT.len(), "signed output larger than unsigned");
        shlosilo_ur_encode_free(enc);
        shlosilo_ur_decode_free(dec);
    }

    /// P0-C: type 缓冲不足 → BufferTooSmall 写需求值
    #[test]
    fn p0c_type_buffer_too_small() {
        use alloc::ffi::CString;
        let payload = [7u8; 8];
        let enc = shlosilo_ur_encode_begin(c"crypto-psbt".as_ptr(), payload.as_ptr(), 8, 8);
        let dec = shlosilo_ur_decode_new();
        let mut frame_buf = [0u8; FRAME_BUF_MAX_LEN];
        let mut flen: c_uint = 0;
        let rc = shlosilo_ur_encode_next(enc, frame_buf.as_mut_ptr(), frame_buf.len() as c_uint, &mut flen);
        assert_eq!(rc, OK);
        let cf = CString::new(&frame_buf[..flen as usize]).unwrap();
        let rc = shlosilo_ur_decode_feed(dec, cf.as_ptr(), core::ptr::null_mut());
        assert_eq!(rc, OK);

        let mut tbuf = [0u8; 4];
        let mut tlen: c_uint = 0;
        let rc = shlosilo_ur_decode_type(dec, tbuf.as_mut_ptr(), tbuf.len() as c_uint, &mut tlen);
        assert_eq!(rc, to_ffi_code(&err(ShlosiloErrorKind::BufferTooSmall)));
        assert!(tlen as usize > "crypto-psbt".len());
        shlosilo_ur_encode_free(enc);
        shlosilo_ur_decode_free(dec);
    }
    /// null 句柄/指针防护
    #[test]
    fn ffi_multipart_null_guards() {
        assert!(shlosilo_ur_encode_begin(core::ptr::null(), core::ptr::null(), 0, 200).is_null());
        assert!(!shlosilo_ur_decode_new().is_null());
        let dec = shlosilo_ur_decode_new();
        assert_eq!(shlosilo_ur_decode_feed(core::ptr::null_mut(), c"x".as_ptr(), core::ptr::null_mut()), ERR_NULL_POINTER);
        assert_eq!(shlosilo_ur_decode_progress(core::ptr::null_mut()), ERR_NULL_POINTER);
        assert_eq!(shlosilo_ur_decode_complete(dec), 0);
        shlosilo_ur_decode_free(dec);
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
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
        // P1-04：seed → mnemonic indices + passphrase
        const _: extern "C" fn(
            *const u16,
            c_int,
            *const u8,
            c_uint,
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
        // P1-04：seed_out 参数删除
        const _: extern "C" fn(
            c_uint,
            c_uint,
            *const u8,
            c_uint,
            *const u8,
            c_uint,
            *mut u8,
            c_uint,
        ) -> c_int = shlosilo_create_account_ffi;
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
        let rc = shlosilo_create_account_ffi(
            12,
            6,
            rolls.as_ptr(),
            rolls.len() as c_uint,
            null(),
            0,
            mnemonic_buf.as_mut_ptr(),
            mnemonic_buf.len() as c_uint,
        );
        assert_eq!(rc, OK, "rc={rc}");
        // 第一个词索引应为合法 BIP-39 index
        let first = u16::from_le_bytes([mnemonic_buf[0], mnemonic_buf[1]]);
        assert!(first < 2048);
    }

    /// 真实调用：export_readonly(CryptoHdKey) 出 ur:crypto-hdkey/
    #[test]
    fn ffi_export_hdkey_smoke() {
        // P1-04：入口收 mnemonic（官方向量 abandon×11 + about），seed 库内现场恢复
        let idx: [u16; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        // m/44'/0'/0'/0/0 flat: hardened bit 0x80000000
        let elems: [u32; 5] = [
            44 | 0x8000_0000,
            0x8000_0000,
            0x8000_0000,
            0,
            0,
        ];
        let mut buf = [0u8; 1024];
        let mut actual: c_uint = 0;
        let rc = shlosilo_export_readonly_ffi(
            idx.as_ptr(),
            idx.len() as c_int,
            null(), // passphrase
            0,
            0,      // BitcoinMainnet
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
        // Gate4 #1: 真实矩阵 = BTC mainnet / ETH mainnet+sepolia+goerli / XMR mainnet
        assert_eq!(n, 5);
        assert_eq!(&net_buf[..5], &[0u8, 10, 11, 12, 90]);

        let mut proto_buf = [0u8; 16];
        let mut p: c_uint = 0;
        let rc = shlosilo_supported_protocols_ffi(
            proto_buf.as_mut_ptr(),
            proto_buf.len() as c_uint,
            &mut p,
        );
        assert_eq!(rc, OK);
        assert_eq!(p, 1); // 只 CryptoHdKey（其余 export arm 均 Unimplemented）
        assert_eq!(proto_buf[0], 0);

        // BufferTooSmall 也要成立: 2 槽装不下 5
        let mut tiny = [0u8; 2];
        let mut t: c_uint = 0;
        let rc = shlosilo_supported_networks_ffi(tiny.as_mut_ptr(), 2, &mut t);
        assert_eq!(rc, ERR_BUFFER_TOO_SMALL);
    }

    // ── P2-03：FFI 入口资源上限 ──

    /// passphrase 超上限（>256B）→ EncodingInvalidFormat
    #[test]
    fn ffi_passphrase_over_limit_rejected() {
        // P1-04：restore_seed_ffi 已删——passphrase 上限改经 export_readonly_ffi 验证
        let idx: [u16; 12] = [0; 12];
        let long_pass = [0x41u8; 257]; // 257 > 256
        let elems: [u32; 1] = [44 | 0x8000_0000];
        let mut buf = [0u8; 64];
        let mut actual: c_uint = 0;
        let rc = shlosilo_export_readonly_ffi(
            idx.as_ptr(),
            idx.len() as c_int,
            long_pass.as_ptr(),
            long_pass.len() as c_uint,
            0, // network
            elems.as_ptr(),
            elems.len() as c_uint,
            0, // protocol
            buf.as_mut_ptr(),
            buf.len() as c_uint,
            &mut actual,
        );
        // R2：FFI 错误码为稳定负码（ShlosiloErrorCode::EncodingError = -21）
        assert_eq!(rc, crate::error::ShlosiloErrorCode::EncodingError as i32);
        // 256 = 上限内 → 通过 passphrase 校验（后续 BIP-39 checksum 拒绝全 0 词组，非 EncodingInvalidFormat）
        let ok_pass = [0x41u8; 256];
        let rc = shlosilo_export_readonly_ffi(
            idx.as_ptr(),
            idx.len() as c_int,
            ok_pass.as_ptr(),
            ok_pass.len() as c_uint,
            0,
            elems.as_ptr(),
            elems.len() as c_uint,
            0,
            buf.as_mut_ptr(),
            buf.len() as c_uint,
            &mut actual,
        );
        // 全 0 词组 checksum 不合法 → MnemonicInvalidChecksum（P1-05 行为，非 passphrase 上限错误）
        assert_eq!(rc, crate::error::ShlosiloErrorCode::InvalidMnemonic as i32, "256B passphrase passes the limit check, rc={rc}");
    }

    /// dice rolls 超上限（>1024）→ DiceRollsInvalidCount
    #[test]
    fn ffi_rolls_over_limit_rejected() {
        let rolls = [1u8; 1025];
        let mut mnemonic_buf = [0u8; 24];
        let rc = shlosilo_create_account_ffi(
            12,
            6,
            rolls.as_ptr(),
            rolls.len() as c_uint,
            null(),
            0,
            mnemonic_buf.as_mut_ptr(),
            mnemonic_buf.len() as c_uint,
        );
        assert_eq!(rc, crate::error::ShlosiloErrorCode::InvalidDiceRolls as i32);
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
        assert_eq!(rc, crate::error::ShlosiloErrorCode::EncodingError as i32);
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

        // 直签对照：mnemonic → seed 用 L1 直调（P1-04：restore_seed_ffi 已删，seed 不跨 FFI）
        // P1-05：mnemonic 必须 checksum 合法——用官方向量 abandon×11 + about (idx[11]=3)
        let mut idx: [u16; 12] = [0; 12];
        idx[11] = 3;
        let m = Mnemonic::from_indices(&idx, WordCount::Words12).unwrap();
        let ff_seed = crate::entropy::bip39_passphrase::mnemonic_to_seed(&m, b"").unwrap();
        let path = crate::derivation::path::DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let sk =
            crate::derivation::bip32_secp256k1::derive_from_seed(ff_seed.as_ref(), &path).unwrap();
        let expected = eip1559::sign_eip1559(&eip1559::Eip1559SignInput {
            tx,
            private_key: crate::types::SecretBytes::new(crate::curve_primitive::secp256k1::scalar_to_bytes(&sk)),
        })
        .unwrap();

        let uri_c = alloc::ffi::CString::new(uri).unwrap();
        let mut out = [0u8; 512];
        let mut actual: c_uint = 0;
        let rc = shlosilo_sign_ur_ffi(
            uri_c.as_ptr(),
            idx.as_ptr(),
            12,
            null(),
            0,
            10, // network = EthereumMainnet（P1-02：ETH chain_id=1 匹配）
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
