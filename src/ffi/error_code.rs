//! ShlosiloError → i32 C-ABI 错误码转换（v2 §3.5）
//!
//! C-ABI 函数返回 `i32`：0 = Ok，负数 = 错误码
//!
//! 与 ShlosiloErrorKind 的数值布局**完全相同**——L3 拿到 i32 直接 dispatch 到错误处理
//!
//! **Phase 2.5 stub**：直接 1:1 转换 ShlosiloErrorKind
//! Phase 5 真实实现：增加 C-ABI 特有的 wrapping 错误码（-1 = Unknown）

use crate::error::{ShlosiloError, ShlosiloErrorCode};

/// ShlosiloError → i32 C-ABI 错误码（稳定负数布局，见 `ShlosiloErrorCode`）
///
/// **R2 整改（2026-08-31）**：原实现直接 `err.kind as i32` 返回正数（如 0x0201_0003），
/// 与「0 = Ok，负数 = 错误」的 C-ABI 契约矛盾。改走 `ShlosiloErrorCode::from_shlosilo_error`
/// 的稳定负码映射（error.rs L2b 分类）。kind 原始值仍可经 Debug 日志获取。
pub fn to_ffi_code(err: &ShlosiloError) -> i32 {
    ShlosiloErrorCode::from_shlosilo_error(*err)
}

/// 通用错误（兜底）：调用方拿到这个 i32 应该 fall back 到 generic error UI
///
/// **错误码对齐（2026-08-31，C 宿主接入前置）**：R2 整改后 `to_ffi_code` 走
/// `ShlosiloErrorCode` 稳定负码，但这四个 FFI 早期返回常量仍是独立旧值
/// （ERR_BUFFER_TOO_SMALL=-3 与映射码 BufferTooSmall=-20 冲突）。现全部并入
/// `ShlosiloErrorCode` 枚举单一真值源：
/// - ERR_UNKNOWN = UnknownError = -1
/// - ERR_NULL_POINTER = InvalidArgument = -2（null 参数即非法参数）
/// - ERR_BUFFER_TOO_SMALL = BufferTooSmall = **-20**（原 -3 作废，shlosilo.h 同步）
/// - ERR_PANIC = FfiPanic = -4（FFI 特有，枚举新增）
pub const ERR_UNKNOWN: i32 = ShlosiloErrorCode::UnknownError as i32;
pub const ERR_NULL_POINTER: i32 = ShlosiloErrorCode::InvalidArgument as i32;
pub const ERR_BUFFER_TOO_SMALL: i32 = ShlosiloErrorCode::BufferTooSmall as i32;
pub const ERR_PANIC: i32 = ShlosiloErrorCode::FfiPanic as i32;

/// 成功
pub const OK: i32 = ShlosiloErrorCode::Ok as i32;

/// i32 → &'static str（错误描述，给 L3 UI 显示）
///
/// 调试用——L3 production UI 应该用整数 dispatch，不用字符串
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
        // R2：FFI 错误码必须是负数（0=Ok 契约），走 ShlosiloErrorCode 稳定映射
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
