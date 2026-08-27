//! ShlosiloError → i32 C-ABI 错误码转换（v2 §3.5）
//!
//! C-ABI 函数返回 `i32`：0 = Ok，负数 = 错误码
//!
//! 与 ShlosiloErrorKind 的数值布局**完全相同**——L3 拿到 i32 直接 dispatch 到错误处理
//!
//! **Phase 2.5 stub**：直接 1:1 转换 ShlosiloErrorKind
//! Phase 5 真实实现：增加 C-ABI 特有的 wrapping 错误码（-1 = Unknown）

use crate::error::ShlosiloError;

/// ShlosiloError → i32（错误码同 ShlosiloErrorKind 数值布局）
pub const fn to_ffi_code(err: &ShlosiloError) -> i32 {
    err.kind as i32
}

/// 通用错误（兜底）：调用方拿到这个 i32 应该 fall back 到 generic error UI
pub const ERR_UNKNOWN: i32 = -1;
pub const ERR_NULL_POINTER: i32 = -2;
pub const ERR_BUFFER_TOO_SMALL: i32 = -3;
pub const ERR_PANIC: i32 = -4;

/// 成功
pub const OK: i32 = 0;

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
        _ => {
            // Phase 5 真实实现：match ShlosiloErrorKind 全部变体
            // 现在 stub：直接说 "Error code: N"
            "Error code from Rust FFI"
        }
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
    fn ffi_code_matches_kind() {
        let err = ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall);
        assert_eq!(to_ffi_code(&err), ShlosiloErrorKind::BufferTooSmall as i32);
    }

    #[test]
    fn describe_known_codes() {
        assert_eq!(describe(OK), "OK");
        assert_eq!(describe(ERR_NULL_POINTER), "Null pointer passed to FFI");
    }
}