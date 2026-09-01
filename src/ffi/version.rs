//! 版本字符串 + 版本号（Phase 5 L3 启动时校验）

/// shlosilo 完整版本（cabi + runtime）
pub const SHLOSILO_VERSION_MAJOR: u16 = 0;
pub const SHLOSILO_VERSION_MINOR: u16 = 5;
pub const SHLOSILO_VERSION_PATCH: u16 = 0;

/// 版本字符串（"v0.5.0-poc4"；带 \0 结尾——C 端可安全 printf/strlen）
pub const SHLOSILO_VERSION_STRING: &str = "v0.5.0-poc4\0";

/// C ABI 版本（**跟 runtime 版本独立**——L3 必须校验 ABI 版本匹配）
///
/// ABI 版本不兼容规则（`shlosilo_cabi_check` 实现为**严格等值**）：
/// - major 不同 → -1（ABI 不兼容，签名/错误码布局变更）
/// - minor 不同 → -2（导出函数集合或语义变更，L3 必须对照新版 shlosilo.h 重编译）
/// - patch 不同 → -3（行为微调，L3 应重新 smoke；检查同样拒绝以保证 determinism）
///
/// 注意：这与传统 semver「minor 增 = 向后兼容」**不同**——本项目 C ABI 处于
/// 0.x 阶段，minor 即破坏性位（与 0.x semver 约定一致）。进入 1.x 后应放宽为
/// major-only 检查。
pub const SHLOSILO_CABI_VERSION_MAJOR: u16 = 0;
pub const SHLOSILO_CABI_VERSION_MINOR: u16 = 3;
pub const SHLOSILO_CABI_VERSION_PATCH: u16 = 0;

/// C ABI 版本字符串（带 \0 结尾）
///
/// **R2 整改（2026-08-31）**：0.1.0 → 0.2.0——错误码布局从正数 kind 直映射
/// 改为 ShlosiloErrorCode 稳定负码（ABI 行为变更），capability 查询补 null guard。
///
/// **审计 #4 整改（2026-09-01）**：0.2.0 → 0.3.0——R3 新增导出
/// shlosilo_sign_typed_ffi / shlosilo_ur_decode_type（导出函数集合变更）；
/// P0-02 入口序言纪律变更（(NULL,len>0) 从静默空切片改为稳定拒绝 = 语义变更）。
pub const SHLOSILO_CABI_VERSION_STRING: &str = "v0.3.0\0";

/// extern "C" 返回版本字符串（C 端 strdup 后用）
#[no_mangle]
pub extern "C" fn shlosilo_version() -> *const u8 {
    SHLOSILO_VERSION_STRING.as_ptr()
}

/// extern "C" 返回 C ABI 版本字符串
#[no_mangle]
pub extern "C" fn shlosilo_cabi_version() -> *const u8 {
    SHLOSILO_CABI_VERSION_STRING.as_ptr()
}

/// L3 启动时校验 ABI 兼容性（major 必须匹配）
///
/// 返回 0 = ABI 兼容，非 0 = 不兼容
#[no_mangle]
pub extern "C" fn shlosilo_cabi_check(
    l3_expected_major: u16,
    l3_expected_minor: u16,
    l3_expected_patch: u16,
) -> i32 {
    if l3_expected_major != SHLOSILO_CABI_VERSION_MAJOR {
        return -1;  // major 不匹配 → ABI 不兼容
    }
    if l3_expected_minor != SHLOSILO_CABI_VERSION_MINOR {
        return -2;  // minor 不匹配 → ABI 不兼容（cabi 改了导出函数签名）
    }
    if l3_expected_patch != SHLOSILO_CABI_VERSION_PATCH {
        return -3;  // patch 不匹配 → 可能行为有微调
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
        // 审计 #4（2026-09-01）：0.2.0 → 0.3.0（R3 新增导出 + P0-02 语义变更）
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