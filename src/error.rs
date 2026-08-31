//! Shlosilo 错误码体系

//!
//! **设计原则**（v2.3 接口笔记 §1）：
//! 1. 错误类型唯一——所有 L1 业务函数返回 `Result<T, ShlosiloError>`
//! 2. 错误码可分类——按 5 大数值区间组织（密码学 / 解析 / 业务 / marshaling / invariant）
//! 3. 错误信息可丢失——Display + Debug 足够；不附 Backtrace（省 binary size）
//!
//! **数值布局**：
//!   0x0000_0000           = Ok
//!   0x0100_0000 - 0x01FF_FFFF  = L1 密码学（按曲线/签名方案分）
//!   0x0200_0000 - 0x02FF_FFFF  = L1 解析（UR / Mnemonic / DerivationPath / DiceRolls）
//!   0x0300_0000 - 0x03FF_FFFF  = 业务级（ChainKind / ExportProtocol / Network / Multisig）
//!   0x0400_0000 - 0x04FF_FFFF  = L2a marshaling（buffer 长度 / kind）
//!   0x0500_0000 - 0x05FF_FFFF  = invariant 违反

#[cfg(feature = "std")]
extern crate std;

use core::fmt;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShlosiloErrorKind {
    Ok = 0,

    // ─── L1 密码学（0x01xx_xxxx） ───
    /// secp256k1 scalar 越界
    CryptoSecp256k1InvalidScalar = 0x0101_0001,
    /// secp256k1 point 不在曲线上
    CryptoSecp256k1InvalidPoint = 0x0101_0002,
    /// ECDSA / Schnorr 签名失败
    CryptoSecp256k1SignFailed = 0x0101_0003,
    /// ed25519 scalar 越界
    CryptoEd25519InvalidScalar = 0x0102_0001,
    /// ed25519 point 不在曲线上
    CryptoEd25519InvalidPoint = 0x0102_0002,
    /// EdDSA / CLSAG 签名失败
    CryptoEd25519SignFailed = 0x0102_0003,
    /// RSA 密钥格式无效
    CryptoRsaKeyInvalid = 0x0103_0001,
    /// RSA-PSS 签名失败
    CryptoRsaSignFailed = 0x0103_0002,
    /// sr25519 签名失败（Phase 8+ 真实实现）
    CryptoSr25519SignFailed = 0x0104_0001,

    // ─── L1 解析（0x02xx_xxxx） ───
    /// UR payload CBOR 解码失败
    UrPayloadInvalidCbor = 0x0201_0001,
    /// UR type tag 不在已知集合
    UrPayloadUnknownType = 0x0201_0002,
    /// UR payload 超过 TxTemplate 容量（真实 PSBT 常超 2KB；禁止静默截断）
    UrPayloadTooLarge = 0x0201_0003,
    /// Mnemonic 单词不在 BIP-39 词表
    MnemonicInvalidWord = 0x0202_0001,
    /// Mnemonic checksum 不匹配
    MnemonicInvalidChecksum = 0x0202_0002,
    /// Mnemonic 词数不是 12/15/18/21/24
    MnemonicInvalidWordCount = 0x0202_0003,
    /// entropy 字节数与 word_count 不匹配
    MnemonicInvalidEntropyLength = 0x0202_0004,
    /// 派生路径语法错误
    DerivationPathInvalidSyntax = 0x0203_0001,
    /// 派生路径 index 越界
    DerivationPathIndexOutOfRange = 0x0203_0002,
    /// 骰子面值不在 1..=sides 范围
    DiceRollsInvalidValue = 0x0204_0001,
    /// 骰子数与要求长度不匹配
    DiceRollsInvalidCount = 0x0204_0002,
    /// 骰子面数 < 2
    InvalidDiceConfig = 0x0204_0003,
    /// rolls 切片为空（用户没投过）
    InsufficientRolls = 0x0204_0004,
    /// RNG 注入 entropy 不足（< ENTROPY_MIN_LEN，misuse guard）
    EntropyInjectionInvalid = 0x0204_0005,
    /// X5 rejection sampling：骰序落入余数区（用户需补掷/重掷——概率 ~2^-75，实际不可遇）
    DiceRejectionRolls = 0x0204_0006,

    // ─── 业务级（0x03xx_xxxx） ───
    /// ChainKind::Unknown（UR type tag 无法识别）
    ChainKindUnsupported = 0x0301_0001,
    /// ExportProtocol 变体未实现（如 ZcashAccounts 占位）
    ExportProtocolUnimplemented = 0x0302_0001,
    /// Network 变体识别失败
    NetworkUnrecognized = 0x0303_0001,
    /// v1 不支持多签
    MultisigNotSupported = 0x0304_0001,
    /// Phase 2 stub：算法/编码未接入（原 unimplemented!() panic，P2-01 改稳定错误码）
    FeatureNotImplemented = 0x0305_0001,

    // ─── L2a marshaling（0x04xx_xxxx） ───
    /// output_buf 容量不足
    BufferTooSmall = 0x0401_0001,
    /// Encoding 输出 buffer 溢出（heapless::Vec/String 满）
    EncodingBufferOverflow = 0x0402_0001,
    /// Encoding 字符串格式无效（base58 / bech32 / base64）
    EncodingInvalidFormat = 0x0402_0002,
    /// Encoding checksum 验证失败
    EncodingInvalidChecksum = 0x0402_0003,
    /// sign_input_kind / export_kind 越界
    BufferKindMismatch = 0x0401_0002,
    /// R4: PSBT 所有权绑定失败——BIP32_DERIVATION pubkey ≠ 派生公钥
    PsbtOwnershipMismatch = 0x0403_0001,

    // ─── Invariant 违反（0x05xx_xxxx） ───
    /// 内部不可能状态（unreachable 触发）
    InvariantViolation = 0x0500_0001,
}

impl ShlosiloErrorKind {
    /// 该错误对应的高 8 位区间（用于 L2b i32 映射分类）
    pub const fn category(self) -> u8 {
        ((self as u32) >> 24) as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorContext {
    None,
    /// 解析失败时附带的出错字节值
    InvalidByte(u8),
    /// 派生路径 index 越界时附带的 index 值
    IndexOutOfRange(u32),
    /// buffer 需要的长度
    RequiredLength(usize),
    /// buffer 实际的长度
    ActualLength(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShlosiloError {
    pub kind: ShlosiloErrorKind,
    pub context: ErrorContext,
}

impl ShlosiloError {
    pub const fn ok() -> Self {
        Self { kind: ShlosiloErrorKind::Ok, context: ErrorContext::None }
    }

    pub const fn new(kind: ShlosiloErrorKind) -> Self {
        Self { kind, context: ErrorContext::None }
    }

    pub const fn with_context(kind: ShlosiloErrorKind, context: ErrorContext) -> Self {
        Self { kind, context }
    }

    pub fn is_ok(&self) -> bool {
        self.kind == ShlosiloErrorKind::Ok
    }
}

impl fmt::Display for ShlosiloError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.kind, &self.context) {
            (ShlosiloErrorKind::Ok, _) => write!(f, "OK"),
            (k, ErrorContext::None) => write!(f, "{:?}", k),
            (k, ctx) => write!(f, "{:?} ({:?})", k, ctx),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ShlosiloError {}

pub type Result<T> = core::result::Result<T, ShlosiloError>;

// ============================================================================
// L2b C-ABI 错误码映射（稳定 i32）
// ============================================================================

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShlosiloErrorCode {
    Ok                       = 0,
    UnknownError             = -1,
    InvalidArgument          = -2,
    /// FFI 边界 catch_unwind 兜底（FFI 特有，L2b 映射不产出）
    FfiPanic                 = -4,
    UnsupportedChainKind     = -10,
    UnsupportedExportProtocol = -11,
    UnsupportedNetwork       = -12,
    MultisigNotSupported     = -13,
    FeatureNotImplemented    = -14,
    PsbtOwnershipRejected    = -15,
    BufferTooSmall           = -20,
    EncodingError            = -21,
    InvalidUrPayload         = -30,
    InvalidMnemonic          = -31,
    InvalidDerivationPath    = -32,
    InvalidDiceRolls         = -33,
    CryptoError              = -40,
    InvariantViolation       = -99,
}

impl ShlosiloErrorCode {
    /// L2b::error::to_code 的实现
    pub fn from_shlosilo_error(e: ShlosiloError) -> i32 {
        let code = match e.kind {
            ShlosiloErrorKind::Ok => Self::Ok,
            ShlosiloErrorKind::ChainKindUnsupported => Self::UnsupportedChainKind,
            ShlosiloErrorKind::ExportProtocolUnimplemented => Self::UnsupportedExportProtocol,
            ShlosiloErrorKind::NetworkUnrecognized => Self::UnsupportedNetwork,
            ShlosiloErrorKind::MultisigNotSupported => Self::MultisigNotSupported,
            ShlosiloErrorKind::FeatureNotImplemented => Self::FeatureNotImplemented,
            ShlosiloErrorKind::BufferTooSmall => Self::BufferTooSmall,
            ShlosiloErrorKind::EncodingBufferOverflow
            | ShlosiloErrorKind::EncodingInvalidFormat
            | ShlosiloErrorKind::EncodingInvalidChecksum => Self::EncodingError,
            ShlosiloErrorKind::BufferKindMismatch => Self::InvalidArgument,
            ShlosiloErrorKind::PsbtOwnershipMismatch => Self::PsbtOwnershipRejected,
            ShlosiloErrorKind::UrPayloadInvalidCbor
            | ShlosiloErrorKind::UrPayloadUnknownType => Self::InvalidUrPayload,
            ShlosiloErrorKind::UrPayloadTooLarge => Self::BufferTooSmall,
            ShlosiloErrorKind::MnemonicInvalidWord
            | ShlosiloErrorKind::MnemonicInvalidChecksum
            | ShlosiloErrorKind::MnemonicInvalidWordCount
            | ShlosiloErrorKind::MnemonicInvalidEntropyLength => Self::InvalidMnemonic,
            ShlosiloErrorKind::DerivationPathInvalidSyntax
            | ShlosiloErrorKind::DerivationPathIndexOutOfRange => Self::InvalidDerivationPath,
            ShlosiloErrorKind::DiceRollsInvalidValue
            | ShlosiloErrorKind::DiceRollsInvalidCount
            | ShlosiloErrorKind::InvalidDiceConfig
            | ShlosiloErrorKind::InsufficientRolls
            | ShlosiloErrorKind::EntropyInjectionInvalid
            | ShlosiloErrorKind::DiceRejectionRolls => Self::InvalidDiceRolls,
            ShlosiloErrorKind::CryptoSecp256k1InvalidScalar
            | ShlosiloErrorKind::CryptoSecp256k1InvalidPoint
            | ShlosiloErrorKind::CryptoSecp256k1SignFailed
            | ShlosiloErrorKind::CryptoEd25519InvalidScalar
            | ShlosiloErrorKind::CryptoEd25519InvalidPoint
            | ShlosiloErrorKind::CryptoEd25519SignFailed
            | ShlosiloErrorKind::CryptoRsaKeyInvalid
            | ShlosiloErrorKind::CryptoRsaSignFailed
            | ShlosiloErrorKind::CryptoSr25519SignFailed => Self::CryptoError,
            ShlosiloErrorKind::InvariantViolation => Self::InvariantViolation,
        };
        code as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_round_trip() {
        let e = ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall);
        let code = ShlosiloErrorCode::from_shlosilo_error(e);
        assert_eq!(code, ShlosiloErrorCode::BufferTooSmall as i32);
    }

    #[test]
    fn ok_is_zero() {
        let code = ShlosiloErrorCode::from_shlosilo_error(ShlosiloError::ok());
        assert_eq!(code, 0);
    }

    #[test]
    fn category_classification() {
        assert_eq!(
            ShlosiloErrorKind::CryptoSecp256k1InvalidScalar.category(),
            0x01
        );
        assert_eq!(ShlosiloErrorKind::MnemonicInvalidWord.category(), 0x02);
        assert_eq!(ShlosiloErrorKind::ChainKindUnsupported.category(), 0x03);
        assert_eq!(ShlosiloErrorKind::BufferTooSmall.category(), 0x04);
        assert_eq!(ShlosiloErrorKind::EncodingBufferOverflow.category(), 0x04);
        assert_eq!(ShlosiloErrorKind::EncodingInvalidFormat.category(), 0x04);
        assert_eq!(ShlosiloErrorKind::EncodingInvalidChecksum.category(), 0x04);
        assert_eq!(ShlosiloErrorKind::InvariantViolation.category(), 0x05);
    }
}