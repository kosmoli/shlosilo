//! Shlosilo error code system

//!
//! **Design principles** (v2.3 interface notes §1):
//! 1. Single error type — all L1 business functions return `Result<T, ShlosiloError>`
//! 2. Error codes are classifiable — organized into 5 numeric ranges (cryptography / parsing / business / marshaling / invariant)
//! 3. Error messages may be lost — Display + Debug suffice; no Backtrace attached (saves binary size)
//!
//! **Numeric layout**:
//!   0x0000_0000           = Ok
//!   0x0100_0000 - 0x01FF_FFFF  = L1 cryptography (grouped by curve/signature scheme)
//!   0x0200_0000 - 0x02FF_FFFF  = L1 parsing (UR / Mnemonic / DerivationPath / DiceRolls)
//!   0x0300_0000 - 0x03FF_FFFF  = business level (ChainKind / ExportProtocol / Network / Multisig)
//!   0x0400_0000 - 0x04FF_FFFF  = L2a marshaling (buffer length / kind)
//!   0x0500_0000 - 0x05FF_FFFF  = invariant violations

#[cfg(feature = "std")]
extern crate std;

use core::fmt;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShlosiloErrorKind {
    Ok = 0,

    // ─── L1 cryptography (0x01xx_xxxx) ───
    /// secp256k1 scalar out of range
    CryptoSecp256k1InvalidScalar = 0x0101_0001,
    /// secp256k1 point not on the curve
    CryptoSecp256k1InvalidPoint = 0x0101_0002,
    /// ECDSA / Schnorr signing failure
    CryptoSecp256k1SignFailed = 0x0101_0003,
    /// ed25519 scalar out of range
    CryptoEd25519InvalidScalar = 0x0102_0001,
    /// ed25519 point not on the curve
    CryptoEd25519InvalidPoint = 0x0102_0002,
    /// EdDSA / CLSAG signing failure
    CryptoEd25519SignFailed = 0x0102_0003,
    /// RSA key format invalid
    CryptoRsaKeyInvalid = 0x0103_0001,
    /// RSA-PSS signing failure
    CryptoRsaSignFailed = 0x0103_0002,
    /// sr25519 signing failure (real implementation at Phase 8+)
    CryptoSr25519SignFailed = 0x0104_0001,

    // ─── L1 parsing (0x02xx_xxxx) ───
    /// UR payload CBOR decoding failure
    UrPayloadInvalidCbor = 0x0201_0001,
    /// UR type tag not in the known set
    UrPayloadUnknownType = 0x0201_0002,
    /// UR payload exceeds TxTemplate capacity (real PSBTs often exceed 2KB; silent truncation forbidden)
    UrPayloadTooLarge = 0x0201_0003,
    /// Mnemonic word not in the BIP-39 wordlist
    MnemonicInvalidWord = 0x0202_0001,
    /// Mnemonic checksum mismatch
    MnemonicInvalidChecksum = 0x0202_0002,
    /// Mnemonic word count is not 12/15/18/21/24
    MnemonicInvalidWordCount = 0x0202_0003,
    /// entropy byte count does not match word_count
    MnemonicInvalidEntropyLength = 0x0202_0004,
    /// Derivation path syntax error
    DerivationPathInvalidSyntax = 0x0203_0001,
    /// Derivation path index out of range
    DerivationPathIndexOutOfRange = 0x0203_0002,
    /// Dice face value outside 1..=sides
    DiceRollsInvalidValue = 0x0204_0001,
    /// Dice roll count does not match the required length
    DiceRollsInvalidCount = 0x0204_0002,
    /// Dice sides < 2
    InvalidDiceConfig = 0x0204_0003,
    /// rolls slice empty (the user has not rolled)
    InsufficientRolls = 0x0204_0004,
    /// RNG injection entropy insufficient (< ENTROPY_MIN_LEN, misuse guard)
    EntropyInjectionInvalid = 0x0204_0005,
    /// X5 rejection sampling: the roll sequence lands in the remainder zone. Security semantics = discard the whole group and reroll completely (appending-only top-ups forbidden — non-uniform); probability ~2^-75, practically unreachable
    DiceRejectionRolls = 0x0204_0006,

    // ─── Business level (0x03xx_xxxx) ───
    /// ChainKind::Unknown (unrecognized UR type tag)
    ChainKindUnsupported = 0x0301_0001,
    /// ExportProtocol variant not implemented (e.g. ZcashAccounts placeholder)
    ExportProtocolUnimplemented = 0x0302_0001,
    /// Network variant recognition failure
    NetworkUnrecognized = 0x0303_0001,
    /// v1 does not support multisig
    MultisigNotSupported = 0x0304_0001,
    /// Phase 2 stub: algorithms/encodings not wired in (originally an unimplemented!() panic; P2-01 switched to stable error codes)
    FeatureNotImplemented = 0x0305_0001,

    // ─── L2a marshaling(0x04xx_xxxx) ───
    /// output_buf capacity insufficient
    BufferTooSmall = 0x0401_0001,
    /// Encoding output buffer overflow (heapless::Vec/String full)
    EncodingBufferOverflow = 0x0402_0001,
    /// Encoding string format invalid (base58 / bech32 / base64)
    EncodingInvalidFormat = 0x0402_0002,
    /// Encoding checksum verification failure
    EncodingInvalidChecksum = 0x0402_0003,
    /// sign_input_kind / export_kind out of range
    BufferKindMismatch = 0x0401_0002,
    /// R4: PSBT ownership binding failure — BIP32_DERIVATION pubkey ≠ derived public key
    PsbtOwnershipMismatch = 0x0403_0001,

    // ─── Invariant violations (0x05xx_xxxx) ───
    /// Internal impossible state (unreachable triggered)
    InvariantViolation = 0x0500_0001,
}

impl ShlosiloErrorKind {
    /// The error's high 8-bit range (used for L2b i32 mapping classification)
    pub const fn category(self) -> u8 {
        ((self as u32) >> 24) as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorContext {
    None,
    /// The offending byte value attached on parse failure
    InvalidByte(u8),
    /// The index value attached when a derivation path index is out of range
    IndexOutOfRange(u32),
    /// The length the buffer requires
    RequiredLength(usize),
    /// The buffer's actual length
    ActualLength(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShlosiloError {
    pub kind: ShlosiloErrorKind,
    pub context: ErrorContext,
}

impl ShlosiloError {
    pub const fn ok() -> Self {
        Self {
            kind: ShlosiloErrorKind::Ok,
            context: ErrorContext::None,
        }
    }

    pub const fn new(kind: ShlosiloErrorKind) -> Self {
        Self {
            kind,
            context: ErrorContext::None,
        }
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
// L2b C-ABI error code mapping (stable i32)
// ============================================================================

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShlosiloErrorCode {
    Ok = 0,
    UnknownError = -1,
    InvalidArgument = -2,
    /// FFI boundary catch_unwind fallback (FFI-specific; never produced by the L2b mapping)
    FfiPanic = -4,
    UnsupportedChainKind = -10,
    UnsupportedExportProtocol = -11,
    UnsupportedNetwork = -12,
    MultisigNotSupported = -13,
    FeatureNotImplemented = -14,
    PsbtOwnershipRejected = -15,
    BufferTooSmall = -20,
    EncodingError = -21,
    InvalidUrPayload = -30,
    InvalidMnemonic = -31,
    InvalidDerivationPath = -32,
    InvalidDiceRolls = -33,
    CryptoError = -40,
    InvariantViolation = -99,
}

impl ShlosiloErrorCode {
    /// Implementation of L2b::error::to_code
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
            ShlosiloErrorKind::UrPayloadInvalidCbor | ShlosiloErrorKind::UrPayloadUnknownType => {
                Self::InvalidUrPayload
            }
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
