//! SLIP-0010 派生 over ed25519（SOL + SUI + NEAR + TON）

use crate::curve_primitive::ed25519::Ed25519Scalar;
use crate::derivation::path::DerivationPath;
use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SLIP-0010 扩展私钥（ed25519 比特字段不同，长度 32 bytes）
pub const SLIP10_EXTENDED_KEY_LEN: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Slip10ExtendedKey {
    bytes: [u8; SLIP10_EXTENDED_KEY_LEN],
}

impl AsRef<[u8]> for Slip10ExtendedKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for Slip10ExtendedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Slip10ExtendedKey(<{} bytes redacted>)", self.bytes.len())
    }
}

/// SLIP-0010 master 派生（ed25519 用 hardened-only 派生）
///
/// # Phase 4 实现
/// `slip10::derive_ed25519_master(seed)`（slip10 14.x crate）
pub fn master_from_seed(_seed: &[u8]) -> Result<Slip10ExtendedKey> {
    unimplemented!("Phase 2.2 stub: slip10_ed25519::master_from_seed 将在 Phase 4 接入 slip10 crate")
}

/// SLIP-0010 路径派生（Phase 4 真实实现）
///
/// 重要：SLIP-0010 for ed25519 要求 **每个 segment 都是 hardened**（包括 account / change / address_index）
pub fn derive(_master: &Slip10ExtendedKey, _path: &DerivationPath) -> Result<Ed25519Scalar> {
    unimplemented!("Phase 2.2 stub: slip10_ed25519::derive 将在 Phase 4 接入 slip10 crate")
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&[u8]) -> Result<Slip10ExtendedKey> = master_from_seed;
    const _: fn(&Slip10ExtendedKey, &DerivationPath) -> Result<Ed25519Scalar> = derive;

    #[test]
    fn extended_key_len() {
        assert_eq!(SLIP10_EXTENDED_KEY_LEN, 32);
    }

    #[test]
    fn extended_key_zeroize_on_drop() {
        assert!(core::mem::needs_drop::<Slip10ExtendedKey>());
    }

    #[test]
    fn stub_phase_documented() {
        let source = include_str!("slip10_ed25519.rs");
        assert!(source.contains("unimplemented!"));
        assert!(source.contains("Phase 4"));
        assert!(source.contains("slip10"));
    }
}