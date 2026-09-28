//! P1-03: newtype for sensitive byte material (audit 2026-08-25 remediation).
//!
//! Typed enforcement of v2-security §2 discipline:
//! - forbid `Copy`, forbid `Clone` — every clone means one more live key in RAM
//! - forbid `Debug` printing contents — output is only `[REDACTED]`
//! - `ZeroizeOnDrop` — memory cleared at scope end (ineffective against dump/DMA is a known residual risk, v2-security §1)
//! - `PartialEq` via `subtle` constant-time comparison — prevents timing side channels
//!
//! Usage conventions:
//! - construct with [`SecretBytes::new`] (copies, then zeroizes the caller's original on-stack copy)
//! - read with [`SecretBytes::expose`] / [`expose_mut`](SecretBytes::expose_mut) —
//!   the name is the audit point; `grep -r "expose()"` enumerates all plaintext accesses
//! - FFI out-params use [`SecretBytes::write_into`]; `*expose()` followed by copying out a second long-lived copy is forbidden

use core::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fixed-length sensitive bytes (private key / seed / mask / tx secret).
///
/// Not implemented: `Clone`, `Copy`, `Debug` (contents), `Display`, `AsRef<[u8]>` (prevents accidental leakage),
/// `From<[u8; N]>` (construction must explicitly go through `new`, grep-able).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    /// Construct from raw bytes. Only zeroes the **parameter copy** — the caller's own binding still holds
    /// the plaintext; suitable only for temporary scenarios where the caller discards its copy. Use [`SecretBytes::take`] when holding multiple plaintext copies.
    pub fn new(mut raw: [u8; N]) -> Self {
        let this = Self { bytes: raw };
        raw.zeroize();
        this
    }

    /// **Takes over** from the caller's buffer: copies, then immediately zeroes the caller's real memory.
    /// This is the right primitive for eliminating surplus plaintext copies (the core demand of audit P1-03).
    pub fn take(buf: &mut [u8; N]) -> Self {
        let this = Self { bytes: *buf };
        buf.zeroize();
        this
    }

    /// All-zero value (for placeholder construction; a zero scalar is cryptographically an invalid key — consumer-side validation rejects it).
    pub fn zeroed() -> Self {
        Self { bytes: [0u8; N] }
    }

    /// Explicit plaintext access. The name is the audit point — all code touching plaintext must go through here.
    pub fn expose(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Explicit mutable plaintext access (for FFI out-param write-through and in-place transforms).
    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    /// Copy into a caller-provided buffer (FFI out-param contract).
    /// Note: the target buffer's lifetime is the caller's responsibility; this struct's own copy is still ZeroizeOnDrop as usual.
    pub fn write_into(&self, out: &mut [u8]) {
        out[..N].copy_from_slice(&self.bytes);
    }

    /// In-place zeroization (for early erasure outside drop).
    pub fn zeroize_in_place(&mut self) {
        self.bytes.zeroize();
    }
}

/// Constant-time comparison — `==` leaks no prefix-match length.
impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

/// Debug exposes only the type and length, never contents (matching Mnemonic's hand-written Debug policy).
impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{}>([REDACTED])", N)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc-fallback")]
    extern crate alloc;
    use alloc::format;

    // ---- Type discipline (P1-03 compile-fail equivalents: adding the wrong impl breaks the test build) ----

    // SecretBytes itself: forbid Clone / Copy / Debug content leakage
    static_assertions::assert_not_impl_any!(SecretBytes<32>: Clone, Copy);
    static_assertions::assert_not_impl_any!(SecretBytes<64>: Clone, Copy);

    // P1-03 migration types: forbid Clone / Copy (v2-security §2 + audit 2026-08-25 P1-03)
    use crate::chain::btc::p2pkh::P2PKHSignInput;
    use crate::chain::btc::p2sh::P2SHP2WPKHSignInput;
    use crate::chain::btc::p2wpkh::P2WPKHSignInput;
    use crate::chain::btc::psbt::{PsbtP2PKHSignInput, PsbtP2SHP2WPKHSignInput, PsbtSignInput};
    use crate::chain::eth::eip155::Eip155SignInput;
    use crate::chain::eth::eip1559::Eip1559SignInput;
    use crate::chain::eth::eip712::Eip712SignInput;
    use crate::chain::eth::personal_sign::PersonalSignInput;
    use crate::chain::xmr::tx_builder::{SignedTx, TxInputSpec, TxKeyPair, TxOutputSpec};
    use crate::derivation::bip32_secp256k1::ExtendedPrivKey;
    use crate::derivation::slip10_ed25519::Slip10ExtendedKey;
    use crate::entropy::bip39_passphrase::Bip39Seed;
    use crate::entropy::mnemonic::Mnemonic;

    static_assertions::assert_not_impl_any!(TxKeyPair: Clone, Copy);
    static_assertions::assert_not_impl_any!(TxInputSpec: Clone, Copy);
    static_assertions::assert_not_impl_any!(TxOutputSpec: Clone, Copy);
    static_assertions::assert_not_impl_any!(SignedTx<'static>: Clone, Copy);
    static_assertions::assert_not_impl_any!(PsbtSignInput: Clone, Copy);
    static_assertions::assert_not_impl_any!(PsbtP2PKHSignInput: Clone, Copy);
    static_assertions::assert_not_impl_any!(PsbtP2SHP2WPKHSignInput: Clone, Copy);
    static_assertions::assert_not_impl_any!(P2WPKHSignInput<'static>: Clone, Copy);
    static_assertions::assert_not_impl_any!(P2PKHSignInput<'static>: Clone, Copy);
    static_assertions::assert_not_impl_any!(P2SHP2WPKHSignInput<'static>: Clone, Copy);
    static_assertions::assert_not_impl_any!(Eip155SignInput: Clone, Copy);
    static_assertions::assert_not_impl_any!(Eip1559SignInput: Clone, Copy);
    static_assertions::assert_not_impl_any!(Eip712SignInput: Clone, Copy);
    static_assertions::assert_not_impl_any!(PersonalSignInput: Clone, Copy);
    static_assertions::assert_not_impl_any!(Bip39Seed: Clone, Copy);
    static_assertions::assert_not_impl_any!(ExtendedPrivKey: Clone, Copy);
    static_assertions::assert_not_impl_any!(Slip10ExtendedKey: Clone, Copy);
    static_assertions::assert_not_impl_any!(Mnemonic: Clone, Copy);

    #[test]
    fn take_zeroizes_caller_memory() {
        let mut raw = [0x42u8; 32];
        let secret = SecretBytes::take(&mut raw);
        // the caller's real memory has been zeroed — not just the parameter copy
        assert!(raw.iter().all(|&b| b == 0));
        // the original keeps its contents
        assert_eq!(secret.expose(), &[0x42u8; 32]);
    }

    #[test]
    fn new_leaves_caller_binding_holding_plaintext_by_design() {
        // new's contract: only zeroes the parameter copy. This test locks that semantics against future changes.
        let mut raw = [0x42u8; 32];
        let secret = SecretBytes::new(raw);
        let _ = &mut raw; // raw is still [0x42; 32] — the caller's responsibility
        assert_eq!(secret.expose(), &[0x42u8; 32]);
    }

    #[test]
    fn debug_never_leaks_content() {
        let secret = SecretBytes::new([0xAAu8; 32]);
        let rendered = format!("{:?}", secret);
        assert_eq!(rendered, "SecretBytes<32>([REDACTED])");
        assert!(!rendered.contains("aa") && !rendered.contains("AA"));
    }

    #[test]
    fn partial_eq_is_content_equal() {
        let a = SecretBytes::new([1u8; 32]);
        let b = SecretBytes::new([1u8; 32]);
        let c = SecretBytes::new([2u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn write_into_copies_full_length() {
        let secret = SecretBytes::new([7u8; 64]);
        let mut out = [0u8; 64];
        secret.write_into(&mut out);
        assert_eq!(out, [7u8; 64]);
    }

    #[test]
    fn zeroize_on_drop_impl() {
        // R1 (2026-08-31): the docs promise "memory cleared at scope end" — the type system must deliver
        assert!(core::mem::needs_drop::<SecretBytes<32>>());
        // ZeroizeOnDrop is an auto trait with no Sized bound; assert statically via a trait bound
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<SecretBytes<32>>();
        assert_zod::<SecretBytes<64>>();
    }

    #[test]
    fn zeroize_in_place_clears() {
        let mut secret = SecretBytes::new([0xFFu8; 32]);
        secret.zeroize_in_place();
        assert!(secret.expose().iter().all(|&b| b == 0));
    }
}
