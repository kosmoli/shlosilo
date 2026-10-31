//! KeySession: entropy-seeded signing session (forms-side, no hardware).
//!
//! Construction derives everything (BIP-39 seed → MoneroPath → spend/view);
//! Drop zeroizes. The 12/24-word-only entropy restriction is a deliberate
//! decision: the SeedSigner steel-plate family only interoperates on 12/24
//! word mnemonics (interface detail decides §1) — 15/18/21 words are rejected
//! even though `Mnemonic` itself accepts them.
//!
//! Residual risk: under `panic = "abort"` (release firmware) unwinding never
//! runs `ZeroizeOnDrop` destructors, so a panic can leave key material in RAM —
//! same residual-risk posture as the `secret_bytes` module docs.

use crate::curve_primitive::ed25519::scalar_to_bytes;
use crate::derivation::monero_reduce_scalar::{derive as monero_derive, MoneroPath};
use crate::entropy::bip39_passphrase::mnemonic_to_seed;
use crate::entropy::mnemonic::Mnemonic;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::types::SecretBytes;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Entropy-seeded signing session. Construct once, borrow keys, drop to erase.
///
/// Not implemented: `Clone`, `Copy` — each clone doubles the live key material
/// (v2-security §2 discipline, same as `SecretBytes` / `MoneroKeyPair`).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeySession {
    seed: SecretBytes<64>,
    spend_sk: SecretBytes<32>,
    view_sk: SecretBytes<32>,
    path: MoneroPath,
    /// WP1 I5/C3: the bound protocol profile as ONE byte (0 = unbound,
    /// 1 = CakeCupcake, 2 = Keystone). Set only via `crate::profile::profile_bind`.
    profile_id: u8,
}

/// Borrowed view of the Monero keys inside a [`KeySession`] (no copies leave the session).
pub struct MoneroKeys<'a> {
    pub spend_sk: &'a SecretBytes<32>,
    pub view_sk: &'a SecretBytes<32>,
    pub path: &'a MoneroPath,
}

// Redacted Debug (MoneroKeyPair style): field names stay visible for
// diagnostics, key/seed contents never print.
impl core::fmt::Debug for KeySession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeySession")
            .field("seed", &"<redacted>")
            .field("spend_sk", &"<redacted>")
            .field("view_sk", &"<redacted>")
            .field("path", &self.path) // MoneroPath is documented non-secret metadata
            .finish()
    }
}

// Same redaction contract as `KeySession`'s Debug.
impl core::fmt::Debug for MoneroKeys<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MoneroKeys")
            .field("spend_sk", &"<redacted>")
            .field("view_sk", &"<redacted>")
            .field("path", &self.path) // MoneroPath is documented non-secret metadata
            .finish()
    }
}

impl KeySession {
    /// Derive a session from raw entropy (16 bytes = 12 words, 32 bytes = 24 words) + optional passphrase.
    ///
    /// Rejects any other entropy length: only the 12/24-word family is supported
    /// (SeedSigner steel-plate interop decision, see module docs).
    pub fn from_entropy(entropy: &[u8], passphrase: &[u8]) -> Result<Self> {
        match entropy.len() {
            16 | 32 => {}
            _ => {
                return Err(ShlosiloError::new(
                    ShlosiloErrorKind::MnemonicInvalidEntropyLength,
                ))
            }
        }
        let m = Mnemonic::from_entropy(entropy)?;
        // Defense-in-depth: always passes for entropy-constructed mnemonics (the
        // length gate above pre-validated the only inputs `Mnemonic` accepts).
        // Kept as a from_entropy regression guard — removing it keeps tests green,
        // but drops the belt-and-braces check if construction semantics ever change.
        m.validate()?;
        // Real BIP-39 seed (PBKDF2-HMAC-SHA512). Note: `Mnemonic::to_seed` is
        // still the Phase 2 placeholder — `mnemonic_to_seed` is the production path.
        let seed = mnemonic_to_seed(&m, passphrase)?;
        let mut seed_buf: [u8; 64] = seed.into_bytes();
        // Take over the plaintext seed BEFORE the fallible derive: if
        // `monero_derive` fails below, `?` returns early and `seed_sb`'s Drop
        // zeroizes the 64 bytes — with the old order they stayed on the stack.
        let seed_sb = SecretBytes::take(&mut seed_buf);
        let kp = monero_derive(seed_sb.expose(), &MoneroPath::mainnet(0))?;
        let mut spend_bytes = scalar_to_bytes(kp.spend_priv());
        let mut view_bytes = scalar_to_bytes(kp.view_priv());
        Ok(Self {
            seed: seed_sb,
            spend_sk: SecretBytes::take(&mut spend_bytes),
            view_sk: SecretBytes::take(&mut view_bytes),
            path: MoneroPath::mainnet(0),
            profile_id: 0,
        })
    }

    /// WP1 I5: the bound profile byte (0 = unbound). Read only at the
    /// dispatch point (`crate::profile::profile_current`).
    pub fn profile_id(&self) -> u8 {
        self.profile_id
    }

    /// WP1 I5: set the bound profile byte (crate-internal — the public path
    /// is `crate::profile::profile_bind`, which availability-checks first).
    pub(crate) fn set_profile_id(&mut self, id: u8) {
        self.profile_id = id;
    }

    /// Borrow the Monero keys + derivation path (no plaintext copies).
    pub fn monero(&self) -> MoneroKeys<'_> {
        MoneroKeys {
            spend_sk: &self.spend_sk,
            view_sk: &self.view_sk,
            path: &self.path,
        }
    }

    /// Borrow the BIP-39 seed (audit point: `expose()` enumerates plaintext access).
    pub fn seed(&self) -> &SecretBytes<64> {
        &self.seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation::monero_reduce_scalar::{derive as monero_derive, MoneroPath};
    use crate::entropy::bip39_passphrase::mnemonic_to_seed;
    use crate::entropy::mnemonic::Mnemonic;

    /// Reference composition: the same pipeline KeySession must implement.
    fn expect_derived(seed: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
        let kp = monero_derive(seed, &MoneroPath::mainnet(0)).expect("derive");
        (
            scalar_to_bytes(kp.spend_priv()),
            scalar_to_bytes(kp.view_priv()),
        )
    }

    #[test]
    fn session_derives_monero_keys_from_entropy() {
        let entropy = [0x11u8; 16]; // 12 词合法熵
        let s = KeySession::from_entropy(&entropy, b"").expect("session");
        let m = Mnemonic::from_entropy(&entropy).expect("mnemonic");
        let seed = mnemonic_to_seed(&m, b"").expect("seed");
        let (spend, view) = expect_derived(seed.as_ref().try_into().expect("64B seed"));
        assert_eq!(s.monero().spend_sk.expose(), &spend);
        assert_eq!(s.monero().view_sk.expose(), &view);
    }

    #[test]
    fn session_rejects_non_12_24_entropy() {
        // SeedSigner 家族只认 12/24 词（接口细节决定 §1）
        // Boundary sweep: every length except 16 (12 words) / 32 (24 words) is
        // rejected, including the word-count boundaries of Mnemonic itself.
        for len in [0usize, 15, 17, 20, 28, 33] {
            let fixture = [0x11u8; 33];
            let err = KeySession::from_entropy(&fixture[..len], b"")
                .expect_err("non-12/24-word entropy must be rejected");
            // Pin the kind: the rejection comes from the KeySession policy layer
            // (12/24-only), not from Mnemonic's own 12/15/18/21/24 rule.
            assert_eq!(err.kind, ShlosiloErrorKind::MnemonicInvalidEntropyLength);
        }
        assert!(KeySession::from_entropy(&[0x11u8; 32], b"").is_ok()); // 24 词 OK
    }

    #[test]
    fn session_seed_exposed_via_audit_point() {
        let s = KeySession::from_entropy(&[0x11u8; 16], b"").expect("session");
        let m = Mnemonic::from_entropy(&[0x11u8; 16]).expect("mnemonic");
        let seed = mnemonic_to_seed(&m, b"").expect("seed");
        assert_eq!(s.seed().expose().as_ref(), seed.as_ref());
    }

    #[test]
    fn session_zeroize_on_drop_impl() {
        // R1 discipline (same as SecretBytes): the type system must deliver the Drop promise
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<KeySession>();
        static_assertions::assert_not_impl_any!(KeySession: Clone, Copy);
    }
}
