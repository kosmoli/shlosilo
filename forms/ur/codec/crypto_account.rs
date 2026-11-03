//! crypto-account UR codec (BCR-2020-006) — keystone-ecosystem account pairing
//!
//! Shape (authoritative: `ur-registry` 1.0.9, the crate keystone's firmware
//! pins — `src/crypto_account.rs` + `src/crypto_output.rs`):
//!
//! ```text
//! crypto-account = map {
//!   1 : uint32                  ; master fingerprint
//!   2 : [ crypto-output, ... ]  ; NO map wrapper, NO tag on the element itself
//! }
//! crypto-output = <script-expression tag>... <tag 303> crypto-hdkey
//! ```
//!
//! Script-expression tags (`ur-registry` `src/script_expression.rs:89-101`):
//! `400` script-hash (P2SH), `403` public-key-hash (P2PKH),
//! `404` witness-public-key-hash (P2WPKH), `409` taproot (P2TR).
//!
//! Zero-heap: one caller-sized stack buffer + structural writes; overflow is a
//! stable error (never truncation).

use super::crypto_hd_key::{self, Bip32XPub};
use crate::derivation::path::DerivationPath;
use crate::encoding::cbor::CborWriter;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::ur::ur_encode::{self, UrEncoded, UrTypeTag};

/// Script-expression registry tags.
pub const SCRIPT_HASH: u64 = 400;
pub const PUBLIC_KEY_HASH: u64 = 403;
pub const WITNESS_PUBLIC_KEY_HASH: u64 = 404;
pub const TAPROOT: u64 = 409;

/// crypto-hdkey registry tag nested inside a crypto-output.
const TAG_CRYPTO_HDKEY: u64 = 303;
const MASTER_FINGERPRINT: u64 = 1;
const OUTPUT_DESCRIPTORS: u64 = 2;

/// Worst-case payload for 4 outputs ≈ 564B (head + mfp + array head +
/// 4 × (2 script tags + hdkey tag + ≤130B hdkey)); 768 keeps one output of
/// headroom. Anything larger fails as `EncodingBufferOverflow`.
const ACCOUNT_BUF: usize = 768;

/// One account output: an account-level xpub plus the script expressions that
/// describe how the wallet spends from it.
pub struct AccountOutput<'a> {
    /// Account-level extended public key (`m/purpose'/coin'/account'`).
    pub xpub: &'a Bip32XPub,
    /// The path that produced `xpub` (becomes the hdkey origin).
    pub path: &'a DerivationPath,
    /// Script expressions, e.g. `[WITNESS_PUBLIC_KEY_HASH]` for BIP-84.
    pub script_expressions: &'a [u64],
}

/// Map a BIP-44 purpose to the script expressions keystone emits for BTC
/// (its `apps/wallets/src/blue_wallet.rs:58-71`). Unknown purposes are
/// rejected — a guessed script type would hand the wallet a wrong policy.
pub fn btc_script_expressions(purpose: u32) -> Result<&'static [u64]> {
    match purpose {
        44 => Ok(&[PUBLIC_KEY_HASH]),
        49 => Ok(&[SCRIPT_HASH, WITNESS_PUBLIC_KEY_HASH]),
        84 => Ok(&[WITNESS_PUBLIC_KEY_HASH]),
        86 => Ok(&[TAPROOT]),
        _ => Err(ShlosiloError::new(
            ShlosiloErrorKind::ExportProtocolUnimplemented,
        )),
    }
}

/// crypto-account UR codec encode
///
/// `master_fingerprint` is the **root** fingerprint (an xpub only carries its
/// parent's); outputs are emitted in caller order.
pub fn encode(master_fingerprint: &[u8; 4], outputs: &[AccountOutput<'_>]) -> Result<UrEncoded> {
    if outputs.is_empty() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut buf = [0u8; ACCOUNT_BUF];
    let n = {
        let mut w = CborWriter::new(&mut buf);
        w.map_head(2)?;
        w.uint(MASTER_FINGERPRINT)?;
        w.uint(u64::from(u32::from_be_bytes(*master_fingerprint)))?;
        w.uint(OUTPUT_DESCRIPTORS)?;
        w.array_head(outputs.len())?;
        for out in outputs {
            for tag in out.script_expressions {
                w.tag(*tag)?;
            }
            w.tag(TAG_CRYPTO_HDKEY)?;
            crypto_hd_key::encode_hdkey_map(&mut w, out.xpub, master_fingerprint, out.path)?;
        }
        w.pos()
    };
    ur_encode::encode(UrTypeTag::CryptoAccount, &buf[..n])
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&[u8; 4], &[AccountOutput<'_>]) -> Result<UrEncoded> = encode;

    #[test]
    fn empty_outputs_rejected() {
        assert!(encode(&[0; 4], &[]).is_err());
    }

    #[test]
    fn purpose_mapping_matches_keystone() {
        assert_eq!(btc_script_expressions(44).unwrap(), &[403]);
        assert_eq!(btc_script_expressions(49).unwrap(), &[400, 404]);
        assert_eq!(btc_script_expressions(84).unwrap(), &[404]);
        assert_eq!(btc_script_expressions(86).unwrap(), &[409]);
        // unknown purpose → stable rejection, never a guess
        assert!(btc_script_expressions(45).is_err());
    }

    #[test]
    fn stub_no_panic_marker() {
        // P2-01: stubs have been switched to stable error codes; panic macros must not regress (skip comment lines)
        for line in include_str!("crypto_account.rs").lines() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            assert!(
                !t.contains(concat!("unimplemented", "!(")),
                "panic macro regressed: {}",
                line
            );
        }
    }
}
