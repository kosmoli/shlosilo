//! Account-export text formats (S2 export legs).
//!
//! Three of the six export shapes a "connect software wallet" screen has to
//! offer are **plain text**, not BC-UR:
//!
//! | shape | consumer | why text |
//! |---|---|---|
//! | `bitcoin:?xpub=<xpub>&label=<name>` | Cake / Cupcake | their pairing QR is a static URI, not a UR message |
//! | Monero view-key JSON, keystone shape | Feather | no Monero wallet-export UR type exists (only tx types 8301-8304) |
//! | Monero view-key JSON, cupcake shape | Cake | same reason, different field set |
//!
//! Authority for each shape (verified in the reference sources):
//!
//! - `bitcoin:` URI — `cupcake/lib/coins/bitcoin/wallet.dart:212-219` builds
//!   `Uri(scheme: "bitcoin", queryParameters: {"xpub": …, "label": …})`; the xpub
//!   is the bare account-level key (the BDK descriptor string is cut at `]` and
//!   the last `/`), i.e. **no fingerprint, no path, no script type**.
//! - keystone JSON — `keystone3-firmware/rust/rust_c/src/wallet/cypherpunk_wallet/cake.rs:35-50`
//!   `json!({"version":0,"primaryAddress":…,"privateViewKey":…,"restoreHeight":0,
//!   "encrypted":false,"source":"Keystone"})`, emitted with `UREncodeResult::text`
//!   (plain text QR, no UR framing). The map is a `serde_json::Map` without
//!   `preserve_order`, so the serialized key order is alphabetical - this module
//!   writes the same order so our bytes match theirs.
//! - cupcake JSON — `cupcake/lib/coins/monero/wallet.dart:273-279`
//!   `{"label":…,"version":0,"primaryAddress":…,"privateViewKey":…,"restoreHeight":…}`:
//!   it has `label`, it has **no** `encrypted`/`source`, and its `restoreHeight`
//!   is the wallet's real refresh height.
//!
//! All three write into a caller buffer: no allocation, no `format!`, and an
//! overflow is an explicit error rather than a truncated string.

use crate::encoding::base58;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

fn overflow() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow)
}

/// Small ASCII writer over a caller buffer.
struct W<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl<'a> W<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, len: 0 }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.len + bytes.len();
        if end > self.out.len() {
            return Err(overflow());
        }
        self.out[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn put_str(&mut self, s: &str) -> Result<()> {
        self.put(s.as_bytes())
    }

    fn put_u64(&mut self, mut v: u64) -> Result<()> {
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        loop {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.put(&buf[i..])
    }
}

/// A label is embedded in two formats; it must not be able to break the
/// surrounding syntax (URI query / JSON string).
fn label_is_safe(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 64
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'-' | b'_' | b'.'))
}

/// `bitcoin:?xpub=<base58check(78-byte xpub)>&label=<name>`
///
/// The URI is what Cake's restore scanner parses
/// (`cake_wallet/lib/view_model/restore/wallet_restore_from_qr_code.dart:185-187`
/// keys off `xpub`/`zpub`), and it must be the **BIP-84 account-level** key:
/// that is the only path cupcake exports and the only one Cake maps the imported
/// account to (`scriptType: "p2wpkh"`, `m/84'/0'/0'`).
pub fn btc_xpub_uri(xpub78: &[u8; 78], label: &str, out: &mut [u8]) -> Result<usize> {
    if !label_is_safe(label) {
        return Err(err());
    }
    let mut b58 = [0u8; 128];
    let n = base58::encode_check_into(xpub78, &mut b58)?;
    let mut w = W::new(out);
    w.put_str("bitcoin:?xpub=")?;
    w.put(&b58[..n])?;
    w.put_str("&label=")?;
    w.put_str(label)?;
    Ok(w.len)
}

/// Monero view-key JSON in the **keystone** shape (what Feather consumes).
///
/// `restore_height` is 0 by contract: the reference firmware hardcodes it, and
/// Feather then asks the operator to type the height
/// (`feather/src/wizard/PageSetRestoreHeight.cpp`). We have no wallet state to
/// read a real height from, so 0 is the honest value.
///
/// Keys are written in the alphabetical order serde_json produces for the
/// reference firmware, so the bytes match what a keystone device emits.
pub fn monero_viewkey_json_keystone(
    primary_address: &str,
    private_view_key_hex: &str,
    out: &mut [u8],
) -> Result<usize> {
    if private_view_key_hex.len() != 64
        || !private_view_key_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(err());
    }
    let mut w = W::new(out);
    w.put_str("{\"encrypted\":false,\"primaryAddress\":\"")?;
    w.put_str(primary_address)?;
    w.put_str("\",\"privateViewKey\":\"")?;
    w.put_str(private_view_key_hex)?;
    w.put_str("\",\"restoreHeight\":0,\"source\":\"Keystone\",\"version\":0}")?;
    Ok(w.len)
}

/// Monero view-key JSON in the **cupcake** shape (what Cake's pairing QR carries).
///
/// Differences from the keystone shape, all of them load-bearing: it has a
/// `label`, it has no `encrypted`/`source`, and `restore_height` is the wallet's
/// real height - which a stateless signer does not know, so the caller passes
/// what the operator chose (0 by default, same as the keystone shape).
pub fn monero_viewkey_json_cupcake(
    label: &str,
    primary_address: &str,
    private_view_key_hex: &str,
    restore_height: u64,
    out: &mut [u8],
) -> Result<usize> {
    if !label_is_safe(label) {
        return Err(err());
    }
    if private_view_key_hex.len() != 64
        || !private_view_key_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(err());
    }
    let mut w = W::new(out);
    w.put_str("{\"label\":\"")?;
    w.put_str(label)?;
    w.put_str("\",\"primaryAddress\":\"")?;
    w.put_str(primary_address)?;
    w.put_str("\",\"privateViewKey\":\"")?;
    w.put_str(private_view_key_hex)?;
    w.put_str("\",\"restoreHeight\":")?;
    w.put_u64(restore_height)?;
    w.put_str(",\"version\":0}")?;
    Ok(w.len)
}

// === format registry (what the export screen lists) =========================

/// The six export shapes the "connect software wallet" screen offers, in the
/// order they are listed to the operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    /// 1: BC-UR `crypto-account` - keystone ecosystem BTC (4 script paths in one QR)
    UrCryptoAccount,
    /// 2: static `bitcoin:?xpub=&label=` - Cake / Cupcake BTC (BIP-84 only)
    BitcoinXpubUri,
    /// 3: BC-UR `crypto-hdkey` - keystone ecosystem ETH (BIP-44 standard)
    UrCryptoHdKey,
    /// 4: BC-UR `crypto-multi-accounts` - aggregated wallets (OKX / Bitget / Nexus)
    UrCryptoMultiAccounts,
    /// 5: keystone-shape Monero view-key JSON - Feather
    MoneroJsonKeystone,
    /// 6: cupcake-shape Monero view-key JSON - Cake pairing leg
    MoneroJsonCupcake,
}

impl ExportFormat {
    /// Every format, in listing order.
    pub const ALL: [ExportFormat; 6] = [
        ExportFormat::UrCryptoAccount,
        ExportFormat::BitcoinXpubUri,
        ExportFormat::UrCryptoHdKey,
        ExportFormat::UrCryptoMultiAccounts,
        ExportFormat::MoneroJsonKeystone,
        ExportFormat::MoneroJsonCupcake,
    ];

    /// The label shown on the selection screen. Deliberately the **format
    /// itself**, not a wallet brand: the operator picks the wire shape their
    /// wallet asks for, and brand names would rot while the shapes do not.
    pub fn screen_label(self) -> &'static str {
        match self {
            Self::UrCryptoAccount => "ur:crypto-account",
            Self::BitcoinXpubUri => "bitcoin:?xpub=&label=",
            Self::UrCryptoHdKey => "ur:crypto-hdkey",
            Self::UrCryptoMultiAccounts => "ur:crypto-multi-accounts",
            Self::MoneroJsonKeystone => "json: monero viewkey",
            Self::MoneroJsonCupcake => "json: monero (cupcake)",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_formats_in_listing_order() {
        assert_eq!(ExportFormat::ALL.len(), 6);
        let labels: heapless::Vec<&str, 6> =
            ExportFormat::ALL.iter().map(|f| f.screen_label()).collect();
        assert_eq!(labels[0], "ur:crypto-account");
        assert_eq!(labels[1], "bitcoin:?xpub=&label=");
        assert_eq!(labels[5], "json: monero (cupcake)");
    }

    #[test]
    fn keystone_json_field_order_is_alphabetical() {
        let mut buf = [0u8; 512];
        let n = monero_viewkey_json_keystone("4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge",
            &"00".repeat(32), &mut buf).unwrap();
        let s = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(s.starts_with("{\"encrypted\":false,\"primaryAddress\":"));
        assert!(s.ends_with(",\"restoreHeight\":0,\"source\":\"Keystone\",\"version\":0}"));
    }

    #[test]
    fn cupcake_json_differs_from_keystone_shape() {
        let mut buf = [0u8; 512];
        let n = monero_viewkey_json_cupcake(
            "test-wallet",
            "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge",
            &"ab".repeat(32),
            123456,
            &mut buf,
        )
        .unwrap();
        let s = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(s.starts_with("{\"label\":\"test-wallet\",\"primaryAddress\":"));
        assert!(s.contains("\"restoreHeight\":123456"));
        assert!(!s.contains("encrypted") && !s.contains("source"));
    }

    #[test]
    fn unsafe_label_is_refused() {
        let mut buf = [0u8; 256];
        let xpub = [0u8; 78];
        for bad in ["", "bad\"quote", "line\nbreak", "amp&ersand"] {
            assert!(
                btc_xpub_uri(&xpub, bad, &mut buf).is_err(),
                "label {bad:?} must be refused (it would break the URI)"
            );
        }
    }

    #[test]
    fn short_buffer_is_an_error_not_a_truncation() {
        let mut tiny = [0u8; 8];
        assert!(monero_viewkey_json_keystone("4AdUnd", &"00".repeat(32), &mut tiny).is_err());
    }
}
