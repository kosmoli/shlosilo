//! Build any of the six account-export shapes from a seed (S2 export legs).
//!
//! This is the layer between "the operator picked a format on the screen" and
//! the wire encoders: it derives whatever that format needs and writes it into
//! a caller buffer. Everything here is pure (seed in, bytes out) so the host
//! tests can pin each shape without a device.
//!
//! The six shapes and who consumes them:
//!
//! | # | `ExportFormat` | consumer |
//! |---|---|---|
//! | 1 | `UrCryptoAccount` | keystone-ecosystem BTC wallets (4 script paths in one UR) |
//! | 2 | `BitcoinXpubUri` | Cake / Cupcake (BIP-84 account key in a static URI) |
//! | 3 | `UrCryptoHdKey` | keystone-ecosystem ETH wallets (MetaMask / Rabby) |
//! | 4 | `UrCryptoMultiAccounts` | aggregated wallets (OKX / Bitget / Nexus) |
//! | 5 | `MoneroJsonKeystone` | Feather |
//! | 6 | `MoneroJsonCupcake` | Cake pairing leg |

use crate::address::xmr as xmr_address;
use crate::curve_primitive::ed25519::{base_mul, scalar_to_bytes};
use crate::derivation::bip32_secp256k1::{master_fingerprint_from_seed, xpub_from_seed};
use crate::derivation::monero_reduce_scalar::{self, MoneroPath};
use crate::derivation::path::DerivationPath;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::network::Network;
/// Re-exported so callers (FFI, the device UI, the SDK-gate dumper) can name the
/// format they want without reaching into the codec layer.
pub use crate::ur::codec::account_text::ExportFormat;
use crate::ur::codec::account_text::{
    btc_xpub_uri, monero_viewkey_json_cupcake, monero_viewkey_json_keystone,
};
use crate::ur::codec::{crypto_account, crypto_hd_key, crypto_multi_accounts};

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// Optional strings a format may carry. All borrowed: nothing here allocates.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExportLabels<'a> {
    /// Wallet name (formats 2 and 6 carry one).
    pub label: Option<&'a str>,
    /// `name` written on each hdkey entry (reference firmware writes its brand).
    pub key_name: Option<&'a str>,
    pub device: Option<&'a str>,
    pub device_id: Option<&'a str>,
    pub device_version: Option<&'a str>,
    /// Restore height for the cupcake-shaped JSON (0 when unknown).
    pub restore_height: u64,
}

/// The BTC account paths exported by `crypto-account` and `crypto-multi-accounts`.
///
/// The reference firmware hands all four to the wallet in one QR
/// (`keystone3-firmware/src/ui/gui_wallet/multi/web3/gui_wallet.c:119-124`) and
/// lets the wallet pick; the script type travels in `script_expressions`.
fn btc_paths(coin: u32) -> [DerivationPath; 4] {
    [
        DerivationPath::parse(&path_str(84, coin)).expect("84"),
        DerivationPath::parse(&path_str(49, coin)).expect("49"),
        DerivationPath::parse(&path_str(44, coin)).expect("44"),
        DerivationPath::parse(&path_str(86, coin)).expect("86"),
    ]
}

fn path_str(purpose: u32, coin: u32) -> heapless::String<24> {
    let mut s = heapless::String::new();
    // `m/<purpose>'/<coin>'/0'` — account 0, always.
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("m/{purpose}'/{coin}'/0'"));
    s
}

fn eth_path(coin: u32) -> DerivationPath {
    // ETH ignores the BTC coin type here: the account path is fixed at
    // m/44'/60'/0' by the reference (metamask.rs:47-56).
    let _ = coin;
    DerivationPath::parse("m/44'/60'/0'").expect("eth path")
}

/// Monero (address, view-key hex) for the two JSON shapes.
fn monero_material(seed: &[u8; 64], network: Network) -> Result<(heapless::String<112>, [u8; 64])> {
    // Monero has one network/account notion here; `MoneroPath::mainnet(0)` is the
    // account-0 path the rest of the crate uses.
    let kp = monero_reduce_scalar::derive(seed, &MoneroPath::mainnet(0))?;
    let spend_pub = base_mul(kp.spend_priv());
    let view_pub = base_mul(kp.view_priv());
    let addr = xmr_address::encode(&spend_pub, &view_pub, network)?;
    let mut s: heapless::String<112> = heapless::String::new();
    s.push_str(addr.as_ref()).map_err(|_| err())?;
    Ok((s, hex32(&scalar_to_bytes(kp.view_priv()))))
}

fn hex32(bytes: &[u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, b) in bytes.iter().enumerate() {
        out[2 * i] = HEX[(b >> 4) as usize];
        out[2 * i + 1] = HEX[(b & 0x0f) as usize];
    }
    out
}

/// The UR type name a shape is framed with, or `None` when the shape is plain
/// text that goes on screen as one static QR (no framing to do).
///
/// This is the decision the reference firmware makes the same way: a UR message
/// that needs more than one 200-byte fragment animates, one that fits stays a
/// single QR (`ur-parse-lib::keystone_ur_encoder::probe_encode`). The device
/// takes this answer and hands payload + type to its frame encoder.
pub fn ur_type(format: ExportFormat) -> Option<crate::ur::ur_encode::UrTypeTag> {
    match format {
        ExportFormat::UrCryptoAccount => Some(crate::ur::ur_encode::UrTypeTag::CryptoAccount),
        ExportFormat::UrCryptoHdKey => Some(crate::ur::ur_encode::UrTypeTag::CryptoHdKey),
        ExportFormat::UrCryptoMultiAccounts => {
            Some(crate::ur::ur_encode::UrTypeTag::CryptoMultiAccounts)
        }
        ExportFormat::BitcoinXpubUri
        | ExportFormat::MoneroJsonKeystone
        | ExportFormat::MoneroJsonCupcake => None,
    }
}

/// The shape's payload bytes, without any UR wrapper.
///
/// For the three BC-UR shapes this is the CBOR message the frame encoder
/// fragments; for the three text shapes it is the text itself (a static QR is
/// its only rendering).
pub fn payload(
    format: ExportFormat,
    seed: &[u8; 64],
    network: Network,
    labels: &ExportLabels<'_>,
    out: &mut [u8],
) -> Result<usize> {
    let coin = match network {
        Network::BitcoinMainnet => 0,
        Network::BitcoinTestnet => 1,
        _ => return Err(err()),
    };
    let mfp = master_fingerprint_from_seed(seed)?;

    match format {
        ExportFormat::UrCryptoAccount => {
            let paths = btc_paths(coin);
            let xpubs: [crypto_hd_key::Bip32XPub; 4] = [
                xpub_from_seed(seed, &paths[0])?,
                xpub_from_seed(seed, &paths[1])?,
                xpub_from_seed(seed, &paths[2])?,
                xpub_from_seed(seed, &paths[3])?,
            ];
            let outputs = [
                crypto_account::AccountOutput {
                    xpub: &xpubs[0],
                    path: &paths[0],
                    script_expressions: crypto_account::btc_script_expressions(84)?,
                },
                crypto_account::AccountOutput {
                    xpub: &xpubs[1],
                    path: &paths[1],
                    script_expressions: crypto_account::btc_script_expressions(49)?,
                },
                crypto_account::AccountOutput {
                    xpub: &xpubs[2],
                    path: &paths[2],
                    script_expressions: crypto_account::btc_script_expressions(44)?,
                },
                crypto_account::AccountOutput {
                    xpub: &xpubs[3],
                    path: &paths[3],
                    script_expressions: crypto_account::btc_script_expressions(86)?,
                },
            ];
            crypto_account::encode_payload(&mfp, &outputs, out)
        }
        ExportFormat::UrCryptoHdKey => {
            let path = eth_path(coin);
            let xpub = xpub_from_seed(seed, &path)?;
            crypto_hd_key::encode_with_meta_payload(
                &xpub,
                &mfp,
                &path,
                labels.key_name,
                Some("account.standard"),
                out,
            )
        }
        ExportFormat::UrCryptoMultiAccounts => {
            let paths = btc_paths(coin);
            let btc0 = xpub_from_seed(seed, &paths[0])?;
            let btc1 = xpub_from_seed(seed, &paths[1])?;
            let btc2 = xpub_from_seed(seed, &paths[2])?;
            let btc3 = xpub_from_seed(seed, &paths[3])?;
            let epath = eth_path(coin);
            let expub = xpub_from_seed(seed, &epath)?;
            let entries = [
                crypto_multi_accounts::MultiAccountEntry {
                    xpub: &btc0,
                    path: &paths[0],
                    standard_children: true,
                    include_chain_code: true,
                    note: None,
                },
                crypto_multi_accounts::MultiAccountEntry {
                    xpub: &btc1,
                    path: &paths[1],
                    standard_children: true,
                    include_chain_code: true,
                    note: None,
                },
                crypto_multi_accounts::MultiAccountEntry {
                    xpub: &btc2,
                    path: &paths[2],
                    standard_children: true,
                    include_chain_code: true,
                    note: None,
                },
                crypto_multi_accounts::MultiAccountEntry {
                    xpub: &btc3,
                    path: &paths[3],
                    standard_children: true,
                    include_chain_code: true,
                    note: None,
                },
                crypto_multi_accounts::MultiAccountEntry {
                    xpub: &expub,
                    path: &epath,
                    standard_children: true,
                    include_chain_code: true,
                    note: Some("account.standard"),
                },
            ];
            crypto_multi_accounts::encode_payload(
                &crypto_multi_accounts::MultiAccountsInput {
                    master_fingerprint: mfp,
                    entries: &entries,
                    key_name: labels.key_name,
                    device: labels.device,
                    device_id: labels.device_id,
                    device_version: labels.device_version,
                },
                out,
            )
        }
        // Text shapes: the payload IS the text (rendered as one static QR).
        ExportFormat::BitcoinXpubUri => {
            let path = DerivationPath::parse(&path_str(84, coin))?;
            let xpub = xpub_from_seed(seed, &path)?;
            let label = labels.label.ok_or_else(err)?;
            btc_xpub_uri(&xpub, label, out)
        }
        ExportFormat::MoneroJsonKeystone => {
            let (addr, view) = monero_material(seed, Network::MoneroMainnet)?;
            let view_hex = core::str::from_utf8(&view).map_err(|_| err())?;
            monero_viewkey_json_keystone(&addr, view_hex, out)
        }
        ExportFormat::MoneroJsonCupcake => {
            let (addr, view) = monero_material(seed, Network::MoneroMainnet)?;
            let view_hex = core::str::from_utf8(&view).map_err(|_| err())?;
            let label = labels.label.ok_or_else(err)?;
            monero_viewkey_json_cupcake(label, &addr, view_hex, labels.restore_height, out)
        }
    }
}

/// Build `format` into `out`; returns the number of bytes written.
pub fn build(
    format: ExportFormat,
    seed: &[u8; 64],
    network: Network,
    labels: &ExportLabels<'_>,
    out: &mut [u8],
) -> Result<usize> {
    // One derivation path for both renderings: the payload is what the device
    // fragments, and the UR string is that payload wrapped for single-QR use
    // (the SDK gate dumps these strings).
    match ur_type(format) {
        Some(tag) => {
            let n = payload(format, seed, network, labels, out)?;
            let enc = crate::ur::ur_encode::encode(tag, &out[..n])?;
            copy_uri(enc.as_str(), out)
        }
        None => payload(format, seed, network, labels, out),
    }
}

fn copy_uri(uri: &str, out: &mut [u8]) -> Result<usize> {
    let bytes = uri.as_bytes();
    if bytes.len() > out.len() {
        return Err(ShlosiloError::new(
            ShlosiloErrorKind::EncodingBufferOverflow,
        ));
    }
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(bytes.len())
}

/// Every format's screen label, in listing order (the device UI asks for this).
pub fn format_count() -> usize {
    ExportFormat::ALL.len()
}

/// Screen label of format `idx` (`None` when out of range).
pub fn format_label(idx: usize) -> Option<&'static str> {
    ExportFormat::ALL.get(idx).map(|f| f.screen_label())
}

/// Resolve format `idx` from its listing position.
pub fn format_at(idx: usize) -> Option<ExportFormat> {
    ExportFormat::ALL.get(idx).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    const SEED: [u8; 64] = [0x11u8; 64];

    fn labels<'a>() -> ExportLabels<'a> {
        ExportLabels {
            label: Some("test-wallet"),
            key_name: Some("TestDevice"),
            device: Some("TestDevice"),
            device_id: Some("SN-1"),
            device_version: Some("0.1"),
            restore_height: 0,
        }
    }

    #[test]
    fn every_format_produces_something_recognisable() {
        let mut out = vec![0u8; 4096];
        for (i, f) in ExportFormat::ALL.iter().enumerate() {
            let n = build(*f, &SEED, Network::BitcoinMainnet, &labels(), &mut out)
                .unwrap_or_else(|e| panic!("format {i} ({:?}) failed: {e:?}", f));
            let s = core::str::from_utf8(&out[..n]).expect("ascii out");
            match f {
                ExportFormat::UrCryptoAccount => {
                    assert!(s.starts_with("ur:crypto-account/"), "got {}", &s[..24])
                }
                ExportFormat::BitcoinXpubUri => {
                    assert!(s.starts_with("bitcoin:?xpub="), "got {}", &s[..24]);
                    assert!(s.contains("&label=test-wallet"));
                }
                ExportFormat::UrCryptoHdKey => assert!(s.starts_with("ur:crypto-hdkey/")),
                ExportFormat::UrCryptoMultiAccounts => {
                    assert!(s.starts_with("ur:crypto-multi-accounts/"))
                }
                ExportFormat::MoneroJsonKeystone => {
                    assert!(s.starts_with("{\"encrypted\":false,\"primaryAddress\":\"4"));
                    assert!(s.contains("\"source\":\"Keystone\""));
                }
                ExportFormat::MoneroJsonCupcake => {
                    assert!(s.starts_with("{\"label\":\"test-wallet\",\"primaryAddress\":\"4"));
                    assert!(!s.contains("encrypted") && !s.contains("source"));
                }
            }
        }
    }

    /// The reference firmware animates as soon as a UR message needs more than
    /// one 200-byte fragment; the device reads this answer to choose between the
    /// frame carousel and a single static QR. Pin the actual split so a payload
    /// that silently grows across the boundary is visible.
    #[test]
    fn ur_payloads_are_measured_against_the_200_byte_fragment() {
        let mut out = vec![0u8; 8192];
        let sizes: Vec<(ExportFormat, usize)> = [
            ExportFormat::UrCryptoAccount,
            ExportFormat::UrCryptoHdKey,
            ExportFormat::UrCryptoMultiAccounts,
        ]
        .iter()
        .map(|f| {
            let n =
                payload(*f, &SEED, Network::BitcoinMainnet, &labels(), &mut out).expect("payload");
            (*f, n)
        })
        .collect();
        for (f, n) in &sizes {
            assert!(ur_type(*f).is_some(), "{f:?} is a UR shape");
            assert!(*n > 0);
        }
        // Account (4 descriptors) and the multi-account bundle are multi-part;
        // a single ETH key is not.
        let n_account = sizes[0].1;
        let n_hdkey = sizes[1].1;
        let n_multi = sizes[2].1;
        assert!(
            n_account > 200,
            "crypto-account payload {n_account} B > 1 fragment"
        );
        assert!(
            n_hdkey <= 200,
            "crypto-hdkey payload {n_hdkey} B fits one fragment"
        );
        assert!(
            n_multi > n_account,
            "the bundle carries more than one account"
        );
        assert!(
            n_multi > 400,
            "multi-accounts payload {n_multi} B is 3+ fragments"
        );
        // Text shapes are never framed.
        for f in [
            ExportFormat::BitcoinXpubUri,
            ExportFormat::MoneroJsonKeystone,
            ExportFormat::MoneroJsonCupcake,
        ] {
            assert!(ur_type(f).is_none(), "{f:?} is plain text");
        }
    }

    #[test]
    fn six_labels_in_listing_order() {
        assert_eq!(format_count(), 6);
        assert_eq!(format_label(0), Some("ur:crypto-account"));
        assert_eq!(format_label(1), Some("bitcoin:?xpub=&label="));
        assert_eq!(format_label(5), Some("json: monero (cupcake)"));
        assert_eq!(format_label(6), None);
    }

    #[test]
    fn formats_that_need_a_label_refuse_without_one() {
        let mut out = vec![0u8; 4096];
        let empty = ExportLabels::default();
        for f in [
            ExportFormat::BitcoinXpubUri,
            ExportFormat::MoneroJsonCupcake,
        ] {
            assert!(
                build(f, &SEED, Network::BitcoinMainnet, &empty, &mut out).is_err(),
                "{f:?} must require a label"
            );
        }
        // formats that do not need one still work
        for f in [
            ExportFormat::UrCryptoAccount,
            ExportFormat::UrCryptoHdKey,
            ExportFormat::UrCryptoMultiAccounts,
            ExportFormat::MoneroJsonKeystone,
        ] {
            assert!(build(f, &SEED, Network::BitcoinMainnet, &empty, &mut out).is_ok());
        }
    }

    #[test]
    fn short_buffer_is_an_error_for_every_format() {
        let mut tiny = [0u8; 16];
        for f in ExportFormat::ALL {
            assert!(
                build(f, &SEED, Network::BitcoinMainnet, &labels(), &mut tiny).is_err(),
                "{f:?} must refuse a 16-byte buffer"
            );
        }
    }

    #[test]
    fn mainnet_and_testnet_pick_different_coin_type() {
        let mut a = vec![0u8; 4096];
        let mut b = vec![0u8; 4096];
        let n1 = build(
            ExportFormat::BitcoinXpubUri,
            &SEED,
            Network::BitcoinMainnet,
            &labels(),
            &mut a,
        )
        .unwrap();
        let n2 = build(
            ExportFormat::BitcoinXpubUri,
            &SEED,
            Network::BitcoinTestnet,
            &labels(),
            &mut b,
        )
        .unwrap();
        assert_ne!(&a[..n1], &b[..n2], "testnet uses coin type 1");
    }
}
