//! Build any of the five account-export shapes from a seed (S2 export legs).
//!
//! This is the layer between "the operator picked a format on the screen" and
//! the wire encoders: it derives whatever that format needs and writes it into
//! a caller buffer. Everything here is pure (seed in, bytes out) so the host
//! tests can pin each shape without a device.
//!
//! The five shapes and who consumes them (all BC-UR standard registry types or
//! plain text; `crypto-multi-accounts` is deliberately absent - it is a Keystone
//! registry extension (tag 1103, `ur-registry`'s `src/extend/`), not BC-UR, and
//! only Keystone's own apps read it).
//!
//! | # | `ExportFormat` | consumer |
//! |---|---|---|
//! | 1 | `UrCryptoAccount` | keystone-ecosystem BTC wallets (4 script paths in one UR) |
//! | 2 | `BitcoinXpubUri` | Cake / Cupcake (BIP-84 account key in a static URI) |
//! | 3 | `UrCryptoHdKey` | keystone-ecosystem ETH wallets (MetaMask / Rabby) |
//! | 4 | `MoneroViewOnlyJsonUnlabelled` | Feather |
//! | 5 | `MoneroViewOnlyJsonLabelled` | Cake pairing leg |

// Primitive axis (S9 batch B): the two Monero JSON shapes are the only part of this file
// that needs the XMR leg, so only they are gated. `ExportFormat` itself is NOT gated — the
// ABI and the device UI enumerate all five formats in every build, and formats 4/5 answer the
// pre-existing `FeatureNotImplemented` when the primitives are not compiled in.
#[cfg(all(feature = "prim-scalar-reduce", feature = "prim-base58-monero"))]
use crate::address::xmr as xmr_address;
#[cfg(all(feature = "prim-scalar-reduce", feature = "prim-base58-monero"))]
use crate::curve_primitive::ed25519::{base_mul_raw, scalar_to_bytes};
use crate::derivation::bip32_secp256k1::{master_fingerprint_from_seed, xpub_from_seed};
#[cfg(all(feature = "prim-scalar-reduce", feature = "prim-base58-monero"))]
use crate::derivation::monero_reduce_scalar::{self, MoneroPath};
use crate::derivation::path::DerivationPath;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::network::Network;
/// Re-exported so callers (FFI, the device UI, the SDK-gate dumper) can name the
/// format they want without reaching into the codec layer.
pub use crate::ur::codec::account_text::ExportFormat;
use crate::ur::codec::account_text::{
    btc_xpub_uri, monero_viewkey_json_labelled, monero_viewkey_json_unlabelled,
};
use crate::ur::codec::{crypto_account, crypto_hd_key};

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
    /// Restore height for the labelled JSON (0 when unknown).
    pub restore_height: u64,
}

/// The BTC account paths exported by `crypto-account`.
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
/// A2-09 (external audit 2026-11-19): the second element is the private view key written out
/// as ASCII hex. It used to be a plain `[u8; 64]` with no owner — the export's *purpose* is to
/// hand that key over, but the intermediate copy in this function is not the exported result
/// and has no reason to outlive the call un-erased.
#[cfg(all(feature = "prim-scalar-reduce", feature = "prim-base58-monero"))]
fn monero_material(
    seed: &[u8; 64],
    network: Network,
) -> Result<(heapless::String<112>, crate::types::SecretBytes<64>)> {
    // Monero has one network/account notion here; `MoneroPath::mainnet(0)` is the
    // account-0 path the rest of the crate uses.
    let kp = monero_reduce_scalar::derive(seed, &MoneroPath::mainnet(0))?;
    // Monero semantics: pub = s*G with the reduced scalar used as-is. The Ed25519
    // keygen primitive (`base_mul`) hashes and clamps, which yields an address whose
    // embedded view key no wallet can match - Feather and Cake both refused it.
    let spend_pub = base_mul_raw(&scalar_to_bytes(kp.spend_priv()))?;
    let view_pub = base_mul_raw(&scalar_to_bytes(kp.view_priv()))?;
    let addr = xmr_address::encode(&spend_pub, &view_pub, network)?;
    let mut s: heapless::String<112> = heapless::String::new();
    s.push_str(addr.as_ref()).map_err(|_| err())?;
    let mut view_hex = hex32(&scalar_to_bytes(kp.view_priv()));
    Ok((s, crate::types::SecretBytes::take(&mut view_hex)))
}

/// Without the XMR leg the two Monero shapes answer the pre-existing `FeatureNotImplemented`
/// (never a wrong address / a zero view key). Same signature so `payload()` has one call site.
#[cfg(not(all(feature = "prim-scalar-reduce", feature = "prim-base58-monero")))]
fn monero_material(
    _seed: &[u8; 64],
    _network: Network,
) -> Result<(heapless::String<112>, crate::types::SecretBytes<64>)> {
    Err(ShlosiloError::new(ShlosiloErrorKind::FeatureNotImplemented))
}

#[cfg(all(feature = "prim-scalar-reduce", feature = "prim-base58-monero"))]
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
        ExportFormat::BitcoinXpubUri
        | ExportFormat::MoneroViewOnlyJsonUnlabelled
        | ExportFormat::MoneroViewOnlyJsonLabelled => None,
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
        // Text shapes: the payload IS the text (rendered as one static QR).
        ExportFormat::BitcoinXpubUri => {
            let path = DerivationPath::parse(&path_str(84, coin))?;
            let xpub = xpub_from_seed(seed, &path)?;
            let label = labels.label.ok_or_else(err)?;
            btc_xpub_uri(&xpub, label, out)
        }
        ExportFormat::MoneroViewOnlyJsonUnlabelled => {
            let (addr, view) = monero_material(seed, Network::MoneroMainnet)?;
            let view_hex = core::str::from_utf8(view.expose()).map_err(|_| err())?;
            monero_viewkey_json_unlabelled(&addr, view_hex, out)
        }
        ExportFormat::MoneroViewOnlyJsonLabelled => {
            let (addr, view) = monero_material(seed, Network::MoneroMainnet)?;
            let view_hex = core::str::from_utf8(view.expose()).map_err(|_| err())?;
            let label = labels.label.ok_or_else(err)?;
            monero_viewkey_json_labelled(label, &addr, view_hex, labels.restore_height, out)
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
    //
    // A2-14: the payload and the URI used to share `out` - the payload was written there, `encode`
    // returned a heap-free but 8 KiB `heapless::String`, and `copy_uri` copied it back over the
    // payload. Two writes for one result, and the caller's buffer briefly held something that was
    // never a valid output. The payload now goes to a bounded stack scratch and `encode_into`
    // writes the URI straight into the caller's buffer, so `out` is written exactly once.
    //
    // The scratch is the same bound `encode_into` enforces anyway (`UR_PAYLOAD_MAX_LEN`), so an
    // export too large to encode still fails with an error instead of being truncated, and the
    // stack footprint of this path goes DOWN: `encode` built an `UR_URI_MAX_LEN` (8 KiB) string
    // that `encode_into` no longer needs.
    match ur_type(format) {
        Some(tag) => {
            let mut scratch = [0u8; crate::ur::ur_encode::UR_PAYLOAD_MAX_LEN];
            let n = payload(format, seed, network, labels, &mut scratch)?;
            crate::ur::ur_encode::encode_into(tag, &scratch[..n], out)
        }
        None => payload(format, seed, network, labels, out),
    }
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

    /// Whether the XMR leg (and therefore formats 4/5) is compiled in.
    const MONERO_LEG: bool = cfg!(all(
        feature = "prim-scalar-reduce",
        feature = "prim-base58-monero"
    ));

    fn is_monero(f: ExportFormat) -> bool {
        matches!(
            f,
            ExportFormat::MoneroViewOnlyJsonUnlabelled | ExportFormat::MoneroViewOnlyJsonLabelled
        )
    }

    /// The formats this build can actually produce. `ExportFormat::ALL` always lists all
    /// five (the ABI and the device menu are shape-stable — that is a hard rule), so the
    /// sweep tests below iterate this instead. A build without the XMR leg additionally
    /// proves that the disabled pair REFUSES — see
    /// `monero_shapes_refuse_with_feature_not_implemented`, which is what keeps the
    /// narrow face from being a silently smaller version of the wide one.
    fn producible() -> impl Iterator<Item = ExportFormat> {
        ExportFormat::ALL
            .iter()
            .copied()
            .filter(|f| MONERO_LEG || !is_monero(*f))
    }

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
    fn build_matches_the_two_step_reference_and_touches_only_its_output() {
        // A2-14: `build` used to write the payload into `out`, then copy the encoded URI back over
        // it. This pins the property that replaced that: the bytes are exactly what
        // payload+encode_into produce (same derivation, same encoding), and nothing past the
        // reported length is written - the buffer is poisoned with 0xAA so a stray write shows up.
        for f in producible() {
            let mut got = vec![0xAAu8; 8192];
            let n = build(f, &SEED, Network::BitcoinMainnet, &labels(), &mut got)
                .unwrap_or_else(|e| panic!("{f:?} failed: {e:?}"));

            let mut pl = vec![0u8; crate::ur::ur_encode::UR_PAYLOAD_MAX_LEN];
            let pn = payload(f, &SEED, Network::BitcoinMainnet, &labels(), &mut pl).unwrap();
            let mut want = vec![0xAAu8; 8192];
            let wn = match ur_type(f) {
                Some(tag) => crate::ur::ur_encode::encode_into(tag, &pl[..pn], &mut want).unwrap(),
                None => {
                    want[..pn].copy_from_slice(&pl[..pn]);
                    pn
                }
            };

            assert_eq!(
                &got[..n],
                &want[..wn],
                "{f:?} differs from the payload+encode_into reference"
            );
            assert!(
                got[n..].iter().all(|b| *b == 0xAA),
                "{f:?} wrote past its reported length {n}"
            );
        }
    }

    #[test]
    fn every_format_produces_something_recognisable() {
        let mut out = vec![0u8; 4096];
        for (i, f) in producible().enumerate() {
            let n = build(f, &SEED, Network::BitcoinMainnet, &labels(), &mut out)
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
                ExportFormat::MoneroViewOnlyJsonUnlabelled => {
                    assert!(s.starts_with("{\"encrypted\":false,\"primaryAddress\":\"4"));
                    assert!(s.contains("\"source\":\"Keystone\""));
                }
                ExportFormat::MoneroViewOnlyJsonLabelled => {
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
        let sizes: Vec<(ExportFormat, usize)> =
            [ExportFormat::UrCryptoAccount, ExportFormat::UrCryptoHdKey]
                .iter()
                .map(|f| {
                    let n = payload(*f, &SEED, Network::BitcoinMainnet, &labels(), &mut out)
                        .expect("payload");
                    (*f, n)
                })
                .collect();
        for (f, n) in &sizes {
            assert!(ur_type(*f).is_some(), "{f:?} is a UR shape");
            assert!(*n > 0);
        }
        // The account bundle (4 descriptors) is multi-part; a single ETH key is not.
        let n_account = sizes[0].1;
        let n_hdkey = sizes[1].1;
        assert!(
            n_account > 200,
            "crypto-account payload {n_account} B > 1 fragment"
        );
        assert!(
            n_hdkey <= 200,
            "crypto-hdkey payload {n_hdkey} B fits one fragment"
        );
        // Text shapes are never framed.
        for f in [
            ExportFormat::BitcoinXpubUri,
            ExportFormat::MoneroViewOnlyJsonUnlabelled,
            ExportFormat::MoneroViewOnlyJsonLabelled,
        ] {
            assert!(ur_type(f).is_none(), "{f:?} is plain text");
        }
    }

    #[test]
    fn five_labels_in_listing_order() {
        assert_eq!(format_count(), 5);
        assert_eq!(format_label(0), Some("ur:crypto-account"));
        assert_eq!(format_label(1), Some("bitcoin:?xpub=&label="));
        assert_eq!(format_label(4), Some("json: monero (cake)"));
        assert_eq!(format_label(5), None);
    }

    #[test]
    fn formats_that_need_a_label_refuse_without_one() {
        let mut out = vec![0u8; 4096];
        let empty = ExportLabels::default();
        // `BitcoinXpubUri` needs a label in every build; the labelled Monero JSON only
        // exists (and therefore only needs one) where the XMR leg is compiled in.
        assert!(
            build(
                ExportFormat::BitcoinXpubUri,
                &SEED,
                Network::BitcoinMainnet,
                &empty,
                &mut out
            )
            .is_err(),
            "BitcoinXpubUri must require a label"
        );
        if MONERO_LEG {
            assert!(
                build(
                    ExportFormat::MoneroViewOnlyJsonLabelled,
                    &SEED,
                    Network::BitcoinMainnet,
                    &empty,
                    &mut out
                )
                .is_err(),
                "MoneroViewOnlyJsonLabelled must require a label"
            );
        }
        // formats that do not need one still work
        for f in [ExportFormat::UrCryptoAccount, ExportFormat::UrCryptoHdKey] {
            assert!(build(f, &SEED, Network::BitcoinMainnet, &empty, &mut out).is_ok());
        }
        if MONERO_LEG {
            assert!(build(
                ExportFormat::MoneroViewOnlyJsonUnlabelled,
                &SEED,
                Network::BitcoinMainnet,
                &empty,
                &mut out
            )
            .is_ok());
        }
    }

    /// The two Monero JSON shapes need the XMR leg. Where it is compiled out they must
    /// REFUSE with the pre-existing kind — a zero view key or a fabricated address would be
    /// worse than an error, and this is the test that holds that line (the sweep tests above
    /// skip the pair only because it cannot be produced, not because the requirement lapsed).
    #[cfg(not(all(feature = "prim-scalar-reduce", feature = "prim-base58-monero")))]
    #[test]
    fn monero_shapes_refuse_with_feature_not_implemented() {
        let mut out = vec![0u8; 4096];
        for f in [
            ExportFormat::MoneroViewOnlyJsonUnlabelled,
            ExportFormat::MoneroViewOnlyJsonLabelled,
        ] {
            let e = build(f, &SEED, Network::BitcoinMainnet, &labels(), &mut out)
                .expect_err("the Monero shapes cannot exist without the XMR leg");
            assert_eq!(
                e.kind,
                ShlosiloErrorKind::FeatureNotImplemented,
                "{f:?} must answer the pre-existing kind"
            );
            assert!(
                out.iter().all(|b| *b == 0),
                "{f:?} must not write the buffer on refusal"
            );
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
