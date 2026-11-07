//! Dump the artifacts the keystone SDK gate parses (`tools/sdk-gate/run.mjs`).
//!
//! Usage: `cargo run --example dump_sdk_artifacts -- <output-dir>`
//!
//! The gate's oracle is `@keystonehq/keystone-sdk`: the parser real wallets use.
//! It is *strict* (a missing field throws instead of defaulting), so these dumps
//! are what tells us whether a wallet can actually consume what the device
//! produces. Nothing here is judged by our own decoders - the node side decodes
//! independently and compares against the expectations written next to each
//! artifact.

use shlosilo::business::sign::{carve_sign_ws, sign_with_entropy_ws, SignInput};
use shlosilo::derivation::bip32_secp256k1::{master_fingerprint_from_seed, xpub_from_seed};
use shlosilo::derivation::path::DerivationPath;
use shlosilo::ur::codec::{crypto_account, crypto_hd_key};
use shlosilo::ur::ur_encode::{self, UrTypeTag};

/// Project test seed (entropy f284fb6c…, empty passphrase).
const SEED_HEX: &str = "d25e113e8f7be9936d67de81eb4d4bb94788b48b39f815f48f79dc029feddc918d07f5ac8ffbfb86514c4a0824ad187c5f6fc8b7c43b29356380aaeabc0267dc";
/// keystone test seed, used for the P2TR PSBT fixture.
const KEYSTONE_SEED_HEX: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
const P2TR_PSBT: &[u8] = include_bytes!("../tests/fixtures/keystone_p2tr_keypath_288b.psbt");

fn hex_decode(s: &str) -> Vec<u8> {
    s.bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16).unwrap();
            let lo = (p[1] as char).to_digit(16).unwrap();
            ((hi << 4) | lo) as u8
        })
        .collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn seed64(hex: &str) -> [u8; 64] {
    let v = hex_decode(hex);
    let mut out = [0u8; 64];
    out.copy_from_slice(&v);
    out
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: dump_sdk_artifacts <output-dir>");
    let dir = std::path::Path::new(&dir);
    std::fs::create_dir_all(dir).expect("create output dir");

    // ---- crypto-hdkey (BIP-84 account) ------------------------------------
    let seed = seed64(SEED_HEX);
    let mfp = master_fingerprint_from_seed(&seed).expect("mfp");
    let path84 = DerivationPath::parse("m/84'/0'/0'").expect("path");
    let xpub84 = xpub_from_seed(&seed, &path84).expect("xpub");
    let hdkey = crypto_hd_key::encode(&xpub84, &mfp, Some(&path84)).expect("hdkey encode");
    std::fs::write(dir.join("hdkey84.ur.txt"), hdkey.as_str()).expect("write hdkey");
    std::fs::write(
        dir.join("hdkey84.expected.json"),
        format!(
            "{{\"fingerprint\":\"{}\",\"path\":\"m/84'/0'/0'\",\"xpub\":\"{}\"}}\n",
            hex_encode(&mfp),
            hex_encode(&xpub84)
        ),
    )
    .expect("write hdkey expectation");

    // ---- crypto-account (BIP-84 + BIP-49) ---------------------------------
    let path49 = DerivationPath::parse("m/49'/0'/0'").expect("path");
    let xpub49 = xpub_from_seed(&seed, &path49).expect("xpub");
    let sl = crypto_account::btc_script_expressions(84).expect("script 84");
    let sl49 = crypto_account::btc_script_expressions(49).expect("script 49");
    let outputs = [
        crypto_account::AccountOutput {
            xpub: &xpub84,
            path: &path84,
            script_expressions: sl,
        },
        crypto_account::AccountOutput {
            xpub: &xpub49,
            path: &path49,
            script_expressions: sl49,
        },
    ];
    let account = crypto_account::encode(&mfp, &outputs).expect("account encode");
    std::fs::write(dir.join("account.ur.txt"), account.as_str()).expect("write account");
    std::fs::write(
        dir.join("account.expected.json"),
        format!(
            "{{\"fingerprint\":\"{}\",\"xpub84\":\"{}\",\"xpub49\":\"{}\"}}\n",
            hex_encode(&mfp),
            hex_encode(&xpub84),
            hex_encode(&xpub49)
        ),
    )
    .expect("write account expectation");

    // ---- signed PSBT, under both names ------------------------------------
    // The 288-byte P2TR fixture is small enough for a single-frame UR, which is
    // what lets the node gate decode it without a fountain reassembly.
    let ks_seed = seed64(KEYSTONE_SEED_HEX);
    let ws_need = shlosilo::business::sign::SignWsLayout::compute().total;
    let mut ws_bytes = vec![0u8; ws_need];
    let mut ws = carve_sign_ws(&mut ws_bytes).expect("ws carve");
    let mut out = vec![0u8; P2TR_PSBT.len() + 1024];
    let n = sign_with_entropy_ws(
        SignInput::Seed { seed: &ks_seed },
        UrTypeTag::CryptoPsbt,
        P2TR_PSBT,
        &[],
        &[],
        Some(&mut ws),
        &mut out,
    )
    .expect("sign");
    let signed = &out[..n];
    std::fs::write(dir.join("psbt_signed.hex"), hex_encode(signed)).expect("write psbt hex");
    let ur = ur_encode::encode(UrTypeTag::CryptoPsbt, signed).expect("ur encode");
    std::fs::write(dir.join("psbt_signed.ur.txt"), ur.as_str()).expect("write psbt ur");
    // The Cake-family short name carries the same payload; the keystone SDK is
    // expected to reject it, which the gate asserts as a documented boundary.
    let alias = ur_encode::encode(UrTypeTag::Psbt, signed).expect("ur encode alias");
    std::fs::write(dir.join("psbt_alias.ur.txt"), alias.as_str()).expect("write alias ur");

    // ---- the six account-export shapes (S2 export legs) -------------------
    // Same seed as the hdkey/account dumps above, so the node side can compare
    // the account material across formats.
    use shlosilo::business::export_format::{build, format_label, ExportFormat, ExportLabels};
    let labels = ExportLabels {
        label: Some("shlosilo-test"),
        key_name: Some("TestDevice"),
        device: Some("TestDevice"),
        device_id: Some("SN-0001"),
        device_version: Some("0.1.0"),
        restore_height: 0,
    };
    let mut buf = vec![0u8; 4096];
    for (i, fmt) in ExportFormat::ALL.iter().enumerate() {
        let n = build(
            *fmt,
            &seed,
            shlosilo::network::Network::BitcoinMainnet,
            &labels,
            &mut buf,
        )
        .unwrap_or_else(|e| panic!("format {i} failed: {e:?}"));
        let s = core::str::from_utf8(&buf[..n]).expect("ascii");
        std::fs::write(dir.join(format!("export_{i}.txt")), s).expect("write export");
        std::fs::write(
            dir.join(format!("export_{i}.label.txt")),
            format_label(i).unwrap_or(""),
        )
        .expect("write label");
    }

    // Payload sizes: the device compares these against the 200-byte fragment to
    // decide carousel vs single QR (see business::export_format::ur_type).
    {
        use shlosilo::business::export_format::{payload, ur_type};
        let mut sizes = String::new();
        for (i, fmt) in ExportFormat::ALL.iter().enumerate() {
            let n = payload(
                *fmt,
                &seed,
                shlosilo::network::Network::BitcoinMainnet,
                &labels,
                &mut buf,
            )
            .expect("payload");
            let ur = if ur_type(*fmt).is_some() {
                "ur"
            } else {
                "text"
            };
            let parts = if ur == "ur" { n.div_ceil(200) } else { 1 };
            sizes.push_str(&format!("{i} {ur} payload={n} parts={parts}\n"));
        }
        std::fs::write(dir.join("export_payload_sizes.txt"), sizes).expect("write sizes");
    }

    println!("dumped artifacts to {}", dir.display());
}
