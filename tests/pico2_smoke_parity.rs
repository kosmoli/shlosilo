//! pico2 signing-smoke parity: the fixture sequence that
//! flux/pico2/src/sign_smoke.rs runs on the board, executed here on the host
//! through the same direct Rust path.
//!
//! The assertions pin the values flux/host-sim/sim_l3.c prints (the C-ABI
//! oracle: word0 index 1565, the crypto-hdkey UR below, the signed ETH tx
//! hex below). On-device console output must match; this test catches drift
//! on the host side before any flashing.

use shlosilo::business;
use shlosilo::derivation::path::DerivationPath;
use shlosilo::entropy::mnemonic::{Mnemonic, WordCount};
use shlosilo::network::Network;
use shlosilo::ur::ur_decode;

/// Fixed dice-roll fixture (matches flux/host-sim/sim_l3.c and the pico2 smoke).
fn fixture_rolls() -> [u8; 64] {
    let mut rolls = [0u8; 64];
    for (i, r) in rolls.iter_mut().enumerate() {
        *r = (i % 6 + 1) as u8;
    }
    rolls
}

/// ETH sign-request fixture UR (matches flux/host-sim/sim_l3.c and the pico2 smoke).
const ETH_SIGN_REQUEST_URI: &str = "ur:eth-sign-request/otaohddmaowpadlalrfrnysgaelrktecmwaelfgmaymwcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcplfaxvdlartlalalaaxadaaadrpceaadt";

/// The crypto-hdkey UR the host-sim prints for the fixture mnemonic at
/// m/44'/0'/0'/0/0 (mainnet).
const EXPECTED_EXPORT_UR: &str = "ur:crypto-hdkey/oxaxhdclaxisyagdbdhsvarersbykegssnhesonthdetkokklomsprldoseymnpansbnwynyioaahdcxaorptnpmcmdibgcevegaetftloemsfhphdcflkswfsgmdyidchkndyprswsnfewpaycysssefxgwamtaaddyoeadlecsdwykaeykaeykaewkaewkaxahaemnvsmn";

/// The signed EIP-1559 tx hex the host-sim prints (111 bytes).
const EXPECTED_SIGNED_HEX: &str = "02f86c0180843b9aca0084773594008252089422222222222222222222222222222222222222228203e780c080a0231db6acdbb8e2b9ce1c7c38f0eaea8520dd327b4c7b9f24627459d57a4548a9a0444004dd6f14355354be998067ad1cc1d467bb9e3d73175c5b2b1215eeba1a72";

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[test]
fn pico2_smoke_fixture_parity() {
    // ── Step 1: create_account ──
    let rolls = fixture_rolls();
    let mut mnemonic_buf = [0u8; 24];
    business::create_account::create_account(WordCount::Words12, 6, &rolls, b"", &mut mnemonic_buf)
        .expect("create_account");

    let mut indices = [0u16; 12];
    for (i, idx) in indices.iter_mut().enumerate() {
        *idx = u16::from_le_bytes([mnemonic_buf[i * 2], mnemonic_buf[i * 2 + 1]]);
    }
    println!("indices = {:?}", indices);
    assert_eq!(indices[0], 1565, "host-sim oracle: word0 index");

    // ── Step 2: export_readonly ──
    let mnemonic = Mnemonic::from_indices(&indices, WordCount::Words12).expect("mnemonic");
    let mut seed = [0u8; 64];
    business::restore_seed::restore_seed(&mnemonic, b"", &mut seed).expect("restore_seed");
    let path = DerivationPath::from_flat([44u32 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 0])
        .expect("path");
    let mut export_out = [0u8; 2048];
    let export_len = business::export_readonly::export_readonly(
        business::export_readonly::ExportProtocol::CryptoHdKey,
        &seed,
        Network::BitcoinMainnet,
        core::slice::from_ref(&path),
        &mut export_out,
    )
    .expect("export_readonly");
    let uri = core::str::from_utf8(&export_out[..export_len]).expect("utf8");
    assert_eq!(uri, EXPECTED_EXPORT_UR, "host-sim oracle: export UR");

    // ── Step 3: sign ──
    let decoded = ur_decode::decode(ETH_SIGN_REQUEST_URI).expect("ur decode");
    let signing_mnemonic = Mnemonic::from_indices(&indices, WordCount::Words12).expect("mnemonic");
    let input = business::sign::SignInput::Mnemonic {
        mnemonic: signing_mnemonic,
        passphrase: b"",
    };
    let mut sign_out = [0u8; 512];
    let sign_len = business::sign::sign_with_entropy(
        input,
        decoded.type_tag(),
        decoded.as_ref(),
        &[],
        &mut sign_out,
    )
    .expect("sign");
    assert_eq!(sign_len, 111, "host-sim oracle: signed tx length");
    assert_eq!(
        to_hex(&sign_out[..sign_len]),
        EXPECTED_SIGNED_HEX,
        "host-sim oracle: signed hex"
    );
}
