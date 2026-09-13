//! pico2 signing-smoke parity: the fixture sequences that the pico2 firmware
//! runs on the board (flux/pico2/src/{sign_smoke,console}.rs), executed here
//! on the host through the same direct Rust path.
//!
//! Two flows:
//! - the boot smoke (dice rolls → export → eth-sign-request fixture), values
//!   shared with flux/host-sim/sim_l3.c (the C-ABI oracle);
//! - the bench channel's real-size path: the 12.4 KiB Sparrow signet PSBT as
//!   a `crypto-psbt` multipart UR, decoded fragment by fragment and signed.
//!
//! On-device console output must match these values; this test catches drift
//! on the host side before any flashing.
//!
//! `gen_bench_channel_files` (ignored, run manually) writes the fixture files
//! the channel bench script feeds to the board.

use shlosilo::business;
use shlosilo::derivation::path::DerivationPath;
use shlosilo::encoding::{cbor, sha256};
use shlosilo::entropy::mnemonic::{Mnemonic, WordCount};
use shlosilo::network::Network;
use shlosilo::ur::ur_decode;
use shlosilo::ur::ur_encode::UrTypeTag;
use shlosilo::ur::ur_multipart::{UrMultipartDecoder, UrMultipartEncoder};

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

/// The Sparrow signet PSBT fixture (12,437 bytes; see tests/fixtures/README).
const SPARROW_PSBT: &[u8] = include_bytes!("fixtures/sparrow_signet_12k.psbt");

/// The test wallet entropy the Sparrow PSBT belongs to (same origin as
/// tests/p63_btc_sign.rs).
const SPARROW_ENTROPY: [u8; 16] = [
    0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29, 0x16,
];

/// Fragment length for the multipart UR fed to the board (bytes of payload
/// per frame; each frame is ~2x that in bytewords).
const SPARROW_FRAGMENT_LEN: usize = 400;

/// Signed Sparrow PSBT: length and SHA-256, pinned from the host run
/// (deterministic: RFC-6979 + fixed fixture). The board must print the same.
const SPARROW_SIGNED_LEN: usize = 12447;
const SPARROW_SIGNED_SHA256: &str =
    "e840183d1c1df23a6d2e199889011759ee1c90de3f7ef7b4f894c4edb1fc9b4b";

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Run the dice-fixture ETH signing flow (steps 1-3 of the smoke) and return
/// the signed output.
fn eth_signed_output() -> Vec<u8> {
    let rolls = fixture_rolls();
    let mut mnemonic_buf = [0u8; 24];
    business::create_account::create_account(WordCount::Words12, 6, &rolls, b"", &mut mnemonic_buf)
        .expect("create_account");
    let mut indices = [0u16; 12];
    for (i, idx) in indices.iter_mut().enumerate() {
        *idx = u16::from_le_bytes([mnemonic_buf[i * 2], mnemonic_buf[i * 2 + 1]]);
    }
    let mnemonic = Mnemonic::from_indices(&indices, WordCount::Words12).expect("mnemonic");
    let decoded = ur_decode::decode(ETH_SIGN_REQUEST_URI).expect("ur decode");
    let input = business::sign::SignInput::Mnemonic {
        mnemonic,
        passphrase: b"",
    };
    let mut out = [0u8; 512];
    let n = business::sign::sign_with_entropy(
        input,
        decoded.type_tag(),
        decoded.as_ref(),
        &[],
        &mut out,
    )
    .expect("sign");
    out[..n].to_vec()
}

/// Sparrow fixture: the `crypto-psbt` payload and its systematic multipart
/// frames (the exact strings the console channel feeds to the board).
fn sparrow_frames() -> (Vec<u8>, Vec<String>) {
    let payload = cbor::encode_bytes(SPARROW_PSBT);
    let mut enc =
        UrMultipartEncoder::new("crypto-psbt", &payload, SPARROW_FRAGMENT_LEN).expect("encoder");
    let n = enc.fragment_count();
    let mut frames = Vec::with_capacity(n);
    for _ in 0..n {
        frames.push(enc.next_frame().expect("frame"));
    }
    (payload, frames)
}

/// Sign the Sparrow payload with the fixture wallet (what the board does on
/// completion of the multipart decode).
fn sparrow_signed_output(payload: &[u8]) -> Vec<u8> {
    let mnemonic = Mnemonic::from_entropy(&SPARROW_ENTROPY).expect("mnemonic");
    let input = business::sign::SignInput::Mnemonic {
        mnemonic,
        passphrase: b"",
    };
    let mut out = [0u8; 16384 + 512];
    let n = business::sign::sign_with_entropy(input, UrTypeTag::CryptoPsbt, payload, &[], &mut out)
        .expect("sign");
    out[..n].to_vec()
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

    // ── Step 3: sign (same flow the board's boot smoke and console run) ──
    let signed = eth_signed_output();
    assert_eq!(signed.len(), 111, "host-sim oracle: signed tx length");
    assert_eq!(
        to_hex(&signed),
        EXPECTED_SIGNED_HEX,
        "host-sim oracle: signed hex"
    );
}

#[test]
fn pico2_sparrow_multipart_parity() {
    let (payload, frames) = sparrow_frames();
    assert!(frames.len() > 1, "fixture must exercise the multipart path");

    let mut dec = UrMultipartDecoder::new();
    for f in &frames {
        dec.receive_frame(f).expect("frame accepted");
    }
    assert!(
        dec.complete(),
        "systematic frames must complete the session"
    );
    assert_eq!(dec.ur_type(), Some("crypto-psbt"));
    let decoded = dec.payload().expect("payload ok").expect("complete");
    assert_eq!(
        decoded, payload,
        "multipart roundtrip must reproduce the payload"
    );

    let signed = sparrow_signed_output(&decoded);
    let digest = sha256::hash(&signed).expect("sha256");
    println!(
        "sparrow: signed {} bytes, sha256={}",
        signed.len(),
        to_hex(&digest)
    );
    assert_eq!(signed.len(), SPARROW_SIGNED_LEN, "pinned signed length");
    assert_eq!(
        to_hex(&digest),
        SPARROW_SIGNED_SHA256,
        "pinned signed sha256"
    );
}

/// Write the bench-channel fixture files to /tmp (the multipart frames the
/// console feeds to the board, plus the expected values to check replies
/// against). Run manually: `cargo test --release --test pico2_smoke_parity
/// -- --ignored --nocapture`.
#[test]
#[ignore = "writes bench-channel fixture files to /tmp (manual run)"]
fn gen_bench_channel_files() {
    let (payload, frames) = sparrow_frames();
    let frag_path = "/tmp/shlosilo_sparrow_fragments.txt";
    std::fs::write(frag_path, frames.join("\n") + "\n").expect("write fragments");

    let eth = eth_signed_output();
    let eth_sha = sha256::hash(&eth).expect("sha256 eth");

    let signed = sparrow_signed_output(&payload);
    let sp_sha = sha256::hash(&signed).expect("sha256 sparrow");

    let expected = format!(
        "eth_hex {}\neth_sha256 {}\nsparrow_len {}\nsparrow_sha256 {}\nfragments {}\nfragment_count {}\npayload_len {}\n",
        to_hex(&eth),
        to_hex(&eth_sha),
        signed.len(),
        to_hex(&sp_sha),
        frag_path,
        frames.len(),
        payload.len(),
    );
    std::fs::write("/tmp/shlosilo_bench_expected.txt", &expected).expect("write expected");
    println!("{expected}");
}
