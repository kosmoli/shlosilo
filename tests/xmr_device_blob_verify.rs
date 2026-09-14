//! Device/host verification for the XMR signing path.
//!
//! Two independent checks over the blob fetched from the board
//! (bench/xmr_bringup.py -> /tmp/xmr_device_signed.bin):
//!
//! 1. `device_blob_decrypts` - structure check that works for ANY device
//!    run (fixed-entropy A/B or the production TRNG path): the blob is a
//!    valid signed txset, decryptable with the fixture wallet's view key.
//! 2. `device_blob_matches_host` - byte-exact A/B against a host
//!    recomputation; requires the blob to have been signed with the FIXED
//!    entropy (`xmrseed`), so it only applies to the A/B run.
//!
//! Reads:
//!   /tmp/xmr_device_signed.bin  (the fetched device blob)
//!   /tmp/xmr_smoke_enc.bin      (the fixture the board signed)
//!
//! Run:
//!   cargo test --release --test xmr_device_blob_verify -- --ignored --nocapture

use shlosilo::business::sign::{sign_with_entropy, SignInput};
use shlosilo::chain::xmr::signed_txset::decrypt_signed_txset;
use shlosilo::derivation::monero_reduce_scalar::{derive, MoneroPath};
use shlosilo::entropy::mnemonic::{Mnemonic, WordCount};
use shlosilo::ur::ur_encode::UrTypeTag;

/// Kept in sync with xmr_device_peak_fixture.rs and the on-device smoke
/// wallet (entropy 0x11x16).
const SMOKE_IDX12: [u16; 12] = [
    136, 1092, 546, 273, 136, 1092, 546, 273, 136, 1092, 546, 283,
];

/// Must match what bench/xmr_bringup.py passed via `xmrseed`.
const FIXED_ENTROPY: [u8; 32] = [0x77u8; 32];

/// The fixture wallet's Monero view key.
fn smoke_view_key() -> [u8; 32] {
    let m = Mnemonic::from_indices(&SMOKE_IDX12, WordCount::Words12).expect("mnemonic");
    let mut seed = [0u8; 64];
    shlosilo::business::restore_seed::restore_seed(&m, &[], &mut seed).expect("restore");
    let kp = derive(&seed, &MoneroPath::mainnet(0)).expect("derive");
    shlosilo::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv())
}

/// The built-in dice fixture's view key (the production default wallet;
/// mirrors flux/pico2/src/sign_smoke.rs::fixture_mnemonic).
fn dice_view_key() -> [u8; 32] {
    let mut rolls = [0u8; 64];
    for (i, r) in rolls.iter_mut().enumerate() {
        *r = (i % 6 + 1) as u8;
    }
    let mut mnemonic_buf = [0u8; 24];
    shlosilo::business::create_account::create_account(
        WordCount::Words12,
        6,
        &rolls,
        b"",
        &mut mnemonic_buf,
    )
    .expect("create_account");
    let mut indices = [0u16; 12];
    for (i, idx) in indices.iter_mut().enumerate() {
        *idx = u16::from_le_bytes([mnemonic_buf[i * 2], mnemonic_buf[i * 2 + 1]]);
    }
    let m = Mnemonic::from_indices(&indices, WordCount::Words12).expect("mnemonic");
    let mut seed = [0u8; 64];
    shlosilo::business::restore_seed::restore_seed(&m, &[], &mut seed).expect("restore");
    let kp = derive(&seed, &MoneroPath::mainnet(0)).expect("derive");
    shlosilo::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv())
}

#[test]
#[ignore = "hardware: needs the fetched device blob (bench/xmr_bringup.py)"]
fn device_blob_decrypts() {
    let device_blob =
        std::fs::read("/tmp/xmr_device_signed.bin").expect("device blob (run bench/xmr_bringup)");
    let view_sec = smoke_view_key();
    let plain =
        decrypt_signed_txset(&device_blob, &view_sec).expect("decrypt device blob with view key");
    eprintln!(
        "device blob decrypts: {} bytes plaintext (blob {} bytes)",
        plain.len(),
        device_blob.len()
    );
    assert!(!plain.is_empty(), "empty plaintext");
}

/// Production-path structural check: the blob was signed by a production
/// image, whose session wallet is the built-in dice fixture (no `entropy`
/// command there). Fixture: xmr_device_peak_fixture::dice_xmr_ur_for_production_path.
#[test]
#[ignore = "hardware: needs a production-path device blob (dice-wallet fixture)"]
fn device_blob_decrypts_dice() {
    let device_blob =
        std::fs::read("/tmp/xmr_device_signed.bin").expect("device blob (run xmr_prod_check)");
    let view_sec = dice_view_key();
    let plain = decrypt_signed_txset(&device_blob, &view_sec)
        .expect("decrypt device blob with dice view key");
    eprintln!(
        "device blob decrypts (dice wallet): {} bytes plaintext (blob {} bytes)",
        plain.len(),
        device_blob.len()
    );
    assert!(!plain.is_empty(), "empty plaintext");
}

#[test]
#[ignore = "hardware A/B: needs the FIXED-entropy device blob (xmrseed run)"]
fn device_blob_matches_host() {
    // Prefer the fixed-entropy blob saved under its stable name (a later
    // TRNG run overwrites /tmp/xmr_device_signed.bin with a random result
    // that cannot match a host recomputation, by design).
    let fixed_path = "/tmp/xmr_device_signed_fixed.bin";
    let blob_path = if std::path::Path::new(fixed_path).exists() {
        fixed_path
    } else {
        "/tmp/xmr_device_signed.bin"
    };
    let device_blob = std::fs::read(blob_path).expect("device blob (run bench/xmr_bringup)");
    eprintln!("A/B source: {blob_path}");
    let enc =
        std::fs::read("/tmp/xmr_smoke_enc.bin").expect("fixture (run xmr_device_peak_fixture)");

    // Host recomputation through the same direct Rust path the board uses.
    let mnemonic = Mnemonic::from_indices(&SMOKE_IDX12, WordCount::Words12).expect("mnemonic");
    let mut out = vec![0u8; 16384];
    let n = sign_with_entropy(
        SignInput::Mnemonic {
            mnemonic,
            passphrase: b"",
        },
        UrTypeTag::XmrTxUnsigned,
        &enc,
        &FIXED_ENTROPY,
        &mut out,
    )
    .expect("host sign");

    eprintln!(
        "host: {n} bytes; device: {} bytes; digests h={} d={}",
        device_blob.len(),
        shlosilo::encoding::sha256::hash(&out[..n]).unwrap()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        shlosilo::encoding::sha256::hash(&device_blob).unwrap()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    assert_eq!(device_blob.len(), n, "length differs");
    assert_eq!(
        &out[..n],
        &device_blob[..],
        "A/B FAILED: device blob differs from the host recomputation"
    );
    eprintln!("A/B MATCH ({n} bytes)");
}
