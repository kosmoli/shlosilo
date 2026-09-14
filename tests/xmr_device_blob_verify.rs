//! Device/host A/B verification for the XMR signing path.
//!
//! The board signed the smoke fixture with FIXED entropy (`xmrseed`); this
//! test recomputes the same signing on the host with the same inputs and
//! requires byte-identical output, then decrypts the board's blob and checks
//! the signed-txset structure. Reads:
//!   /tmp/xmr_device_signed.bin  (fetched from the board by bench/xmr_sign.py)
//!   /tmp/xmr_smoke_enc.bin      (the same fixture the board signed)
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

/// Must match what bench/xmr_sign.py passed via `xmrseed`.
const FIXED_ENTROPY: [u8; 32] = [0x77u8; 32];

#[test]
#[ignore = "hardware A/B: needs the fetched device blob (bench/xmr_sign.py)"]
fn device_blob_matches_host() {
    let device_blob =
        std::fs::read("/tmp/xmr_device_signed.bin").expect("device blob (run bench/xmr_sign.py)");
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
        &shlosilo::encoding::sha256::hash(&out[..n]).unwrap()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        &shlosilo::encoding::sha256::hash(&device_blob).unwrap()[..8]
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

    // Independent structure check: decrypt the board's blob with the wallet's
    // view key and confirm it parses as a signed txset.
    let seed = {
        let m = Mnemonic::from_indices(&SMOKE_IDX12, WordCount::Words12).expect("mnemonic");
        let mut s = [0u8; 64];
        shlosilo::business::restore_seed::restore_seed(&m, &[], &mut s).expect("restore");
        s
    };
    let kp = derive(&seed, &MoneroPath::mainnet(0)).expect("derive");
    let view_sec = shlosilo::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv());
    let plain = decrypt_signed_txset(&device_blob, &view_sec).expect("decrypt device blob");
    eprintln!("device blob decrypts: {} bytes plaintext", plain.len());
    assert!(!plain.is_empty());
}
