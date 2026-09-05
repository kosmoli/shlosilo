//! Real-fixture end-to-end verification (ignored; needs real wallet artifacts):
//!   cargo test --test real_fixture -- --ignored --nocapture
//!
//! fixture (monero-wallet-cli, test0830, a real wallet receiving 0.001 XMR):
//!   /tmp/test0830_outputs_all — export_outputs all(OUTPUT_EXPORT, 1 output)
//!   /tmp/test0830_cli_ki_all     — export_key_images (KEY_IMAGE_EXPORT, CLI self-computed golden reference)
//!
//! Pipeline: decrypt → verify signature → pk1/pk2 ownership → epee parse → shlosilo computes key image + signature →
//!       KEY_IMAGE_EXPORT encrypt → read-back decrypt cross-check → byte-for-byte compare against the CLI's self-computed key image.

use shlosilo::chain::xmr::key_image_export::{
    decrypt_export_payload, generate_key_image_export, KEY_IMAGE_EXPORT_MAGIC, OUTPUT_EXPORT_MAGIC,
};
use shlosilo::chain::xmr::output_export::{ExportedTransferDetails, KEY_IMAGE_RECORD_LEN};

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut a = [0u8; 32];
    for i in 0..32 {
        a[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    a
}

#[test]
#[ignore]
fn real_wallet_output_export_e2e() {
    let payload = std::fs::read("/tmp/test0830_outputs_all").expect("fixture not found");
    let keys = std::fs::read_to_string("/tmp/test0830_keys.hex").expect("keys");
    let mut it = keys.split_whitespace();
    let spend_sk = hex_to_32(it.next().unwrap().trim());
    let view_sk = hex_to_32(it.next().unwrap().trim());

    // (1) Standalone decryption checks (signature/ownership/parsing)
    let (_pk1, _pk2, plain) =
        decrypt_export_payload(&payload, OUTPUT_EXPORT_MAGIC, &view_sk).expect("decrypt failed");
    let details = ExportedTransferDetails::from_bytes(&plain).expect("parse failed");
    assert_eq!(details.details.len(), 1, "expected exactly 1 output");
    let d0 = &details.details[0];
    // The full-featured CLI wallet computes key images itself and the request bit is 0 — recorded as fact, not asserted
    println!(
        "output: amount={} flags={:#b} major={} minor={}",
        d0.amount, d0.flags, d0.major, d0.minor
    );

    // (2) Full pipeline (includes pk1 ownership check + input_sk·G == output_pubkey)
    use rand_chacha::rand_core::SeedableRng as _;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);
    let encrypted = generate_key_image_export(&view_sk, &spend_sk, &payload, &mut rng)
        .expect("generate_key_image_export failed");
    std::fs::write("/tmp/test0830_keyimages", &encrypted).unwrap();

    // (3) Read-back cross-verification (decryption from the hot-end perspective)
    let (_rpk1, _rpk2, wire) = decrypt_export_payload(&encrypted, KEY_IMAGE_EXPORT_MAGIC, &view_sk)
        .expect("roundtrip decrypt failed");
    assert_eq!(
        wire.len(),
        KEY_IMAGE_RECORD_LEN,
        "1 output = one 96B record"
    );

    // (4) Golden reference: byte-for-byte comparison against the CLI's self-computed key image
    let cli_ki = std::fs::read("/tmp/test0830_cli_ki_all").expect("cli key image fixture");
    let (_cpk1, _cpk2, cwire) = decrypt_export_payload(&cli_ki, KEY_IMAGE_EXPORT_MAGIC, &view_sk)
        .expect("cli key image decrypt failed");
    assert_eq!(cwire.len(), KEY_IMAGE_RECORD_LEN);
    // record = [32B image][64B sig]; the image must match (the signature contains randomness, so only verify, don't compare)
    assert_eq!(&wire[..32], &cwire[..32], "key image mismatch vs CLI");
    println!(
        "key image: {}",
        wire[..32]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
}
