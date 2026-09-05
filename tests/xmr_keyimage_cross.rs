//! XMR key image export reverse cross-validation (shlosilo encrypt → keystone decrypt).
//!
//! Flow: shlosilo generates the OUTPUT_EXPORT encrypted payload + end-to-end key image export,
//! writes the KEY_IMAGE_EXPORT encrypted artifact to `/tmp/xmr_shlosilo_ki_fixture.bin`;
//! the keystone fork-side test reads it and consumes it with `decrypt_data_with_pvk` (see
//! keystone3-firmware/rust/apps/monero src/utils/mod.rs `shlosilo_ki_fixture_test`）。
//!
//! Dependencies: run this test first to produce the fixture, then run the keystone-side test.
#![cfg(test)]

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use shlosilo::chain::xmr::key_image_export::{
    decrypt_export_payload, generate_key_image_export, OUTPUT_EXPORT_MAGIC,
};
use shlosilo::chain::xmr::output_export::ExportedTransferDetails;
use shlosilo::chain::xmr::subaddress::calc_output_key_offset;

const SPEND_SK: [u8; 32] = [5u8; 32];
const VIEW_SK: [u8; 32] = [5u8; 32];

fn point(sk: &[u8; 32]) -> [u8; 32] {
    (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*sk))
        .compress()
        .to_bytes()
}

#[test]
fn generate_shlosilo_keyimage_fixture_for_keystone() {
    let mut rng = ChaCha20Rng::seed_from_u64(2026);

    // Real output: input_sk = spend + offset(view, tx_pub, 0, 0, 0)
    // tx_pub must be a valid curve point (in a real transaction it is the one-time output key)
    let tx_pub = (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order([0x42u8; 32]))
        .compress()
        .to_bytes();
    let offset = calc_output_key_offset(&VIEW_SK, &tx_pub, 0, 0, 0).unwrap();
    let input_sk = Scalar::from_bytes_mod_order(SPEND_SK) + Scalar::from_bytes_mod_order(offset);
    let out_pub = (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes();

    // ExportedTransferDetails plaintext (main-address output)
    let mut plain = Vec::new();
    plain.extend_from_slice(&[0x01, 0x00, 0x01, 0x00]); // has_transfers, offset, count, blob_size
    plain.extend_from_slice(&[0x01]); // version
    plain.extend_from_slice(&out_pub);
    plain.extend_from_slice(&[0x00]); // internal_output_index
    plain.extend_from_slice(&[0x64]); // global_output_index = 100
    plain.extend_from_slice(&tx_pub);
    plain.push(0b0001_0100); // rct | key_image_request
    plain.extend_from_slice(&[0x80, 0x96, 0x98, 0x91, 0x04]); // amount varint ~ 1.0 XMR
    plain.extend_from_slice(&[0x00, 0x00, 0x00]); // no add keys, major=0, minor=0

    // Self-check: shlosilo can parse it itself
    let details = ExportedTransferDetails::from_bytes(&plain).unwrap();
    assert_eq!(details.details.len(), 1);
    assert!(details.details[0].is_key_image_request());

    // shlosilo encrypt (simulates the Feather hot-end encrypting the output export)
    let spend_pub = point(&SPEND_SK);
    let view_pub = point(&VIEW_SK);

    // End-to-end: OUTPUT_EXPORT encrypted input is required. The public API does not expose encrypt,
    // so this test first fixes the nonce and replicates the keystone encrypt logic (consistent with utils/mod.rs encrypt_data_with_pvk),
    // and this logic is independently replicated for decryption in the keystone-side test; both sides implement the same wire spec, which is the cross-validation.
    let enc_req = shlosilo_encrypt_export_for_test(&plain, &spend_pub, &view_pub, &mut rng);

    // shlosilo end-to-end → KEY_IMAGE_EXPORT encrypted artifact
    let enc_resp = generate_key_image_export(&VIEW_SK, &SPEND_SK, &enc_req, &mut rng).unwrap();

    // Self-check: shlosilo decrypts its own round loop
    let (_, _, resp_plain) = decrypt_export_payload(
        &enc_resp,
        shlosilo::chain::xmr::key_image_export::KEY_IMAGE_EXPORT_MAGIC,
        &VIEW_SK,
    )
    .unwrap();
    assert!(!resp_plain.is_empty());

    // Write the fixture for the keystone side to consume
    std::fs::write("/tmp/xmr_shlosilo_ki_fixture.bin", &enc_resp).unwrap();
    std::fs::write("/tmp/xmr_shlosilo_ki_viewkey.hex", hex(&VIEW_SK)).unwrap();
}

fn shlosilo_encrypt_export_for_test<
    R: rand_chacha::rand_core::RngCore + rand_chacha::rand_core::CryptoRng,
>(
    plain: &[u8],
    spend_pub: &[u8; 32],
    view_pub: &[u8; 32],
    rng: &mut R,
) -> Vec<u8> {
    // Replicate keystone encrypt_data_with_pvk (OUTPUT magic: no u32 prefix, with pk1||pk2)
    // Encryption key = cryptonight_hash_v0(view_sk); sig = Monero Schnorr(keccak(nonce||ct), view_sk)
    // Note: the same logic inside the shlosilo lib is already covered by unit tests; this constructs inputs at the integration layer.
    let mut nonce8 = [0u8; 8];
    rng.fill_bytes(&mut nonce8);

    let key: [u8; 32] = cuprate_cryptonight::cryptonight_hash_v0(&VIEW_SK);
    use chacha20::cipher::KeyIvInit as _;
    let mut cipher = chacha20::ChaCha20Legacy::new_from_slices(&key, &nonce8).unwrap();
    use chacha20::cipher::StreamCipher;
    let mut buffer = Vec::with_capacity(64 + plain.len());
    buffer.extend_from_slice(spend_pub);
    buffer.extend_from_slice(view_pub);
    buffer.extend_from_slice(plain);
    cipher.apply_keystream(&mut buffer);

    let mut signed = Vec::with_capacity(8 + buffer.len());
    signed.extend_from_slice(&nonce8);
    signed.extend_from_slice(&buffer);
    let hash = shlosilo::encoding::keccak256::hash(&signed).unwrap();
    let v_scalar = Scalar::from_bytes_mod_order(VIEW_SK);
    let sig =
        shlosilo::chain::xmr::key_image_export::generate_monero_signature(&hash, &v_scalar, rng)
            .unwrap();

    let mut out = Vec::new();
    out.extend_from_slice(OUTPUT_EXPORT_MAGIC);
    out.extend_from_slice(&signed);
    out.extend_from_slice(&sig);
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
