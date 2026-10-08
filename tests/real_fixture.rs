//! Real-fixture end-to-end verification (ignored; needs real wallet artifacts):
//!   cargo test --test real_fixture -- --ignored --nocapture
//!
//! fixture (monero-wallet-cli, test0830, a real wallet receiving 0.001 XMR):
//!   /tmp/test0830_outputs_all — export_outputs all(OUTPUT_EXPORT, 1 output)
//!   /tmp/test0830_cli_ki_all     — export_key_images (KEY_IMAGE_EXPORT, CLI self-computed golden reference)
//!
//! Pipeline: decrypt → verify signature → pk1/pk2 ownership → epee parse → shlosilo computes key image + signature →
//!       KEY_IMAGE_EXPORT encrypt → read-back decrypt cross-check → byte-for-byte compare against the CLI's self-computed key image →
//!       self-implemented verification of BOTH 64B signatures (container envelope + per-record accompanying sig).

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

// ---- Self-implemented signature verification (sig-semantics pin) ----------
// Independent of the library check paths: these re-derive the verify formulas
// from the spec (Monero crypto.cpp `check_signature` / `check_ring_signature`)
// so the sig semantics are anchored to the CLI golden, not just to our own
// generator. Pinned here: the `c‖r` scalar order, the Hs input layout, and the
// `keccak256(nonce‖cipher)` container message formula. All quantities are
// known from the fixtures (P from the request details, I from the record).

/// Monero Hs: keccak256(data) reduced mod L (sc_reduce32).
fn hs(data: &[u8]) -> [u8; 32] {
    use curve25519_dalek::scalar::Scalar;
    let h = shlosilo::encoding::keccak256::hash(data).expect("keccak");
    Scalar::from_bytes_mod_order(h).to_bytes()
}

/// Container envelope signature: Monero Schnorr over
/// `keccak256(nonce ‖ ciphertext-before-sig)`, pubkey = view_pub.
/// sig = `c‖r`; valid ⇔ c == Hs(hash ‖ view_pub ‖ (r·B + c·view_pub)).
fn verify_container_sig(container: &[u8], magic: &[u8], view_sk: &[u8; 32]) -> bool {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    if container.len() < magic.len() + 8 + 64 {
        return false;
    }
    let raw = &container[magic.len()..container.len() - 64]; // nonce ‖ cipher
    let sig = &container[container.len() - 64..];
    let msg = shlosilo::encoding::keccak256::hash(raw).expect("keccak");
    let view_pub = (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*view_sk))
        .compress()
        .to_bytes();
    let c = Scalar::from_bytes_mod_order(sig[..32].try_into().unwrap());
    let r = Scalar::from_bytes_mod_order(sig[32..].try_into().unwrap());
    let p: curve25519_dalek::EdwardsPoint = monero_ed25519::CompressedPoint::from(view_pub)
        .decompress()
        .expect("view_pub point")
        .into();
    let r_point = (ED25519_BASEPOINT_TABLE * &r) + (p * c);
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(&msg);
    buf[32..64].copy_from_slice(&view_pub);
    buf[64..].copy_from_slice(&r_point.compress().to_bytes());
    hs(&buf) == c.to_bytes()
}

/// Accompanying key-image signature (ring=1, Monero `check_ring_signature`
/// layout): record = `[32B image][64B sig]`, sig = `c‖r`; valid ⇔
/// c == Hs(image ‖ L ‖ R) with L = r·B + c·P, R = r·Hp(P) + c·I —
/// proving I = x·Hp(P) for the x behind P = x·G.
fn verify_key_image_sig(record: &[u8], out_pub: &[u8; 32]) -> bool {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    if record.len() != KEY_IMAGE_RECORD_LEN {
        return false;
    }
    let image = &record[..32];
    let sig = &record[32..96];
    let img: [u8; 32] = image.try_into().unwrap();
    let c = Scalar::from_bytes_mod_order(sig[..32].try_into().unwrap());
    let r = Scalar::from_bytes_mod_order(sig[32..].try_into().unwrap());
    let p: curve25519_dalek::EdwardsPoint = monero_ed25519::CompressedPoint::from(*out_pub)
        .decompress()
        .expect("out_pub point")
        .into();
    let i: curve25519_dalek::EdwardsPoint = monero_ed25519::CompressedPoint::from(img)
        .decompress()
        .expect("image point")
        .into();
    let hp_p: curve25519_dalek::EdwardsPoint = monero_ed25519::Point::biased_hash(*out_pub).into();
    let l = (ED25519_BASEPOINT_TABLE * &r) + (p * c);
    let rr = (hp_p * r) + (i * c);
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(image);
    buf[32..64].copy_from_slice(&l.compress().to_bytes());
    buf[64..].copy_from_slice(&rr.compress().to_bytes());
    hs(&buf) == c.to_bytes()
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
    let mut pool: [shlosilo::chain::xmr::output_export::ExportedTransferDetail; 8] =
        core::array::from_fn(|_| {
            shlosilo::chain::xmr::output_export::ExportedTransferDetail::default()
        });
    let details = ExportedTransferDetails::from_bytes(&plain, &mut pool).expect("parse failed");
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
    let mut pool: [shlosilo::chain::xmr::output_export::ExportedTransferDetail; 8] =
        core::array::from_fn(|_| {
            shlosilo::chain::xmr::output_export::ExportedTransferDetail::default()
        });
    let encrypted = generate_key_image_export(&view_sk, &spend_sk, &payload, &mut pool, &mut rng)
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
    // 64B accompanying signature: verify instead of compare (randomized) —
    // the self-implemented ring=1 formula pins c‖r order + Hs layout against
    // the CLI golden (external anchor), for both records.
    assert!(
        verify_key_image_sig(&cwire[..], &d0.pubkey),
        "CLI golden accompanying signature must verify"
    );
    assert!(
        verify_key_image_sig(&wire[..], &d0.pubkey),
        "our accompanying signature must verify"
    );
    // Container envelope: keccak256(nonce‖cipher) Schnorr formula, both sides.
    assert!(
        verify_container_sig(&cli_ki, KEY_IMAGE_EXPORT_MAGIC, &view_sk),
        "CLI golden container signature must verify"
    );
    assert!(
        verify_container_sig(&encrypted, KEY_IMAGE_EXPORT_MAGIC, &view_sk),
        "our container signature must verify"
    );
    println!(
        "key image: {}",
        wire[..32]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
}

/// T3 golden: the business receive leg (`process_output_export`) over the same
/// real-wallet fixture must produce a key image byte-identical to the CLI's
/// self-computed `export_key_images` reference. The accompanying signature
/// carries randomness, so it is verified with the self-implemented ring=1
/// formula instead of compared (same rule as above).
#[test]
#[ignore]
fn real_wallet_business_process_output_export() {
    let payload = std::fs::read("/tmp/test0830_outputs_all").expect("fixture not found");
    let keys = std::fs::read_to_string("/tmp/test0830_keys.hex").expect("keys");
    let mut it = keys.split_whitespace();
    let spend_sk = hex_to_32(it.next().unwrap().trim());
    let view_sk = hex_to_32(it.next().unwrap().trim());

    // The output pubkey P (public verify input) comes from the request details.
    let (_pk1, _pk2, req_plain) = decrypt_export_payload(&payload, OUTPUT_EXPORT_MAGIC, &view_sk)
        .expect("request decrypt failed");
    let mut req_pool: [shlosilo::chain::xmr::output_export::ExportedTransferDetail; 8] =
        core::array::from_fn(|_| {
            shlosilo::chain::xmr::output_export::ExportedTransferDetail::default()
        });
    let req_details = ExportedTransferDetails::from_bytes(&req_plain, &mut req_pool)
        .expect("request parse failed");
    let out_pub = req_details.details[0].pubkey;

    let mut ws_raw = vec![0u8; shlosilo::business::xmr_pairing::pairing_ws_len()];
    let mut ws = shlosilo::business::xmr_pairing::carve_pairing_ws(&mut ws_raw).expect("carve ws");
    use rand_chacha::rand_core::SeedableRng as _;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);
    let mut out = vec![0u8; 8192];
    let outcome = shlosilo::business::xmr_pairing::process_output_export(
        &view_sk, &spend_sk, &payload, &mut ws, &mut out, &mut rng,
    )
    .expect("process_output_export failed");
    assert_eq!(outcome.output_count, 1, "expected exactly 1 output");
    assert!(outcome.written > 0);

    // Read-back: decrypt the produced container and the CLI golden; compare images.
    let (_rpk1, _rpk2, wire) = shlosilo::chain::xmr::key_image_export::decrypt_export_payload(
        &out[..outcome.written],
        shlosilo::chain::xmr::key_image_export::KEY_IMAGE_EXPORT_MAGIC,
        &view_sk,
    )
    .expect("roundtrip decrypt failed");
    assert_eq!(
        wire.len(),
        KEY_IMAGE_RECORD_LEN,
        "1 output = one 96B record"
    );

    let cli_ki = std::fs::read("/tmp/test0830_cli_ki_all").expect("cli key image fixture");
    let (_cpk1, _cpk2, cwire) = shlosilo::chain::xmr::key_image_export::decrypt_export_payload(
        &cli_ki,
        shlosilo::chain::xmr::key_image_export::KEY_IMAGE_EXPORT_MAGIC,
        &view_sk,
    )
    .expect("cli key image decrypt failed");
    assert_eq!(cwire.len(), KEY_IMAGE_RECORD_LEN);
    assert_eq!(
        &wire[..32],
        &cwire[..32],
        "key image mismatch vs CLI golden"
    );
    // 64B accompanying signature + container envelope: self-implemented verify
    // (pins the sig semantics against the CLI golden — see the helpers above).
    assert!(
        verify_key_image_sig(&cwire[..], &out_pub),
        "CLI golden accompanying signature must verify"
    );
    assert!(
        verify_key_image_sig(&wire[..], &out_pub),
        "our accompanying signature must verify"
    );
    assert!(
        verify_container_sig(&cli_ki, KEY_IMAGE_EXPORT_MAGIC, &view_sk),
        "CLI golden container signature must verify"
    );
    assert!(
        verify_container_sig(&out[..outcome.written], KEY_IMAGE_EXPORT_MAGIC, &view_sk),
        "our container signature must verify"
    );
}
