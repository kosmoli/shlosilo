//! Watch-only vs full-wallet `export_outputs` container probe (diagnostic, not a
//! regression test). Root-cause experiment: does wallet2's `export_outputs`
//! container differ structurally (envelope signature / pk1-pk2 plaintext fields)
//! between a full wallet (spend+view) and a watch-only wallet (view only)?
//!
//! Run: `cargo test --test watchonly_probe -- --nocapture`
//! Inputs (env `WATCHONLY_PROBE_DIR`, default
//! `/home/komo/works/xmr-stagenet-lab/watchonly_probe`):
//!   full_outputs_all.bin  — full wallet export
//!   watch_outputs_all.bin — watch-only wallet export
//!   keys.hex              — "<spend_sk hex> <view_sk hex>"
//! Optional control (if present): /tmp/test0830_outputs_all + /tmp/test0830_keys.hex
//! (a different full wallet whose container is known to pass the device chain).

use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::rand_core::SeedableRng as _;
use shlosilo::chain::xmr::key_image_export::{
    decrypt_export_payload, generate_key_image_export, KEY_IMAGE_EXPORT_MAGIC, OUTPUT_EXPORT_MAGIC,
};
use shlosilo::chain::xmr::output_export::{ExportedTransferDetail, ExportedTransferDetails};
use shlosilo::chain::xmr::unsigned_txset::verify_monero_signature_pubkey;

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut a = [0u8; 32];
    for i in 0..32 {
        a[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    a
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn derive_pub(sk: &[u8; 32]) -> [u8; 32] {
    (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*sk))
        .compress()
        .to_bytes()
}

/// Self-implemented Monero Schnorr verify (independent of the library path):
/// sig = c‖r; valid ⇔ c == Hs(hash ‖ P ‖ (r·B + c·P)).
fn verify_sig_with(hash: &[u8; 32], pub32: &[u8; 32], sig: &[u8]) -> bool {
    let c = Scalar::from_bytes_mod_order(sig[..32].try_into().unwrap());
    let r = Scalar::from_bytes_mod_order(sig[32..].try_into().unwrap());
    let p: curve25519_dalek::EdwardsPoint = monero_ed25519::CompressedPoint::from(*pub32)
        .decompress()
        .expect("pubkey point")
        .into();
    let r_point = (ED25519_BASEPOINT_TABLE * &r) + (p * c);
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(hash);
    buf[32..64].copy_from_slice(pub32);
    buf[64..].copy_from_slice(&r_point.compress().to_bytes());
    // Hs: keccak256 reduced mod L (Monero sc_reduce32 semantics)
    let h = shlosilo::encoding::keccak256::hash(&buf).expect("keccak");
    Scalar::from_bytes_mod_order(h) == c
}

/// Signature-bypassing decrypt (diagnostic): ChaCha20Legacy(CN-V0(view_sk), nonce).
/// Returns (plaintext, nonce, sig).
fn forced_decrypt(container: &[u8], view_sk: &[u8; 32]) -> (Vec<u8>, [u8; 8], [u8; 64]) {
    let magic = OUTPUT_EXPORT_MAGIC;
    assert!(container.len() >= magic.len() + 8 + 64);
    assert_eq!(&container[..magic.len()], magic, "magic mismatch");
    let raw = &container[magic.len()..container.len() - 64]; // nonce ‖ cipher
    let nonce: [u8; 8] = raw[..8].try_into().unwrap();
    let sig: [u8; 64] = container[container.len() - 64..].try_into().unwrap();
    let key = cuprate_cryptonight::cryptonight_hash_v0(view_sk);
    let mut cipher = chacha20::ChaCha20Legacy::new_from_slices(&key, &nonce).unwrap();
    let mut plain = raw[8..].to_vec();
    cipher.apply_keystream(&mut plain);
    (plain, nonce, sig)
}

fn analyze(label: &str, container: &[u8], spend_sk: &[u8; 32], view_sk: &[u8; 32]) -> Vec<u8> {
    let magic = OUTPUT_EXPORT_MAGIC;
    let view_pub = derive_pub(view_sk);
    let spend_pub = derive_pub(spend_sk);
    println!("==== {} ({} bytes)", label, container.len());
    assert!(container.len() >= magic.len() + 8 + 64, "too short");
    println!("magic : {}", hex(&container[..magic.len()]));
    let raw = &container[magic.len()..container.len() - 64];
    let sig = &container[container.len() - 64..];
    println!("nonce : {}", hex(&raw[..8]));
    println!("sig   : {}", hex(sig));
    println!(
        "layout: magic({}) + nonce(8) + cipher({}) + sig(64)",
        magic.len(),
        raw.len() - 8
    );

    let h_raw = shlosilo::encoding::keccak256::hash(raw).expect("keccak");
    let h_all = shlosilo::encoding::keccak256::hash(&container[..container.len() - 64]).expect("k");
    let h_ct = shlosilo::encoding::keccak256::hash(&raw[8..]).expect("k");
    for (hn, h) in [
        ("keccak(nonce‖cipher)", &h_raw),
        ("keccak(magic‖nonce‖cipher)", &h_all),
        ("keccak(cipher)", &h_ct),
    ] {
        println!(
            "sig under view_pub  [{hn}]: self={} api={}",
            verify_sig_with(h, &view_pub, sig),
            verify_monero_signature_pubkey(h, &view_pub, sig).unwrap_or(false)
        );
        println!(
            "sig under spend_pub [{hn}]: self={} api={}",
            verify_sig_with(h, &spend_pub, sig),
            verify_monero_signature_pubkey(h, &spend_pub, sig).unwrap_or(false)
        );
    }

    // The device path: signature first, then decrypt.
    match decrypt_export_payload(container, OUTPUT_EXPORT_MAGIC, view_sk) {
        Ok((pk1, pk2, plain)) => {
            println!(
                "device-path decrypt: OK  pk1={} pk2={} plain_len={}",
                hex(&pk1),
                hex(&pk2),
                plain.len()
            );
        }
        Err(e) => println!("device-path decrypt: ERR {e:?}  <-- device would show rc -21"),
    }

    // Forced decrypt (sig bypassed) — the actual plaintext regardless of envelope.
    let (plain, _n, _s) = forced_decrypt(container, view_sk);
    let pk1 = &plain[..32];
    let pk2 = &plain[32..64];
    println!("forced plaintext ({} B):", plain.len());
    println!("  pk1 = {} (== spend_pub {})", hex(pk1), pk1 == spend_pub);
    println!("  pk2 = {} (== view_pub  {})", hex(pk2), pk2 == view_pub);
    println!("  rest = {}", hex(&plain[64..]));

    let mut pool: [ExportedTransferDetail; 8] =
        core::array::from_fn(|_| ExportedTransferDetail::default());
    match ExportedTransferDetails::from_bytes(&plain[64..], &mut pool) {
        Ok(d) => {
            println!("  epee parse: {} output(s)", d.details.len());
            for (i, t) in d.details.iter().enumerate() {
                println!(
                    "   [{i}] amount={} flags={:#x} internal={} global={} major={} minor={} pubkey={} tx_pubkey={}",
                    t.amount,
                    t.flags,
                    t.internal_output_index,
                    t.global_output_index,
                    t.major,
                    t.minor,
                    hex(&t.pubkey),
                    hex(&t.tx_pubkey)
                );
            }
        }
        Err(e) => println!("  epee parse: ERR {e:?}"),
    }
    plain
}

/// Concluded root-cause experiment (2026-10-11): does wallet2's
/// `export_outputs` container differ structurally between a full wallet and a
/// watch-only wallet? Kept as a lab tool, not a CI test -- it needs the
/// captured wallet fixtures under WATCHONLY_PROBE_DIR (machine-bound) and the
/// question it asked has been answered. Run manually with:
///   `cargo test --offline --test watchonly_probe -- --ignored --nocapture`
#[test]
#[ignore = "lab fixture-dependent root-cause experiment; run manually with --ignored"]
fn watchonly_vs_full_export_outputs() {
    let dir = std::env::var("WATCHONLY_PROBE_DIR")
        .unwrap_or_else(|_| "/home/komo/works/xmr-stagenet-lab/watchonly_probe".into());
    let keys = std::fs::read_to_string(format!("{dir}/keys.hex")).expect("keys.hex");
    let mut it = keys.split_whitespace();
    let spend_sk = hex_to_32(it.next().unwrap());
    let view_sk = hex_to_32(it.next().unwrap());
    println!("spend_sk = {}", hex(&spend_sk));
    println!("view_sk  = {}", hex(&view_sk));
    println!("spend_pub = {}", hex(&derive_pub(&spend_sk)));
    println!("view_pub  = {}", hex(&derive_pub(&view_sk)));

    let full = std::fs::read(format!("{dir}/full_outputs_all.bin")).expect("full container");
    let watch = std::fs::read(format!("{dir}/watch_outputs_all.bin")).expect("watch container");
    let p_full = analyze("FULL wallet export_outputs", &full, &spend_sk, &view_sk);
    let p_watch = analyze(
        "WATCH-ONLY wallet export_outputs",
        &watch,
        &spend_sk,
        &view_sk,
    );

    // Full pairing pipeline on BOTH containers: decrypt → pk1/pk2 ownership →
    // key image + accompanying sig → KEY_IMAGE_EXPORT container.
    for (label, container) in [("full", &full), ("watch", &watch)] {
        let mut pool: [ExportedTransferDetail; 8] =
            core::array::from_fn(|_| ExportedTransferDetail::default());
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);
        let out = generate_key_image_export(&view_sk, &spend_sk, container, &mut pool, &mut rng);
        match out {
            Ok(enc) => {
                let (_a, _b, wire) = decrypt_export_payload(&enc, KEY_IMAGE_EXPORT_MAGIC, &view_sk)
                    .expect("readback");
                println!(
                    "pipeline[{label}]: OK keyimage_container={} B, records={} B, image={}",
                    enc.len(),
                    wire.len(),
                    hex(&wire[..32.min(wire.len())])
                );
            }
            Err(e) => println!("pipeline[{label}]: ERR {e:?}  <-- device pairing would fail"),
        }
    }

    println!("==== plaintext diff");
    println!("full plain len  = {}", p_full.len());
    println!("watch plain len = {}", p_watch.len());
    if p_full == p_watch {
        println!("plaintexts IDENTICAL (container diff is nonce/sig randomness only)");
    } else {
        println!("plaintexts DIFFER:");
        println!("  full  = {}", hex(&p_full));
        println!("  watch = {}", hex(&p_watch));
    }

    // Control: a known-good full-wallet container from a different wallet.
    if let (Ok(c), Ok(k)) = (
        std::fs::read("/tmp/test0830_outputs_all"),
        std::fs::read_to_string("/tmp/test0830_keys.hex"),
    ) {
        let mut it = k.split_whitespace();
        let cs = hex_to_32(it.next().unwrap().trim());
        let cv = hex_to_32(it.next().unwrap().trim());
        analyze("CONTROL test0830 full-wallet export_outputs", &c, &cs, &cv);
    } else {
        println!("(control /tmp/test0830_* not present — skipped)");
    }
}
