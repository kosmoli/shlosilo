//! P64: XMR multi-input fixture workflow (real-funds, device-loadable wallet).
//!
//! Task 4 of the pico2 handoff: multi-input XMR fixture + host timing before
//! device work. The device can only rebuild wallet keys from an `entropy <hex>`
//! command (BIP-39 → Keystone Monero path m/44'/128'/0'/0/0 → spend = Hs(raw),
//! view = Hs(spend)), so a monero CLI random-seed wallet cannot be re-derived
//! on-device. This workflow therefore uses a *deterministic* wallet whose spend
//! key is imported into monero CLI (view key and address derive identically on
//! both sides: view = Hs(spend)):
//!
//! 1. `gen_deterministic_wallet` (host tool) — entropy → spend key + address
//! 2. monero CLI/RPC: import the spend key → `sh_dev` wallet (address must match)
//! 3. fund the address (external)
//! 4. watch-only clone + CLI transfer → `unsigned_monero_tx` (multi-input)
//! 5. `decrypt_and_parse_fixture` — verify the fixture (expects 2 sources)
//! 6. `sign_and_time` — host signing + timing (milestone estimate)
//! 7. device: `entropy <hex>` + UR → signed txset → broadcast (final verdict)
//!
//! Run:
//!   P64_ENTROPY_HEX=$(cat /tmp/p64_env | cut -d= -f2) cargo test --release \
//!     --test p64_xmr_multi_input -- --ignored --nocapture

use shlosilo::address::xmr::encode;
use shlosilo::business::restore_seed::restore_seed;
use shlosilo::curve_primitive::ed25519::{point_to_compressed, scalar_to_bytes};
use shlosilo::derivation::monero_reduce_scalar::{derive, MoneroPath};
use shlosilo::entropy::mnemonic::Mnemonic;
use shlosilo::network::Network;

/// Fixture generated from the real wallet (2-input unsigned txset).
const FIXTURE: &[u8] = include_bytes!("fixtures/unsigned_txset_2in.bin");

/// Fixture under test: `P64_FIXTURE_PATH` overrides the embedded default
/// (lets the same workflow check both the host-keys and device-keys variants).
fn fixture_bytes() -> Vec<u8> {
    match std::env::var("P64_FIXTURE_PATH") {
        Ok(p) => std::fs::read(&p).expect("read P64_FIXTURE_PATH"),
        Err(_) => FIXTURE.to_vec(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn env_hex(name: &str) -> Option<[u8; 32]> {
    let Ok(s) = std::env::var(name) else {
        return None;
    };
    let v: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect::<Option<_>>()?;
    v.try_into().ok()
}

/// Host tool: build the deterministic device wallet material from the entropy.
/// Prints spend key + address; import the spend key into monero CLI next.
#[test]
#[ignore = "host tool for fixture setup (task 4)"]
fn gen_deterministic_wallet() {
    let entropy_hex =
        std::env::var("P64_ENTROPY_HEX").expect("set P64_ENTROPY_HEX (64 hex chars = 32 bytes)");
    let entropy: Vec<u8> = (0..entropy_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&entropy_hex[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(entropy.len(), 32, "need 32 bytes (24 words)");

    let m = Mnemonic::from_entropy(&entropy).expect("mnemonic from entropy");
    let mut seed = [0u8; 64];
    restore_seed(&m, &[], &mut seed).expect("bip39 seed (empty passphrase)");
    let kp = derive(&seed, &MoneroPath::mainnet(0)).expect("keystone monero derive");

    // Monero semantics: pubkey = raw_scalar * G. NOT ed25519-dalek's RFC-8032
    // seed-based `SigningKey::verifying_key()` (which curve_primitive::ed25519
    // ::base_mul uses); that one computes clamp(SHA512(seed))*G and produces
    // wrong keys for Monero-style raw scalars. Use curve25519_dalek directly
    // (same pattern as tests/xmr_device_peak_fixture.rs).
    let spend_pub = monero_pub(&scalar_to_bytes(kp.spend_priv()));
    let view_pub = monero_pub(&scalar_to_bytes(kp.view_priv()));
    let addr = encode(&spend_pub, &view_pub, Network::MoneroMainnet).expect("address encode");

    println!("== deterministic device wallet ==");
    println!("entropy_hex = {entropy_hex}");
    println!("words       = {:?}", m.word_count());
    println!("spend_priv  = {}", hex(&scalar_to_bytes(kp.spend_priv())));
    println!("view_priv   = {}", hex(&scalar_to_bytes(kp.view_priv())));
    println!("spend_pub   = {}", hex(&point_to_compressed(&spend_pub)));
    println!("view_pub    = {}", hex(&point_to_compressed(&view_pub)));
    println!("address     = {addr}");
    println!("== import into monero: generate_from_keys(spendkey) and compare address ==");
}

/// Monero-correct pubkey: raw_scalar * G → Ed25519Point wrapper.
fn monero_pub(sec: &[u8; 32]) -> shlosilo::curve_primitive::ed25519::Ed25519Point {
    use shlosilo::curve_primitive::ed25519::point_from_compressed;
    let s = curve25519_dalek::Scalar::from_bytes_mod_order(*sec);
    let compressed = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &s)
        .compress()
        .to_bytes();
    point_from_compressed(&compressed).expect("valid point")
}

/// Verify the real-wallet 2-input fixture: decrypt + parse + structural checks.
#[test]
#[ignore = "needs the fixture view key via env (SHLOSILO_TEST_XMR_VIEW_SK)"]
fn decrypt_and_parse_fixture() {
    use shlosilo::chain::xmr::unsigned_txset::{decrypt_unsigned_txset, deserialize_unsigned_tx};

    let Some(view_sk) = env_hex("SHLOSILO_TEST_XMR_VIEW_SK") else {
        eprintln!("SKIP: SHLOSILO_TEST_XMR_VIEW_SK not set");
        return;
    };
    let plain =
        decrypt_unsigned_txset(&fixture_bytes(), &view_sk).expect("decrypt 2-input fixture");

    let mut p_txes = core::array::from_fn::<
        Option<shlosilo::chain::xmr::unsigned_txset::TxConstructionData<'_>>,
        8,
        _,
    >(|_| None);
    let mut p_src =
        core::array::from_fn::<Option<shlosilo::chain::xmr::unsigned_txset::TxSourceEntry>, 32, _>(
            |_| None,
        );
    let mut p_sd =
        core::array::from_fn::<shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry, 64, _>(
            |_| shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry::default(),
        );
    let mut p_sel = [0usize; 256];
    let mut p_ex = [0u8; 8192];
    let mut p_de =
        core::array::from_fn::<shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry, 64, _>(
            |_| shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry::default(),
        );
    let mut p_su = [0u32; 256];
    let utx = deserialize_unsigned_tx(
        &plain,
        shlosilo::chain::xmr::unsigned_txset::UnsignedTxPools {
            txes: &mut p_txes,
            sources: &mut p_src,
            splitted_dsts: &mut p_sd,
            selected_transfers: &mut p_sel,
            extra: &mut p_ex,
            dests: &mut p_de,
            subaddr_indices: &mut p_su,
        },
    )
    .expect("deserialize");
    assert_eq!(utx.txes.len(), 1, "one tx");
    let tx = utx.txes.iter().flatten().next().unwrap();
    assert_eq!(tx.sources.len(), 2, "TWO inputs (task 4 target)");
    // Both fixtures spend two equal UTXOs; do not hardcode which fixture.
    assert_eq!(
        tx.sources.iter().flatten().next().unwrap().amount,
        tx.sources.iter().flatten().nth(1).unwrap().amount,
        "equal inputs"
    );
    for (i, s) in tx.sources.iter().flatten().enumerate() {
        assert_eq!(s.outputs.len(), 16, "ring 16 (source {i})");
        assert!(s.real_output < 16, "real index in range (source {i})");
    }
    let out_sum: u64 = tx.splitted_dsts.iter().map(|d| d.amount).sum();
    let in_sum: u64 = tx.sources.iter().flatten().map(|s| s.amount).sum();
    let fee = in_sum - out_sum;
    assert!(in_sum > out_sum && fee < 1_000_000_000, "sane fee: {fee}");
    println!(
        "2-input fixture OK: sources={} dests={} in={} out={} fee={}",
        tx.sources.len(),
        tx.splitted_dsts.len(),
        in_sum,
        out_sum,
        fee
    );
    for (i, s) in tx.sources.iter().flatten().enumerate() {
        println!(
            "  src[{i}]: amount={} real_output={} ring={} tx_key={}",
            s.amount,
            s.real_output,
            s.outputs.len(),
            hex(s.real_out_tx_key.as_slice())
        );
    }
    for (i, d) in tx.splitted_dsts.iter().enumerate() {
        println!(
            "  dst[{i}]: amount={} subaddr={} spend_pk={}",
            d.amount,
            d.is_subaddress,
            hex(&d.spend_public_key)
        );
    }
}

/// Host tool: encode the encrypted fixture into multipart UR frames for the
/// device (fountain frames; the device accepts any order and signs on
/// completion). Writes one frame per line.
///
/// Input: P64_ENC_PATH (encrypted unsigned txset, e.g. the CLI's
/// `unsigned_monero_tx`); output: P64_FRAMES_OUT (default /tmp/xmr_2in_frames.txt).
#[test]
#[ignore = "host tool: encodes the fixture into device-feedable UR frames"]
fn encode_ur_frames() {
    use shlosilo::ur::ur_multipart::UrMultipartEncoder;

    let enc_path = std::env::var("P64_ENC_PATH").expect("set P64_ENC_PATH");
    let out_path =
        std::env::var("P64_FRAMES_OUT").unwrap_or_else(|_| "/tmp/xmr_2in_frames.txt".to_string());
    let payload = std::fs::read(&enc_path).expect("read encrypted fixture");

    let mut encer = UrMultipartEncoder::new("xmr-txunsigned", &payload, 200).expect("encoder");
    let n = encer.fragment_count();
    println!("payload {} bytes -> {n} fountain fragments", payload.len());

    // Two rounds: the fountain decoder needs (close to) n independent parts;
    // one extra round covers any drops and lets the device complete early.
    let mut frames = Vec::new();
    for _ in 0..(2 * n + 2) {
        frames.push(encer.next_frame().expect("frame"));
    }
    let out = frames.join("\n");
    std::fs::write(&out_path, &out).expect("write frames");
    println!(
        "{n} fragments/round, wrote {} frames -> {out_path}",
        frames.len()
    );
    println!(
        "first frame ({} chars): {}…",
        frames[0].len(),
        &frames[0][..60.min(frames[0].len())]
    );
}

/// Host A/B blob: sign the dev fixture with the SAME fixed entropy the device
/// uses (`xmrseed`), producing the expected blob for byte-exact comparison.
///
/// Run: P64_FIXTURE_PATH=... cargo test --release --test p64_xmr_multi_input
///      -- --ignored --nocapture sign_with_fixed_entropy_for_ab
#[test]
#[ignore = "host A/B reference (task 4 device comparison)"]
fn sign_with_fixed_entropy_for_ab() {
    use shlosilo::business::sign::{sign_with_entropy, SignInput};
    use shlosilo::ur::ur_encode::UrTypeTag;

    let entropy_hex =
        std::env::var("P64_ENTROPY_HEX").expect("set P64_ENTROPY_HEX (32 bytes = 24 words)");
    let entropy: Vec<u8> = (0..entropy_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&entropy_hex[i..i + 2], 16).unwrap())
        .collect();
    let m = Mnemonic::from_entropy(&entropy).expect("mnemonic");

    // Fixed signer entropy — must match the device's `xmrseed` value (32 x 0x77).
    let fixed_entropy = [0x77u8; 32];

    let enc = fixture_bytes();
    let mut out = vec![0u8; 16384];
    let n = sign_with_entropy(
        SignInput::Mnemonic {
            mnemonic: m,
            passphrase: b"",
        },
        UrTypeTag::XmrTxUnsigned,
        &enc,
        &fixed_entropy,
        &mut out,
    )
    .expect("sign with fixed entropy");
    let out_path =
        std::env::var("P64_AB_OUT").unwrap_or_else(|_| "/tmp/p64_host_ab.bin".to_string());
    std::fs::write(&out_path, &out[..n]).expect("write A/B blob");
    println!("host A/B blob: {n} bytes -> {out_path}");
}

/// Extract the raw transaction bytes from a signed-txset blob for broadcast.
///
/// The plaintext framing is ours (`00 | varint ptx_count | 01 | tx | dust |
/// fee | ...`). Locate the tx boundary via the known fee value, verify the
/// framing, and write the raw tx for `send_raw_transaction`.
///
/// Run: P64_BLOB_PATH=/tmp/xmr_2in_device.bin SHLOSILO_TEST_XMR_VIEW_SK=... \
///      cargo test --release --test p64_xmr_multi_input -- --ignored --nocapture \
///      extract_tx_for_broadcast
#[test]
#[ignore = "host extraction tool: device blob → raw tx bytes for broadcast"]
fn extract_tx_for_broadcast() {
    use shlosilo::chain::xmr::signed_txset::decrypt_signed_txset;

    let Some(view_sk) = env_hex("SHLOSILO_TEST_XMR_VIEW_SK") else {
        eprintln!("SKIP: SHLOSILO_TEST_XMR_VIEW_SK not set");
        return;
    };
    let blob_path =
        std::env::var("P64_BLOB_PATH").unwrap_or_else(|_| "/tmp/xmr_2in_device.bin".to_string());
    let blob = std::fs::read(&blob_path).expect("read blob");
    let plain = decrypt_signed_txset(&blob, &view_sk).expect("decrypt device blob");
    println!("plaintext: {} bytes", plain.len());
    assert_eq!(plain[0], 0x00, "signed_tx_set version 0");
    assert_eq!(plain[1], 0x01, "one ptx");
    assert_eq!(plain[2], 0x01, "pending_tx version 1");
    assert_eq!(plain[3], 0x02, "tx version 2 (ringct)");

    // The fee for this fixture (from the parse test): 44,380,000.
    let fee: u64 = 44_380_000;
    let fee_le = fee.to_le_bytes();
    let mut pat = [0u8; 16];
    pat[8..16].copy_from_slice(&fee_le);
    let pos = plain[3..]
        .windows(16)
        .position(|w| w == pat)
        .expect("dust(0)+fee pattern after the tx")
        + 3;
    let tx = &plain[3..pos];
    println!("raw tx: {} bytes", tx.len());
    // Cross-check against the host-side measurement of the same tx shape.
    if tx.len() != 2219 {
        println!("NOTE: length {} != host-measured 2219", tx.len());
    }
    let out =
        std::env::var("P64_TX_OUT").unwrap_or_else(|_| "/tmp/p64_tx_from_device.bin".to_string());
    std::fs::write(&out, tx).expect("write raw tx");
    use shlosilo::encoding::sha256;
    let d = sha256::hash(tx).expect("sha256");
    println!("raw tx sha256: {}", hex(&d));
    println!("wrote {out}");
}

/// Host signing + timing on the 2-input fixture (vs the 1-input baseline).
#[test]
#[ignore = "needs spend+view env keys; signs the real-funds fixture (host timing run)"]
fn sign_and_time() {
    use shlosilo::chain::xmr::tx_signer::sign_tx_from_construction;
    use shlosilo::chain::xmr::unsigned_txset::{decrypt_unsigned_txset, deserialize_unsigned_tx};

    let (Some(view_sk), Some(spend_sk)) = (
        env_hex("SHLOSILO_TEST_XMR_VIEW_SK"),
        env_hex("SHLOSILO_TEST_XMR_SPEND_SK"),
    ) else {
        eprintln!("SKIP: SHLOSILO_TEST_XMR_VIEW_SK / SHLOSILO_TEST_XMR_SPEND_SK not set");
        return;
    };

    let plain = decrypt_unsigned_txset(&fixture_bytes(), &view_sk).expect("decrypt");

    let mut p_txes = core::array::from_fn::<
        Option<shlosilo::chain::xmr::unsigned_txset::TxConstructionData<'_>>,
        8,
        _,
    >(|_| None);
    let mut p_src =
        core::array::from_fn::<Option<shlosilo::chain::xmr::unsigned_txset::TxSourceEntry>, 32, _>(
            |_| None,
        );
    let mut p_sd =
        core::array::from_fn::<shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry, 64, _>(
            |_| shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry::default(),
        );
    let mut p_sel = [0usize; 256];
    let mut p_ex = [0u8; 8192];
    let mut p_de =
        core::array::from_fn::<shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry, 64, _>(
            |_| shlosilo::chain::xmr::unsigned_txset::TxDestinationEntry::default(),
        );
    let mut p_su = [0u32; 256];
    let utx = deserialize_unsigned_tx(
        &plain,
        shlosilo::chain::xmr::unsigned_txset::UnsignedTxPools {
            txes: &mut p_txes,
            sources: &mut p_src,
            splitted_dsts: &mut p_sd,
            selected_transfers: &mut p_sel,
            extra: &mut p_ex,
            dests: &mut p_de,
            subaddr_indices: &mut p_su,
        },
    )
    .expect("deserialize");
    let tx_data = utx.txes.iter().flatten().next().unwrap();
    assert_eq!(tx_data.sources.len(), 2);

    use rand_core::OsRng;
    let mut rng = OsRng;
    let t0 = std::time::Instant::now();
    let bytes =
        sign_tx_from_construction(tx_data, &spend_sk, &view_sk, &mut rng).expect("2-input sign");
    let ms = t0.elapsed().as_millis();
    println!("2-input host sign: {ms} ms, {} bytes", bytes.len());
    assert_eq!(bytes[0], 2, "tx version 2");

    // Export for the oracle (monerod send_raw_transaction / wallet-rpc submit)
    if let Ok(path) = std::env::var("P64_SIGNED_OUT") {
        std::fs::write(&path, hex(&bytes)).expect("write signed hex");
        println!("wrote {path}");
    }
}
