//! P6.6: build a signable 1-input XMR UR from the smoke test's existing idx12 mnemonic.
//! Measures BP+ peak heap on device; does not depend on env credentials.
//!
//! Also builds the DICE-wallet variant (`dice_xmr_ur_for_production_path`):
//! production images have no `entropy` console command (bench-only, audit
//! #17), so their session wallet is the built-in dice fixture
//! (flux/pico2/src/sign_smoke.rs::fixture_mnemonic). The production path can
//! only sign a fixture encrypted to THAT wallet - this test builds one,
//! mirroring the device's derivation exactly (same rolls -> create_account ->
//! from_indices -> restore_seed).

use rand_chacha::rand_core::SeedableRng;
use shlosilo::business::sign::{sign_with_entropy, SignInput};
use shlosilo::chain::xmr::signed_txset::encrypt_unsigned_txset;
use shlosilo::chain::xmr::transaction::bytes_to_monerod_scalar;
use shlosilo::chain::xmr::unsigned_txset::{
    serialize_unsigned_tx, MultisigKLRki, OutputEntry, RctConfig, TxConstructionData,
    TxDestinationEntry, TxSourceEntry, UnsignedTx,
};
use shlosilo::derivation::monero_reduce_scalar::{derive, MoneroPath};
use shlosilo::entropy::mnemonic::{Mnemonic, WordCount};
use shlosilo::types::SecretBytes;
use shlosilo::ur::ur_encode::{encode, UrTypeTag, UR_PAYLOAD_MAX_LEN};

/// kept in sync with the forgebox-helloworld smoke `idx12` (entropy 0x11×16, a valid 12-word mnemonic).
const SMOKE_IDX12: [u16; 12] = [
    136, 1092, 546, 273, 136, 1092, 546, 273, 136, 1092, 546, 283,
];

fn point_of(n: u64) -> [u8; 32] {
    (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &curve25519_dalek::Scalar::from(n))
        .compress()
        .to_bytes()
}

fn owned_source_ring16(
    spend_sec: &[u8; 32],
    view_sec: &[u8; 32],
    amount: u64,
    real_mask: [u8; 32],
    tx_pub: [u8; 32],
) -> TxSourceEntry {
    use monero_ed25519::Commitment as MonCommitment;
    let key_offset =
        shlosilo::chain::xmr::subaddress::calc_output_key_offset(view_sec, &tx_pub, 0, 0, 0)
            .unwrap();
    let spend_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(*spend_sec);
    let offset_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(key_offset);
    let wallet_dest = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
        * &(spend_scalar + offset_scalar))
        .compress()
        .to_bytes();
    let c_real = MonCommitment::new(bytes_to_monerod_scalar(&real_mask), amount)
        .commit()
        .compress()
        .to_bytes();
    let mut outputs = Vec::with_capacity(16);
    outputs.push(OutputEntry {
        index: 0,
        dest: wallet_dest,
        mask: c_real,
    });
    for i in 1u64..16 {
        outputs.push(OutputEntry {
            index: i * 17,
            dest: point_of(100 + i),
            mask: point_of(200 + i),
        });
    }
    TxSourceEntry {
        outputs,
        real_output: 0,
        real_out_tx_key: tx_pub.into(),
        real_out_additional_tx_keys: vec![].into(),
        real_output_in_tx_index: 0,
        amount,
        rct: true,
        mask: SecretBytes::new(real_mask),
        multisig_kLRki: MultisigKLRki {
            k: [0; 32],
            l: [0; 32],
            r: [0; 32],
            ki: [0; 32],
        },
    }
}

/// Seed -> the encrypted unsigned txset + its UR, for the wallet `seed`.
/// Shared by the idx12 test and the dice-wallet (production-path) test.
fn build_fixture(seed: &[u8; 64]) -> (String, zeroize::Zeroizing<Vec<u8>>) {
    let kp = derive(seed, &MoneroPath::mainnet(0)).unwrap();
    let spend_sec = shlosilo::curve_primitive::ed25519::scalar_to_bytes(kp.spend_priv());
    let view_sec = shlosilo::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv());

    let dest_pt = point_of(1);
    let change = dest(400, dest_pt);
    let pay = dest(500, dest_pt);
    let tx_data = TxConstructionData {
        sources: vec![owned_source_ring16(
            &spend_sec,
            &view_sec,
            1000,
            [0x66u8; 32],
            point_of(5),
        )],
        change_dts: change.clone(),
        splitted_dsts: vec![change, pay],
        selected_transfers: vec![0],
        extra: vec![],
        unlock_time: 0,
        use_rct: 1,
        rct_config: RctConfig {
            version: 0,
            range_proof_type: 0,
            bp_version: 4,
        },
        dests: vec![],
        subaddr_account: 0,
        subaddr_indices: vec![],
    };
    let unsigned = UnsignedTx {
        txes: vec![tx_data],
    };
    let plain = serialize_unsigned_tx(&unsigned);
    let mut enc_rng = rand_chacha::ChaCha20Rng::from_seed([0xABu8; 32]);
    let encrypted = encrypt_unsigned_txset(plain, &view_sec, &mut enc_rng).expect("encrypt");
    assert!(
        encrypted.len() <= UR_PAYLOAD_MAX_LEN,
        "encrypted {} > UR_PAYLOAD_MAX_LEN",
        encrypted.len()
    );

    let ur = encode(UrTypeTag::XmrTxUnsigned, &encrypted).expect("encode UR");
    assert!(
        ur.as_str().len() < 4096,
        "URI {} >= ffi 4096",
        ur.as_str().len()
    );
    assert!(ur.as_str().starts_with("ur:xmr-txunsigned/"));
    (ur.as_str().to_string(), encrypted)
}

fn seed_of(indices: &[u16; 12]) -> [u8; 64] {
    let m = Mnemonic::from_indices(indices, WordCount::Words12).expect("mnemonic");
    let mut seed = [0u8; 64];
    shlosilo::business::restore_seed::restore_seed(&m, &[], &mut seed).expect("restore");
    seed
}

fn smoke_seed() -> [u8; 64] {
    seed_of(&SMOKE_IDX12)
}

/// The built-in dice fixture, mirroring flux/pico2/src/sign_smoke.rs
/// (`fixture_rolls` + `fixture_mnemonic`): 64 x d6, [1..6] cycling.
fn dice_seed() -> [u8; 64] {
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
    .expect("create_account on the dice rolls");
    let mut indices = [0u16; 12];
    for (i, idx) in indices.iter_mut().enumerate() {
        *idx = u16::from_le_bytes([mnemonic_buf[i * 2], mnemonic_buf[i * 2 + 1]]);
    }
    assert_eq!(indices[0], 1565, "device smoke report word0");
    seed_of(&indices)
}

fn dest(amount: u64, pt: [u8; 32]) -> TxDestinationEntry {
    TxDestinationEntry {
        original: vec![],
        amount,
        spend_public_key: pt,
        view_public_key: pt,
        is_subaddress: false,
        is_integrated: false,
    }
}

#[test]
fn idx12_xmr_ur_signs_and_fits_single_fragment() {
    let seed = smoke_seed();
    let (ur, encrypted) = build_fixture(&seed);

    let entropy = [0x77u8; 32];
    let mut out = vec![0u8; 16384];
    let n = sign_with_entropy(
        SignInput::Seed { seed: &seed },
        UrTypeTag::XmrTxUnsigned,
        &encrypted,
        &entropy,
        &mut out,
    )
    .expect("sign idx12 xmr");
    assert!(n > 64, "signed blob too small: {n}");

    std::fs::write("/tmp/xmr_smoke_ur.txt", &ur).expect("write ur");
    std::fs::write("/tmp/xmr_smoke_enc.bin", &encrypted).expect("write enc");
    // The host recomputation with the same fixed entropy the A/B uses; the
    // device blob (bench/xmr_sign.py) must match this byte-for-byte.
    std::fs::write("/tmp/xmr_host_signed.bin", &out[..n]).expect("write host signed");
    eprintln!(
        "XMR smoke UR: encrypted={} uri={} signed={}",
        encrypted.len(),
        ur.len(),
        n
    );
}

/// Production-path fixture: encrypted to the dice wallet, which is what a
/// production image signs with (no `entropy` command there). Feed
/// /tmp/xmr_dice_ur.txt to a production board and decrypt the fetched blob
/// with the dice view key (xmr_device_blob_verify::device_blob_decrypts_dice).
#[test]
fn dice_xmr_ur_for_production_path() {
    let seed = dice_seed();
    let (ur, encrypted) = build_fixture(&seed);

    // Sanity: the dice wallet must be able to sign its own fixture.
    let entropy = [0x77u8; 32];
    let mut out = vec![0u8; 16384];
    let n = sign_with_entropy(
        SignInput::Seed { seed: &seed },
        UrTypeTag::XmrTxUnsigned,
        &encrypted,
        &entropy,
        &mut out,
    )
    .expect("sign dice xmr");
    assert!(n > 64, "signed blob too small: {n}");

    std::fs::write("/tmp/xmr_dice_ur.txt", &ur).expect("write dice ur");
    std::fs::write("/tmp/xmr_dice_enc.bin", &encrypted).expect("write dice enc");
    eprintln!(
        "dice XMR UR: encrypted={} uri={} host-signed={}",
        encrypted.len(),
        ur.len(),
        n
    );
}
