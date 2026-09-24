//! P1-06: key image derivation oracle comparison against the real fixture
//! Uses the source entry of the P6.3 fixture (unsigned_txset) + external view/spend keys to
//! verify the full path calc_output_key_offset → derive_key_image_with_offset.
//!
//! Note: the XMR fixture is an independent wallet; the view key is an external credential ([REDACTED] principle).
//! Inject via the environment variables SHLOSILO_TEST_XMR_VIEW_SK / SHLOSILO_TEST_XMR_SPEND_SK.

use shlosilo::chain::xmr::subaddress::{
    calc_output_key_offset, derive_input_from_source, derive_input_spend_key,
};
use shlosilo::chain::xmr::unsigned_txset::deserialize_unsigned_tx;

const PLAIN: &[u8] = include_bytes!("fixtures/txset_plain.bin");

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

fn hex4(b: &[u8]) -> String {
    b[..4].iter().map(|x| format!("{:02x}", x)).collect()
}

/// P1-06: key image derivation from the real fixture (oracle compared against the keystone algorithm)
#[test]
#[ignore = "X7: needs external credentials/env (SHLOSILO_TEST_XMR_*) — missing env no longer silently counts as passed; run: cargo test -- --ignored with env injected"]
fn derive_key_image_from_real_fixture() {
    let Some(view_sk) = env_hex("SHLOSILO_TEST_XMR_VIEW_SK") else {
        eprintln!("SKIP: SHLOSILO_TEST_XMR_VIEW_SK not set");
        return;
    };
    let Some(spend_sk) = env_hex("SHLOSILO_TEST_XMR_SPEND_SK") else {
        eprintln!("SKIP: SHLOSILO_TEST_XMR_SPEND_SK not set");
        return;
    };

    // Parse the fixture (plaintext, already verified in P6.3)
    let utx = deserialize_unsigned_tx(PLAIN).expect("deserialize");
    let tx = &utx.txes[0];
    let src = &tx.sources[0];

    eprintln!(
        "real_output={} real_out_tx_key={}.. real_output_in_tx_index={} amount={} subaddr_indices={:?}",
        src.real_output,
        hex4(src.real_out_tx_key.as_slice()),
        src.real_output_in_tx_index,
        src.amount,
        tx.subaddr_indices
    );
    let real = &src.outputs[src.real_output as usize];
    eprintln!(
        "real output dest={}.. mask={}..",
        hex4(&real.dest),
        hex4(&real.mask)
    );

    // Main-address offset (major=0, minor=0)
    let offset_main = calc_output_key_offset(
        &view_sk,
        &src.real_out_tx_key,
        src.real_output_in_tx_index,
        0,
        0,
    )
    .expect("offset main");
    eprintln!("offset(main) = {}..", hex4(&offset_main));

    // Subaddress offset (subaddr_indices=[1])
    let offset_sub = calc_output_key_offset(
        &view_sk,
        &src.real_out_tx_key,
        src.real_output_in_tx_index,
        tx.subaddr_account,
        tx.subaddr_indices[0],
    )
    .expect("offset sub");
    eprintln!("offset(sub)  = {}..", hex4(&offset_sub));

    // Main-address spend derivation, verifying output_pubkey
    let spend_main = derive_input_spend_key(&spend_sk, &offset_main).expect("derive input main");
    let spend_main_dalek = shlosilo::chain::xmr::reduce_scalar::reduce_scalar_to_dalek(&spend_main);
    let derived_pub = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &spend_main_dalek)
        .compress()
        .to_bytes();
    eprintln!(
        "main: derived_pub={}.. vs real dest={}.. match={}",
        hex4(&derived_pub),
        hex4(&real.dest),
        derived_pub == real.dest
    );

    let spend_sub = derive_input_spend_key(&spend_sk, &offset_sub).expect("derive input sub");
    let spend_sub_dalek = shlosilo::chain::xmr::reduce_scalar::reduce_scalar_to_dalek(&spend_sub);
    let derived_sub_pub = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &spend_sub_dalek)
        .compress()
        .to_bytes();
    eprintln!(
        "sub:  derived_pub={}.. vs real dest={}.. match={}",
        hex4(&derived_sub_pub),
        hex4(&real.dest),
        derived_sub_pub == real.dest
    );

    // Full derivation (includes output_pubkey verification internally) — success = this input belongs to this wallet
    let (image, offset) = derive_input_from_source(
        &view_sk,
        &spend_sk,
        src,
        tx.subaddr_account,
        &tx.subaddr_indices,
    )
    .expect("derive input from source");
    eprintln!(
        "key image = {}.. (offset {}..)",
        hex4(&image),
        hex4(&offset)
    );

    // Key image non-zero
    assert_ne!(image, [0u8; 32], "key image must be non-zero");
    assert_eq!(image.len(), 32);
}
