//! P1-06：真实 fixture 的 key image 派生 oracle 对照
//! 用 P6.3 fixture（unsigned_txset）的 source entry + 外部 view/spend key，
//! 验证 calc_output_key_offset → derive_key_image_with_offset 全路径。
//!
//! 注意：XMR fixture 是独立钱包，view key 是外部凭证（[REDACTED] 原则）。
//! 用环境变量 SHLOSILO_TEST_XMR_VIEW_SK / SHLOSILO_TEST_XMR_SPEND_SK 注入。

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

/// P1-06：真实 fixture 的 key image 派生（oracle 对照 keystone 算法）
#[test]
#[ignore = "X7: 需外部凭据/env（SHLOSILO_TEST_XMR_*）——缺 env 不再静默计入 passed；跑法: cargo test -- --ignored 并注入 env"]
fn derive_key_image_from_real_fixture() {
    let Some(view_sk) = env_hex("SHLOSILO_TEST_XMR_VIEW_SK") else {
        eprintln!("SKIP: SHLOSILO_TEST_XMR_VIEW_SK not set");
        return;
    };
    let Some(spend_sk) = env_hex("SHLOSILO_TEST_XMR_SPEND_SK") else {
        eprintln!("SKIP: SHLOSILO_TEST_XMR_SPEND_SK not set");
        return;
    };

    // 解析 fixture（明文，P6.3 已验证）
    let utx = deserialize_unsigned_tx(PLAIN).expect("deserialize");
    let tx = &utx.txes[0];
    let src = &tx.sources[0];

    eprintln!(
        "real_output={} real_out_tx_key={}.. real_output_in_tx_index={} amount={} subaddr_indices={:?}",
        src.real_output,
        hex4(&src.real_out_tx_key),
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

    // 主地址 offset（major=0, minor=0）
    let offset_main = calc_output_key_offset(
        &view_sk,
        &src.real_out_tx_key,
        src.real_output_in_tx_index,
        0,
        0,
    )
    .expect("offset main");
    eprintln!("offset(main) = {}..", hex4(&offset_main));

    // 子地址 offset（subaddr_indices=[1]）
    let offset_sub = calc_output_key_offset(
        &view_sk,
        &src.real_out_tx_key,
        src.real_output_in_tx_index,
        tx.subaddr_account,
        tx.subaddr_indices[0],
    )
    .expect("offset sub");
    eprintln!("offset(sub)  = {}..", hex4(&offset_sub));

    // 主地址 spend 派生验证 output_pubkey
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

    // 完整派生（内部含 output_pubkey 验证）——成功 = 该 input 属于此 wallet
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

    // key image 非零
    assert_ne!(image, [0u8; 32], "key image must be non-zero");
    assert_eq!(image.len(), 32);
}
