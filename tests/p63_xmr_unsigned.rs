//! P6.3/P1-06 XMR unsigned_txset 端到端：entropy → BIP39 seed → Monero 派生 →
//! decrypt → epee deserialize → 与 P6.3 已知解析结果对照
//!
//! fixture：
//! - tests/fixtures/unsigned_txset.bin（Feather wallet-rpc 生成，2047B 加密）
//! - tests/fixtures/txset_plain.bin（P6.3 python 解密明文，1952B）
//! - /home/komo/testTX/unsigned_txset_meta.json（fee/dest/tx_key）

use shlosilo::chain::xmr::unsigned_txset::{decrypt_unsigned_txset, deserialize_unsigned_tx};

const ENCRYPTED: &[u8] = include_bytes!("fixtures/unsigned_txset.bin");
const PLAIN: &[u8] = include_bytes!("fixtures/txset_plain.bin");

/// P1-06：解密 unsigned_txset fixture
///
/// 注意：XMR fixture 是**独立钱包**（非 test260824-sig 的 entropy f284...），
/// 其 view key 是 P6.3 wallet-rpc viewkey 命令取得的外部凭证。
/// 测试用环境变量 SHLOSILO_TEST_XMR_VIEW_SK 注入（[REDACTED] 原则，不硬编码）。
#[test]
fn decrypt_with_external_view_key() {
    let view_hex = std::env::var("SHLOSILO_TEST_XMR_VIEW_SK");
    let Ok(view_hex) = view_hex else {
        eprintln!("SKIP: SHLOSILO_TEST_XMR_VIEW_SK not set (XMR fixture view key is external credential)");
        return;
    };
    let view_sk: [u8; 32] = {
        let v: Vec<u8> = (0..view_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&view_hex[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().expect("32-byte view key")
    };
    let plain = decrypt_unsigned_txset(ENCRYPTED, &view_sk).expect("decrypt with real view key");
    assert_eq!(plain, PLAIN, "plaintext must match P6.3 python result");
    let utx = deserialize_unsigned_tx(&plain).expect("deserialize");
    assert!(!utx.txes.is_empty(), "at least one tx");
    let tx = &utx.txes[0];
    let src = &tx.sources[0];
    assert_eq!(src.outputs.len(), 16, "ring size 16 (P6.3)");
    assert_eq!(src.real_output, 13, "real output index 13 (P6.3)");
    assert_eq!(src.amount, 2_000_000_000, "input 0.002 XMR (P6.3)");
    let out_sum: u64 = tx.splitted_dsts.iter().map(|d| d.amount).sum();
    assert_eq!(out_sum + 30_640_000, src.amount, "fee = 30640000 (P6.3)");
    let dest = &tx.splitted_dsts[1];
    assert_eq!(dest.amount, 100_000_000, "DEST1 1 XMR (P6.3)");
    assert!(dest.is_subaddress, "DEST1 is subaddress (P6.3)");
    let change = &tx.change_dts;
    assert!(!change.is_subaddress, "change to main address (P6.3)");
}

/// P1-06：P6.3 已解密明文 → epee deserialize → 结构对照
#[test]
fn deserialize_p63_plain() {
    let utx = deserialize_unsigned_tx(PLAIN).expect("deserialize P6.3 plaintext");
    let tx = &utx.txes[0];
    assert_eq!(tx.sources.len(), 1);
    let src = &tx.sources[0];
    assert_eq!(src.outputs.len(), 16);
    assert_eq!(src.real_output, 13);
    assert_eq!(src.amount, 2_000_000_000);
    assert_eq!(src.rct, true);
    assert_eq!(src.multisig_kLRki.k, [0u8; 32], "non-multisig kLRki zero");
    // outputs：splitted_dsts = [change(1869360000, main), dest(100000000, subaddress)]
    assert_eq!(tx.splitted_dsts.len(), 2, "change + dest (P6.3)");
    assert_eq!(tx.splitted_dsts[0].amount, 1_869_360_000, "splitted[0]=change");
    assert!(!tx.splitted_dsts[0].is_subaddress);
    assert_eq!(tx.splitted_dsts[1].amount, 100_000_000);
    assert!(tx.splitted_dsts[1].is_subaddress);
    assert_eq!(tx.change_dts.amount, 1_869_360_000, "change 1869360000 (P6.3)");
    assert_eq!(tx.change_dts.spend_public_key, tx.splitted_dsts[0].spend_public_key);
    // RCTConfig（fixture 真实值，与 keystone 逐行解析一致）：
    // version=0, range_proof_type=3(Bulletproof), bp_version=4(RCTTypeBulletproof2)
    // ——Feather wallet-rpc 生成时即此值（非 BP+，主网默认随版本演进）
    assert_eq!(tx.rct_config.range_proof_type, 3, "RangeProofType::Bulletproof");
    assert_eq!(tx.rct_config.bp_version, 4, "RCTTypeBulletproof2 (fixture)");
    assert_eq!(tx.subaddr_indices, vec![1], "subaddress index 1 (P6.3)");
    // fee 校验：input − change(change_dts) − dest(splitted[1]) = fee
    let fee = src.amount - tx.change_dts.amount - tx.splitted_dsts[1].amount;
    assert_eq!(fee, 30_640_000, "fee 30640000 (P6.3)");
}
