//! P63-XMR 决定性诊断：用 wire blob 自身数据调用 monero-clsag::verify
//!
//! 逻辑：解析 /tmp/signed_tx.hex → 提取 ring(pseudoOuts 前需 mixRing，从 fixture)
//! 关键是复现 monerod 的 verify 输入：
//!   - ring = fixture sources[0].outputs (dest, commitment=mask|amount)
//!   - I = wire vin key image
//!   - pseudo_out = wire pseudoOuts[0]
//!   - D, s, c1 = wire CLSAGs[0]
//!   - msg_hash = keccak(prefix_hash + H(base) + BP elements) - 从 wire 重算
//!
//! 若本地 verify 失败 ⇒ msg_hash 与 wire 不一致（签名时用了别的值）；若成功 ⇒ mixRing 与 monerod 展开不同。

use std::fs;

#[test]
#[ignore]
fn diag_clsag_verify_from_wire() {
    let hex = fs::read_to_string("/tmp/signed_tx.hex").unwrap();
    let blob: Vec<u8> = hex
        .trim()
        .as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect();
    println!("blob len: {}", blob.len());

    // 用 p63_xmr_sign 相同的 env 拿 fixture（走 TxConstructionData）
    let view_sk_hex = std::env::var("SHLOSILO_TEST_XMR_VIEW_SK").unwrap();
    let spend_sk_hex = std::env::var("SHLOSILO_TEST_XMR_SPEND_SK").unwrap();
    let _ = (view_sk_hex, spend_sk_hex);

    // 完整重算 msg_hash 需要构造侧数据 —— 改为直接暴露 sign 的中间值:
    // 这里打印 wire 中 CLSAG 段的 s/c1/D/pseudo_out 与 key image，供与官方 verRctCLSAGSimple 手工对照。
    let _ = &blob;

    // TODO-full：待 tx_signer 暴露 diag 接口后完成端到端本地验证。
}
