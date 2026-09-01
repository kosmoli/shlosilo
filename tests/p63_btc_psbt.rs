//! P6.3 BTC 真实 fixture 互验（Sparrow signet test.psbt）
//!
//! Oracle（由 /tmp/psbt_dump.py 独立解析确认）：
//! - 1 input: txid c39ad4eb..:197, P2SH-P2WPKH (spk=160014cfd9...), 651157 sat
//! - BIP32_DERIVATION: fingerprint f3b9960b, path m/84'/1'/0'/0/2
//!   （coin type 1' = signet/testnet，address index 2 —— 非默认路径，P1-02 验收场景）
//! - outputs: 1000 sat P2WPKH + 650087 sat 找零 P2WPKH
//! - SIGHASH_ALL

use shlosilo::chain::btc::psbt::{parse_psbt, input_type, get_witness_utxo};

const PSBT_BYTES: &[u8] = include_bytes!("fixtures/sparrow_signet_12k.psbt");

fn der_path(input_map: &[shlosilo::chain::btc::psbt::KeyValue]) -> Option<(Vec<u8>, Vec<u32>)> {
    let kv = input_map.iter().find(|kv| kv.key.first() == Some(&input_type::BIP32_DERIVATION))?;
    let pk = kv.key[1..].to_vec();
    // BIP-174: value = master_fingerprint(4B) + path elements (u32LE each), no explicit depth
    if kv.value.len() < 8 || (kv.value.len() - 4) % 4 != 0 {
        return None;
    }
    let depth = (kv.value.len() - 4) / 4;
    let mut path = Vec::with_capacity(depth);
    for j in 0..depth {
        let o = 4 + 4 * j;
        path.push(u32::from_le_bytes([
            kv.value[o], kv.value[o+1], kv.value[o+2], kv.value[o+3],
        ]));
    }
    Some((pk, path))
}

/// P6.3-1：真实 Sparrow PSBT 必须能被 parse_psbt 解析
#[test]
fn p63_parse_sparrow_psbt() {
    let psbt = parse_psbt(PSBT_BYTES).expect("sparrow psbt must parse");
    assert_eq!(psbt.unsigned_tx.inputs.len(), 1);
    assert_eq!(psbt.unsigned_tx.outputs.len(), 2);
}

/// P6.3-2（P1-02 验收）：BIP32_DERIVATION 读出真实路径 m/84'/1'/0'/0/2，
/// 不再是硬编码 m/84'/0'/0'/0/0
#[test]
fn p63_read_real_derivation_path() {
    let psbt = parse_psbt(PSBT_BYTES).unwrap();
    let (pk, path) = der_path(&psbt.inputs[0]).expect("BIP32_DERIVATION must exist");
    // hardened flags
    const H: u32 = 0x8000_0000;
    assert_eq!(path.len(), 5);
    assert_eq!(path[0], 84 | H);
    // coin type 1' = signet —— 若这里断言 0' 则说明读的是硬编码值而非 fixture
    assert_eq!(path[1], 1 | H, "coin type must come from PSBT (1'=signet), not hardcoded 0'");
    assert_eq!(path[2], H);
    assert_eq!(path[3], 0);
    assert_eq!(path[4], 2, "address index 2 from fixture");
    assert_eq!(pk.len(), 33, "compressed pubkey");
}

/// P6.3-3：UTXO 脚本类型——native P2WPKH（0014 开头），业务层走 sign_psbt_p2wpkh。
/// （初判 P2SH 嵌套是 oracle 脚本 compact_size 混淆；decode_witness_utxo 已正确剥长度前缀。）
#[test]
fn p63_utxo_is_native_p2wpkh() {
    let psbt = parse_psbt(PSBT_BYTES).unwrap();
    let (amount, spk) = get_witness_utxo(&psbt.inputs[0]).expect("witness utxo");
    assert_eq!(amount, 651_157);
    assert_eq!(&spk[..2], &[0x00, 0x14], "native P2WPKH witness program");
    assert_eq!(spk.len(), 22);
}
