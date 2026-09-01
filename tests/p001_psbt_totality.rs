//! P0-01 整改落地测试(2026-09-01 第三次复审 #4)——PSBT parser totality
//!
//! 审计要求:同 parser 多处同模式需系统性加固,不是只补 723 行。
//! 覆盖:
//! - checked_add(take_bytes):恶意 CompactSize 长度不得溢出 panic
//! - 预算(PSBT_WIRE_MAX_LEN):长度/计数域不得触发 OOM 预分配
//! - 非规范 CompactSize 拒绝(同值多编码解析歧义)
//! - 全部四个 panic 点位:decode_witness_utxo:723 / deserialize_unsigned_tx:272 /
//!   decode_map:356 / Vec::with_capacity:251
//! - 真实 fixture 兼容性(p63_btc_psbt.rs 锁定,不在此重复)

use shlosilo::chain::btc::psbt::{decode_witness_utxo, parse_psbt};

fn psbt_magic() -> Vec<u8> {
    vec![0x70, 0x73, 0x62, 0x74, 0xff]
}

/// 最小合法 unsigned tx 骨架(1 输入 0 输出),script_sig_len 可注入
fn tx_with_script_sig_len(len_wire: &[u8]) -> Vec<u8> {
    let mut tx = Vec::new();
    tx.extend_from_slice(&2i32.to_le_bytes()); // version
    tx.push(1); // n_inputs = 1
    tx.extend_from_slice(&[0u8; 32]); // txid
    tx.extend_from_slice(&0u32.to_le_bytes()); // vout
    tx.extend_from_slice(len_wire); // script_sig_len(注入点)
    tx.extend_from_slice(&0xffffffffu32.to_le_bytes()); // sequence
    tx.push(0); // n_outputs
    tx.extend_from_slice(&0u32.to_le_bytes()); // locktime
    tx
}

/// 把 global map(unsigned_tx)+ 空 input/output map 包成完整 PSBT
fn wrap_psbt(tx: &[u8]) -> Vec<u8> {
    let mut b = psbt_magic();
    b.push(1); // keylen
    b.push(0x00); // key = UNSIGNED_TX
    b.push(tx.len() as u8); // valuelen(< 0xfd)
    b.extend_from_slice(tx);
    b.push(0x00); // global separator
    b.push(0x00); // input map separator
    b.push(0x00); // output map separator
    b
}

// ── 1. 审计原始指控:decode_witness_utxo 加法溢出 ──

#[test]
fn p001_witness_utxo_len_overflow_rejected() {
    // amount ‖ 0xff ‖ u64::MAX —— 审计复现向量
    let mut v = Vec::new();
    v.extend_from_slice(&651_157u64.to_le_bytes());
    v.push(0xff);
    v.extend_from_slice(&u64::MAX.to_le_bytes());
    assert!(decode_witness_utxo(&v).is_err());
}

#[test]
fn p001_witness_utxo_oversized_len_rejected() {
    // 不溢出但超预算(0xfe ‖ 0xffffffff):必须拒绝,不得尝试分配 4GB
    let mut v = Vec::new();
    v.extend_from_slice(&651_157u64.to_le_bytes());
    v.push(0xfe);
    v.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    assert!(decode_witness_utxo(&v).is_err());
}

#[test]
fn p001_witness_utxo_trailing_garbage_tolerated() {
    // 合法 spk + 尾随垃圾:CTxOut 语义允许(上层只消费 spk);不 panic 即可
    let mut v = Vec::new();
    v.extend_from_slice(&651_157u64.to_le_bytes());
    v.push(3); // spk_len = 3
    v.extend_from_slice(&[0x00, 0x14, 0x99]); // 占位 spk
    v.push(0xde); // 尾随垃圾
    let r = decode_witness_utxo(&v);
    assert!(r.is_ok());
    assert_eq!(r.unwrap().1, vec![0x00, 0x14, 0x99]);
}

// ── 2. deserialize_unsigned_tx:script_sig_len / script_pubkey_len 溢出 ──

#[test]
fn p001_script_sig_len_overflow_rejected() {
    let tx = tx_with_script_sig_len(&{
        let mut w = vec![0xff];
        w.extend_from_slice(&u64::MAX.to_le_bytes());
        w
    });
    let r = parse_psbt(&wrap_psbt(&tx));
    assert!(
        r.is_err(),
        "恶意 script_sig_len 必须稳定报错(修复前 panic psbt.rs:272)"
    );
}

#[test]
fn p001_script_pubkey_len_oversized_rejected() {
    // outputs: 1 个 output,value(8B) + script_pubkey_len = 0xfe ‖ 0xffffffff
    let mut tx = Vec::new();
    tx.extend_from_slice(&2i32.to_le_bytes());
    tx.push(1); // n_inputs
    tx.extend_from_slice(&[0u8; 32]);
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx.push(0); // script_sig_len = 0
    tx.extend_from_slice(&0xffffffffu32.to_le_bytes());
    tx.push(1); // n_outputs = 1
    tx.extend_from_slice(&1000u64.to_le_bytes()); // value
    tx.push(0xfe); // spk_len prefix
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // 超预算
    let r = parse_psbt(&wrap_psbt(&tx));
    assert!(r.is_err());
}

// ── 3. decode_map:key_len / value_len 溢出 ──

#[test]
fn p001_map_value_len_overflow_rejected() {
    // global map 第一条就塞恶意 value_len
    let mut b = psbt_magic();
    b.push(1);
    b.push(0x00);
    b.push(0xff);
    b.extend_from_slice(&u64::MAX.to_le_bytes());
    let r = parse_psbt(&b);
    assert!(
        r.is_err(),
        "恶意 value_len 必须稳定报错(修复前 panic psbt.rs:356)"
    );
}

#[test]
fn p001_map_key_len_oversized_rejected() {
    let mut b = psbt_magic();
    b.push(0xfe); // keylen prefix
    b.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    let r = parse_psbt(&b);
    assert!(r.is_err());
}

// ── 4. with_capacity OOM:n_inputs / n_outputs 巨量 ──

#[test]
fn p001_huge_input_count_no_oom() {
    let mut tx = Vec::new();
    tx.extend_from_slice(&2i32.to_le_bytes());
    tx.push(0xff); // n_inputs prefix
    tx.extend_from_slice(&u64::MAX.to_le_bytes());
    let r = parse_psbt(&wrap_psbt(&tx));
    assert!(
        r.is_err(),
        "恶意 input count 必须报错(修复前 capacity overflow abort)"
    );
}

#[test]
fn p001_large_but_in_budget_input_count_no_huge_alloc() {
    // n_inputs = 60000 < PSBT_WIRE_MAX_LEN(64KB) 预算内;
    // with_capacity(60000) 可接受(真实输入会立即因字节不足报错,不循环分配)
    let mut tx = Vec::new();
    tx.extend_from_slice(&2i32.to_le_bytes());
    tx.push(0xfd); // n_inputs 2-byte prefix
    tx.extend_from_slice(&60_000u16.to_le_bytes());
    // 后面没有 input bytes——必须快速报错而非挂起/崩溃
    let r = parse_psbt(&wrap_psbt(&tx));
    assert!(r.is_err());
}

// ── 5. 非规范 CompactSize 拒绝 ──

#[test]
fn p001_noncanonical_compact_size_rejected() {
    // script_sig_len = 5 用 0xfd ‖ 0x0005 编码(非规范)——拒绝
    let mut t = Vec::new();
    t.extend_from_slice(&2i32.to_le_bytes());
    t.push(1);
    t.extend_from_slice(&[0u8; 32]);
    t.extend_from_slice(&0u32.to_le_bytes());
    t.extend_from_slice(&[0xfd, 0x05, 0x00]); // 非规范 5
    t.extend_from_slice(&[0xaa; 5]); // 5 字节 script_sig
    t.extend_from_slice(&0xffffffffu32.to_le_bytes());
    t.push(0);
    t.extend_from_slice(&0u32.to_le_bytes());
    let r = parse_psbt(&wrap_psbt(&t));
    assert!(
        r.is_err(),
        "非规范 CompactSize(0xfd 前缀编码 <0xfd 的值)必须拒绝"
    );
}

#[test]
fn p001_zero_prefix_0xff_rejected() {
    // 0xff ‖ 0x0000000000000005(值 5,非规范 8 字节编码)——拒绝
    let mut t = Vec::new();
    t.extend_from_slice(&2i32.to_le_bytes());
    t.push(1);
    t.extend_from_slice(&[0u8; 32]);
    t.extend_from_slice(&0u32.to_le_bytes());
    t.push(0xff);
    t.extend_from_slice(&5u64.to_le_bytes()); // 值 5 < 0x1_0000_0000,非规范
    t.extend_from_slice(&[0xaa; 5]);
    t.extend_from_slice(&0xffffffffu32.to_le_bytes());
    t.push(0);
    t.extend_from_slice(&0u32.to_le_bytes());
    let r = parse_psbt(&wrap_psbt(&t));
    assert!(r.is_err());
}

// ── 6. 合法 PSBT 不受预算影响(冒烟) ──

#[test]
fn p001_valid_minimal_psbt_still_parses() {
    let tx = tx_with_script_sig_len(&[0x00]); // script_sig_len = 0
    let psbt = parse_psbt(&wrap_psbt(&tx));
    assert!(psbt.is_ok());
    let p = psbt.unwrap();
    assert_eq!(p.unsigned_tx.inputs.len(), 1);
    assert_eq!(p.unsigned_tx.outputs.len(), 0);
}
