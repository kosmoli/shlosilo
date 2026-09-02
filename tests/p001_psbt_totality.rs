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

/// 把 global map(unsigned_tx)+ 与之一致的空 input/output map 包成完整 PSBT
/// (审计 #5 exact-consumption 后:map 数必须与 unsigned_tx 的 n_inputs/n_outputs
/// 一致,多余 separator 会被整体消费检查拒绝)
fn wrap_psbt(tx: &[u8]) -> Vec<u8> {
    wrap_psbt_full(tx, 1, 0)
}

/// 显式指定 n_inputs/n_outputs 的版本(恶意 count / 多 output 测试用)
fn wrap_psbt_full(tx: &[u8], n_inputs: usize, n_outputs: usize) -> Vec<u8> {
    let mut b = psbt_magic();
    b.push(1); // keylen
    b.push(0x00); // key = UNSIGNED_TX
    b.push(tx.len() as u8); // valuelen(< 0xfd)
    b.extend_from_slice(tx);
    b.push(0x00); // global separator
    b.extend(std::iter::repeat_n(0x00, n_inputs)); // input map separators
    b.extend(std::iter::repeat_n(0x00, n_outputs)); // output map separators
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
fn p001_witness_utxo_trailing_garbage_rejected() {
    // 审计 #5 P0-02(替换旧反向测试"trailing_garbage_tolerated"):
    // exact-consumption——CTxOut 值尾随字节 = 非规范编码,必须拒绝
    // (旧测试错误地把尾随垃圾定义为"应接受")
    let mut v = Vec::new();
    v.extend_from_slice(&651_157u64.to_le_bytes());
    v.push(3); // spk_len = 3
    v.extend_from_slice(&[0x00, 0x14, 0x99]); // 占位 spk
    v.push(0xde); // 尾随垃圾
    let r = decode_witness_utxo(&v);
    assert!(
        r.is_err(),
        "CTxOut trailing bytes must be rejected (exact-consumption)"
    );
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
    let r = parse_psbt(&wrap_psbt_full(&tx, 1, 1));
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
    let r = parse_psbt(&wrap_psbt_full(&tx, 0, 0));
    assert!(
        r.is_err(),
        "恶意 input count 必须报错(修复前 capacity overflow abort)"
    );
}

#[test]
fn p001_count_exceeding_physical_bytes_rejected_before_alloc() {
    // 审计 #5 P0-02 + 第六次复审 P2-01:物理可行性判断已提成纯 helper
    // count_physically_feasible(见 psbt.rs),本测试断言 helper 行为,
    // 不再依赖时序观察(复审判定:100ms 阈值不可靠,with_capacity 不 memset,
    // host allocator 完全可能更快;旧漏洞回归时时序测试仍会通过)。
    //
    // 行为链:恶意 n_inputs=60000 + 小 wire → helper false → parser 在
    // Vec::with_capacity 之前返回 Err(helper 调用位置在实现中位于
    // with_capacity 之前,由代码顺序锁定)。
    let mut tx = Vec::new();
    tx.extend_from_slice(&2i32.to_le_bytes());
    tx.push(0xfd); // n_inputs 2-byte prefix
    tx.extend_from_slice(&60_000u16.to_le_bytes());
    let r = parse_psbt(&wrap_psbt_full(&tx, 0, 0));
    assert!(r.is_err(), "physically infeasible count must be rejected");
}

// ---- count_physically_feasible 直接单测(复审 P2-01/P2-02 证据锚点) ----

#[test]
fn p001_helper_rejects_count_exceeding_physical_capacity() {
    use shlosilo::chain::btc::psbt::count_physically_feasible;
    // 60000 inputs 需要 60000*41 = 2,460,000B wire;剩余只有 1000B,拒绝
    assert!(!count_physically_feasible(60_000, 1000, 41));
    // locktime 裕量边界:41*1+4=45 才容 1 个;44 不够(复审 P2-01 曾用 44 通过?)
    assert!(!count_physically_feasible(1, 44, 41));
    assert!(count_physically_feasible(1, 45, 41));
    // 9B/output 同样预留 locktime(复审 P2-02:此前 outputs 漏留)
    assert!(!count_physically_feasible(1, 12, 9));
    assert!(count_physically_feasible(1, 13, 9));
    // remaining < 4 时 saturate 到 0,任何 count>0 拒绝
    assert!(!count_physically_feasible(1, 3, 41));
    // 合法交易量级不误伤
    assert!(count_physically_feasible(100, 100 * 41 + 100, 41));
}

#[test]
fn p001_duplicate_map_key_rejected() {
    // 审计 #5 P0-02:重复 key 拒绝——BIP-174 "key must be unique in a map",
    // 重复 = first-wins/last-wins parser differential 向量
    let mut b = psbt_magic();
    // global map:两条相同 key=[0x00](UNSIGNED_TX)
    b.push(1); // keylen
    b.push(0x00); // key = UNSIGNED_TX
    b.push(4); // valuelen
    b.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // value1
    b.push(1); // keylen
    b.push(0x00); // key = UNSIGNED_TX(重复!)
    b.push(4); // valuelen
    b.extend_from_slice(&[0x05, 0x06, 0x07, 0x08]); // value2
    let r = parse_psbt(&b);
    assert!(r.is_err(), "duplicate map key must be rejected");
}

#[test]
fn p001_psbt_trailing_bytes_after_output_maps_rejected() {
    // 审计 #5 P0-02:整体 exact-consumption——所有 map 解析完后剩余字节 = 拒绝
    let tx = tx_with_script_sig_len(&[0x00]);
    let mut b = wrap_psbt(&tx);
    b.push(0xde);
    b.push(0xad); // 尾随垃圾
    let r = parse_psbt(&b);
    assert!(
        r.is_err(),
        "PSBT trailing bytes after output maps must be rejected"
    );
}

#[test]
fn p001_unsigned_tx_trailing_bytes_rejected() {
    // 审计 #5 P0-02:unsigned tx 内嵌尾随——sighash preimage 一致性风险
    let mut tx = Vec::new();
    tx.extend_from_slice(&2i32.to_le_bytes());
    tx.push(1); // n_inputs
    tx.extend_from_slice(&[0u8; 32]);
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx.push(0); // script_sig_len
    tx.extend_from_slice(&0xffffffffu32.to_le_bytes()); // sequence
    tx.push(0); // n_outputs
    tx.extend_from_slice(&0u32.to_le_bytes()); // locktime
    tx.push(0xde); // 内嵌尾随
    let r = parse_psbt(&wrap_psbt(&tx));
    assert!(r.is_err(), "unsigned tx trailing bytes must be rejected");
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

// ── 7. 审计 #5 开-01:NON_WITNESS_UTXO full-tx/txid/vout 绑定 ──

/// 构造最小 legacy full tx(version+1in+1out+locktime)
fn make_full_tx(vout_value: u64, spk_byte: u8) -> Vec<u8> {
    let mut tx = Vec::new();
    tx.extend_from_slice(&2i32.to_le_bytes()); // version
    tx.push(1); // n_inputs = 1
    tx.extend_from_slice(&[0xaau8; 32]); // parent txid(占位)
    tx.extend_from_slice(&0u32.to_le_bytes()); // vout
    tx.push(0); // script_sig len
    tx.extend_from_slice(&0xffffffffu32.to_le_bytes()); // sequence
    tx.push(1); // n_outputs = 1
    tx.extend_from_slice(&vout_value.to_le_bytes()); // value
    tx.push(3); // spk len
    tx.extend_from_slice(&[spk_byte, 0x14, 0x99]); // spk
    tx.extend_from_slice(&0u32.to_le_bytes()); // locktime
    tx
}

#[test]
fn kai01_nonwitness_full_tx_bound_happy_path() {
    use shlosilo::chain::btc::p2wpkh::OutPoint;
    use shlosilo::chain::btc::psbt::{get_utxo_any, KeyValue};
    use shlosilo::encoding::sha256;
    let full_tx = make_full_tx(651_157, 0x00);
    // txid = dsha256(serialized)
    let txid: [u8; 32] = sha256::hash_twice(&full_tx).unwrap();

    // PSBT input map:NON_WITNESS_UTXO = full tx
    let input_map: std::vec::Vec<KeyValue> = vec![KeyValue {
        key: vec![0x00], // NON_WITNESS_UTXO
        value: full_tx.clone(),
    }];
    // prev_out 匹配
    let prev_out = OutPoint { txid, vout: 0 };
    let r = get_utxo_any(&input_map, &prev_out);
    assert!(r.is_some(), "bound NON_WITNESS_UTXO must resolve");
    let (amt, _spk) = r.unwrap();
    assert_eq!(amt, 651_157);
}

#[test]
fn kai01_nonwitness_txid_mismatch_rejected() {
    use shlosilo::chain::btc::p2wpkh::OutPoint;
    use shlosilo::chain::btc::psbt::{get_utxo_any, KeyValue};
    use shlosilo::encoding::sha256;
    let full_tx = make_full_tx(651_157, 0x00);
    let input_map: std::vec::Vec<KeyValue> = vec![KeyValue {
        key: vec![0x00],
        value: full_tx.clone(),
    }];

    // 攻击者给的 prev_out.txid ≠ full-tx 实际 txid → 拒绝
    let fake_txid = {
        let mut t = sha256::hash_twice(&full_tx).unwrap();
        t[0] ^= 0xff;
        t
    };
    let prev_out = OutPoint {
        txid: fake_txid,
        vout: 0,
    };
    assert!(
        get_utxo_any(&input_map, &prev_out).is_none(),
        "txid mismatch must be rejected (fake UTXO attack)"
    );
}

#[test]
fn kai01_nonwitness_vout_oob_rejected() {
    use shlosilo::chain::btc::p2wpkh::OutPoint;
    use shlosilo::chain::btc::psbt::{get_utxo_any, KeyValue};
    use shlosilo::encoding::sha256;
    let full_tx = make_full_tx(651_157, 0x00);
    let input_map: std::vec::Vec<KeyValue> = vec![KeyValue {
        key: vec![0x00],
        value: full_tx,
    }];
    let txid = sha256::hash_twice(&make_full_tx(651_157, 0x00)).unwrap();
    // full tx 只有 1 个 output,vout=1 越界
    let prev_out = OutPoint { txid, vout: 1 };
    assert!(
        get_utxo_any(&input_map, &prev_out).is_none(),
        "vout out-of-range must be rejected"
    );
}
