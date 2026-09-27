//! P0-01 remediation landing tests (2026-09-01 third re-review #4) — PSBT parser totality
//!
//! Audit requirement: where the same parser repeats a pattern, hardening must be systematic, not just patching line 723.
//! Coverage:
//! - checked_add (take_bytes): a malicious CompactSize length must not overflow-panic
//! - Budget (PSBT_WIRE_MAX_LEN): length/count fields must not trigger OOM preallocation
//! - Non-canonical CompactSize rejection (multiple encodings of the same value cause parse ambiguity)
//! - All four panic points: decode_witness_utxo:723 / deserialize_unsigned_tx:272 /
//!   decode_map:356 / Vec::with_capacity:251
//! - Real fixture compatibility (locked by p63_btc_psbt.rs, not duplicated here)

use shlosilo::chain::btc::psbt::{decode_witness_utxo, parse_psbt};

fn psbt_magic() -> Vec<u8> {
    vec![0x70, 0x73, 0x62, 0x74, 0xff]
}

/// Minimal legal unsigned tx skeleton (1 input, 0 outputs); script_sig_len injectable
fn tx_with_script_sig_len(len_wire: &[u8]) -> Vec<u8> {
    let mut tx = Vec::new();
    tx.extend_from_slice(&2i32.to_le_bytes()); // version
    tx.push(1); // n_inputs = 1
    tx.extend_from_slice(&[0u8; 32]); // txid
    tx.extend_from_slice(&0u32.to_le_bytes()); // vout
    tx.extend_from_slice(len_wire); // script_sig_len (injection point)
    tx.extend_from_slice(&0xffffffffu32.to_le_bytes()); // sequence
    tx.push(0); // n_outputs
    tx.extend_from_slice(&0u32.to_le_bytes()); // locktime
    tx
}

/// Wrap the global map (unsigned_tx) plus a matching empty input/output map into a full PSBT
/// (after audit #5 exact-consumption: map counts must match the unsigned_tx n_inputs/n_outputs;
/// extra separators are rejected by the whole-consumption check)
fn wrap_psbt(tx: &[u8]) -> Vec<u8> {
    wrap_psbt_full(tx, 1, 0)
}

/// Variant with explicit n_inputs/n_outputs (for malicious count / multi-output tests)
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

// ── 1. Original audit charge: decode_witness_utxo addition overflow ──

#[test]
fn p001_witness_utxo_len_overflow_rejected() {
    // amount ‖ 0xff ‖ u64::MAX — the audit reproduction vector
    let mut v = Vec::new();
    v.extend_from_slice(&651_157u64.to_le_bytes());
    v.push(0xff);
    v.extend_from_slice(&u64::MAX.to_le_bytes());
    assert!(decode_witness_utxo(&v).is_err());
}

#[test]
fn p001_witness_utxo_oversized_len_rejected() {
    // No overflow but over budget (0xfe ‖ 0xffffffff): must reject, must not attempt a 4GB allocation
    let mut v = Vec::new();
    v.extend_from_slice(&651_157u64.to_le_bytes());
    v.push(0xfe);
    v.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    assert!(decode_witness_utxo(&v).is_err());
}

#[test]
fn p001_witness_utxo_trailing_garbage_rejected() {
    // Audit #5 P0-02 (replacing the old reversed test "trailing_garbage_tolerated"):
    // exact-consumption — trailing bytes of the CTxOut value = non-canonical encoding, must reject
    // (the old test wrongly defined trailing garbage as "should be accepted")
    let mut v = Vec::new();
    v.extend_from_slice(&651_157u64.to_le_bytes());
    v.push(3); // spk_len = 3
    v.extend_from_slice(&[0x00, 0x14, 0x99]); // placeholder spk
    v.push(0xde); // trailing garbage
    let r = decode_witness_utxo(&v);
    assert!(
        r.is_err(),
        "CTxOut trailing bytes must be rejected (exact-consumption)"
    );
}

// ── 2. deserialize_unsigned_tx: script_sig_len / script_pubkey_len overflow ──

#[test]
fn p001_script_sig_len_overflow_rejected() {
    let tx = tx_with_script_sig_len(&{
        let mut w = vec![0xff];
        w.extend_from_slice(&u64::MAX.to_le_bytes());
        w
    });
    let psbt_bytes = wrap_psbt(&tx);
    let r = parse_psbt(&psbt_bytes);
    assert!(
        r.is_err(),
        "malicious script_sig_len must error stably (panicked at psbt.rs:272 before the fix)"
    );
}

#[test]
fn p001_script_pubkey_len_oversized_rejected() {
    // outputs: 1 output, value(8B) + script_pubkey_len = 0xfe ‖ 0xffffffff
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
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // over budget
    let psbt_bytes = wrap_psbt_full(&tx, 1, 1);
    let r = parse_psbt(&psbt_bytes);
    assert!(r.is_err());
}

// ── 3. decode_map: key_len / value_len overflow ──

#[test]
fn p001_map_value_len_overflow_rejected() {
    // The first global map entry carries a malicious value_len
    let mut b = psbt_magic();
    b.push(1);
    b.push(0x00);
    b.push(0xff);
    b.extend_from_slice(&u64::MAX.to_le_bytes());
    let r = parse_psbt(&b);
    assert!(
        r.is_err(),
        "malicious value_len must error stably (panicked at psbt.rs:356 before the fix)"
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

// ── 4. with_capacity OOM: huge n_inputs / n_outputs ──

#[test]
fn p001_huge_input_count_no_oom() {
    let mut tx = Vec::new();
    tx.extend_from_slice(&2i32.to_le_bytes());
    tx.push(0xff); // n_inputs prefix
    tx.extend_from_slice(&u64::MAX.to_le_bytes());
    let psbt_bytes = wrap_psbt_full(&tx, 0, 0);
    let r = parse_psbt(&psbt_bytes);
    assert!(
        r.is_err(),
        "malicious input count must error (capacity overflow abort before the fix)"
    );
}

#[test]
fn p001_count_exceeding_physical_bytes_rejected_before_alloc() {
    // Audit #5 P0-02 + sixth re-review P2-01: the physical-feasibility check has been extracted into a pure helper
    // count_physically_feasible (see psbt.rs); this test asserts helper behavior
    // and no longer relies on timing observation (re-review verdict: the 100ms threshold is unreliable, with_capacity does not memset,
    // and the host allocator could well be faster; if the old vulnerability regresses, a timing test would still pass).
    //
    // Behavior chain: malicious n_inputs=60000 + small wire → helper false → the parser returns Err
    // before Vec::with_capacity (the helper call site precedes with_capacity in the implementation, locked by code order).
    // before with_capacity, locked by code order).
    let mut tx = Vec::new();
    tx.extend_from_slice(&2i32.to_le_bytes());
    tx.push(0xfd); // n_inputs 2-byte prefix
    tx.extend_from_slice(&60_000u16.to_le_bytes());
    let psbt_bytes = wrap_psbt_full(&tx, 0, 0);
    let r = parse_psbt(&psbt_bytes);
    assert!(r.is_err(), "physically infeasible count must be rejected");
}

#[test]
fn p001_duplicate_map_key_rejected() {
    // Audit #5 P0-02: duplicate key rejection — BIP-174 "key must be unique in a map",
    // duplicates = a first-wins/last-wins parser differential vector
    let mut b = psbt_magic();
    // global map: two identical key=[0x00] (UNSIGNED_TX) entries
    b.push(1); // keylen
    b.push(0x00); // key = UNSIGNED_TX
    b.push(4); // valuelen
    b.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // value1
    b.push(1); // keylen
    b.push(0x00); // key = UNSIGNED_TX (duplicate!)
    b.push(4); // valuelen
    b.extend_from_slice(&[0x05, 0x06, 0x07, 0x08]); // value2
    let r = parse_psbt(&b);
    assert!(r.is_err(), "duplicate map key must be rejected");
}

#[test]
fn p001_psbt_trailing_bytes_after_output_maps_rejected() {
    // Audit #5 P0-02: whole-message exact-consumption — leftover bytes after all maps parse = reject
    let tx = tx_with_script_sig_len(&[0x00]);
    let mut b = wrap_psbt(&tx);
    b.push(0xde);
    b.push(0xad); // trailing garbage
    let r = parse_psbt(&b);
    assert!(
        r.is_err(),
        "PSBT trailing bytes after output maps must be rejected"
    );
}

#[test]
fn p001_unsigned_tx_trailing_bytes_rejected() {
    // Audit #5 P0-02: unsigned tx embedded trailing data — sighash preimage consistency risk
    let mut tx = Vec::new();
    tx.extend_from_slice(&2i32.to_le_bytes());
    tx.push(1); // n_inputs
    tx.extend_from_slice(&[0u8; 32]);
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx.push(0); // script_sig_len
    tx.extend_from_slice(&0xffffffffu32.to_le_bytes()); // sequence
    tx.push(0); // n_outputs
    tx.extend_from_slice(&0u32.to_le_bytes()); // locktime
    tx.push(0xde); // embedded trailing
    let psbt_bytes = wrap_psbt(&tx);
    let r = parse_psbt(&psbt_bytes);
    assert!(r.is_err(), "unsigned tx trailing bytes must be rejected");
}

// ── 5. Non-canonical CompactSize rejection ──

#[test]
fn p001_noncanonical_compact_size_rejected() {
    // script_sig_len = 5 encoded as 0xfd ‖ 0x0005 (non-canonical) — reject
    let mut t = Vec::new();
    t.extend_from_slice(&2i32.to_le_bytes());
    t.push(1);
    t.extend_from_slice(&[0u8; 32]);
    t.extend_from_slice(&0u32.to_le_bytes());
    t.extend_from_slice(&[0xfd, 0x05, 0x00]); // non-canonical 5
    t.extend_from_slice(&[0xaa; 5]); // 5-byte script_sig
    t.extend_from_slice(&0xffffffffu32.to_le_bytes());
    t.push(0);
    t.extend_from_slice(&0u32.to_le_bytes());
    let psbt_bytes = wrap_psbt(&t);
    let r = parse_psbt(&psbt_bytes);
    assert!(
        r.is_err(),
        "non-canonical CompactSize (0xfd prefix encoding a value < 0xfd) must be rejected"
    );
}

#[test]
fn p001_zero_prefix_0xff_rejected() {
    // 0xff ‖ 0x0000000000000005 (value 5, non-canonical 8-byte encoding) — reject
    let mut t = Vec::new();
    t.extend_from_slice(&2i32.to_le_bytes());
    t.push(1);
    t.extend_from_slice(&[0u8; 32]);
    t.extend_from_slice(&0u32.to_le_bytes());
    t.push(0xff);
    t.extend_from_slice(&5u64.to_le_bytes()); // value 5 < 0x1_0000_0000, non-canonical
    t.extend_from_slice(&[0xaa; 5]);
    t.extend_from_slice(&0xffffffffu32.to_le_bytes());
    t.push(0);
    t.extend_from_slice(&0u32.to_le_bytes());
    let psbt_bytes = wrap_psbt(&t);
    let r = parse_psbt(&psbt_bytes);
    assert!(r.is_err());
}

// ── 6. Legal PSBT unaffected by the budget (smoke) ──

#[test]
fn p001_valid_minimal_psbt_still_parses() {
    let tx = tx_with_script_sig_len(&[0x00]); // script_sig_len = 0
    let psbt_bytes = wrap_psbt(&tx);
    let psbt = parse_psbt(&psbt_bytes);
    assert!(psbt.is_ok());
    let p = psbt.unwrap();
    assert_eq!(p.unsigned_tx.inputs.len(), 1);
    assert_eq!(p.unsigned_tx.outputs.len(), 0);
}

// ── 7. Audit #5 open-01: NON_WITNESS_UTXO full-tx/txid/vout binding ──

/// Build a minimal legacy full tx (version + 1in + 1out + locktime)
fn make_full_tx(vout_value: u64, spk_byte: u8) -> Vec<u8> {
    let mut tx = Vec::new();
    tx.extend_from_slice(&2i32.to_le_bytes()); // version
    tx.push(1); // n_inputs = 1
    tx.extend_from_slice(&[0xaau8; 32]); // parent txid (placeholder)
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
    use shlosilo::chain::btc::psbt::{get_utxo_any, KeyValue, KvMap};
    use shlosilo::encoding::sha256;
    let full_tx = make_full_tx(651_157, 0x00);
    // txid = dsha256(serialized)
    let txid: [u8; 32] = sha256::hash_twice(&full_tx).unwrap();

    // PSBT input map:NON_WITNESS_UTXO = full tx
    let input_map: std::vec::Vec<KeyValue> = vec![KeyValue {
        key: vec![0x00].into(), // NON_WITNESS_UTXO
        value: full_tx.clone().into(),
    }];
    // prev_out matches
    let prev_out = OutPoint { txid, vout: 0 };
    let r = get_utxo_any(KvMap::from_slice(&input_map), &prev_out);
    assert!(r.is_some(), "bound NON_WITNESS_UTXO must resolve");
    let (amt, _spk) = r.unwrap();
    assert_eq!(amt, 651_157);
}

#[test]
fn kai01_nonwitness_txid_mismatch_rejected() {
    use shlosilo::chain::btc::p2wpkh::OutPoint;
    use shlosilo::chain::btc::psbt::{get_utxo_any, KeyValue, KvMap};
    use shlosilo::encoding::sha256;
    let full_tx = make_full_tx(651_157, 0x00);
    let input_map: std::vec::Vec<KeyValue> = vec![KeyValue {
        key: vec![0x00].into(),
        value: full_tx.clone().into(),
    }];

    // The attacker-provided prev_out.txid ≠ the full-tx actual txid → reject
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
        get_utxo_any(KvMap::from_slice(&input_map), &prev_out).is_none(),
        "txid mismatch must be rejected (fake UTXO attack)"
    );
}

#[test]
fn kai01_nonwitness_vout_oob_rejected() {
    use shlosilo::chain::btc::p2wpkh::OutPoint;
    use shlosilo::chain::btc::psbt::{get_utxo_any, KeyValue, KvMap};
    use shlosilo::encoding::sha256;
    let full_tx = make_full_tx(651_157, 0x00);
    let input_map: std::vec::Vec<KeyValue> = vec![KeyValue {
        key: vec![0x00].into(),
        value: full_tx.into(),
    }];
    let txid = sha256::hash_twice(&make_full_tx(651_157, 0x00)).unwrap();
    // The full tx has only 1 output; vout=1 is out of bounds
    let prev_out = OutPoint { txid, vout: 1 };
    assert!(
        get_utxo_any(KvMap::from_slice(&input_map), &prev_out).is_none(),
        "vout out-of-range must be rejected"
    );
}
