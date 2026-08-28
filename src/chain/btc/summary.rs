//! PSBT 解析摘要 / 风险标记（Phase 5 v9.18）
//!
//! L1 纯函数：从已解析的 `Psbt` 抽出确认屏需要的数字与警告。
//! 不做找零身份识别（那要 xpub/fingerprint，属钱包上下文）。
//! 调用方可选传入 `own_spks` 标记「自己的」output。
//!
//! 对标 keystone `parse_psbt` 的 overview 字段子集：
//! fee、fee > amount、missing UTXO、未知脚本、巨大 output、RBF、locktime、CSV。

extern crate alloc;
use alloc::vec::Vec;

use crate::chain::btc::p2wpkh::Transaction;
use crate::chain::btc::psbt::{get_utxo_any, Psbt};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// BIP-125: nSequence < 0xfffffffe 表示可替换
pub const RBF_THRESHOLD: u32 = 0xfffffffe;
/// nLockTime 高度/时间分界（BIP-65 / Bitcoin Core）
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;
/// BIP-68 disable flag
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
/// BIP-68 type flag（set = 时间，clear = 高度）
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
/// 超过此值视为「巨大」（21M BTC，单位 sat）
pub const MAX_MONEY_SATS: u64 = 21_000_000 * 100_000_000;
/// P2PKH dust
pub const DUST_SATS: u64 = 546;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpkKind {
    P2pkh,
    P2sh,
    P2wpkh,
    P2wsh,
    P2tr,
    OpReturn,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocktimeKind {
    None,
    Height(u32),
    Timestamp(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelativeLock {
    None,
    Blocks(u32),
    Time512s(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputSummary {
    pub value: u64,
    pub spk_kind: SpkKind,
    pub is_own: bool,
    pub is_dust: bool,
    pub is_huge: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputSummary {
    pub value: Option<u64>,
    pub sequence: u32,
    pub rbf: bool,
    pub relative_lock: RelativeLock,
    pub spk_kind: Option<SpkKind>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PsbtSummary {
    pub version: i32,
    pub locktime: LocktimeKind,
    pub inputs: Vec<InputSummary>,
    pub outputs: Vec<OutputSummary>,
    pub total_in: Option<u64>,
    pub total_out: u64,
    pub fee: Option<u64>,
    pub fee_unknown: bool,
    pub fee_larger_than_amount: bool,
    pub rbf: bool,
    pub has_unknown_script: bool,
    pub has_huge_output: bool,
}

pub fn classify_spk(spk: &[u8]) -> SpkKind {
    if spk.len() == 25 && spk[0] == 0x76 && spk[1] == 0xa9 && spk[2] == 0x14 && spk[23] == 0x88 && spk[24] == 0xac {
        return SpkKind::P2pkh;
    }
    if spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87 {
        return SpkKind::P2sh;
    }
    if spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14 {
        return SpkKind::P2wpkh;
    }
    if spk.len() == 34 && spk[0] == 0x00 && spk[1] == 0x20 {
        return SpkKind::P2wsh;
    }
    if spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20 {
        return SpkKind::P2tr;
    }
    if !spk.is_empty() && spk[0] == 0x6a {
        return SpkKind::OpReturn;
    }
    SpkKind::Unknown
}

fn relative_lock(sequence: u32) -> RelativeLock {
    if sequence == 0xffffffff || (sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0 {
        return RelativeLock::None;
    }
    let value = sequence & 0x0000ffff;
    if (sequence & SEQUENCE_LOCKTIME_TYPE_FLAG) != 0 {
        RelativeLock::Time512s(value)
    } else {
        RelativeLock::Blocks(value)
    }
}

fn locktime_kind(n: u32) -> LocktimeKind {
    if n == 0 {
        LocktimeKind::None
    } else if n < LOCKTIME_THRESHOLD {
        LocktimeKind::Height(n)
    } else {
        LocktimeKind::Timestamp(n)
    }
}

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

pub fn summarize_psbt(psbt: &Psbt, own_spks: &[&[u8]]) -> Result<PsbtSummary> {
    let n = psbt.unsigned_tx.inputs.len();
    let mut values = Vec::with_capacity(n);
    for i in 0..n {
        let v = psbt.inputs.get(i).and_then(|m| get_utxo_any(m).map(|(amt, _)| amt));
        values.push(v);
    }
    summarize_tx(&psbt.unsigned_tx, &values, own_spks)
}

pub fn summarize_tx(
    tx: &Transaction,
    input_values: &[Option<u64>],
    own_spks: &[&[u8]],
) -> Result<PsbtSummary> {
    if input_values.len() != tx.inputs.len() {
        return Err(err());
    }
    let mut inputs = Vec::with_capacity(tx.inputs.len());
    let mut total_in: Option<u64> = Some(0);
    let mut rbf = false;
    for (i, txin) in tx.inputs.iter().enumerate() {
        let seq = txin.sequence;
        if seq < RBF_THRESHOLD {
            rbf = true;
        }
        let value = input_values[i];
        if let Some(v) = value {
            if let Some(t) = total_in.as_mut() {
                *t = t.saturating_add(v);
            }
        } else {
            total_in = None;
        }
        inputs.push(InputSummary {
            value,
            sequence: seq,
            rbf: seq < RBF_THRESHOLD,
            relative_lock: relative_lock(seq),
            spk_kind: None,
        });
    }

    let mut outputs = Vec::with_capacity(tx.outputs.len());
    let mut total_out: u64 = 0;
    let mut has_unknown_script = false;
    let mut has_huge_output = false;
    let mut external_out: u64 = 0;
    for txout in &tx.outputs {
        total_out = total_out.saturating_add(txout.value);
        let kind = classify_spk(&txout.script_pubkey);
        if kind == SpkKind::Unknown {
            has_unknown_script = true;
        }
        let is_huge = txout.value > MAX_MONEY_SATS;
        if is_huge {
            has_huge_output = true;
        }
        let is_own = own_spks.contains(&txout.script_pubkey.as_slice());
        if !is_own {
            external_out = external_out.saturating_add(txout.value);
        }
        outputs.push(OutputSummary {
            value: txout.value,
            spk_kind: kind,
            is_own,
            is_dust: txout.value > 0 && txout.value < DUST_SATS,
            is_huge,
        });
    }

    let fee_unknown = total_in.is_none();
    let fee = match total_in {
        Some(tin) => {
            if tin < total_out {
                return Err(err());
            }
            Some(tin - total_out)
        }
        None => None,
    };
    let fee_larger_than_amount = match fee {
        Some(f) => external_out > 0 && f > external_out,
        None => false,
    };

    Ok(PsbtSummary {
        version: tx.version,
        locktime: locktime_kind(tx.lock_time),
        inputs,
        outputs,
        total_in,
        total_out,
        fee,
        fee_unknown,
        fee_larger_than_amount,
        rbf,
        has_unknown_script,
        has_huge_output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::btc::p2wpkh::{OutPoint, TxIn, TxOut};
    use crate::chain::btc::psbt::{input_type, KeyValue};
    use alloc::vec;

    fn p2wpkh_spk(first: u8) -> Vec<u8> {
        let mut s = vec![0x00, 0x14];
        s.extend_from_slice(&[first; 20]);
        s
    }

    fn p2pkh_spk() -> Vec<u8> {
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(&[0x11u8; 20]);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    }

    fn witness_utxo_bytes(value: u64, spk: &[u8]) -> Vec<u8> {
        TxOut {
            value,
            script_pubkey: spk.to_vec(),
        }
        .serialize()
    }

    fn sample_psbt(in_value: u64, out_value: u64, sequence: u32, lock_time: u32, out_spk: Vec<u8>) -> Psbt {
        let txin = TxIn {
            prev_out: OutPoint {
                txid: [0x11u8; 32],
                vout: 1,
            },
            script_sig: vec![],
            sequence,
            witness: vec![],
        };
        let txout = TxOut {
            value: out_value,
            script_pubkey: out_spk.clone(),
        };
        let unsigned_tx = Transaction {
            version: 2,
            inputs: vec![txin],
            outputs: vec![txout],
            lock_time,
        };
        let in_spk = p2wpkh_spk(0xab);
        Psbt {
            unsigned_tx,
            inputs: vec![vec![KeyValue {
                key: vec![input_type::WITNESS_UTXO],
                value: witness_utxo_bytes(in_value, &in_spk),
            }]],
            outputs: vec![vec![]],
        }
    }

    #[test]
    fn classify_known_scripts() {
        assert_eq!(classify_spk(&p2wpkh_spk(1)), SpkKind::P2wpkh);
        assert_eq!(classify_spk(&p2pkh_spk()), SpkKind::P2pkh);
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&[0u8; 32]);
        assert_eq!(classify_spk(&p2tr), SpkKind::P2tr);
        let mut p2sh = vec![0xa9, 0x14];
        p2sh.extend_from_slice(&[0u8; 20]);
        p2sh.push(0x87);
        assert_eq!(classify_spk(&p2sh), SpkKind::P2sh);
        let mut p2wsh = vec![0x00, 0x20];
        p2wsh.extend_from_slice(&[0u8; 32]);
        assert_eq!(classify_spk(&p2wsh), SpkKind::P2wsh);
        assert_eq!(classify_spk(&[0x6a, 0x01, 0xff]), SpkKind::OpReturn);
        assert_eq!(classify_spk(&[0x51]), SpkKind::Unknown);
    }

    #[test]
    fn fee_and_rbf_from_psbt_full_round_trip_shape() {
        // 与 psbt_full_round_trip 同形状：200_000 in, 50_000 out, seq 0xffffffee, lock 12345
        let psbt = sample_psbt(200_000, 50_000, 0xffffffee, 12345, p2wpkh_spk(0xab));
        let s = summarize_psbt(&psbt, &[]).unwrap();
        assert_eq!(s.total_in, Some(200_000));
        assert_eq!(s.total_out, 50_000);
        assert_eq!(s.fee, Some(150_000));
        assert!(!s.fee_unknown);
        assert!(s.rbf);
        assert_eq!(s.locktime, LocktimeKind::Height(12345));
        assert!(!s.has_unknown_script);
        assert!(s.fee_larger_than_amount);
        assert_eq!(s.outputs[0].spk_kind, SpkKind::P2wpkh);
        assert!(!s.outputs[0].is_own);
    }

    #[test]
    fn own_spk_marks_change() {
        let spk = p2wpkh_spk(0x42);
        let psbt = sample_psbt(100_000, 90_000, 0xffffffff, 0, spk.clone());
        let s = summarize_psbt(&psbt, &[spk.as_slice()]).unwrap();
        assert!(s.outputs[0].is_own);
        assert!(!s.fee_larger_than_amount); // 外部金额 0，fee 对外部金额不算「大于」
        assert_eq!(s.fee, Some(10_000));
        assert_eq!(s.locktime, LocktimeKind::None);
        assert!(!s.rbf);
    }

    #[test]
    fn missing_utxo_fee_unknown() {
        let mut psbt = sample_psbt(1, 1, 0xffffffff, 0, p2wpkh_spk(1));
        psbt.inputs[0].clear();
        let s = summarize_psbt(&psbt, &[]).unwrap();
        assert!(s.fee_unknown);
        assert_eq!(s.fee, None);
        assert_eq!(s.total_in, None);
    }

    #[test]
    fn input_less_than_output_rejected() {
        let psbt = sample_psbt(10, 20, 0xffffffff, 0, p2wpkh_spk(1));
        assert!(summarize_psbt(&psbt, &[]).is_err());
    }

    #[test]
    fn unknown_and_huge_output_flagged() {
        let huge = vec![0x51];
        let psbt = sample_psbt(MAX_MONEY_SATS, MAX_MONEY_SATS, 0xffffffff, 0, huge);
        // value == MAX is not huge; bump output via summarize_tx
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: [0; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: MAX_MONEY_SATS + 1,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };
        let s = summarize_tx(&tx, &[Some(MAX_MONEY_SATS + 1)], &[]).unwrap();
        assert!(s.has_unknown_script);
        assert!(s.has_huge_output);
        assert!(s.outputs[0].is_huge);
        let _ = psbt;
    }

    #[test]
    fn locktime_timestamp() {
        let psbt = sample_psbt(100, 50, 0xffffffff, LOCKTIME_THRESHOLD + 1, p2wpkh_spk(1));
        let s = summarize_psbt(&psbt, &[]).unwrap();
        assert_eq!(s.locktime, LocktimeKind::Timestamp(LOCKTIME_THRESHOLD + 1));
    }

    #[test]
    fn csv_relative_blocks() {
        // disable flag clear, type flag clear, value = 10 blocks
        let seq = 10u32;
        let psbt = sample_psbt(100, 50, seq, 0, p2wpkh_spk(1));
        let s = summarize_psbt(&psbt, &[]).unwrap();
        assert_eq!(s.inputs[0].relative_lock, RelativeLock::Blocks(10));
        assert!(s.rbf); // 10 < 0xfffffffe
    }

    #[test]
    fn csv_relative_time() {
        let seq = SEQUENCE_LOCKTIME_TYPE_FLAG | 3;
        let psbt = sample_psbt(100, 50, seq, 0, p2wpkh_spk(1));
        let s = summarize_psbt(&psbt, &[]).unwrap();
        assert_eq!(s.inputs[0].relative_lock, RelativeLock::Time512s(3));
    }

    #[test]
    fn dust_output() {
        let psbt = sample_psbt(1000, 100, 0xffffffff, 0, p2pkh_spk());
        let s = summarize_psbt(&psbt, &[]).unwrap();
        assert!(s.outputs[0].is_dust);
        assert_eq!(s.outputs[0].spk_kind, SpkKind::P2pkh);
    }
}
