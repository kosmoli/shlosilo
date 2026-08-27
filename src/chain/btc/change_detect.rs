//! BTC 找零识别（Phase 5 v9.21）
//!
//! 对标 keystone `ParseContext`（mfp + xpub 标 change）的最小 L1 等价物：
//! 从 PSBT output map 的 BIP32_DERIVATION（0x02）读出 master fingerprint，
//! 与本机 master fingerprint 比对 → 标记找零。
//!
//! L1 纯函数：不做地址重派生（那需要 seed / xpub，属业务层）；fingerprint 匹配
//! 与 keystone `check_my_input` 的归属判定同源。

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::chain::btc::psbt::{output_type, Psbt};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// 单个 output 的归属信息
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeInfo {
    /// BIP32_DERIVATION 存在且其 fingerprint 与本机 mfp 一致
    pub is_own: bool,
    /// BIP32_DERIVATION 中的 master fingerprint（无该字段时为 None）
    pub origin_fingerprint: Option<[u8; 4]>,
}

/// 解析 BIP32_DERIVATION value 前缀：fingerprint(4) || depth(1) || ...
fn parse_origin_fingerprint(value: &[u8]) -> Option<[u8; 4]> {
    if value.len() < 4 {
        return None;
    }
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&value[..4]);
    Some(fp)
}

/// 标记每个 output 是否为本钱包找零。
///
/// 规则（与 keystone 归属信号一致）：
/// - output map 有 BIP32_DERIVATION 且其 master fingerprint == 本机 mfp → 找零
/// - 无该字段或 fingerprint 不同 → 非找零
pub fn detect_change_outputs(psbt: &Psbt, master_fingerprint: &[u8; 4]) -> Result<Vec<ChangeInfo>> {
    if psbt.outputs.len() != psbt.unsigned_tx.outputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut infos = Vec::with_capacity(psbt.outputs.len());
    for out_map in &psbt.outputs {
        let origin = out_map
            .iter()
            .find(|kv| kv.key == vec![output_type::BIP32_DERIVATION])
            .and_then(|kv| parse_origin_fingerprint(&kv.value));
        let is_own = origin.as_ref() == Some(master_fingerprint);
        infos.push(ChangeInfo {
            is_own,
            origin_fingerprint: origin,
        });
    }
    Ok(infos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut};
    use crate::chain::btc::psbt::{input_type, KeyValue};
    use alloc::vec;

    const MY_FP: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
    const OTHER_FP: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

    fn bip32_derivation_value(fp: &[u8; 4]) -> Vec<u8> {
        // fingerprint(4) || depth(1) || parent_fp(4) || child_num(4) || chain_code(32) || key(33)
        let mut v = Vec::new();
        v.extend_from_slice(fp);
        v.push(3); // depth
        v.extend_from_slice(&[0u8; 4]); // parent fp
        v.extend_from_slice(&0u32.to_le_bytes()); // child num
        v.extend_from_slice(&[0xaa; 32]); // chain code
        v.extend_from_slice(&[0x02; 33]); // compressed key
        v
    }

    fn sample_psbt(out_fps: Vec<Option<[u8; 4]>>) -> Psbt {
        let txin = TxIn {
            prev_out: OutPoint {
                txid: [0x11u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
            witness: vec![],
        };
        let outputs: Vec<TxOut> = out_fps
            .iter()
            .map(|_| TxOut {
                value: 1000,
                script_pubkey: vec![0x00, 0x14],
            })
            .collect();
        let unsigned_tx = Transaction {
            version: 2,
            inputs: vec![txin],
            outputs,
            lock_time: 0,
        };
        let out_maps: Vec<Vec<KeyValue>> = out_fps
            .into_iter()
            .map(|fp| match fp {
                Some(f) => vec![KeyValue {
                    key: vec![output_type::BIP32_DERIVATION],
                    value: bip32_derivation_value(&f),
                }],
                None => vec![],
            })
            .collect();
        Psbt {
            unsigned_tx,
            inputs: vec![vec![KeyValue {
                key: vec![input_type::WITNESS_UTXO],
                value: {
                    let mut v = vec![0x00, 0x14];
                    v.extend_from_slice(&2000u64.to_le_bytes());
                    v.extend_from_slice(&[0x00, 0x14]);
                    v.extend_from_slice(&[0u8; 20]);
                    v
                },
            }]],
            outputs: out_maps,
        }
    }

    #[test]
    fn own_fingerprint_marks_change() {
        let psbt = sample_psbt(vec![Some(MY_FP), Some(OTHER_FP), None]);
        let infos = detect_change_outputs(&psbt, &MY_FP).unwrap();
        assert_eq!(infos.len(), 3);
        assert!(infos[0].is_own);
        assert_eq!(infos[0].origin_fingerprint, Some(MY_FP));
        assert!(!infos[1].is_own);
        assert_eq!(infos[1].origin_fingerprint, Some(OTHER_FP));
        assert!(!infos[2].is_own);
        assert_eq!(infos[2].origin_fingerprint, None);
    }

    #[test]
    fn no_derivations_no_change() {
        let psbt = sample_psbt(vec![None, None]);
        let infos = detect_change_outputs(&psbt, &MY_FP).unwrap();
        assert!(infos.iter().all(|i| !i.is_own));
    }
}
