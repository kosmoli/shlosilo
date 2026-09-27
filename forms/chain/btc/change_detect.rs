//! BTC change detection (Phase 5 v9.21)
//!
//! A minimal L1 equivalent of keystone's `ParseContext` (mfp + xpub marking change):
//! read the master fingerprint from the BIP32_DERIVATION (0x02) of the PSBT output map,
//! compare it with this device's master fingerprint → mark change.
//!
//! L1 pure function: no address re-derivation (that needs seed / xpub and belongs to the business layer); fingerprint matching
//! shares the same origin as keystone `check_my_input`'s ownership decision.

extern crate alloc;
use alloc::vec::Vec;

#[cfg(test)]
use crate::chain::btc::p2wpkh::bt_vec;
use crate::chain::btc::psbt::{output_type, Psbt};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// Ownership info for a single output
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeInfo {
    /// BIP32_DERIVATION exists and its fingerprint matches this device's mfp
    pub is_own: bool,
    /// The master fingerprint inside BIP32_DERIVATION (None when the field is absent)
    pub origin_fingerprint: Option<[u8; 4]>,
}

/// Parse the BIP32_DERIVATION value prefix: fingerprint(4) || depth(1) || ...
fn parse_origin_fingerprint(value: &[u8]) -> Option<[u8; 4]> {
    if value.len() < 4 {
        return None;
    }
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&value[..4]);
    Some(fp)
}

/// Mark whether each output is change for this wallet.
///
/// Rules (consistent with keystone's ownership signals):
/// - The output map has BIP32_DERIVATION and its master fingerprint == this device's mfp → change
/// - Field absent or fingerprint differs → not change
pub fn detect_change_outputs(
    psbt: &Psbt<'_>,
    master_fingerprint: &[u8; 4],
) -> Result<Vec<ChangeInfo>> {
    if psbt.unsigned_tx.outputs.len() != psbt.unsigned_tx.outputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut infos = Vec::with_capacity(psbt.unsigned_tx.outputs.len());
    for i in 0..psbt.unsigned_tx.outputs.len() {
        let out_map = psbt.output_map(i);
        let origin = out_map
            .iter()
            .find(|kv| kv.key == &[output_type::BIP32_DERIVATION][..])
            .and_then(|kv| parse_origin_fingerprint(kv.value));
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
    use crate::chain::btc::psbt::psbt_from_maps_leaky;
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

    fn sample_psbt(out_fps: Vec<Option<[u8; 4]>>) -> Psbt<'static> {
        let txin = TxIn {
            prev_out: OutPoint {
                txid: [0x11u8; 32],
                vout: 0,
            },
            script_sig: vec![].into(),
            sequence: 0xffffffff,
            witness: vec![],
        };
        let outputs: Vec<TxOut> = out_fps
            .iter()
            .map(|_| TxOut {
                value: 1000,
                script_pubkey: vec![0x00, 0x14].into(),
            })
            .collect();
        let unsigned_tx = Transaction {
            version: 2,
            inputs: bt_vec![txin],
            outputs: heapless::Vec::from_slice(&outputs).unwrap(),
            lock_time: 0,
        };
        let out_maps: Vec<Vec<KeyValue>> = out_fps
            .into_iter()
            .map(|fp| match fp {
                Some(f) => vec![KeyValue {
                    key: vec![output_type::BIP32_DERIVATION].into(),
                    value: bip32_derivation_value(&f).into(),
                }],
                None => vec![],
            })
            .collect();
        psbt_from_maps_leaky(
            unsigned_tx,
            &[vec![KeyValue {
                key: vec![input_type::WITNESS_UTXO].into(),
                value: {
                    let mut v = vec![0x00, 0x14];
                    v.extend_from_slice(&2000u64.to_le_bytes());
                    v.extend_from_slice(&[0x00, 0x14]);
                    v.extend_from_slice(&[0u8; 20]);
                    v.into()
                },
            }]],
            &out_maps,
        )
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
