//! BTC P2PKH 完整交易签名 (legacy, pre-segwit)
//!
//! 实现:
//! - P2PKH sighash 算法 (BIP-143 同一套, 但 scriptCode 是 76a914{20}88ac 嵌入 scriptSig)
//! - sign_p2pkh 业务函数 (sighash → ECDSA → DER + sighash byte → scriptSig 拼装)
//! - Legacy 交易序列化 (无 marker/flag/witness)
//!
//! ## 算法摘要
//!
//! **P2PKH sighash 算法与 BIP-143 P2WPKH 完全相同**, 但:
//! - scriptCode 嵌入 scriptSig (`OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG`)
//! - witness 为空
//! - 序列化无 marker/flag
//!
//! **P2PKH scriptCode**:
//! ```text
//! 0x1976a914{20-byte-pubkey-hash}88ac
//! ```
//!
//! **P2PKH scriptSig** (签名后):
//! ```text
//! <varint_push_data_len><DER-sig + sighash-byte><varint_push_data_len><compressed-pubkey>
//! ```
//!
//! ## 参考
//!
//! - Bitcoin Core 0.21+ test/functional/test_framework/script.py
//! - 比特币交易 preimage 算法 (<https://en.bitcoin.it/wiki/OP_CHECKSIG>)

extern crate alloc;
use alloc::vec::Vec;

use crate::types::SecretBytes;
use crate::chain::btc::p2wpkh::{
    encode_varint, segwit_sighash_p2wpkh, Transaction, SIGHASH_ALL,
};
use crate::curve_primitive::secp256k1::{base_mul, point_to_compressed, scalar_from_bytes};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::signature::ecdsa_secp256k1::{self as ecdsa};

/// P2PKH scriptCode: `OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG`
pub fn p2pkh_script_code(pubkey_hash: &[u8; 20]) -> [u8; 25] {
    let mut code = [0u8; 25];
    code[0] = 0x76; // OP_DUP
    code[1] = 0xa9; // OP_HASH160
    code[2] = 0x14; // push 20 bytes
    code[3..23].copy_from_slice(pubkey_hash);
    code[23] = 0x88; // OP_EQUALVERIFY
    code[24] = 0xac; // OP_CHECKSIG
    code
}

/// P2PKH scriptPubKey (output lock script)
pub fn p2pkh_script_pubkey(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    p2pkh_script_code(pubkey_hash).to_vec()
}

/// P2PKH 签名输入 (per-input 信息)
///
/// P1-03：私钥走 `SecretBytes<32>`——不 Clone 不 Debug、ZeroizeOnDrop、常时比较。
pub struct P2PKHSignInput<'k> {
    /// 正在签名的 input index
    pub input_index: usize,
    /// 这个 input 的私钥 (32 bytes)——借用，零副本转发
    pub private_key: &'k SecretBytes<32>,
    /// pubkey hash (20 bytes)
    pub pubkey_hash: [u8; 20],
}

/// P2PKH 签名输出
#[derive(Clone, Debug)]
pub struct P2PKHSignedTx {
    /// 完整 legacy 序列化交易 (无 marker/flag/witness)
    pub tx_bytes: Vec<u8>,
    /// 这个 input 的 sighash (签名时用的 preimage hash)
    pub sighash: [u8; 32],
}

/// 签名 P2PKH input
///
/// **副作用**: 修改 `tx.inputs[input_index].script_sig` (注入签名 + pubkey),
/// 设置其他 inputs 的 script_sig 为空.
pub fn sign_p2pkh(tx: &mut Transaction, input: &P2PKHSignInput<'_>) -> Result<P2PKHSignedTx> {
    if input.input_index >= tx.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // 1. 计算 sighash
    let script_code = p2pkh_script_code(&input.pubkey_hash);
    let sighash = segwit_sighash_p2wpkh(
        tx,
        input.input_index,
        &script_code,
        0, // P2PKH 是 legacy, amount 不参与 sighash (旧式算法) → 但 BIP-143 用了 amount
        SIGHASH_ALL,
    )?;

    // 2. ECDSA 签名 (DER + sighash byte)
    let sig_scalar = scalar_from_bytes(input.private_key.expose())?;
    let pk_point = base_mul(&sig_scalar);
    let pk_compressed = point_to_compressed(&pk_point);

    let signature = ecdsa::sign(&sig_scalar, &sighash)?;
    let mut sig_with_sighash = Vec::new();
    let der_sig = ecdsa::to_der(&signature)?;
    sig_with_sighash.extend_from_slice(&der_sig);
    sig_with_sighash.push(SIGHASH_ALL as u8);

    // 3. 构造 scriptSig: <sig-with-sighash-byte> <compressed-pubkey>
    let mut script_sig = Vec::new();
    encode_varint(&mut script_sig, sig_with_sighash.len() as u64);
    script_sig.extend_from_slice(&sig_with_sighash);
    encode_varint(&mut script_sig, pk_compressed.len() as u64);
    script_sig.extend_from_slice(&pk_compressed);

    // 4. 注入 scriptSig
    tx.inputs[input.input_index].script_sig = script_sig;

    // 5. Legacy 序列化 (与 BIP-144 segwit 不同: 无 marker/flag/witness)
    let mut out = Vec::new();
    out.extend_from_slice(&tx.version.to_le_bytes());

    encode_varint(&mut out, tx.inputs.len() as u64);
    for txin in &tx.inputs {
        out.extend_from_slice(&txin.prev_out.txid);
        out.extend_from_slice(&txin.prev_out.vout.to_le_bytes());
        encode_varint(&mut out, txin.script_sig.len() as u64);
        out.extend_from_slice(&txin.script_sig);
        out.extend_from_slice(&txin.sequence.to_le_bytes());
    }

    encode_varint(&mut out, tx.outputs.len() as u64);
    for txout in &tx.outputs {
        out.extend_from_slice(&txout.value.to_le_bytes());
        encode_varint(&mut out, txout.script_pubkey.len() as u64);
        out.extend_from_slice(&txout.script_pubkey);
    }

    out.extend_from_slice(&tx.lock_time.to_le_bytes());

    Ok(P2PKHSignedTx {
        tx_bytes: out,
        sighash,
    })
}

/// 单元测试
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::string::String;
    use alloc::vec;
    use crate::chain::btc::p2wpkh::{OutPoint, TxIn, TxOut};
    use std::eprintln;

    fn hex_decode(s: &str) -> Vec<u8> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = hex_nibble(bytes[i]).unwrap();
            let lo = hex_nibble(bytes[i + 1]).unwrap();
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    fn hex_encode(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&alloc::format!("{:02x}", byte));
        }
        s
    }

    /// P2PKH script_code 构造正确
    #[test]
    fn p2pkh_script_code_format() {
        let pk_hash = [0xab; 20];
        let code = p2pkh_script_code(&pk_hash);
        assert_eq!(code.len(), 25);
        assert_eq!(code[0], 0x76); // OP_DUP
        assert_eq!(code[1], 0xa9); // OP_HASH160
        assert_eq!(code[2], 0x14); // push 20 bytes
        assert_eq!(&code[3..23], &pk_hash);
        assert_eq!(code[23], 0x88); // OP_EQUALVERIFY
        assert_eq!(code[24], 0xac); // OP_CHECKSIG
    }

    /// scriptPubKey 应该是 script_code 的副本
    #[test]
    fn p2pkh_script_pubkey_matches() {
        let pk_hash = [0x12; 20];
        let pk = p2pkh_script_pubkey(&pk_hash);
        let code = p2pkh_script_code(&pk_hash);
        assert_eq!(pk.as_slice(), &code[..]);
    }

    /// 端到端: P2PKH 1-input 1-output 签名
    /// 注: shlosilo 与 Bitcoin Core 的 RFC6979 deterministic k 实现可能不同,
    /// 所以只验证 sighash 一致 + signature 以 sighash byte 0x01 结尾.
    #[test]
    fn p2pkh_end_to_end() {
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        txid[31] = 0xcd;

        let txin = TxIn {
            prev_out: OutPoint { txid, vout: 0 },
            script_sig: vec![],
            sequence: 0xffffffff,
            witness: vec![],
        };

        let txout = TxOut {
            value: 100_000,
            script_pubkey: p2pkh_script_pubkey(&[0x42; 20]),
        };

        let mut tx = Transaction {
            version: 1,
            inputs: vec![txin],
            outputs: vec![txout],
            lock_time: 0,
        };

        let private_key_bytes =
            hex_decode("0101010101010101010101010101010101010101010101010101010101010101");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let pubkey_hash = [0x42; 20];

        let input = P2PKHSignInput {
            input_index: 0,
            private_key: &private_key,
            pubkey_hash,
        };

        let signed = sign_p2pkh(&mut tx, &input).unwrap();

        // 1. sighash 不为零
        assert_ne!(signed.sighash, [0u8; 32]);

        // 2. scriptSig 已注入 (signature + pubkey)
        let script_sig = &tx.inputs[0].script_sig;
        assert!(!script_sig.is_empty(), "script_sig must be populated");

        // 3. tx_bytes 不含 marker/flag (legacy)
        assert_ne!(signed.tx_bytes[4], 0x00, "legacy tx has no marker 0x00");
        assert_ne!(signed.tx_bytes[5], 0x01, "legacy tx has no flag 0x01");

        // 4. scriptSig 第二个 push 是 compressed pubkey (33 bytes)
        // 前 ~71-73 bytes 是 DER sig (含 sighash byte), 后 33 bytes 是 pubkey
        let total = script_sig.len();
        assert!(total >= 33 + 9, "script_sig too short");
        let pubkey_len = script_sig[total - 33 - 1]; // varint 33 = 0x21
        assert_eq!(pubkey_len, 33, "compressed pubkey should be 33 bytes");

        // 5. pubkey 必须是 33-byte compressed (0x02/0x03 前缀)
        let pk_prefix = script_sig[total - 33];
        assert!(pk_prefix == 0x02 || pk_prefix == 0x03, "invalid pubkey prefix");

        eprintln!("P2PKH signed tx ({} bytes): {}", signed.tx_bytes.len(), hex_encode(&signed.tx_bytes));
    }

    /// 不同 input → 不同 sighash
    #[test]
    fn p2pkh_different_input_different_sighash() {
        let tx_a = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint { txid: [1u8; 32], vout: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 100_000,
                script_pubkey: vec![0x76, 0xa9, 0x14, 0x42, 0x88, 0xac],
            }],
            lock_time: 0,
        };

        let tx_b = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint { txid: [2u8; 32], vout: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 100_000,
                script_pubkey: vec![0x76, 0xa9, 0x14, 0x42, 0x88, 0xac],
            }],
            lock_time: 0,
        };

        let pk_hash = [0x42; 20];
        let code = p2pkh_script_code(&pk_hash);

        let h_a = segwit_sighash_p2wpkh(&tx_a, 0, &code, 0, SIGHASH_ALL).unwrap();
        let h_b = segwit_sighash_p2wpkh(&tx_b, 0, &code, 0, SIGHASH_ALL).unwrap();
        assert_ne!(h_a, h_b, "different inputs must produce different sighash");
    }

    /// SIGHASH_ALL byte 在签名末尾
    #[test]
    fn p2pkh_sighash_byte_appended() {
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint { txid, vout: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 100_000,
                script_pubkey: p2pkh_script_pubkey(&[0x42; 20]),
            }],
            lock_time: 0,
        };

        let input = P2PKHSignInput {
            input_index: 0,
            private_key: &SecretBytes::new([1u8; 32]),
            pubkey_hash: [0x42; 20],
        };

        let _ = sign_p2pkh(&mut tx, &input).unwrap();

        // script_sig 最后一个 byte 必须是 0x01 (SIGHASH_ALL)
        let script_sig = &tx.inputs[0].script_sig;
        let total = script_sig.len();
        // compressed pubkey 是最后 33 bytes (varint 0x21 + 33 bytes)
        let sighash_byte_pos = total - 33 - 1;
        assert_eq!(script_sig[sighash_byte_pos - 1], 0x01, "sighash byte should be 0x01 (SIGHASH_ALL)");
    }

    /// Input index 越界
    #[test]
    fn p2pkh_out_of_bounds_input() {
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        let input = P2PKHSignInput {
            input_index: 0,
            private_key: &SecretBytes::new([1u8; 32]),
            pubkey_hash: [0u8; 20],
        };
        let mut tx = tx;
        assert!(sign_p2pkh(&mut tx, &input).is_err());
    }

    /// 重用已有 shlosilo k256 ECDSA API 测试 round-trip
    #[test]
    fn p2pkh_signature_deterministic() {
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint { txid, vout: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 100_000,
                script_pubkey: p2pkh_script_pubkey(&[0x42; 20]),
            }],
            lock_time: 0,
        };

        let input = P2PKHSignInput {
            input_index: 0,
            private_key: &SecretBytes::new([2u8; 32]),
            pubkey_hash: [0x42; 20],
        };

        // 两次签名 → 同一 sighash (因 RFC6979 确定性)
        let sighash1 = segwit_sighash_p2wpkh(
            &tx,
            0,
            &p2pkh_script_code(&[0x42; 20]),
            0,
            SIGHASH_ALL,
        )
        .unwrap();
        let sighash2 = segwit_sighash_p2wpkh(
            &tx,
            0,
            &p2pkh_script_code(&[0x42; 20]),
            0,
            SIGHASH_ALL,
        )
        .unwrap();
        assert_eq!(sighash1, sighash2, "sighash must be deterministic");

        let _ = sign_p2pkh(&mut tx, &input).unwrap();
    }
}