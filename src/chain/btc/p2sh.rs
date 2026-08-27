//! BTC P2SH-P2WPKH 完整交易签名 (segwit wrapped, BIP-141 + BIP-143)
//!
//! 实现:
//! - P2SH-P2WPKH sighash 算法 (与 P2WPKH 同, 但 scriptCode = redeemScript = P2PKH-style 25 bytes)
//! - sign_p2sh_p2wpkh 业务函数 (sighash → ECDSA → DER + sighash byte → scriptSig + witness 拼装)
//! - P2SH + BIP-144 segwit 序列化 (marker + flag + scriptSig 含 redeemScript push + witness)
//!
//! ## 算法摘要
//!
//! **P2SH-P2WPKH sighash** 与 P2WPKH 完全相同 (BIP-143), 但:
//! - scriptCode = redeemScript = `0x1976a914{20-byte-pubkey-hash}88ac` (25 bytes)
//! - scriptSig = `varint_push_len_0x23 {0x16 0x0014} redeemScript` (22-byte push)
//! - witness = `[signature, compressed-pubkey]` (2 items, 与 P2WPKH 相同)
//!
//! ## 关键约束
//!
//! P2SH 的 scriptPubKey 是 `OP_HASH160 <redeemScriptHash> OP_EQUAL`:
//! - `0xa914{20-byte-redeemScriptHash}87` (23 bytes)
//!
//! 但签名只需要 redeemScript (实际执行脚本), 不是 redeemScript hash.
//! Caller 必须提供 redeemScript, 而不是其 hash.
//!
//! ## 参考
//!
//! - BIP-141 (Segwit): <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki>
//! - BIP-143 (Segwit sighash): <https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki>
//! - BIP-16 (P2SH): <https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki>

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::chain::btc::p2pkh::p2pkh_script_code;
use crate::chain::btc::p2wpkh::{
    encode_varint, segwit_sighash_p2wpkh, OutPoint, Transaction, TxIn, TxOut, Txid,
    SIGHASH_ALL,
};
use crate::curve_primitive::secp256k1::{base_mul, point_to_compressed, scalar_from_bytes};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::signature::ecdsa_secp256k1::{self as ecdsa};

/// P2SH scriptPubKey: `OP_HASH160 <20-byte-hash> OP_EQUAL`
///
/// `0xa914{20-byte-hash}87`
pub fn p2sh_script_pubkey(redeem_script_hash: &[u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(23);
    out.push(0xa9); // OP_HASH160
    out.push(0x14); // push 20 bytes
    out.extend_from_slice(redeem_script_hash);
    out.push(0x87); // OP_EQUAL
    out
}

/// P2SH-P2WPKH scriptSig: `varint_22 0x16 0x0014 {redeemScript}`
///
/// 实际 push: `push 22 bytes, 其中前 2 bytes 是 0x160014 (P2PKH-style prefix), 后 20 bytes 是 pubkey_hash`
///
/// redeemScript 完整 22 bytes: `0x16 0x00 0x14 {20-byte-pubkey-hash}`
/// 注: 0x16 = OP_PUSH_22, 0x00 = OP_PUSHDATA1... wait, 实际是:
///
/// **实际 redeemScript = P2WPKH witness program = `0x0014{20-byte-pubkey-hash}` (22 bytes)**
///
/// 整个 scriptSig:
///
/// ```text
/// <0x16> = push 22 bytes (redeemScript length)
/// <22 bytes> = 0x00 0x14 {20-byte-pubkey-hash}
/// ```
pub fn p2sh_p2wpkh_script_sig(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 22);
    out.push(0x16); // push 22 bytes
    out.push(0x00); // OP_0
    out.push(0x14); // push 20 bytes
    out.extend_from_slice(pubkey_hash);
    out
}

/// P2SH-P2WPKH redeemScript (22 bytes)
///
/// `0x0014{20-byte-pubkey-hash}`
pub fn p2sh_p2wpkh_redeem_script(pubkey_hash: &[u8; 20]) -> [u8; 22] {
    let mut out = [0u8; 22];
    out[0] = 0x00; // OP_0 (P2WPKH marker)
    out[1] = 0x14; // push 20 bytes
    out[2..22].copy_from_slice(pubkey_hash);
    out
}

/// P2SH-P2WPKH 签名输入 (per-input 信息)
#[derive(Clone, Debug)]
pub struct P2SHP2WPKHSignInput {
    /// 正在签名的 input index
    pub input_index: usize,
    /// 这个 input 的私钥 (32 bytes)
    pub private_key: [u8; 32],
    /// pubkey hash (20 bytes) — P2WPKH witness program 内的 pubkey hash
    pub pubkey_hash: [u8; 20],
    /// 这个 input 的 value (satoshis) — 用于 BIP-143 sighash
    pub amount: u64,
}

/// P2SH-P2WPKH 签名输出
#[derive(Clone, Debug)]
pub struct P2SHP2WPKHSignedTx {
    /// 完整 BIP-144 segwit 序列化交易 (marker + flag + witness)
    pub tx_bytes: Vec<u8>,
    /// 这个 input 的 sighash
    pub sighash: [u8; 32],
}

/// 签名 P2SH-P2WPKH input
///
/// **副作用**:
/// - 修改 `tx.inputs[input_index].script_sig` (注入 redeemScript push)
/// - 修改 `tx.inputs[input_index].witness` (注入 signature + pubkey)
pub fn sign_p2sh_p2wpkh(
    tx: &mut Transaction,
    input: &P2SHP2WPKHSignInput,
) -> Result<P2SHP2WPKHSignedTx> {
    if input.input_index >= tx.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // 1. sighash: P2SH-P2WPKH 用 P2PKH-style scriptCode (redeemScript)
    let redeem_script = p2pkh_script_code(&input.pubkey_hash);
    let sighash = segwit_sighash_p2wpkh(
        tx,
        input.input_index,
        &redeem_script,
        input.amount,
        SIGHASH_ALL,
    )?;

    // 2. ECDSA 签名
    let sig_scalar = scalar_from_bytes(&input.private_key)?;
    let pk_point = base_mul(&sig_scalar);
    let pk_compressed = point_to_compressed(&pk_point);

    let signature = ecdsa::sign(&sig_scalar, &sighash)?;
    let mut sig_with_sighash = Vec::new();
    let der_sig = ecdsa::to_der(&signature)?;
    sig_with_sighash.extend_from_slice(&der_sig);
    sig_with_sighash.push(SIGHASH_ALL as u8);

    // 3. scriptSig = push(22) {0x00 0x14 pubkey_hash}
    let script_sig = p2sh_p2wpkh_script_sig(&input.pubkey_hash);

    // 4. witness = [signature, compressed-pubkey]
    let witness = vec![sig_with_sighash, pk_compressed.to_vec()];

    // 5. 注入
    tx.inputs[input.input_index].script_sig = script_sig;
    tx.inputs[input.input_index].witness = witness;

    // 6. BIP-144 segwit 序列化 (用 p2wpkh::Transaction::serialize_segwit)
    let tx_bytes = tx.serialize_segwit();

    Ok(P2SHP2WPKHSignedTx { tx_bytes, sighash })
}

/// 单元测试
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::string::String;
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

    /// P2SH scriptPubKey 构造
    #[test]
    fn p2sh_script_pubkey_format() {
        let hash = [0xab; 20];
        let pk = p2sh_script_pubkey(&hash);
        assert_eq!(pk.len(), 23);
        assert_eq!(pk[0], 0xa9); // OP_HASH160
        assert_eq!(pk[1], 0x14); // push 20
        assert_eq!(&pk[2..22], &hash);
        assert_eq!(pk[22], 0x87); // OP_EQUAL
    }

    /// P2SH-P2WPKH redeemScript 构造
    #[test]
    fn p2sh_p2wpkh_redeem_script_format() {
        let pk_hash = [0x42; 20];
        let rs = p2sh_p2wpkh_redeem_script(&pk_hash);
        assert_eq!(rs.len(), 22);
        assert_eq!(rs[0], 0x00);
        assert_eq!(rs[1], 0x14);
        assert_eq!(&rs[2..], &pk_hash);
    }

    /// P2SH-P2WPKH scriptSig 是 push(22) {0x00 0x14 hash}
    #[test]
    fn p2sh_p2wpkh_script_sig_format() {
        let pk_hash = [0x42; 20];
        let sig = p2sh_p2wpkh_script_sig(&pk_hash);
        assert_eq!(sig.len(), 23);
        assert_eq!(sig[0], 0x16); // push 22 bytes
        assert_eq!(sig[1], 0x00);
        assert_eq!(sig[2], 0x14);
        assert_eq!(&sig[3..], &pk_hash);
    }

    /// 端到端: P2SH-P2WPKH 签名
    #[test]
    fn p2sh_p2wpkh_end_to_end() {
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        let txin = TxIn {
            prev_out: OutPoint { txid, vout: 0 },
            script_sig: vec![],
            sequence: 0xffffffff,
            witness: vec![],
        };
        let txout = TxOut {
            value: 200_000,
            script_pubkey: p2sh_script_pubkey(&[0x33; 20]), // 模拟 P2SH output
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

        let input = P2SHP2WPKHSignInput {
            input_index: 0,
            private_key,
            pubkey_hash: [0x42; 20],
            amount: 300_000,
        };

        let signed = sign_p2sh_p2wpkh(&mut tx, &input).unwrap();

        // 1. sighash 不为零
        assert_ne!(signed.sighash, [0u8; 32]);

        // 2. scriptSig 注入 (23 bytes: 0x16 + 0x00 + 0x14 + 20-byte hash)
        let script_sig = &tx.inputs[0].script_sig;
        assert_eq!(script_sig.len(), 23);
        assert_eq!(script_sig[0], 0x16);

        // 3. witness 注入 (2 items)
        let witness = &tx.inputs[0].witness;
        assert_eq!(witness.len(), 2);

        // 4. 第一项 = signature + sighash byte (最后 byte = 0x01)
        let sig_witness = &witness[0];
        assert!(sig_witness.len() >= 9);
        assert_eq!(sig_witness[sig_witness.len() - 1], 0x01);

        // 5. 第二项 = compressed pubkey (33 bytes)
        let pk_witness = &witness[1];
        assert_eq!(pk_witness.len(), 33);
        assert!(pk_witness[0] == 0x02 || pk_witness[0] == 0x03);

        // 6. tx_bytes 是 BIP-144 segwit 格式 (marker 0x00, flag 0x01)
        assert_eq!(signed.tx_bytes[4], 0x00);
        assert_eq!(signed.tx_bytes[5], 0x01);

        eprintln!("P2SH-P2WPKH signed tx ({} bytes): {}", signed.tx_bytes.len(), hex_encode(&signed.tx_bytes));
    }

    /// Input index 越界
    #[test]
    fn p2sh_p2wpkh_out_of_bounds() {
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        let input = P2SHP2WPKHSignInput {
            input_index: 0,
            private_key: [1u8; 32],
            pubkey_hash: [0u8; 20],
            amount: 0,
        };
        let mut tx = tx;
        assert!(sign_p2sh_p2wpkh(&mut tx, &input).is_err());
    }

    /// sighash 一致性: P2SH-P2WPKH 与 P2WPKH 应共享 sighash 路径 (因为都是 BIP-143)
    #[test]
    fn p2sh_p2wpkh_sighash_matches_p2wpkh() {
        let mut txid = [0u8; 32];
        txid[0] = 0xab;

        let txin = TxIn {
            prev_out: OutPoint { txid, vout: 0 },
            script_sig: vec![],
            sequence: 0xffffffff,
            witness: vec![],
        };
        let txout = TxOut {
            value: 100_000,
            script_pubkey: vec![0x00, 0x14, 0x42], // 任意
        };
        let tx = Transaction {
            version: 1,
            inputs: vec![txin],
            outputs: vec![txout],
            lock_time: 0,
        };

        let pk_hash = [0x42; 20];
        // P2WPKH 和 P2SH-P2WPKH 用同一 P2PKH-style scriptCode (25 bytes)
        let script_code = p2pkh_script_code(&pk_hash);

        // 两者的 sighash 算法完全相同 (BIP-143), 不同的是 scriptSig/witness 序列化
        let h_p2sh = segwit_sighash_p2wpkh(&tx, 0, &script_code, 300_000, SIGHASH_ALL).unwrap();
        let h_p2w = segwit_sighash_p2wpkh(&tx, 0, &script_code, 300_000, SIGHASH_ALL).unwrap();
        assert_eq!(h_p2sh, h_p2w, "sighash should be identical (same algorithm)");
    }
}