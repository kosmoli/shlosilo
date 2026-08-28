//! BTC PSBT (Partially Signed Bitcoin Transaction, BIP-174) 解析、签名、序列化
//!
//! **格式概要**:
//! ```text
//! magic: 0x70 0x73 0x62 0x74 0xff  ("psbt" + 0xff)
//! <global-map>     0x00   separator
//! <input-map>*     0x00   separator (每个 input 一对)
//! <output-map>*    0x00   separator (每个 output 一对)
//! ```
//!
//! **key-value 编码**: `<keylen><key><valuelen><value>` (compact size varint)
//! - key = `<type-byte><data>` (type-byte 0x00 = separator, 永远 value-length = 0)
//! - value = `<data>`
//!
//! **BIP-174 关键字段** (本实现覆盖 P2WPKH 1-input 1-output 最简场景):
//!
//! | Type | Field | Scope |
//! |---|---|---|
//! | 0x00 | PSBT_GLOBAL_UNSIGNED_TX | Global |
//! | 0x01 | PSBT_IN_NON_WITNESS_UTXO | Input (legacy) |
//! | 0x02 | PSBT_IN_WITNESS_UTXO | Input (segwit) |
//! | 0x03 | PSBT_IN_PARTIAL_SIG | Input (signer 贡献的签名) |
//! | 0x04 | PSBT_IN_SIGHASH_TYPE | Input (sighash flag) |
//! | 0x05 | PSBT_IN_REDEEM_SCRIPT | Input (P2SH redeemScript) |
//! | 0x06 | PSBT_IN_WITNESS_SCRIPT | Input (P2WSH witnessScript) |
//! | 0x07 | PSBT_IN_BIP32_DERIVATION | Input (HD keypath) |
//! | 0x08 | PSBT_IN_SCRIPTSIG | Input (final scriptSig) |
//! | 0x09 | PSBT_IN_SCRIPTWITNESS | Input (final witness) |
//! | 0x00 | PSBT_GLOBAL_UNSIGNED_TX | Global |
//!
//! **算法**:
//! 1. 解析 magic + global-map + 各 input/output map
//! 2. 找到要签名的 input (按 witness_utxo 或 non_witness_utxo)
//! 3. 调用 v9.3 sign 函数 (P2WPKH / P2PKH / P2SH-P2WPKH)
//! 4. 将签名注入 input map: `0x03 || {pubkey} → {DER-sig + sighash-byte}`
//! 5. 序列化最终 PSBT
//!
//! **参考**: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::chain::btc::p2pkh::sign_p2pkh;
use crate::types::SecretBytes;
use crate::chain::btc::p2sh::sign_p2sh_p2wpkh;
use crate::chain::btc::p2wpkh::{sign_p2wpkh, OutPoint, Transaction, TxIn, TxOut};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// PSBT magic bytes: "psbt" + 0xff
pub const PSBT_MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

/// Global map types (BIP-174)
pub mod global_type {
    pub const UNSIGNED_TX: u8 = 0x00;
}

pub mod input_type {
    //! BIP-174 标准输入类型编号。
    //! P6.3 审计后修正（2026-08-26）：原常量整体偏移 +1（NON_WITNESS_UTXO=0x01 等），
    //! 与 Sparrow/bitcoind 等外部实现互操作时全部错位——真实 fixture test.psbt 暴露。

    pub const NON_WITNESS_UTXO: u8 = 0x00;
    pub const WITNESS_UTXO: u8 = 0x01;
    pub const PARTIAL_SIG: u8 = 0x02;
    pub const SIGHASH_TYPE: u8 = 0x03;
    pub const REDEEM_SCRIPT: u8 = 0x04;
    pub const WITNESS_SCRIPT: u8 = 0x05;
    pub const BIP32_DERIVATION: u8 = 0x06;
    /// Final scriptSig (for legacy P2PKH + P2SH inputs)
    pub const FINAL_SCRIPT_SIG: u8 = 0x07;
    /// Final script Witness (for segwit P2WPKH/P2WSH inputs)
    pub const FINAL_SCRIPTWITNESS: u8 = 0x08;

    // === BIP-371 Taproot PSBT fields ===
    /// 0x13: Taproot key-path signature (key = [0x13], value = 64-byte Schnorr sig)
    pub const TAP_KEY_SIG: u8 = 0x13;
    /// 0x14: Taproot script-path signature (key = [0x14 || 32-byte leaf_hash], value = 64-byte Schnorr sig || 1-byte sighash)
    pub const TAP_SCRIPT_SIG: u8 = 0x14;
    /// 0x15: Taproot leaf scripts (key = [0x15 || 32-byte leaf_hash], value = [script || 1-byte leaf_version])
    pub const TAP_LEAF_SCRIPTS: u8 = 0x15;
    /// 0x16: Taproot BIP-32 derivation (key = [0x16 || 32-byte x-only pubkey], value = bip32 path + fingerprint)
    pub const TAP_BIP32_DERIVATION: u8 = 0x16;
    /// 0x17: Taproot internal key (key = [], value = 32-byte x-only internal pubkey)
    pub const TAP_INTERNAL_KEY: u8 = 0x17;
    /// 0x18: Taproot merkle root (key = [], value = 32-byte merkle root; empty = keypath-only)
    pub const TAP_MERKLE_ROOT: u8 = 0x18;
}

/// Output map types (BIP-174 + BIP-371)
pub mod output_type {
    pub const REDEEM_SCRIPT: u8 = 0x00;
    pub const WITNESS_SCRIPT: u8 = 0x01;
    pub const BIP32_DERIVATION: u8 = 0x02;

    // === BIP-371 Taproot PSBT output fields ===
    /// 0x65: Taproot internal key (key = [], value = 32-byte x-only internal pubkey)
    pub const TAP_INTERNAL_KEY: u8 = 0x65;
    /// 0x66: Taproot tree (key = [], value = taproot tree encoding)
    pub const TAP_TREE: u8 = 0x66;
}

/// Key-value pair in PSBT map
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyValue {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// PSBT 解析后的中间表示
#[derive(Clone, Debug)]
pub struct Psbt {
    /// unsigned tx (与 input/output map 的 index 一致)
    pub unsigned_tx: Transaction,
    /// input maps (length == tx.inputs.len())
    pub inputs: Vec<Vec<KeyValue>>,
    /// output maps (length == tx.outputs.len())
    pub outputs: Vec<Vec<KeyValue>>,
}

/// Encoded map (序列化后)
#[derive(Clone, Debug)]
struct EncodedMap {
    entries: Vec<KeyValue>,
}

impl EncodedMap {
    fn new() -> Self {
        Self { entries: Vec::new() }
    }

    fn add(&mut self, key: Vec<u8>, value: Vec<u8>) {
        // 移除已存在的同 key (PSBT 规范: 同 key 必须只有一个 value)
        self.entries.retain(|kv| kv.key != key);
        self.entries.push(KeyValue { key, value });
    }

    fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        self.entries.iter().find(|kv| kv.key == key).map(|kv| &kv.value)
    }

    /// 序列化为字节 (keylen || key || valuelen || value)*
    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for kv in &self.entries {
            encode_compact_size(&mut out, kv.key.len() as u64);
            out.extend_from_slice(&kv.key);
            encode_compact_size(&mut out, kv.value.len() as u64);
            out.extend_from_slice(&kv.value);
        }
        out
    }
}

/// Compact size varint 编码 (Bitcoin 协议标准)
fn encode_compact_size(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// Compact size varint 解码
fn decode_compact_size(bytes: &[u8], pos: &mut usize) -> Result<u64> {
    if *pos >= bytes.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let first = bytes[*pos];
    *pos += 1;
    match first {
        0xff => {
            if *pos + 8 > bytes.len() {
                return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            let n = u64::from_le_bytes(bytes[*pos..*pos + 8].try_into().map_err(|_| {
                ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
            })?);
            *pos += 8;
            Ok(n)
        }
        0xfe => {
            if *pos + 4 > bytes.len() {
                return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            let n = u32::from_le_bytes(bytes[*pos..*pos + 4].try_into().map_err(|_| {
                ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
            })?) as u64;
            *pos += 4;
            Ok(n)
        }
        0xfd => {
            if *pos + 2 > bytes.len() {
                return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            let n = u16::from_le_bytes(bytes[*pos..*pos + 2].try_into().map_err(|_| {
                ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
            })?) as u64;
            *pos += 2;
            Ok(n)
        }
        n if n < 0xfd => Ok(n as u64),
        _ => Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)),
    }
}

/// 序列化 unsigned tx (与 P2WPKH.legacy 一致, 不含 marker/flag)
fn serialize_unsigned_tx(tx: &Transaction) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tx.version.to_le_bytes());
    encode_compact_size(&mut out, tx.inputs.len() as u64);
    for txin in &tx.inputs {
        out.extend_from_slice(&txin.prev_out.txid);
        out.extend_from_slice(&txin.prev_out.vout.to_le_bytes());
        encode_compact_size(&mut out, txin.script_sig.len() as u64);
        out.extend_from_slice(&txin.script_sig);
        out.extend_from_slice(&txin.sequence.to_le_bytes());
    }
    encode_compact_size(&mut out, tx.outputs.len() as u64);
    for txout in &tx.outputs {
        out.extend_from_slice(&txout.value.to_le_bytes());
        encode_compact_size(&mut out, txout.script_pubkey.len() as u64);
        out.extend_from_slice(&txout.script_pubkey);
    }
    out.extend_from_slice(&tx.lock_time.to_le_bytes());
    out
}

/// 反序列化 unsigned tx (按 PSBT 格式, 不含 marker/flag/witness)
fn deserialize_unsigned_tx(bytes: &[u8]) -> Result<Transaction> {
    let mut pos = 0;

    // version (4 bytes LE)
    if pos + 4 > bytes.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let version = i32::from_le_bytes(bytes[pos..pos + 4].try_into().map_err(|_| {
        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
    })?);
    pos += 4;

    // inputs count
    let n_inputs = decode_compact_size(bytes, &mut pos)?;
    let mut inputs = Vec::with_capacity(n_inputs as usize);
    for _ in 0..n_inputs {
        // txid (32 bytes)
        if pos + 32 > bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;

        // vout (4 bytes)
        if pos + 4 > bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let vout = u32::from_le_bytes(bytes[pos..pos + 4].try_into().map_err(|_| {
            ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
        })?);
        pos += 4;

        // scriptSig len + bytes
        let script_sig_len = decode_compact_size(bytes, &mut pos)?;
        if pos + script_sig_len as usize > bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let script_sig = bytes[pos..pos + script_sig_len as usize].to_vec();
        pos += script_sig_len as usize;

        // sequence (4 bytes)
        if pos + 4 > bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let sequence = u32::from_le_bytes(bytes[pos..pos + 4].try_into().map_err(|_| {
            ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
        })?);
        pos += 4;

        inputs.push(TxIn {
            prev_out: OutPoint { txid, vout },
            script_sig,
            sequence,
            witness: Vec::new(),
        });
    }

    // outputs count
    let n_outputs = decode_compact_size(bytes, &mut pos)?;
    let mut outputs = Vec::with_capacity(n_outputs as usize);
    for _ in 0..n_outputs {
        // value (8 bytes)
        if pos + 8 > bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let value = u64::from_le_bytes(bytes[pos..pos + 8].try_into().map_err(|_| {
            ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
        })?);
        pos += 8;

        // scriptPubKey len + bytes
        let script_pubkey_len = decode_compact_size(bytes, &mut pos)?;
        if pos + script_pubkey_len as usize > bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let script_pubkey = bytes[pos..pos + script_pubkey_len as usize].to_vec();
        pos += script_pubkey_len as usize;

        outputs.push(TxOut { value, script_pubkey });
    }

    // lock_time (4 bytes)
    if pos + 4 > bytes.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let lock_time = u32::from_le_bytes(bytes[pos..pos + 4].try_into().map_err(|_| {
        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
    })?);

    Ok(Transaction {
        version,
        inputs,
        outputs,
        lock_time,
    })
}

/// 解析 encoded map (直到 separator 0x00)
fn decode_map(bytes: &[u8], pos: &mut usize) -> Result<EncodedMap> {
    let mut map = EncodedMap::new();
    loop {
        if *pos >= bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        // keylen
        let key_len = decode_compact_size(bytes, pos)?;
        if key_len == 0 {
            // separator (0x00 key)
            return Ok(map);
        }
        if *pos + key_len as usize > bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let key = bytes[*pos..*pos + key_len as usize].to_vec();
        *pos += key_len as usize;

        // valuelen
        let value_len = decode_compact_size(bytes, pos)?;
        if *pos + value_len as usize > bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let value = bytes[*pos..*pos + value_len as usize].to_vec();
        *pos += value_len as usize;

        map.entries.push(KeyValue { key, value });
    }
}

/// 编码 global map: 包含 unsigned tx
fn encode_global_map(tx: &Transaction) -> EncodedMap {
    let mut map = EncodedMap::new();
    let key = vec![global_type::UNSIGNED_TX];
    let value = serialize_unsigned_tx(tx);
    map.add(key, value);
    map
}

/// Parse PSBT bytes into Psbt struct
pub fn parse_psbt(bytes: &[u8]) -> Result<Psbt> {
    if bytes.len() < 5 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    if bytes[..5] != PSBT_MAGIC {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    let mut pos = 5;

    // global map
    let global_map = decode_map(bytes, &mut pos)?;
    let tx_bytes = global_map.get(&[global_type::UNSIGNED_TX]).ok_or({
        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
    })?;
    let unsigned_tx = deserialize_unsigned_tx(tx_bytes)?;

    let n_inputs = unsigned_tx.inputs.len();
    let n_outputs = unsigned_tx.outputs.len();

    // input maps
    let mut inputs = Vec::with_capacity(n_inputs);
    for _ in 0..n_inputs {
        inputs.push(decode_map(bytes, &mut pos)?.entries);
    }

    // output maps
    let mut outputs = Vec::with_capacity(n_outputs);
    for _ in 0..n_outputs {
        outputs.push(decode_map(bytes, &mut pos)?.entries);
    }

    Ok(Psbt {
        unsigned_tx,
        inputs,
        outputs,
    })
}

/// Serialize Psbt back to bytes
pub fn serialize_psbt(psbt: &Psbt) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&PSBT_MAGIC);

    // global map
    let global_map = encode_global_map(&psbt.unsigned_tx);
    out.extend_from_slice(&global_map.serialize());
    out.push(0x00); // separator (keylen=0)

    // input maps
    for entries in &psbt.inputs {
        let map = EncodedMap {
            entries: entries.clone(),
        };
        out.extend_from_slice(&map.serialize());
        out.push(0x00);
    }

    // output maps
    for entries in &psbt.outputs {
        let map = EncodedMap {
            entries: entries.clone(),
        };
        out.extend_from_slice(&map.serialize());
        out.push(0x00);
    }

    out
}

/// PSBT 签名输入 (per-input 信息)
///
/// P1-03：私钥走 `SecretBytes<32>`——不 Clone 不 Debug、ZeroizeOnDrop、常时比较。
pub struct PsbtSignInput {
    /// input index
    pub input_index: usize,
    /// 这个 input 的私钥 (32 bytes)
    pub private_key: SecretBytes<32>,
    /// pubkey hash (20 bytes) — P2WPKH witness program
    pub pubkey_hash: [u8; 20],
    /// 这个 input 的 value (satoshis) — 用于 BIP-143 sighash
    pub amount: u64,
}

/// 签名 PSBT P2WPKH input
///
/// 在 input map 注入:
/// - 0x03 PARTIAL_SIG: key = `<type-byte 0x03><33-byte compressed pubkey>`, value = `<DER-sig + 0x01 sighash-byte>`
pub fn sign_psbt_p2wpkh(psbt: &mut Psbt, sign_input: &PsbtSignInput) -> Result<()> {
    let input_idx = sign_input.input_index;
    if input_idx >= psbt.unsigned_tx.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // 1. 复制 unsigned tx 用于 sighash 计算 (不能改 psbt.unsigned_tx 本身)
    let mut tx = psbt.unsigned_tx.clone();

    // 2. 调用 v9.3 sign_p2wpkh 写入 witness
    let p2wpkh_input = crate::chain::btc::p2wpkh::P2WPKHSignInput {
        input_index: sign_input.input_index,
        private_key: &sign_input.private_key,
        amount: sign_input.amount,
        pubkey_hash: sign_input.pubkey_hash,
    };
    let _signed = sign_p2wpkh(&mut tx, &p2wpkh_input)?;

    // 3. 提取 witness 中的 sig (第 0 项) → 注入 PARTIAL_SIG
    let witness = &tx.inputs[input_idx].witness;
    let sig_with_sighash = &witness[0];
    let compressed_pk = &witness[1];

    // PARTIAL_SIG key = `<0x03><compressed-pubkey>`
    let mut key = Vec::with_capacity(1 + 33);
    key.push(input_type::PARTIAL_SIG);
    key.extend_from_slice(compressed_pk);

    // value = `<DER-sig + 0x01>`
    let value = sig_with_sighash.clone();

    psbt.inputs[input_idx].retain(|kv| kv.key != key);
    psbt.inputs[input_idx].push(KeyValue { key, value });

    Ok(())
}

/// PSBT 签名输入 (P2PKH 专用, 不需要 amount)
///
/// P1-03：私钥走 `SecretBytes<32>`。
pub struct PsbtP2PKHSignInput {
    pub input_index: usize,
    pub private_key: SecretBytes<32>,
    pub pubkey_hash: [u8; 20],
}

/// PSBT 签名输入 (P2SH-P2WPKH 专用, 需要 amount)
///
/// P1-03：私钥走 `SecretBytes<32>`。
pub struct PsbtP2SHP2WPKHSignInput {
    pub input_index: usize,
    pub private_key: SecretBytes<32>,
    pub pubkey_hash: [u8; 20],
    pub amount: u64,
}

/// 签名 PSBT P2PKH input
///
/// 与 P2WPKH 不同: 注入 FINAL_SCRIPT_SIG (type 0x08) 而不是 PARTIAL_SIG.
/// Finalizer 提取 FINAL_SCRIPT_SIG 到 tx.inputs[].scriptSig (final tx).
pub fn sign_psbt_p2pkh(psbt: &mut Psbt, sign_input: &PsbtP2PKHSignInput) -> Result<()> {
    let input_idx = sign_input.input_index;
    if input_idx >= psbt.unsigned_tx.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // 1. 复制 unsigned tx 用于 sighash + scriptSig 注入
    let mut tx = psbt.unsigned_tx.clone();

    // 2. 调用 v9.3 sign_p2pkh
    let p2pkh_input = crate::chain::btc::p2pkh::P2PKHSignInput {
        input_index: sign_input.input_index,
        private_key: &sign_input.private_key,
        pubkey_hash: sign_input.pubkey_hash,
    };
    let _signed = sign_p2pkh(&mut tx, &p2pkh_input)?;

    // 3. 提取 scriptSig → 注入 FINAL_SCRIPT_SIG (0x08)
    let script_sig = tx.inputs[input_idx].script_sig.clone();

    let key = vec![input_type::FINAL_SCRIPT_SIG];
    let value = script_sig;

    psbt.inputs[input_idx].retain(|kv| kv.key != key);
    psbt.inputs[input_idx].push(KeyValue { key, value });

    Ok(())
}

/// 签名 PSBT P2SH-P2WPKH input
///
/// 注入:
/// - FINAL_SCRIPT_SIG (0x08) = push 22-byte redeemScript
/// - FINAL_SCRIPTWITNESS (0x09) = serialized witness (item count + items)
///
/// 注: FINAL_SCRIPTWITNESS 是 BIP-174 特殊格式, value 是已经序列化好的 witness bytes.
/// shlosilo 复用 v9.3 sign_p2sh_p2wpkh 的 witness 输出 (vec![sig, pk]).
pub fn sign_psbt_p2sh_p2wpkh(
    psbt: &mut Psbt,
    sign_input: &PsbtP2SHP2WPKHSignInput,
) -> Result<()> {
    let input_idx = sign_input.input_index;
    if input_idx >= psbt.unsigned_tx.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // 1. 复制 unsigned tx
    let mut tx = psbt.unsigned_tx.clone();

    // 2. 调用 v9.3 sign_p2sh_p2wpkh
    let p2sh_input = crate::chain::btc::p2sh::P2SHP2WPKHSignInput {
        input_index: sign_input.input_index,
        private_key: &sign_input.private_key,
        pubkey_hash: sign_input.pubkey_hash,
        amount: sign_input.amount,
    };
    let _signed = sign_p2sh_p2wpkh(&mut tx, &p2sh_input)?;

    // 3. 提取 scriptSig → FINAL_SCRIPT_SIG
    let script_sig = tx.inputs[input_idx].script_sig.clone();
    let key_script_sig = vec![input_type::FINAL_SCRIPT_SIG];
    let value_script_sig = script_sig;

    // 4. 提取 witness → FINAL_SCRIPTWITNESS (serialize witness as bytes)
    let witness = &tx.inputs[input_idx].witness;
    let mut witness_bytes = Vec::new();
    encode_compact_size(&mut witness_bytes, witness.len() as u64);
    for item in witness {
        encode_compact_size(&mut witness_bytes, item.len() as u64);
        witness_bytes.extend_from_slice(item);
    }

    let key_witness = vec![input_type::FINAL_SCRIPTWITNESS];
    let value_witness = witness_bytes;

    // 5. 注入 PSBT input map
    psbt.inputs[input_idx].retain(|kv| kv.key != key_script_sig);
    psbt.inputs[input_idx].push(KeyValue {
        key: key_script_sig,
        value: value_script_sig,
    });
    psbt.inputs[input_idx].retain(|kv| kv.key != key_witness);
    psbt.inputs[input_idx].push(KeyValue {
        key: key_witness,
        value: value_witness,
    });

    Ok(())
}


// === v9.9 P2TR PSBT helpers (BIP-371) ===

/// P2TR sign input (keypath-only)
#[derive(Clone, Debug)]
pub struct PsbtP2TRSignInput {
    pub input_index: usize,
    pub internal_key_x: [u8; 32],
    pub tweaked_schnorr_sig: [u8; 64],
}

/// P2TR sign input (scriptpath)
#[derive(Clone, Debug)]
pub struct PsbtP2TRScriptPathSignInput {
    pub input_index: usize,
    pub internal_key_x: [u8; 32],
    pub leaf_hash: [u8; 32],
    pub schnorr_sig: [u8; 64],
    pub sighash_type: u8,
}

/// Sign PSBT P2TR input (BIP-371 keypath-only).
/// Caller provides pre-computed tweaked Schnorr signature.
/// Injects PSBT_IN_TAP_KEY_SIG (0x13) into input map.
pub fn sign_psbt_p2tr_keypath(
    psbt: &mut Psbt,
    sign_input: &PsbtP2TRSignInput,
) -> Result<()> {
    let input_idx = sign_input.input_index;
    if input_idx >= psbt.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // Verify scriptPubKey of the matching UTXO is a P2TR (OP_1 <0x20> <32-byte-x>).
    // WITNESS_UTXO value = CTxOut: amount(8 LE) || varint(spk_len) || scriptPubKey
    let (_amount, spk) = get_utxo_any(&psbt.inputs[input_idx])
        .ok_or(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    if decode_p2tr_script_pubkey(&spk).is_err() {
        // 0x51 = OP_1 (witness v1), 0x20 = push 32 bytes
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // Inject TAP_KEY_SIG (0x13) — key = [0x13], value = 64-byte sig
    let key = vec![input_type::TAP_KEY_SIG];
    let value = sign_input.tweaked_schnorr_sig.to_vec();

    // Remove any pre-existing entry
    psbt.inputs[input_idx].retain(|kv| kv.key != key);
    psbt.inputs[input_idx].push(KeyValue { key, value });
    Ok(())
}

/// Sign PSBT P2TR input (BIP-371 scriptpath).
/// Caller provides Schnorr signature for a specific leaf.
/// Injects PSBT_IN_TAP_SCRIPT_SIG (0x14) with key = [0x14 || leaf_hash (32 bytes)].
pub fn sign_psbt_p2tr_scriptpath(
    psbt: &mut Psbt,
    sign_input: &PsbtP2TRScriptPathSignInput,
) -> Result<()> {
    let input_idx = sign_input.input_index;
    if input_idx >= psbt.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // Verify scriptPubKey is P2TR. WITNESS_UTXO value = CTxOut format.
    let (_amount, spk) = get_utxo_any(&psbt.inputs[input_idx])
        .ok_or(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    if decode_p2tr_script_pubkey(&spk).is_err() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // Inject TAP_SCRIPT_SIG (0x14): key = [0x14 || leaf_hash (32)], value = sig(64) || sighash_byte(1)
    let mut key = Vec::with_capacity(33);
    key.push(input_type::TAP_SCRIPT_SIG);
    key.extend_from_slice(&sign_input.leaf_hash);

    let mut value = Vec::with_capacity(65);
    value.extend_from_slice(&sign_input.schnorr_sig);
    value.push(sign_input.sighash_type);

    psbt.inputs[input_idx].retain(|kv| kv.key != key);
    psbt.inputs[input_idx].push(KeyValue { key, value });
    Ok(())
}

/// Decode P2TR scriptPubKey: returns x-only output key (32 bytes)
pub fn decode_p2tr_script_pubkey(script_pubkey: &[u8]) -> Result<[u8; 32]> {
    if script_pubkey.len() != 34 || script_pubkey[0] != 0x51 || script_pubkey[1] != 0x20 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut x = [0u8; 32];
    x.copy_from_slice(&script_pubkey[2..]);
    Ok(x)
}

/// Parse a BIP-174 WITNESS_UTXO value: CTxOut format
/// `<amount (8B LE)> <compact_size spk_len> <scriptPubKey>`
///
/// **注意**: v9.9 曾误实现为 `amount || spk` 直接拼接（漏掉 varint 长度前缀），
/// keystone 真实 PSBT 抓出了这个 bug。
pub fn decode_witness_utxo(value: &[u8]) -> Result<(u64, Vec<u8>)> {
    if value.len() < 8 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let amount = u64::from_le_bytes(value[..8].try_into().map_err(|_| {
        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
    })?);
    let mut pos = 8;
    let spk_len = decode_compact_size(value, &mut pos)? as usize;
    if pos + spk_len > value.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    Ok((amount, value[pos..pos + spk_len].to_vec()))
}

/// Get the spent output (value, spk) from an input map's WITNESS_UTXO field
pub fn get_witness_utxo(input_map: &[KeyValue]) -> Option<(u64, Vec<u8>)> {
    let kv = input_map
        .iter()
        .find(|kv| kv.key == vec![input_type::WITNESS_UTXO])?;
    decode_witness_utxo(&kv.value).ok()
}

/// Get spent output from either WITNESS_UTXO (0x02) or NON_WITNESS_UTXO (0x01) field.
///
/// keystone 的 `test_taproot_sign` fixture 把 CTxOut 放在 0x01 字段（非标准但实际存在），
/// 标准 BIP-174 用 0x02。两个 value 均为 CTxOut 格式，decode 逻辑相同。
pub fn get_utxo_any(input_map: &[KeyValue]) -> Option<(u64, Vec<u8>)> {
    for t in [input_type::WITNESS_UTXO, input_type::NON_WITNESS_UTXO] {
        if let Some(kv) = input_map.iter().find(|kv| kv.key == vec![t]) {
            if let Ok(utxo) = decode_witness_utxo(&kv.value) {
                return Some(utxo);
            }
        }
    }
    None
}

/// Get TAP_INTERNAL_KEY from input map (BIP-371 0x17)
pub fn get_tap_internal_key(input_map: &[KeyValue]) -> Option<[u8; 32]> {
    let kv = input_map.iter().find(|kv| kv.key == vec![input_type::TAP_INTERNAL_KEY])?;
    if kv.value.len() != 32 {
        return None;
    }
    let mut x = [0u8; 32];
    x.copy_from_slice(&kv.value);
    Some(x)
}

/// Set TAP_INTERNAL_KEY in input map
pub fn set_tap_internal_key(input_map: &mut Vec<KeyValue>, internal_key_x: &[u8; 32]) -> Result<()> {
    let key = vec![input_type::TAP_INTERNAL_KEY];
    input_map.retain(|kv| kv.key != key);
    input_map.push(KeyValue {
        key,
        value: internal_key_x.to_vec(),
    });
    Ok(())
}

/// Get TAP_MERKLE_ROOT from input map (BIP-371 0x18)
pub fn get_tap_merkle_root(input_map: &[KeyValue]) -> Option<[u8; 32]> {
    let kv = input_map.iter().find(|kv| kv.key == vec![input_type::TAP_MERKLE_ROOT])?;
    if kv.value.len() != 32 {
        return None;
    }
    let mut x = [0u8; 32];
    x.copy_from_slice(&kv.value);
    Some(x)
}

/// Check if input is P2TR (has P2TR witness UTXO and TAP_INTERNAL_KEY set)
/// WITNESS_UTXO value = CTxOut: amount(8 LE) || varint(spk_len) || scriptPubKey
pub fn is_p2tr_input(input_map: &[KeyValue]) -> bool {
    if get_tap_internal_key(input_map).is_none() {
        return false;
    }
    get_witness_utxo(input_map)
        .map(|(_amount, spk)| decode_p2tr_script_pubkey(&spk).is_ok())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    extern crate std;
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

    /// magic bytes 正确
    #[test]
    fn magic_bytes() {
        assert_eq!(PSBT_MAGIC, [0x70, 0x73, 0x62, 0x74, 0xff]);
    }

    /// compact size round-trip
    #[test]
    fn compact_size_round_trip() {
        let mut out = Vec::new();
        encode_compact_size(&mut out, 10);
        assert_eq!(out, vec![10]);

        out.clear();
        encode_compact_size(&mut out, 0xfd);
        assert_eq!(out, vec![0xfd, 0xfd, 0x00]);

        out.clear();
        encode_compact_size(&mut out, 0xffff);
        assert_eq!(out, vec![0xfd, 0xff, 0xff]);

        out.clear();
        encode_compact_size(&mut out, 0x10000);
        assert_eq!(&out[..5], &[0xfe, 0x00, 0x00, 0x01, 0x00]);
    }

    /// 完整 PSBT 构造 (P2WPKH 1-input 1-output) round-trip
    #[test]
    fn psbt_construction_round_trip() {
        // 简化 P2WPKH 测试:
        // - 1 input, txid = 0xab...cd, vout = 0
        // - 1 output, value = 100_000, scriptPubKey = P2WPKH program
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        txid[31] = 0xcd;

        let txin = TxIn {
            prev_out: OutPoint { txid, vout: 0 },
            script_sig: vec![],
            sequence: 0xffffffff,
            witness: vec![],
        };

        // P2WPKH scriptPubKey = `0x00 0x14 {20-byte pubkey-hash}`
        let mut pk_hash = [0u8; 20];
        pk_hash[0] = 0x42;
        let mut script_pubkey = Vec::with_capacity(22);
        script_pubkey.push(0x00);
        script_pubkey.push(0x14);
        script_pubkey.extend_from_slice(&pk_hash);

        let txout = TxOut {
            value: 100_000,
            script_pubkey,
        };

        let unsigned_tx = Transaction {
            version: 2,
            inputs: vec![txin],
            outputs: vec![txout],
            lock_time: 0,
        };

        let mut psbt = Psbt {
            unsigned_tx: unsigned_tx.clone(),
            inputs: vec![Vec::new()],
            outputs: vec![Vec::new()],
        };

        let bytes = serialize_psbt(&psbt);

        // 验证 magic
        assert_eq!(&bytes[..5], &PSBT_MAGIC);

        // 解析回去
        let parsed = parse_psbt(&bytes).unwrap();
        assert_eq!(parsed.unsigned_tx.version, unsigned_tx.version);
        assert_eq!(parsed.unsigned_tx.inputs.len(), 1);
        assert_eq!(parsed.unsigned_tx.outputs.len(), 1);
        assert_eq!(parsed.unsigned_tx.inputs[0].prev_out.txid, txid);
        assert_eq!(parsed.unsigned_tx.outputs[0].value, 100_000);
    }

    /// 解析错误 magic
    #[test]
    fn psbt_invalid_magic() {
        let bytes = vec![0x00, 0x01, 0x02, 0x03, 0x04];
        assert!(parse_psbt(&bytes).is_err());
    }

    /// parse + serialize 完整流程 (含 input/output map entries)
    #[test]
    fn psbt_full_round_trip() {
        let mut txid = [0u8; 32];
        txid[0] = 0x11;
        let txin = TxIn {
            prev_out: OutPoint { txid, vout: 1 },
            script_sig: vec![],
            sequence: 0xffffffee,
            witness: vec![],
        };
        let mut pk_hash = [0u8; 20];
        pk_hash[0] = 0xab;
        let mut script_pubkey = Vec::with_capacity(22);
        script_pubkey.push(0x00);
        script_pubkey.push(0x14);
        script_pubkey.extend_from_slice(&pk_hash);

        let txout = TxOut {
            value: 50_000,
            script_pubkey,
        };

        let unsigned_tx = Transaction {
            version: 2,
            inputs: vec![txin],
            outputs: vec![txout],
            lock_time: 12345,
        };

        // 添加 witness_utxo 到 input map
        let witness_utxo = TxOut {
            value: 200_000,
            script_pubkey: {
                let mut s = Vec::with_capacity(22);
                s.push(0x00);
                s.push(0x14);
                s.extend_from_slice(&pk_hash);
                s
            },
        };
        let mut witness_utxo_bytes = Vec::new();
        witness_utxo_bytes.extend_from_slice(&witness_utxo.value.to_le_bytes());
        encode_compact_size(
            &mut witness_utxo_bytes,
            witness_utxo.script_pubkey.len() as u64,
        );
        witness_utxo_bytes.extend_from_slice(&witness_utxo.script_pubkey);

        let mut psbt = Psbt {
            unsigned_tx: unsigned_tx.clone(),
            inputs: vec![vec![KeyValue {
                key: vec![input_type::WITNESS_UTXO],
                value: witness_utxo_bytes,
            }]],
            outputs: vec![Vec::new()],
        };

        let bytes = serialize_psbt(&psbt);
        let parsed = parse_psbt(&bytes).unwrap();

        // 验证 input map 保留
        assert_eq!(parsed.inputs.len(), 1);
        assert!(parsed.inputs[0]
            .iter()
            .any(|kv| kv.key == vec![input_type::WITNESS_UTXO]));
    }

    /// 签名 P2WPKH PSBT input
    #[test]
    fn psbt_sign_p2wpkh() {
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        let txin = TxIn {
            prev_out: OutPoint { txid, vout: 0 },
            script_sig: vec![],
            sequence: 0xffffffff,
            witness: vec![],
        };
        let mut pk_hash = [0u8; 20];
        pk_hash[0] = 0x42;
        let mut script_pubkey = Vec::with_capacity(22);
        script_pubkey.push(0x00);
        script_pubkey.push(0x14);
        script_pubkey.extend_from_slice(&pk_hash);
        let txout = TxOut {
            value: 100_000,
            script_pubkey,
        };

        let mut psbt = Psbt {
            unsigned_tx: Transaction {
                version: 2,
                inputs: vec![txin],
                outputs: vec![txout],
                lock_time: 0,
            },
            inputs: vec![Vec::new()],
            outputs: vec![Vec::new()],
        };

        let private_key_bytes =
            hex_decode("0101010101010101010101010101010101010101010101010101010101010101");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let sign_input = PsbtSignInput {
            input_index: 0,
            private_key,
            pubkey_hash: pk_hash,
            amount: 200_000,
        };

        sign_psbt_p2wpkh(&mut psbt, &sign_input).unwrap();

        // 验证 input map 注入 PARTIAL_SIG
        assert_eq!(psbt.inputs.len(), 1);
        let partial_sig = psbt.inputs[0]
            .iter()
            .find(|kv| kv.key.starts_with(&[input_type::PARTIAL_SIG]));
        assert!(partial_sig.is_some(), "PARTIAL_SIG must be injected");
        let partial_sig = partial_sig.unwrap();
        // key = 0x03 || compressed_pubkey
        assert_eq!(partial_sig.key[0], input_type::PARTIAL_SIG);
        assert_eq!(partial_sig.key.len(), 1 + 33);
        // value 末尾必须是 sighash byte 0x01
        assert_eq!(partial_sig.value[partial_sig.value.len() - 1], 0x01);

        eprintln!(
            "PARTIAL_SIG key: {} value: {}",
            hex_encode(&partial_sig.key),
            hex_encode(&partial_sig.value)
        );
    }

    /// 越界 input index
    #[test]
    fn psbt_sign_out_of_bounds() {
        let psbt = Psbt {
            unsigned_tx: Transaction {
                version: 1,
                inputs: vec![],
                outputs: vec![],
                lock_time: 0,
            },
            inputs: vec![],
            outputs: vec![],
        };
        let mut psbt = psbt;
        let sign_input = PsbtSignInput {
            input_index: 0,
            private_key: SecretBytes::new([0; 32]),
            pubkey_hash: [0; 20],
            amount: 0,
        };
        assert!(sign_psbt_p2wpkh(&mut psbt, &sign_input).is_err());
    }

    /// 签名 PSBT P2PKH input → FINAL_SCRIPT_SIG
    #[test]
    fn psbt_sign_p2pkh() {
        // 简化 P2PKH 测试
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        let txin = TxIn {
            prev_out: OutPoint { txid, vout: 0 },
            script_sig: vec![],
            sequence: 0xffffffff,
            witness: vec![],
        };
        // P2PKH scriptPubKey = `0x76a914{20-byte pubkey-hash}88ac`
        let mut pk_hash = [0u8; 20];
        pk_hash[0] = 0x42;
        let mut script_pubkey = Vec::with_capacity(25);
        script_pubkey.push(0x76);
        script_pubkey.push(0xa9);
        script_pubkey.push(0x14);
        script_pubkey.extend_from_slice(&pk_hash);
        script_pubkey.push(0x88);
        script_pubkey.push(0xac);

        let txout = TxOut {
            value: 100_000,
            script_pubkey,
        };

        let mut psbt = Psbt {
            unsigned_tx: Transaction {
                version: 1,
                inputs: vec![txin],
                outputs: vec![txout],
                lock_time: 0,
            },
            inputs: vec![Vec::new()],
            outputs: vec![Vec::new()],
        };

        let private_key_bytes =
            hex_decode("0101010101010101010101010101010101010101010101010101010101010101");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let sign_input = PsbtP2PKHSignInput {
            input_index: 0,
            private_key,
            pubkey_hash: pk_hash,
        };

        sign_psbt_p2pkh(&mut psbt, &sign_input).unwrap();

        // 验证 FINAL_SCRIPT_SIG 注入
        let final_scriptsig = psbt.inputs[0]
            .iter()
            .find(|kv| kv.key == vec![input_type::FINAL_SCRIPT_SIG]);
        assert!(final_scriptsig.is_some(), "FINAL_SCRIPT_SIG must be injected");
        let final_scriptsig = final_scriptsig.unwrap();
        // value 是 scriptSig: <push sig><push pk>
        assert!(final_scriptsig.value.len() > 33); // sig + compressed pk
        // scriptSig 末尾应是 compressed pubkey (33 bytes)
        let pk_bytes = &final_scriptsig.value[final_scriptsig.value.len() - 33..];
        assert!(pk_bytes[0] == 0x02 || pk_bytes[0] == 0x03);

        eprintln!(
            "FINAL_SCRIPT_SIG ({} bytes): {}",
            final_scriptsig.value.len(),
            hex_encode(&final_scriptsig.value)
        );
    }

    /// P2PKH PSBT 越界
    #[test]
    fn psbt_sign_p2pkh_out_of_bounds() {
        let psbt = Psbt {
            unsigned_tx: Transaction {
                version: 1,
                inputs: vec![],
                outputs: vec![],
                lock_time: 0,
            },
            inputs: vec![],
            outputs: vec![],
        };
        let mut psbt = psbt;
        let sign_input = PsbtP2PKHSignInput {
            input_index: 0,
            private_key: SecretBytes::new([0; 32]),
            pubkey_hash: [0; 20],
        };
        assert!(sign_psbt_p2pkh(&mut psbt, &sign_input).is_err());
    }

    /// 签名 PSBT P2SH-P2WPKH input → FINAL_SCRIPT_SIG + FINAL_SCRIPTWITNESS
    #[test]
    fn psbt_sign_p2sh_p2wpkh() {
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        let txin = TxIn {
            prev_out: OutPoint { txid, vout: 0 },
            script_sig: vec![],
            sequence: 0xffffffff,
            witness: vec![],
        };
        // P2SH scriptPubKey = `0xa914{20-byte-hash}87`
        let mut redeem_hash = [0u8; 20];
        redeem_hash[0] = 0x33;
        let mut script_pubkey = Vec::with_capacity(23);
        script_pubkey.push(0xa9);
        script_pubkey.push(0x14);
        script_pubkey.extend_from_slice(&redeem_hash);
        script_pubkey.push(0x87);

        let txout = TxOut {
            value: 200_000,
            script_pubkey,
        };

        let mut psbt = Psbt {
            unsigned_tx: Transaction {
                version: 2,
                inputs: vec![txin],
                outputs: vec![txout],
                lock_time: 0,
            },
            inputs: vec![Vec::new()],
            outputs: vec![Vec::new()],
        };

        let private_key_bytes =
            hex_decode("0101010101010101010101010101010101010101010101010101010101010101");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let pk_hash = [0x42; 20]; // 与 sign_p2sh_p2wpkh 一致

        let sign_input = PsbtP2SHP2WPKHSignInput {
            input_index: 0,
            private_key,
            pubkey_hash: pk_hash,
            amount: 300_000,
        };

        sign_psbt_p2sh_p2wpkh(&mut psbt, &sign_input).unwrap();

        // 验证 FINAL_SCRIPT_SIG 注入
        let final_scriptsig = psbt.inputs[0]
            .iter()
            .find(|kv| kv.key == vec![input_type::FINAL_SCRIPT_SIG]);
        assert!(final_scriptsig.is_some(), "FINAL_SCRIPT_SIG must be injected");
        let final_scriptsig = final_scriptsig.unwrap();
        // scriptSig = push 22 (0x16) + 0x00 + 0x14 + pubkey_hash
        assert_eq!(final_scriptsig.value.len(), 23);
        assert_eq!(final_scriptsig.value[0], 0x16);

        // 验证 FINAL_SCRIPTWITNESS 注入
        let final_witness = psbt.inputs[0]
            .iter()
            .find(|kv| kv.key == vec![input_type::FINAL_SCRIPTWITNESS]);
        assert!(final_witness.is_some(), "FINAL_SCRIPTWITNESS must be injected");
        let final_witness = final_witness.unwrap();
        // witness 序列化: <item_count><item_len><item_data>*
        // 2 items: signature + pubkey
        assert_eq!(final_witness.value[0], 2); // 2 witness items
        // 接下来是 varint(sig_len) + sig
        eprintln!(
            "FINAL_SCRIPTWITNESS ({} bytes): {}",
            final_witness.value.len(),
            hex_encode(&final_witness.value)
        );
    }

    /// P2SH-P2WPKH PSBT 越界
    #[test]
    fn psbt_sign_p2sh_p2wpkh_out_of_bounds() {
        let psbt = Psbt {
            unsigned_tx: Transaction {
                version: 1,
                inputs: vec![],
                outputs: vec![],
                lock_time: 0,
            },
            inputs: vec![],
            outputs: vec![],
        };
        let mut psbt = psbt;
        let sign_input = PsbtP2SHP2WPKHSignInput {
            input_index: 0,
            private_key: SecretBytes::new([0; 32]),
            pubkey_hash: [0; 20],
            amount: 0,
        };
        assert!(sign_psbt_p2sh_p2wpkh(&mut psbt, &sign_input).is_err());
    }

    // === v9.9 P2TR PSBT tests ===

    /// Helper: build a P2TR PSBT input (with witness UTXO containing P2TR scriptPubKey)
    fn make_p2tr_input(output_key_x: &[u8; 32]) -> Vec<KeyValue> {
        let mut input = Vec::new();
        // 1. WITNESS_UTXO: value = CTxOut = amount(8) || varint(spk_len=34=0x22) || spk
        // P2TR scriptPubKey = OP_1 PUSH 32 <x-only-pubkey>
        let mut utxo = Vec::new();
        utxo.extend_from_slice(&100_000u64.to_le_bytes()); // amount
        utxo.push(0x22); // varint: spk len = 34
        utxo.push(0x51); // OP_1
        utxo.push(0x20); // push 32
        utxo.extend_from_slice(output_key_x);
        input.push(KeyValue {
            key: vec![input_type::WITNESS_UTXO],
            value: utxo,
        });
        // 2. TAP_INTERNAL_KEY
        set_tap_internal_key(&mut input, output_key_x).unwrap();
        input
    }

    /// P2TR keypath-only: inject TAP_KEY_SIG (0x13)
    #[test]
    fn psbt_p2tr_keypath_sign() {
        let output_key_x = [0x99u8; 32];
        let input = make_p2tr_input(&output_key_x);

        let mut psbt = Psbt {
            unsigned_tx: Transaction {
                version: 2,
                inputs: vec![crate::chain::btc::p2wpkh::TxIn {
                    prev_out: crate::chain::btc::p2wpkh::OutPoint {
                        txid: [1u8; 32],
                        vout: 0,
                    },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                    witness: vec![],
                }],
                outputs: vec![],
                lock_time: 0,
            },
            inputs: vec![input],
            outputs: vec![vec![]],
        };

        let schnorr_sig = [0xabu8; 64];
        let sign_input = PsbtP2TRSignInput {
            input_index: 0,
            internal_key_x: output_key_x,
            tweaked_schnorr_sig: schnorr_sig,
        };

        sign_psbt_p2tr_keypath(&mut psbt, &sign_input).unwrap();

        // Verify TAP_KEY_SIG injected
        let injected = psbt.inputs[0]
            .iter()
            .find(|kv| kv.key == vec![input_type::TAP_KEY_SIG])
            .expect("TAP_KEY_SIG not injected");
        assert_eq!(injected.value, schnorr_sig.to_vec());
        assert_eq!(injected.key, vec![0x13u8]);
    }

    /// P2TR scriptpath: inject TAP_SCRIPT_SIG (0x14) with leaf_hash
    #[test]
    fn psbt_p2tr_scriptpath_sign() {
        let output_key_x = [0x88u8; 32];
        let leaf_hash = [0x77u8; 32];
        let input = make_p2tr_input(&output_key_x);

        let mut psbt = Psbt {
            unsigned_tx: Transaction {
                version: 2,
                inputs: vec![crate::chain::btc::p2wpkh::TxIn {
                    prev_out: crate::chain::btc::p2wpkh::OutPoint {
                        txid: [2u8; 32],
                        vout: 0,
                    },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                    witness: vec![],
                }],
                outputs: vec![],
                lock_time: 0,
            },
            inputs: vec![input],
            outputs: vec![vec![]],
        };

        let schnorr_sig = [0xccu8; 64];
        let sign_input = PsbtP2TRScriptPathSignInput {
            input_index: 0,
            internal_key_x: output_key_x,
            leaf_hash,
            schnorr_sig,
            sighash_type: 0x00, // SIGHASH_DEFAULT
        };

        sign_psbt_p2tr_scriptpath(&mut psbt, &sign_input).unwrap();

        // Verify TAP_SCRIPT_SIG injected with key = [0x14 || leaf_hash (32)]
        let expected_key_len = 1 + 32;
        let injected = psbt.inputs[0]
            .iter()
            .find(|kv| kv.key.len() == expected_key_len && kv.key[0] == input_type::TAP_SCRIPT_SIG)
            .expect("TAP_SCRIPT_SIG not injected");
        assert_eq!(injected.key[1..], leaf_hash);
        assert_eq!(injected.value.len(), 65); // sig(64) + sighash(1)
        assert_eq!(&injected.value[0..64], &schnorr_sig);
        assert_eq!(injected.value[64], 0x00); // sighash byte
    }

    /// P2TR keypath sign should reject non-P2TR input
    #[test]
    fn psbt_p2tr_keypath_rejects_non_p2tr() {
        // Build P2WPKH input (not P2TR)
        let mut input = Vec::new();
        let mut utxo = Vec::new();
        utxo.extend_from_slice(&100_000u64.to_le_bytes());
        utxo.push(0x00); // OP_0
        utxo.push(0x14); // push 20
        utxo.extend_from_slice(&[0x99u8; 20]);
        input.push(KeyValue {
            key: vec![input_type::WITNESS_UTXO],
            value: utxo,
        });

        let mut psbt = Psbt {
            unsigned_tx: Transaction {
                version: 2,
                inputs: vec![crate::chain::btc::p2wpkh::TxIn {
                    prev_out: crate::chain::btc::p2wpkh::OutPoint {
                        txid: [3u8; 32],
                        vout: 0,
                    },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                    witness: vec![],
                }],
                outputs: vec![],
                lock_time: 0,
            },
            inputs: vec![input],
            outputs: vec![vec![]],
        };

        let sign_input = PsbtP2TRSignInput {
            input_index: 0,
            internal_key_x: [0x42u8; 32],
            tweaked_schnorr_sig: [0u8; 64],
        };

        let result = sign_psbt_p2tr_keypath(&mut psbt, &sign_input);
        assert!(result.is_err(), "should reject non-P2TR input");
    }

    /// decode_p2tr_script_pubkey round-trip
    #[test]
    fn decode_p2tr_script_pubkey_test() {
        let output_key_x = [0x77u8; 32];
        let mut script_pubkey = Vec::new();
        script_pubkey.push(0x51);
        script_pubkey.push(0x20);
        script_pubkey.extend_from_slice(&output_key_x);

        let decoded = decode_p2tr_script_pubkey(&script_pubkey).unwrap();
        assert_eq!(decoded, output_key_x);

        // Invalid: too short
        assert!(decode_p2tr_script_pubkey(&[0x51, 0x20]).is_err());
        // Invalid: wrong opcode
        assert!(decode_p2tr_script_pubkey(&[0x50, 0x20]).is_err());
    }

    /// is_p2tr_input detection
    #[test]
    fn is_p2tr_input_test() {
        let output_key_x = [0x55u8; 32];
        let p2tr_input = make_p2tr_input(&output_key_x);
        assert!(is_p2tr_input(&p2tr_input));

        // Without TAP_INTERNAL_KEY → not P2TR
        let without_tap_key = vec![p2tr_input[0].clone()];
        assert!(!is_p2tr_input(&without_tap_key));
    }

    /// TAP_INTERNAL_KEY set/get round-trip
    #[test]
    fn tap_internal_key_round_trip() {
        let mut input = Vec::new();
        let internal_key = [0xabu8; 32];
        set_tap_internal_key(&mut input, &internal_key).unwrap();
        let retrieved = get_tap_internal_key(&input).unwrap();
        assert_eq!(retrieved, internal_key);
    }

    /// PSBT_IN_TAP_MERKLE_ROOT encoding
    #[test]
    fn psbt_tap_merkle_root_field() {
        let mut input = vec![KeyValue {
            key: vec![input_type::TAP_MERKLE_ROOT],
            value: [0xaau8; 32].to_vec(),
        }];
        // No merkle root → keypath-only
        assert!(get_tap_merkle_root(&input).is_some());
        assert_eq!(get_tap_merkle_root(&input).unwrap(), [0xaau8; 32]);

        // Empty input → no merkle root
        input.clear();
        assert!(get_tap_merkle_root(&input).is_none());
    }

    /// v9.13d 端到端: keystone PSBT → parse → shlosilo sighash+签名 → 注入 TAP_KEY_SIG → serialize
    ///
    /// 完整闭环:
    /// 1. 解析 keystone test_taproot_sign 的真实 PSBT
    /// 2. 从 unsigned_tx + WITNESS_UTXO 构造 BIP-341 sighash 输入 → sighash 必须等于 oracle 值
    /// 3. sign_p2tr_keypath(internal_sk) → Schnorr 签名
    /// 4. sign_psbt_p2tr_keypath 注入 PSBT_IN_TAP_KEY_SIG (0x13)
    /// 5. 序列化回 PSBT → 再解析 → 验证字段存在且签名可验证
    #[test]
    fn psbt_taproot_end_to_end_keystone_fixture() {
        use crate::chain::btc::taproot::{
            bip341_keypath_sighash, sign_p2tr_keypath, P2TRKeypathSignInput,
            SpentOutput, TaprootSighashInput, SIGHASH_DEFAULT,
        };

        // keystone wrapped_psbt.rs test_taproot_sign fixture (完整 PSBT hex)
        let psbt_hex = "70736274ff01005e02000000013aee4d6b51da574900e56d173041115bd1e1d01d4697a845784cf716a10c98060000000000ffffffff0100190000000000002251202258f2d4637b2ca3fd27614868b33dee1a242b42582d5474f51730005fa99ce8000000000001012bbc1900000000000022512022f3956cc27a6a9b0e0003a0afc113b04f31b95d5cad222a65476e8440371bd10103040000000001134092864dc9e56b6260ecbd54ec16b94bb597a2e6be7cca0de89d75e17921e0e1528cba32dd04217175c237e1835b5db1c8b384401718514f9443dce933c6ba9c872116b68df382cad577d8304d5a8e640c3cb42d77c10016ab754caa4d6e68b6cb296d190073c5da0a5600008001000080000000800000000002000000011720b68df382cad577d8304d5a8e640c3cb42d77c10016ab754caa4d6e68b6cb296d011820c913dc9a8009a074e7bbc493b9d8b7e741ba137f725f99d44fbce99300b2bb0a0000";
        let psbt_bytes = hex_decode(psbt_hex);
        let mut psbt = parse_psbt(&psbt_bytes).expect("parse keystone PSBT");
        assert_eq!(psbt.unsigned_tx.inputs.len(), 1);
        assert_eq!(psbt.unsigned_tx.inputs[0].sequence, 0xffffffff);

        // 1. 从 input map 提取 Taproot 元数据
        let internal_key_x = get_tap_internal_key(&psbt.inputs[0]).unwrap();
        let merkle_root = get_tap_merkle_root(&psbt.inputs[0]);
        assert_eq!(
            &hex_encode(&internal_key_x),
            "b68df382cad577d8304d5a8e640c3cb42d77c10016ab754caa4d6e68b6cb296d"
        );
        assert_eq!(
            merkle_root.map(|r| hex_encode(&r)).as_deref(),
            Some("c913dc9a8009a074e7bbc493b9d8b7e741ba137f725f99d44fbce99300b2bb0a")
        );
        // input_type 常量修正（BIP-174 对齐）后：fixture 的 UTXO 在 0x01 = WITNESS_UTXO（标准），
        // is_p2tr_input 能正确识别该 P2TR 输入
        assert!(is_p2tr_input(&psbt.inputs[0]), "standard WITNESS_UTXO(0x01) with P2TR spk must be detected as taproot input");

        // 2. spent output (value + spk): fixture 把 TxOut 放在 0x01 字段（CTxOut 格式），
        //    标准 WITNESS_UTXO(0x02) 同样是 CTxOut 格式，decode_witness_utxo 通用
        let utxo_kv = psbt.inputs[0]
            .iter()
            .find(|kv| kv.key[0] == input_type::NON_WITNESS_UTXO || kv.key[0] == input_type::WITNESS_UTXO)
            .unwrap();
        let (value, spent_spk) = decode_witness_utxo(&utxo_kv.value).unwrap();
        assert_eq!(value, 0x19bc);
        assert_eq!(&spent_spk[..2], &[0x51, 0x20]);

        // 3. 构造 sighash 输入并计算 — 必须等于 oracle 值
        let prevouts = [(
            psbt.unsigned_tx.inputs[0].prev_out.txid,
            psbt.unsigned_tx.inputs[0].prev_out.vout,
        )];
        let sequences = [psbt.unsigned_tx.inputs[0].sequence];
        let spent_outputs = [SpentOutput {
            value,
            script_pubkey: spent_spk.clone(),
        }];
        let tx_outputs: alloc::vec::Vec<SpentOutput> = psbt
            .unsigned_tx
            .outputs
            .iter()
            .map(|o| SpentOutput {
                value: o.value,
                script_pubkey: o.script_pubkey.clone(),
            })
            .collect();
        let sighash_input = TaprootSighashInput {
            tx_version: psbt.unsigned_tx.version as u32,
            locktime: psbt.unsigned_tx.lock_time,
            prevouts: &prevouts,
            sequences: &sequences,
            spent_outputs: &spent_outputs,
            tx_outputs: &tx_outputs,
            input_index: 0,
            hash_type: SIGHASH_DEFAULT,
            annex_present: false,
            tapleaf_hash: None,
        };
        let sighash = bip341_keypath_sighash(&sighash_input).unwrap();
        assert_eq!(
            &hex_encode(&sighash),
            "90ecc5ee16cde022e26535908bbfdada42bd19b2f7dd1d6db8699946523d4ec3",
            "sighash from parsed PSBT must equal oracle"
        );

        // 4. 签名（internal sk 来自 m/86'/1'/0'/0/2，与 fixture 同 seed）
        let internal_sk =
            hex_decode_32arr("1fb777f1a6fb9b76724551f8bc8ad91b77f33b8c456d65d746035391d724922a");
        let aux_rand = [0u8; 32];
        let witness_sig = sign_p2tr_keypath(
            &P2TRKeypathSignInput {
                internal_sk,
                merkle_root,
            },
            &sighash,
            &aux_rand,
            SIGHASH_DEFAULT,
        )
        .unwrap();
        let mut sig64 = [0u8; 64];
        sig64.copy_from_slice(&witness_sig);

        // 5. 注入 PSBT_IN_TAP_KEY_SIG 并序列化
        sign_psbt_p2tr_keypath(
            &mut psbt,
            &PsbtP2TRSignInput {
                input_index: 0,
                internal_key_x,
                tweaked_schnorr_sig: sig64,
            },
        )
        .unwrap();
        let serialized = serialize_psbt(&psbt);
        assert_eq!(&serialized[..5], &PSBT_MAGIC);

        // 6. 再解析 → 字段存在、签名可验证
        let reparsed = parse_psbt(&serialized).unwrap();
        let injected = reparsed.inputs[0]
            .iter()
            .find(|kv| kv.key == vec![input_type::TAP_KEY_SIG])
            .expect("TAP_KEY_SIG must be present after injection");
        assert_eq!(injected.value.len(), 64);

        // 签名对 output key + sighash 可验证（k256 schnorr）
        let output_key_x = decode_p2tr_script_pubkey(&spent_spk).unwrap();
        let vk = k256::schnorr::VerifyingKey::from_bytes((&output_key_x).into()).unwrap();
        let k_sig = k256::schnorr::Signature::try_from(injected.value.as_slice()).unwrap();
        use k256::schnorr::signature::hazmat::PrehashVerifier;
        assert!(
            vk.verify_prehash(&sighash, &k_sig).is_ok(),
            "injected PSBT signature must verify against output key + sighash"
        );
    }

    fn hex_decode_32arr(s: &str) -> [u8; 32] {
        let v = hex_decode(s.strip_prefix("0x").unwrap_or(s));
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

}