//! ETH EIP-4844 Blob transaction 签名（Phase 5 v8.1 PoC4 保留）
//!
//! ⚠️ **DEPRECATED (v9.0, 2026-08-22)**:
//! - 用户决定正式项目移除 EIP-4844 (L2 rollup 内部使用, 用户签名器不会收到)
//! - 此文件保留在 `src/_experimental/` 作为协议层参考
//! - 不参与 `chain::eth` 编译路径
//!
//! 实现：EIP-4844 signing hash + sign_eip4844 业务函数
//!
//! ## KZG 边界（shlosilo 是签名器，只负责签名这一步）
//!
//! shlosilo **不实现** KZG commitment / proof 生成（不引入 c-kzg/eth-kzg 库，
//! 避免 + 1.5MB~2MB binary + 50MB trusted setup）。调用方需自行提供：
//! - `blob_versioned_hashes: Vec<[u8; 32]>` — 32-byte SHA256 truncated commitment
//!
//! ## 算法摘要
//!
//! **EIP-4844 signing hash**:
 //! ```
//! keccak256(0x03 || rlp([
//!   chain_id,
//!   nonce,
//!   max_priority_fee_per_gas,
//!   max_fee_per_gas,
//!   gas_limit,
//!   destination,
//!   amount,
//!   data,
//!   access_list,
//!   max_fee_per_blob_gas,         // NEW vs EIP-1559
//!   blob_versioned_hashes,        // NEW: [versioned_hash, ...]
//! ]))
//! ```
//!
//! **EIP-4844 signed transaction format**:
//! ```
//! 0x03 || rlp([
//!   chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
//!   destination, amount, data, access_list,
//!   max_fee_per_blob_gas, blob_versioned_hashes,
//!   y_parity, r, s,
//! ])
//! ```
//!
//! **blob_versioned_hashes RLP encoding**:
//! - 数组: `rlp([hash1, hash2, ...])` — 每个 hash 32 bytes
//! - 0 hashes: `rlp([])` = `0xc0`
//! - 1 hash: `rlp([hash])` = `0xc1 0xa0 hash[0..32]`
//!
//! **不签名 elements** (per EIP-4844):
//! - `blobs` themselves (128KB each, stored on consensus layer)
//! - `commitments` (KZG polynomial commitments)
//! - `proofs` (KZG proofs)

extern crate alloc;
use crate::chain::eth::rlp;
use crate::chain::eth::sign;
use crate::encoding::keccak256;
use crate::error::Result;
use alloc::vec::Vec;

/// 32-byte Ethereum address
pub type Address = [u8; 20];

/// Versioned hash (EIP-4844 32 bytes, version byte = 0x01 prefix)
pub type VersionedHash = [u8; 32];

// ─── access_list RLP encoding (与 EIP-2930 复用) ──────────────────

/// EIP-2930 access list item
#[derive(Clone, Debug)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<[u8; 32]>,
}

/// RLP encode single access list item
fn encode_access_list_item(item: &AccessListItem) -> Vec<u8> {
    let addr_rlp = rlp::encode_bytes(&item.address);
    let storage_keys_rlp = if item.storage_keys.is_empty() {
        rlp::encode_list(&[])
    } else {
        let keys: Vec<Vec<u8>> = item
            .storage_keys
            .iter()
            .map(|k| rlp::encode_bytes(k))
            .collect();
        rlp::encode_list(&keys)
    };
    rlp::encode_list(&[addr_rlp, storage_keys_rlp])
}

/// RLP encode access list (list of items)
pub fn encode_access_list(items: &[AccessListItem]) -> Vec<u8> {
    if items.is_empty() {
        return rlp::encode_list(&[]);
    }
    let encoded: Vec<Vec<u8>> = items.iter().map(encode_access_list_item).collect();
    rlp::encode_list(&encoded)
}

/// RLP encode list of versioned hashes (32 bytes each)
fn encode_blob_versioned_hashes(hashes: &[VersionedHash]) -> Vec<u8> {
    if hashes.is_empty() {
        return rlp::encode_list(&[]);
    }
    let encoded: Vec<Vec<u8>> = hashes.iter().map(|h| rlp::encode_bytes(h)).collect();
    rlp::encode_list(&encoded)
}

// ─── EIP-4844 数据结构 ─────────────────────────────────────────────

/// EIP-4844 Blob transaction（未签名）
#[derive(Clone, Debug)]
pub struct Eip4844Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    /// 20-byte destination address (EIP-4844 必带 to，不能为 None)
    pub destination: Address,
    pub amount: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
    /// Wei per blob gas
    pub max_fee_per_blob_gas: u128,
    /// blob_versioned_hashes (32 bytes each)
    /// 调用方需自行提供 (KZG commitment → SHA256[0..31] || 0x01)
    pub blob_versioned_hashes: Vec<VersionedHash>,
}

/// 签名输入
#[derive(Clone, Debug)]
pub struct Eip4844SignInput {
    pub tx: Eip4844Transaction,
    pub private_key: [u8; 32],
}

/// 签名输出
#[derive(Clone, Debug)]
pub struct Eip4844SignedTx {
    /// 完整签名交易 bytes (0x03 || rlp([..., y_parity, r, s]))
    pub tx_bytes: Vec<u8>,
    /// signing hash
    pub signing_hash: [u8; 32],
    /// signature r
    pub r: [u8; 32],
    /// signature s
    pub s: [u8; 32],
    /// y_parity: 0 或 1
    pub y_parity: u8,
}

// ─── EIP-4844 signing hash ────────────────────────────────────────

/// 计算 EIP-4844 signing hash
///
/// `keccak256(0x03 || rlp([chain_id, nonce, max_prio, max_fee, gas_limit, dest, amount, data, access_list, max_fee_per_blob_gas, blob_versioned_hashes]))`
pub fn signing_hash(tx: &Eip4844Transaction) -> Result<[u8; 32]> {
    let preimage = signing_preimage(tx);
    keccak256::hash(&preimage)
}

/// 计算 signing preimage bytes
pub fn signing_preimage(tx: &Eip4844Transaction) -> Vec<u8> {
    let chain_id_rlp = rlp::encode_uint(tx.chain_id as u128);
    let nonce_rlp = rlp::encode_uint(tx.nonce as u128);
    let max_prio_rlp = rlp::encode_uint(tx.max_priority_fee_per_gas);
    let max_fee_rlp = rlp::encode_uint(tx.max_fee_per_gas);
    let gas_limit_rlp = rlp::encode_uint(tx.gas_limit as u128);
    let dest_rlp = rlp::encode_bytes(&tx.destination);
    let amount_rlp = rlp::encode_uint(tx.amount);
    let data_rlp = rlp::encode_bytes(&tx.data);
    let access_list_rlp = encode_access_list(&tx.access_list);
    let max_fee_per_blob_gas_rlp = rlp::encode_uint(tx.max_fee_per_blob_gas);
    let blob_versioned_hashes_rlp = encode_blob_versioned_hashes(&tx.blob_versioned_hashes);

    let unsigned_rlp = rlp::encode_list(&[
        chain_id_rlp,
        nonce_rlp,
        max_prio_rlp,
        max_fee_rlp,
        gas_limit_rlp,
        dest_rlp,
        amount_rlp,
        data_rlp,
        access_list_rlp,
        max_fee_per_blob_gas_rlp,
        blob_versioned_hashes_rlp,
    ]);

    let mut preimage = Vec::with_capacity(1 + unsigned_rlp.len());
    preimage.push(0x03);
    preimage.extend_from_slice(&unsigned_rlp);
    preimage
}

// ─── sign_eip4844 业务函数 ─────────────────────────────────────────

/// 签名 EIP-4844 blob transaction
///
/// **Note**: KZG commitment/proof 生成由调用方负责, shlosilo 不实现 c-kzg/eth-kzg
/// (避免 + 1.5MB binary + 50MB trusted setup)。调用方需提供 blob_versioned_hashes。
pub fn sign_eip4844(input: &Eip4844SignInput) -> Result<Eip4844SignedTx> {
    let sk = sign::sk_from_pk(&input.private_key)?;

    // 1. signing hash
    let sighash = signing_hash(&input.tx)?;

    // 2. ECDSA sign + low-s + y_parity
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    let y_parity = sign::apply_low_s(&sighash, &sk, &mut r_bytes, &mut s_bytes)?;

    // 3. Build signed transaction
    let chain_id_rlp = rlp::encode_uint(input.tx.chain_id as u128);
    let nonce_rlp = rlp::encode_uint(input.tx.nonce as u128);
    let max_prio_rlp = rlp::encode_uint(input.tx.max_priority_fee_per_gas);
    let max_fee_rlp = rlp::encode_uint(input.tx.max_fee_per_gas);
    let gas_limit_rlp = rlp::encode_uint(input.tx.gas_limit as u128);
    let dest_rlp = rlp::encode_bytes(&input.tx.destination);
    let amount_rlp = rlp::encode_uint(input.tx.amount);
    let data_rlp = rlp::encode_bytes(&input.tx.data);
    let access_list_rlp = encode_access_list(&input.tx.access_list);
    let max_fee_per_blob_gas_rlp = rlp::encode_uint(input.tx.max_fee_per_blob_gas);
    let blob_versioned_hashes_rlp = encode_blob_versioned_hashes(&input.tx.blob_versioned_hashes);
    let y_parity_rlp = rlp::encode_uint(y_parity as u128);
    let r_rlp = rlp::encode_uint256(&r_bytes);
    let s_rlp = rlp::encode_uint256(&s_bytes);

    let signed_rlp = rlp::encode_list(&[
        chain_id_rlp,
        nonce_rlp,
        max_prio_rlp,
        max_fee_rlp,
        gas_limit_rlp,
        dest_rlp,
        amount_rlp,
        data_rlp,
        access_list_rlp,
        max_fee_per_blob_gas_rlp,
        blob_versioned_hashes_rlp,
        y_parity_rlp,
        r_rlp,
        s_rlp,
    ]);

    let mut tx_bytes = Vec::with_capacity(1 + signed_rlp.len());
    tx_bytes.push(0x03);
    tx_bytes.extend_from_slice(&signed_rlp);

    Ok(Eip4844SignedTx {
        tx_bytes,
        signing_hash: sighash,
        r: r_bytes,
        s: s_bytes,
        y_parity,
    })
}

// ─── KZG stub (留给上层实现) ───────────────────────────────────────

/// 生成 blob commitment (KZG) — **stub**, 上层需自行实现
///
/// shlosilo 不实现 KZG (避免 + 1.5MB binary + 50MB trusted setup).
/// 调用方需引入 c-kzg-ethereum 或 rust-kzg 实现此函数。
#[deprecated(note = "KZG not implemented in shlosilo; caller must provide")]
pub fn kzg_commitment_stub(_blob: &[u8]) -> [u8; 48] {
    unimplemented!("KZG commitment not implemented in shlosilo; caller must provide")
}

/// 生成 blob KZG proof — **stub**, 上层需自行实现
#[deprecated(note = "KZG not implemented in shlosilo; caller must provide")]
pub fn kzg_proof_stub(_blob: &[u8], _commitment: &[u8; 48]) -> [u8; 48] {
    unimplemented!("KZG proof not implemented in shlosilo; caller must provide")
}

// ─── 测试 ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut i = 0;
        while i < bytes.len() {
            let hi = hex_nibble(bytes[i]).expect("valid hex");
            let lo = hex_nibble(bytes[i + 1]).expect("valid hex");
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    /// EIP-4844 test vector
    /// private_key: 0x4646464646464646464646464646464646464646464646464646464646464646
    /// chain_id: 1, nonce: 0
    /// max_prio: 1 gwei, max_fee: 20 gwei, gas_limit: 21000
    /// destination: 0x3535353535353535353535353535353535353535
    /// amount: 0, data: empty, access_list: empty
    /// max_fee_per_blob_gas: 1
    /// 1 blob, versioned_hash = 0x01 || 31 bytes of zeros
    ///
    /// Expected signing hash: 67c17f93bd8dc979e38a701df2b37002795a7aa8870fd080205e7b3141f6d1ba
    #[test]
    fn eip4844_signing_hash_test_vector() {
        let mut blob_versioned_hashes = Vec::new();
        let mut h = [0u8; 32];
        h[0] = 0x01;
        blob_versioned_hashes.push(h);

        let tx = Eip4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: [0x35u8; 20],
            amount: 0,
            data: Vec::new(),
            access_list: Vec::new(),
            max_fee_per_blob_gas: 1,
            blob_versioned_hashes,
        };
        let hash = signing_hash(&tx).unwrap();
        let expected_hex = "67c17f93bd8dc979e38a701df2b37002795a7aa8870fd080205e7b3141f6d1ba";
        let expected_bytes = hex_decode(expected_hex);
        assert_eq!(&hash[..], &expected_bytes[..], "signing hash mismatch");
    }

    /// 完整 sign_eip4844 + 比对 signed tx
    #[test]
    fn sign_eip4844_full_pipeline() {
        let private_key_bytes =
            hex_decode("4646464646464646464646464646464646464646464646464646464646464646");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);

        let mut blob_versioned_hashes = Vec::new();
        let mut h = [0u8; 32];
        h[0] = 0x01;
        blob_versioned_hashes.push(h);

        let tx = Eip4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: [0x35u8; 20],
            amount: 0,
            data: Vec::new(),
            access_list: Vec::new(),
            max_fee_per_blob_gas: 1,
            blob_versioned_hashes,
        };

        let input = Eip4844SignInput { tx, private_key };
        let signed = sign_eip4844(&input).unwrap();

        // 验证 signing hash
        let expected_hash =
            "67c17f93bd8dc979e38a701df2b37002795a7aa8870fd080205e7b3141f6d1ba";
        let expected_hash_bytes = hex_decode(expected_hash);
        assert_eq!(&signed.signing_hash[..], &expected_hash_bytes[..]);

        // 验证 r
        let expected_r = "9c74ed2f882f74d48611408cfd3b00abe2492044200ad37afafd56e09731dbc3";
        let expected_r_bytes = hex_decode(expected_r);
        assert_eq!(&signed.r[..], &expected_r_bytes[..], "r mismatch");

        // 验证 y_parity
        assert_eq!(signed.y_parity, 0);

        // 验证完整 signed tx
        let expected_tx = "03f88e0180843b9aca008504a817c8008252089435353535353535353535353535353535353535358080c001e1a0010000000000000000000000000000000000000000000000000000000000000080a09c74ed2f882f74d48611408cfd3b00abe2492044200ad37afafd56e09731dbc3a014c5178194790a8d75f27eda8dc191d93f164511ff0e5df8307204f127d1dd75";
        let expected_tx_bytes = hex_decode(expected_tx);
        assert_eq!(
            &signed.tx_bytes[..],
            &expected_tx_bytes[..],
            "signed tx mismatch"
        );
    }

    /// 多 blob 测试
    #[test]
    fn multiple_blobs() {
        let mut blob_versioned_hashes = Vec::new();
        for i in 1..=3 {
            let mut h = [0u8; 32];
            h[0] = 0x01;
            h[31] = i; // 区分 hash
            blob_versioned_hashes.push(h);
        }

        let tx = Eip4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: [0x35u8; 20],
            amount: 0,
            data: Vec::new(),
            access_list: Vec::new(),
            max_fee_per_blob_gas: 1,
            blob_versioned_hashes,
        };
        // 验证 signing hash 不 panic
        let private_key_bytes =
            hex_decode("4646464646464646464646464646464646464646464646464646464646464646");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let input = Eip4844SignInput { tx, private_key };
        let signed = sign_eip4844(&input).unwrap();
        // y_parity 取决于 R.y parity, 0 或 1 都 normal
        assert!(signed.y_parity == 0 || signed.y_parity == 1);
    }

    /// 确定性
    #[test]
    fn deterministic_signing() {
        let private_key_bytes =
            hex_decode("4646464646464646464646464646464646464646464646464646464646464646");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);

        let mut blob_versioned_hashes = Vec::new();
        let mut h = [0u8; 32];
        h[0] = 0x01;
        blob_versioned_hashes.push(h);

        let tx = Eip4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: [0x35u8; 20],
            amount: 0,
            data: Vec::new(),
            access_list: Vec::new(),
            max_fee_per_blob_gas: 1,
            blob_versioned_hashes,
        };

        let input = Eip4844SignInput {
            tx: tx.clone(),
            private_key,
        };
        let signed1 = sign_eip4844(&input).unwrap();
        let signed2 = sign_eip4844(&input).unwrap();
        assert_eq!(signed1.tx_bytes, signed2.tx_bytes);
    }

    /// 不同 max_fee_per_blob_gas → 不同 signing hash
    #[test]
    fn different_blob_fee_different_hash() {
        let mut blob_versioned_hashes = Vec::new();
        let mut h = [0u8; 32];
        h[0] = 0x01;
        blob_versioned_hashes.push(h);

        let make_tx = |max_fee_per_blob_gas: u128| Eip4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: [0x35u8; 20],
            amount: 0,
            data: Vec::new(),
            access_list: Vec::new(),
            max_fee_per_blob_gas,
            blob_versioned_hashes: blob_versioned_hashes.clone(),
        };

        let hash1 = signing_hash(&make_tx(1)).unwrap();
        let hash2 = signing_hash(&make_tx(2)).unwrap();
        assert_ne!(hash1, hash2);
    }

    /// 空 blob_versioned_hashes (0 blob)
    #[test]
    fn zero_blob() {
        let tx = Eip4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: [0x35u8; 20],
            amount: 0,
            data: Vec::new(),
            access_list: Vec::new(),
            max_fee_per_blob_gas: 1,
            blob_versioned_hashes: Vec::new(),
        };
        // 0 blob 仍可签名 (struct 允许), 但 EIP-4844 实际协议要求 ≥ 1 blob
        // 这里只验证 signing hash 不 panic
        let _hash = signing_hash(&tx).unwrap();
    }
}