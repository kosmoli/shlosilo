//! ETH EIP-2930 Access List transaction 签名（Phase 5 v8 PoC4 保留）
//!
//! ⚠️ **DEPRECATED (v9.0, 2026-08-22)**:
//! - 用户决定正式项目移除 EIP-2930 (过渡 type, 钱包实际使用率 < 1%)
//! - 此文件保留在 `src/_experimental/` 作为协议层参考
//! - 不参与 `chain::eth` 编译路径
//!
//! 实现：
//! - EIP-2930 transaction 数据结构（含 access_list）
//! - EIP-2930 signing hash（`keccak256(0x01 || rlp([chain_id, nonce, gas_price, gas_limit, destination, amount, data, access_list]))`）
//! - sign_eip2930 业务函数（sighash → ECDSA → r/s + y_parity → 拼装 signed tx）
//!
//! ## 算法摘要
//!
//! **EIP-2930 signing hash**（type 0x01 prefix）：
//! ```
//! keccak256(0x01 || rlp([
//!   chain_id,
//!   nonce,
//!   gas_price,
//!   gas_limit,
//!   destination,
//!   amount,
//!   data,
//!   access_list,           // EIP-2930 新增字段
//! ]))
//! ```
//!
//! **EIP-2930 signed transaction format**：
//! ```
//! 0x01 || rlp([
//!   chain_id, nonce, gas_price, gas_limit, destination, amount, data, access_list,
//!   y_parity, r, s,
//! ])
//! ```
//!
//! **y_parity**: 0 或 1（不是 EIP-155 的 v = 27/28，也不是 EIP-155 的 v = chain_id*2+35+recid）

extern crate alloc;
use crate::chain::eth::rlp;
use crate::chain::eth::sign;
use crate::encoding::keccak256;
use crate::error::Result;
use alloc::vec::Vec;

/// 20-byte Ethereum address
pub type Address = [u8; 20];

/// EIP-2930 Access List 单项: (address, storage_keys[])
#[derive(Clone, Debug)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<[u8; 32]>,
}

/// EIP-2930 Access List transaction（未签名）
#[derive(Clone, Debug)]
pub struct Eip2930Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    /// 20-byte destination address, or None for contract creation
    pub destination: Option<[u8; 20]>,
    pub amount: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
}

/// 签名输入
#[derive(Clone, Debug)]
pub struct Eip2930SignInput {
    pub tx: Eip2930Transaction,
    pub private_key: [u8; 32],
}

/// 签名输出
#[derive(Clone, Debug)]
pub struct Eip2930SignedTx {
    /// 完整签名交易 bytes (0x01 || rlp([..., y_parity, r, s]))
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

// ─── access_list RLP encoding ──────────────────────────────────────

/// RLP encode single access list item:
/// `rlp([address(20 bytes), rlp([storage_keys...])])`
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

// ─── EIP-2930 signing hash ────────────────────────────────────────

/// 计算 EIP-2930 signing hash
///
/// `keccak256(0x01 || rlp([chain_id, nonce, gas_price, gas_limit, destination, amount, data, access_list]))`
pub fn signing_hash(tx: &Eip2930Transaction) -> Result<[u8; 32]> {
    let preimage = signing_preimage(tx);
    keccak256::hash(&preimage)
}

/// 计算 signing preimage bytes
pub fn signing_preimage(tx: &Eip2930Transaction) -> Vec<u8> {
    let chain_id_rlp = rlp::encode_uint(tx.chain_id as u128);
    let nonce_rlp = rlp::encode_uint(tx.nonce as u128);
    let gas_price_rlp = rlp::encode_uint(tx.gas_price);
    let gas_limit_rlp = rlp::encode_uint(tx.gas_limit as u128);
    let dest_rlp = match &tx.destination {
        Some(addr) => rlp::encode_bytes(addr),
        None => rlp::encode_bytes(b""),
    };
    let amount_rlp = rlp::encode_uint(tx.amount);
    let data_rlp = rlp::encode_bytes(&tx.data);
    let access_list_rlp = encode_access_list(&tx.access_list);

    let unsigned_rlp = rlp::encode_list(&[
        chain_id_rlp,
        nonce_rlp,
        gas_price_rlp,
        gas_limit_rlp,
        dest_rlp,
        amount_rlp,
        data_rlp,
        access_list_rlp,
    ]);

    let mut preimage = Vec::with_capacity(1 + unsigned_rlp.len());
    preimage.push(0x01);
    preimage.extend_from_slice(&unsigned_rlp);
    preimage
}

// ─── sign_eip2930 业务函数 ─────────────────────────────────────────

/// 签名 EIP-2930 transaction
pub fn sign_eip2930(input: &Eip2930SignInput) -> Result<Eip2930SignedTx> {
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
    let gas_price_rlp = rlp::encode_uint(input.tx.gas_price);
    let gas_limit_rlp = rlp::encode_uint(input.tx.gas_limit as u128);
    let dest_rlp = match &input.tx.destination {
        Some(addr) => rlp::encode_bytes(addr),
        None => rlp::encode_bytes(b""),
    };
    let amount_rlp = rlp::encode_uint(input.tx.amount);
    let data_rlp = rlp::encode_bytes(&input.tx.data);
    let access_list_rlp = encode_access_list(&input.tx.access_list);
    let y_parity_rlp = rlp::encode_uint(y_parity as u128);
    let r_rlp = rlp::encode_uint256(&r_bytes);
    let s_rlp = rlp::encode_uint256(&s_bytes);

    let signed_rlp = rlp::encode_list(&[
        chain_id_rlp,
        nonce_rlp,
        gas_price_rlp,
        gas_limit_rlp,
        dest_rlp,
        amount_rlp,
        data_rlp,
        access_list_rlp,
        y_parity_rlp,
        r_rlp,
        s_rlp,
    ]);

    let mut tx_bytes = Vec::with_capacity(1 + signed_rlp.len());
    tx_bytes.push(0x01);
    tx_bytes.extend_from_slice(&signed_rlp);

    Ok(Eip2930SignedTx {
        tx_bytes,
        signing_hash: sighash,
        r: r_bytes,
        s: s_bytes,
        y_parity,
    })
}

// ─── 测试 ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

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

    /// EIP-2930 test vector
    /// private_key: 0x4646464646464646464646464646464646464646464646464646464646464646
    /// chain_id: 1, nonce: 9, gas_price: 20 gwei, gas_limit: 21000
    /// destination: 0x3535353535353535353535353535353535353535
    /// amount: 1 ETH
    /// access_list: empty
    ///
    /// Expected signing hash: f9825220fb999f9c52f1edb0849af4a1c260f9574449070ce421ec3e90a2cc44
    #[test]
    fn eip2930_signing_hash_test_vector() {
        let tx = Eip2930Transaction {
            chain_id: 1,
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new(),
            access_list: Vec::new(),
        };
        let hash = signing_hash(&tx).unwrap();
        let expected_hex = "f9825220fb999f9c52f1edb0849af4a1c260f9574449070ce421ec3e90a2cc44";
        let expected_bytes = hex_decode(expected_hex);
        assert_eq!(&hash[..], &expected_bytes[..], "signing hash mismatch");
    }

    /// 完整 sign_eip2930 + 比对 signed tx
    #[test]
    fn sign_eip2930_full_pipeline() {
        let private_key_bytes =
            hex_decode("4646464646464646464646464646464646464646464646464646464646464646");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);

        let tx = Eip2930Transaction {
            chain_id: 1,
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new(),
            access_list: Vec::new(),
        };

        let input = Eip2930SignInput { tx, private_key };
        let signed = sign_eip2930(&input).unwrap();

        // 验证 signing hash
        let expected_hash =
            "f9825220fb999f9c52f1edb0849af4a1c260f9574449070ce421ec3e90a2cc44";
        let expected_hash_bytes = hex_decode(expected_hash);
        assert_eq!(&signed.signing_hash[..], &expected_hash_bytes[..]);
    }

    /// access_list 非空测试 (storage key 列表)
    #[test]
    fn access_list_with_storage_keys() {
        let tx = Eip2930Transaction {
            chain_id: 1,
            nonce: 0,
            gas_price: 1,
            gas_limit: 21000,
            destination: Some([0x12u8; 20]),
            amount: 0,
            data: Vec::new(),
            access_list: vec![AccessListItem {
                address: [0xab; 20],
                storage_keys: vec![[0x01; 32], [0x02; 32]],
            }],
        };
        // 验证 signing hash 不 panic
        let _hash = signing_hash(&tx).unwrap();
    }

    /// 确定性
    #[test]
    fn deterministic_signing() {
        let private_key_bytes =
            hex_decode("4646464646464646464646464646464646464646464646464646464646464646");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);

        let tx = Eip2930Transaction {
            chain_id: 1,
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new(),
            access_list: Vec::new(),
        };
        let input = Eip2930SignInput { tx: tx.clone(), private_key };
        let signed1 = sign_eip2930(&input).unwrap();
        let signed2 = sign_eip2930(&input).unwrap();
        assert_eq!(signed1.tx_bytes, signed2.tx_bytes);
    }
}