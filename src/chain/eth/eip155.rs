//! ETH EIP-155 Legacy transaction 签名（Phase 5 v8）
//!
//! 实现：
//! - EIP-155 transaction 数据结构
//! - EIP-155 signing hash（`keccak256(rlp([nonce, gas_price, gas_limit, destination, amount, data, chain_id, 0, 0]))`）
//! - sign_eip155 业务函数（sighash → ECDSA → r/s + y_parity → v = chain_id*2 + 35 + y_parity → 拼装 signed tx）
//!
//! ## 算法摘要
//!
//! **EIP-155 signing hash**（注意没有 type prefix，跟 EIP-1559 不同）：
//! ```text
//! keccak256(rlp([
//!   nonce,
//!   gas_price,
//!   gas_limit,
//!   destination,           // 20-byte address, empty if contract creation
//!   amount,
//!   data,
//!   chain_id,
//!   0,                     // EIP-155 标记
//!   0,                     // EIP-155 标记
//! ]))
//! ```text
//!
//! **EIP-155 signed transaction format**（无 type prefix）：
//! ```text
//! rlp([
//!   nonce, gas_price, gas_limit, destination, amount, data,
//!   v, r, s,
//! ])
//! ```text
//!
//! **v** = `chain_id * 2 + 35 + y_parity`（y_parity = 0 或 1）
//! - mainnet chain_id = 1 → v = 37 或 38
//! - 旧未签名 v 是 27/28（pre-EIP-155）

extern crate alloc;
use crate::chain::eth::rlp;
use crate::chain::eth::sign;
use crate::encoding::keccak256;
use crate::error::Result;
use crate::types::SecretBytes;
use alloc::vec::Vec;

/// EIP-155 Legacy transaction（未签名）
#[derive(Clone, Debug)]
pub struct Eip155Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    /// 20-byte destination address, or None for contract creation
    pub destination: Option<[u8; 20]>,
    pub amount: u128,
    pub data: Vec<u8>,
}

/// 签名输入
///
/// P1-03：私钥走 `SecretBytes<32>`——不 Clone 不 Debug、ZeroizeOnDrop、常时比较。
pub struct Eip155SignInput {
    pub tx: Eip155Transaction,
    pub private_key: SecretBytes<32>,
}

/// 签名输出
#[derive(Clone, Debug)]
pub struct Eip155SignedTx {
    /// 完整签名交易 bytes (rlp([..., v, r, s])) — 无 type prefix
    pub tx_bytes: Vec<u8>,
    /// signing hash
    pub signing_hash: [u8; 32],
    /// signature r
    pub r: [u8; 32],
    /// signature s
    pub s: [u8; 32],
    /// v = chain_id * 2 + 35 + y_parity
    pub v: u64,
}

// ─── EIP-155 signing hash ────────────────────────────────────────

/// 计算 EIP-155 signing hash
///
/// `keccak256(rlp([nonce, gas_price, gas_limit, destination, amount, data, chain_id, 0, 0]))`
pub fn signing_hash(tx: &Eip155Transaction) -> Result<[u8; 32]> {
    let preimage = signing_preimage(tx);
    keccak256::hash(&preimage)
}

/// 计算 signing preimage bytes
pub fn signing_preimage(tx: &Eip155Transaction) -> Vec<u8> {
    let nonce_rlp = rlp::encode_uint(tx.nonce as u128);
    let gas_price_rlp = rlp::encode_uint(tx.gas_price);
    let gas_limit_rlp = rlp::encode_uint(tx.gas_limit as u128);

    let dest_rlp = match &tx.destination {
        Some(addr) => rlp::encode_bytes(addr),
        None => rlp::encode_bytes(b""),
    };

    let amount_rlp = rlp::encode_uint(tx.amount);
    let data_rlp = rlp::encode_bytes(&tx.data);
    let chain_id_rlp = rlp::encode_uint(tx.chain_id as u128);
    let zero_rlp = rlp::encode_uint(0);
    let zero_rlp_2 = rlp::encode_uint(0);

    rlp::encode_list(&[
        nonce_rlp,
        gas_price_rlp,
        gas_limit_rlp,
        dest_rlp,
        amount_rlp,
        data_rlp,
        chain_id_rlp,
        zero_rlp,
        zero_rlp_2,
    ])
}

// ─── sign_eip155 业务函数 ──────────────────────────────────────────

/// 签名 EIP-155 legacy transaction
pub fn sign_eip155(input: &Eip155SignInput) -> Result<Eip155SignedTx> {
    let sk = sign::sk_from_pk(input.private_key.expose())?;

    // 1. signing hash
    let sighash = signing_hash(&input.tx)?;

    // 2. ECDSA sign + low-s enforcement + y_parity
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    let y_parity = sign::apply_low_s(&sighash, &sk, &mut r_bytes, &mut s_bytes)?;

    // 3. v = chain_id * 2 + 35 + y_parity
    let v = input.tx.chain_id * 2 + 35 + y_parity as u64;

    // 4. Build signed transaction (no type prefix)
    let nonce_rlp = rlp::encode_uint(input.tx.nonce as u128);
    let gas_price_rlp = rlp::encode_uint(input.tx.gas_price);
    let gas_limit_rlp = rlp::encode_uint(input.tx.gas_limit as u128);
    let dest_rlp = match &input.tx.destination {
        Some(addr) => rlp::encode_bytes(addr),
        None => rlp::encode_bytes(b""),
    };
    let amount_rlp = rlp::encode_uint(input.tx.amount);
    let data_rlp = rlp::encode_bytes(&input.tx.data);
    let v_rlp = rlp::encode_uint(v as u128);
    let r_rlp = rlp::encode_uint256(&r_bytes);
    let s_rlp = rlp::encode_uint256(&s_bytes);

    let signed_rlp = rlp::encode_list(&[
        nonce_rlp,
        gas_price_rlp,
        gas_limit_rlp,
        dest_rlp,
        amount_rlp,
        data_rlp,
        v_rlp,
        r_rlp,
        s_rlp,
    ]);

    let tx_bytes = signed_rlp;

    Ok(Eip155SignedTx {
        tx_bytes,
        signing_hash: sighash,
        r: r_bytes,
        s: s_bytes,
        v,
    })
}

// ─── 测试 ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
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

    /// EIP-155 test vector（Python + pycryptodome + ecdsa lib 算的对照值）
    /// private_key: 0x4646464646464646464646464646464646464646464646464646464646464646
    /// chain_id: 1, nonce: 9, gas_price: 20 gwei, gas_limit: 21000
    /// destination: 0x3535353535353535353535353535353535353535
    /// amount: 1 ETH
    ///
    /// Expected signing hash: daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53
    /// Expected signed tx: f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83
    #[test]
    fn eip155_signing_hash_test_vector() {
        let tx = Eip155Transaction {
            chain_id: 1,
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new(),
        };
        let hash = signing_hash(&tx).unwrap();
        let expected_hex = "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53";
        let expected_bytes = hex_decode(expected_hex);
        assert_eq!(&hash[..], &expected_bytes[..], "signing hash mismatch");
    }

    /// 完整 sign_eip155 + 比对 signed tx
    #[test]
    fn sign_eip155_full_pipeline() {
        let private_key_bytes =
            hex_decode("4646464646464646464646464646464646464646464646464646464646464646");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let tx = Eip155Transaction {
            chain_id: 1,
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new(),
        };

        let input = Eip155SignInput { tx, private_key };
        let signed = sign_eip155(&input).unwrap();

        // 验证 signing hash
        let expected_hash =
            "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53";
        let expected_hash_bytes = hex_decode(expected_hash);
        assert_eq!(&signed.signing_hash[..], &expected_hash_bytes[..]);

        // 验证 v = chain_id * 2 + 35 + y_parity
        // Python ecdsa lib + k256 0.14 都输出 low-s + y_parity=0 (s < n/2)
        // → v = 1*2 + 35 + 0 = 37
        assert_eq!(signed.v, 37);

        // 验证完整 signed tx
        // v = 0x25 (37), r = 0x28ef..., s = 0x67cb...
        let expected_tx = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
        let expected_tx_bytes = hex_decode(expected_tx);
        assert_eq!(&signed.tx_bytes[..], &expected_tx_bytes[..], "signed tx mismatch");
    }

    /// 确定性：相同输入 → 相同输出
    #[test]
    fn deterministic_signing() {
        let private_key_bytes =
            hex_decode("4646464646464646464646464646464646464646464646464646464646464646");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let tx = Eip155Transaction {
            chain_id: 1,
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new(),
        };

        let input = Eip155SignInput { tx: tx.clone(), private_key };
        let signed1 = sign_eip155(&input).unwrap();
        let signed2 = sign_eip155(&input).unwrap();
        assert_eq!(signed1.tx_bytes, signed2.tx_bytes, "must be deterministic");
    }

    /// 不同 chain_id → 不同 signing hash
    #[test]
    fn different_chain_id_different_hash() {
        let tx_mainnet = Eip155Transaction {
            chain_id: 1,
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new(),
        };
        let mut tx_sepolia = tx_mainnet.clone();
        tx_sepolia.chain_id = 11155111;
        let hash_mainnet = signing_hash(&tx_mainnet).unwrap();
        let hash_sepolia = signing_hash(&tx_sepolia).unwrap();
        assert_ne!(hash_mainnet, hash_sepolia);
    }
}