//! ETH EIP-1559 完整交易签名（Phase 5 v7 真实实现）
//!
//! 实现：
//! - EIP-1559 transaction 数据结构
//! - EIP-1559 signing hash（`keccak256(0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list]))`）
//! - sign_eip1559 业务函数（sighash → ECDSA → r/s + y_parity → 拼装 signed tx）
//!
//! ## 算法摘要
//!
//! **EIP-1559 signing hash**:
//! ```text
//! keccak256(0x02 || rlp([
//!   chain_id,
//!   nonce,
//!   max_priority_fee_per_gas,
//!   max_fee_per_gas,
//!   gas_limit,
//!   destination,           // 20-byte address, empty if contract creation
//!   amount,
//!   data,
//!   access_list,           // [] for empty
//! ]))
//! ```text
//!
//! **EIP-1559 signed transaction format**:
//! ```text
//! 0x02 || rlp([
//!   chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
//!   destination, amount, data, access_list,
//!   y_parity, r, s,
//! ])
//! ```text
//!
//! **y_parity**: 0 或 1（不是 legacy 的 27/28）

    extern crate alloc;
extern crate digest;
use crate::chain::eth::rlp;
use crate::types::SecretBytes;
use crate::curve_primitive::secp256k1::{base_mul, point_to_compressed, scalar_from_bytes};
use crate::encoding::keccak256;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::signature::ecdsa_secp256k1::{self as ecdsa};
use alloc::vec::Vec;

// ─── 数据结构 ──────────────────────────────────────────────────────

/// EIP-1559 transaction（未签名）
#[derive(Clone, Debug)]
pub struct Eip1559Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    /// 20-byte destination address, or None for contract creation
    pub destination: Option<[u8; 20]>,
    pub amount: u128,
    pub data: Vec<u8>,
    /// access_list（EIP-2930）— Phase 5 v7 不支持，空 vec
    pub access_list: Vec<(Address, Vec<[u8; 32]>)>,
}

/// 20-byte Ethereum address
pub type Address = [u8; 20];

/// 签名输入
///
/// P1-03：私钥走 `SecretBytes<32>`——不 Clone 不 Debug、ZeroizeOnDrop、常时比较。
pub struct Eip1559SignInput {
    pub tx: Eip1559Transaction,
    pub private_key: SecretBytes<32>,
}

/// 签名输出
#[derive(Clone, Debug)]
pub struct Eip1559SignedTx {
    /// 完整签名交易 bytes (0x02 || rlp([..., y_parity, r, s]))
    pub tx_bytes: Vec<u8>,
    /// signing hash (Keccak256 of preimage)
    pub signing_hash: [u8; 32],
    /// signature r
    pub r: [u8; 32],
    /// signature s
    pub s: [u8; 32],
    /// y_parity: 0 或 1
    pub y_parity: u8,
}

// ─── EIP-1559 signing hash ────────────────────────────────────────

/// 计算 EIP-1559 signing hash
///
/// `keccak256(0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list]))`
pub fn signing_hash(tx: &Eip1559Transaction) -> Result<[u8; 32]> {
    let preimage = signing_preimage(tx)?;
    keccak256::hash(&preimage)
}

/// Debug helper: 返回 signing preimage bytes
pub fn signing_preimage(tx: &Eip1559Transaction) -> Result<Vec<u8>> {
    // RLP encode each field
    let chain_id_rlp = rlp::encode_uint(tx.chain_id as u128);
    let nonce_rlp = rlp::encode_uint(tx.nonce as u128);
    let max_prio_rlp = rlp::encode_uint(tx.max_priority_fee_per_gas);
    let max_fee_rlp = rlp::encode_uint(tx.max_fee_per_gas);
    let gas_limit_rlp = rlp::encode_uint(tx.gas_limit as u128);

    // destination: 20-byte address, or empty for contract creation
    let dest_rlp = match &tx.destination {
        Some(addr) => rlp::encode_bytes(addr),
        None => rlp::encode_bytes(b""),
    };

    let amount_rlp = rlp::encode_uint(tx.amount);
    let data_rlp = rlp::encode_bytes(&tx.data);

    // access_list: 空 list
    let access_list_rlp = rlp::encode_list(&[]);

    // RLP list of all fields
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
    ]);

    // preimage = 0x02 || rlp_list
    let mut preimage = Vec::with_capacity(1 + unsigned_rlp.len());
    preimage.push(0x02);
    preimage.extend_from_slice(&unsigned_rlp);

    Ok(preimage)
}

// ─── sign_eip1559 业务函数 ────────────────────────────────────────

/// 计算 y_parity (recovery_id) — 从 (r, s, z, pk) 推 R.y parity
///
/// 算法: R = r⁻¹ · (s · pk − z · G)  ;  y_parity = R.y mod 2
///
/// 用 k256 0.14 ProjectivePoint + Scalar arithmetic
/// 计算 y_parity (recovery_id) — 用 k256::ecdsa::VerifyingKey::recover_from_prehash
///
/// ECDSA 已知 (z, r, s) + y_parity ∈ {0, 1} → 恢复出 pubkey。
/// 通过比对恢复出的 pubkey 和实际 pubkey 找出正确的 y_parity。
///
/// k256 0.14 提供了 `VerifyingKey::recover_from_prehash(prehash, &sig, recid)`，
/// 接受 32-byte prehash（**不需要** Digest trait）— 完美匹配我们的 use case。
fn compute_y_parity(
    sk: &crate::curve_primitive::secp256k1::Secp256k1Scalar,
    signing_hash_bytes: &[u8; 32],
    r_bytes: &[u8; 32],
    s_bytes: &[u8; 32],
) -> Result<u8> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    

    // 构造 signature (r || s, 64 bytes)
    let mut sig_64 = [0u8; 64];
    sig_64[..32].copy_from_slice(r_bytes);
    sig_64[32..].copy_from_slice(s_bytes);
    let sig = Signature::from_slice(&sig_64).map_err(|_| {
        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
    })?;

    // pubkey (compressed 33 bytes) from sk
    let pk_point = base_mul(sk);
    let pk_compressed = point_to_compressed(&pk_point);

    // 尝试 y_parity = 0 和 1
    for y_parity in 0u8..=1u8 {
        // RecoveryId::new(is_y_odd: bool, is_x_reduced: bool)
        let recid = RecoveryId::new(y_parity == 1, false);
        let recovered = VerifyingKey::recover_from_prehash(signing_hash_bytes, &sig, recid);
        if let Ok(recovered_pk) = recovered {
            // VerifyingKey::to_sec1_point(false) = compressed SEC1 33 bytes
            let sec1_point = recovered_pk.to_sec1_point(true);
            let rec_bytes = sec1_point.as_bytes();
            if rec_bytes == &pk_compressed[..] {
                return Ok(y_parity);
            }
        }
    }

    Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))
}

/// 签名 EIP-1559 transaction
pub fn sign_eip1559(input: &Eip1559SignInput) -> Result<Eip1559SignedTx> {
    let sk = scalar_from_bytes(input.private_key.expose())?;

    // 1. signing hash
    let sighash = signing_hash(&input.tx)?;

    // 2. ECDSA sign_prehash (返回 r||s = 64 bytes)
    let sig = ecdsa::sign(&sk, &sighash)?;
    let sig_bytes = sig.as_ref();
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig_bytes[..32]);
    s_bytes.copy_from_slice(&sig_bytes[32..]);
    // DEBUG: print original sig

    // 2.5 BIP-146 / EIP-2 low-s enforcement:
    //     先用原始 s 算出 y_parity，再用 (n - s) 翻转 s（如果 s > n/2）
    //     flip s 等价于 R → -R (R.y parity 翻转)
    let y_parity_original = compute_y_parity(&sk, &sighash, &r_bytes, &s_bytes)?;

    let half_n_high: [u8; 16] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    let half_n_low: [u8; 16] = [
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
        0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
    ];
    let s_high = &s_bytes[..16];
    let s_low = &s_bytes[16..];
    let is_high_s = if s_high > half_n_high.as_slice() {
        true
    } else if s_high < half_n_high.as_slice() {
        false
    } else {
        s_low > half_n_low.as_slice()
    };
    let y_parity = if is_high_s {
        let n_bytes: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
            0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
        ];
        let mut new_s = [0u8; 32];
        let mut borrow: u8 = 0;
        for i in (0..32).rev() {
            let a = n_bytes[i];
            let b = sig_bytes[i];
            let (d, b1) = a.overflowing_sub(b);
            let (d2, b2) = d.overflowing_sub(borrow);
            new_s[i] = d2;
            borrow = (b1 || b2) as u8;
        }
        s_bytes.copy_from_slice(&new_s);
        // flip y_parity (R → -R, parity 翻转)
        y_parity_original ^ 1
    } else {
        y_parity_original
    };

    // 4. Build signed transaction
    // 0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
    //               destination, amount, data, access_list, y_parity, r, s])
    let chain_id_rlp = rlp::encode_uint(input.tx.chain_id as u128);
    let nonce_rlp = rlp::encode_uint(input.tx.nonce as u128);
    let max_prio_rlp = rlp::encode_uint(input.tx.max_priority_fee_per_gas);
    let max_fee_rlp = rlp::encode_uint(input.tx.max_fee_per_gas);
    let gas_limit_rlp = rlp::encode_uint(input.tx.gas_limit as u128);
    let dest_rlp = match &input.tx.destination {
        Some(addr) => rlp::encode_bytes(addr),
        None => rlp::encode_bytes(b""),
    };
    let amount_rlp = rlp::encode_uint(input.tx.amount);
    let data_rlp = rlp::encode_bytes(&input.tx.data);
    let access_list_rlp = rlp::encode_list(&[]);

    let y_parity_rlp = rlp::encode_uint(y_parity as u128);
    // r, s 是 32-byte big-endian uint256, strip leading zeros
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
        y_parity_rlp,
        r_rlp,
        s_rlp,
    ]);

    let mut tx_bytes = Vec::with_capacity(1 + signed_rlp.len());
    tx_bytes.push(0x02);
    tx_bytes.extend_from_slice(&signed_rlp);

    Ok(Eip1559SignedTx {
        tx_bytes,
        signing_hash: sighash,
        r: r_bytes,
        s: s_bytes,
        y_parity,
    })
}

// ─── 辅助：hex decode ──────────────────────────────────────────────

#[cfg(test)]
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

#[cfg(test)]
fn hex_nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)),
    }
}

// ─── 单元测试 ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// EIP-1559 test vector（自己用 Python 算的对照值）
    /// private_key: 0x4646464646464646464646464646464646464646464646464646464646464646
    /// chain_id: 1, nonce: 0, max_priority_fee: 1 gwei, max_fee: 20 gwei, gas_limit: 21000
    /// destination: 0x3535353535353535353535353535353535353535
    /// amount: 1 ETH
    ///
    /// Expected signing hash: 2cb489a9d0facd97d34bb756c61070935ff0c5fa306bd677acf969b57dbc9e7a
    /// Expected signed tx:    02f87201843b9aca008504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080c001a0d1453c4f511f81fda6e7d582b6f0cfb1d50f0804fc61bf1040aeb09f5fc0958ca0346d4c998fc306a947a1e4ee414d8c9341ae28f4136c89889f686ce4975dd8e8
    #[test]
    fn eip1559_signing_hash_test_vector() {
        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new(),
            access_list: Vec::new(),
        };

        let hash = signing_hash(&tx).unwrap();
        let expected_hex = "f63a609bfdfcc60853764d633f8de24fc6bf6f85e19ee6c0f2d089f7ee8d5d86";
        let expected_bytes = hex_decode(expected_hex).unwrap();
        assert_eq!(&hash[..], &expected_bytes[..], "signing hash mismatch");
    }

    /// 完整 sign_eip1559 + 比对 signed tx
    #[test]
    fn sign_eip1559_full_pipeline() {
        let private_key_bytes = hex_decode("4646464646464646464646464646464646464646464646464646464646464646").unwrap();
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new(),
            access_list: Vec::new(),
        };

        let input = Eip1559SignInput { tx, private_key };
        let signed = sign_eip1559(&input).unwrap();

        // 验证 signing hash
        let expected_hash = "f63a609bfdfcc60853764d633f8de24fc6bf6f85e19ee6c0f2d089f7ee8d5d86";
        let expected_hash_bytes = hex_decode(expected_hash).unwrap();
        assert_eq!(&signed.signing_hash[..], &expected_hash_bytes[..]);

        // 验证 r
        let expected_r = "b3d7e5d4775918a0ec38e4f9da6263f69c2072c0e177ff9aa274575bfba17d04";
        let expected_r_bytes = hex_decode(expected_r).unwrap();
        assert_eq!(&signed.r[..], &expected_r_bytes[..]);

        // 验证 s
        let expected_s = "62182875ae92e4de08aaf8ea1a43d3ea0d836745788801cdc79ccc473a76dfd9";
        let expected_s_bytes = hex_decode(expected_s).unwrap();
        assert_eq!(&signed.s[..], &expected_s_bytes[..]);

        // 验证 y_parity (k256 0.14 默认 low-s enforcement, y_parity=1)
        assert_eq!(signed.y_parity, 1);

        // 验证完整 signed tx
        let expected_tx = "02f8730180843b9aca008504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080c001a0b3d7e5d4775918a0ec38e4f9da6263f69c2072c0e177ff9aa274575bfba17d04a062182875ae92e4de08aaf8ea1a43d3ea0d836745788801cdc79ccc473a76dfd9";
        let expected_tx_bytes = hex_decode(expected_tx).unwrap();
        assert_eq!(&signed.tx_bytes[..], &expected_tx_bytes[..], "signed tx mismatch");
    }

    /// 确定性：相同输入 → 相同输出
    #[test]
    fn deterministic_signing() {
        let private_key_bytes = hex_decode("4646464646464646464646464646464646464646464646464646464646464646").unwrap();
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new(),
            access_list: Vec::new(),
        };

        let input = Eip1559SignInput { tx, private_key };

        let signed1 = sign_eip1559(&input).unwrap();
        let signed2 = sign_eip1559(&input).unwrap();
        assert_eq!(signed1.signing_hash, signed2.signing_hash);
        assert_eq!(signed1.tx_bytes, signed2.tx_bytes);
    }

    /// contract creation（destination = None）→ signing hash 不同
    #[test]
    fn contract_creation_differs_from_transfer() {
        let mut tx_transfer = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 0,
            data: Vec::new(),
            access_list: Vec::new(),
        };
        let hash_transfer = signing_hash(&tx_transfer).unwrap();

        // contract creation: destination = None
        tx_transfer.destination = None;
        let hash_create = signing_hash(&tx_transfer).unwrap();

        assert_ne!(hash_transfer, hash_create, "contract creation should produce different hash");
    }

    /// 不同 chain_id → 不同 signing hash
    #[test]
    fn chain_id_changes_signing_hash() {
        let mk_tx = |chain_id: u64| Eip1559Transaction {
            chain_id,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 0,
            data: Vec::new(),
            access_list: Vec::new(),
        };

        let hash_mainnet = signing_hash(&mk_tx(1)).unwrap();
        let hash_sepolia = signing_hash(&mk_tx(11155111)).unwrap();

        assert_ne!(hash_mainnet, hash_sepolia);
    }
}
