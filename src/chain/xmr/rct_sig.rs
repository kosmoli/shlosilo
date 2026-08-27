//! Monero RingCT 签名 (Phase 5 v9.5 Phase B)
//!
//! 实现 RctSig (Ring Confidential Transactions) — 隐藏 amount 的签名方案.
//! shlosilo 集成:
//! - RctSigBase (type=2/3, fee, pseudo_outs)
//! - RctSigPrunable (commitments + encrypted_amounts + bulletproofs + clsag_sigs)
//! - Bulletproofs+ 范围证明 (monero-bulletproofs crate)
//! - CLSAG 环签名 (monero-clsag crate, 复用 v8)
//!
//! ## 算法 (RingCTType 2/3 = Bulletproofs+)
//!
//! ```text
//! RctSig {
//!   Base {
//!     type: RingCTType (2 = BP per-output, 3 = BP aggregated, post-fork 1788000),
//!     fee: u64,
//!     pseudo_outs: Vec<[u8; 32]>,  // 每 input 一个 pseudo output commitment
//!   },
//!   Prunable {
//!     commitments: Vec<[u8; 32]>,  // 每 output 一个 commitment (C_i = mask_i * G + amount_i * H)
//!     encrypted_amounts: Vec<[u8; 8]>,  // 8 bytes ecdh encrypted amount per output
//!     bulletproofs: Vec<Bulletproof>,  // 范围证明 (BP+ aggregated for type=3)
//!     clsag_sigs: Vec<ClsagProof>,     // 每 input 一个 CLSAG
//!   },
//! }
//! ```
//!
//! **未实现 (Phase C 后续)**:
//! - 完整 extra 字段生成 (tx_pub_key 派生)
//! - 端到端"输入 → 输出 → sign → serialize → verify"
//!
//! **参考**:
//! - <https://github.com/monero-project/monero/blob/master/src/ringct/rctSigs.cpp>
//! - <https://github.com/monero-project/monero/blob/master/src/ringct/rctTypes.h>

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use monero_bulletproofs::{Bulletproof, MAX_COMMITMENTS};
use monero_ed25519::{Commitment as MoneroCommitment, CompressedPoint, Scalar};
use rand_core::{CryptoRng, RngCore};

use crate::chain::xmr::clsag::{self as clsag_mod, ClsagProof, KeyImage, KEY_IMAGE_LEN};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// RingCTType (BIP-compatible with XMR consensus)
pub mod rct_type {
    /// Type 0: full borromean (pre-fork, deprecated)
    pub const FULL: u8 = 0;
    /// Type 1: simple borromean (deprecated)
    pub const SIMPLE: u8 = 1;
    /// Type 2: bulletproofs (per-output BP+ range proof)
    pub const BULLETPROOFS: u8 = 2;
    /// Type 3: bulletproofs2 (aggregated BP+, post-fork 1788000)
    pub const BULLETPROOFS_PLUS: u8 = 3;
}

/// RctSigBase — 固定部分 (不依赖 ring members, 可提前序列化)
#[derive(Clone, Debug)]
pub struct RctSigBase {
    /// RingCT type (only 2 or 3 supported in shlosilo)
    pub rct_type: u8,
    /// tx fee (公开)
    pub fee: u64,
    /// pseudo output commitments (每 input 一个, 32 bytes)
    /// pseudo_outs[i] = Commitment(pseudo_mask_i, 0).commit()
    /// (Bull 0 范围 + 0 amount — 让 sum_input_commitments = sum_output_commitments + fee*G)
    pub pseudo_outs: Vec<[u8; 32]>,
}

impl RctSigBase {
    pub fn new(rct_type: u8, fee: u64, pseudo_outs: Vec<[u8; 32]>) -> Self {
        Self { rct_type, fee, pseudo_outs }
    }

    /// Serialize base (BIP-compatible with XMR wire format)
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.rct_type);
        // fee (varint)
        crate::chain::xmr::transaction::encode_varint(&mut out, self.fee);
        // pseudo_outs_count (varint)
        crate::chain::xmr::transaction::encode_varint(&mut out, self.pseudo_outs.len() as u64);
        for p in &self.pseudo_outs {
            out.extend_from_slice(p);
        }
        out
    }
}

/// RctSigPrunable — prunable 部分 (依赖 ring members, 大, 可剪裁)
#[derive(Clone, Debug)]
pub struct RctSigPrunable {
    /// output commitments (每 output 一个, 32 bytes Ed25519 point)
    /// commitments[i] = Commitment(mask_i, amount_i).commit()
    pub commitments: Vec<[u8; 32]>,
    /// encrypted amounts per output (8 bytes ecdh-encrypted amount)
    pub encrypted_amounts: Vec<[u8; 8]>,
    /// Bulletproofs (type=2: 每 output 一个 BP; type=3: 一个 aggregated BP)
    pub bulletproofs: Vec<Bulletproof>,
    /// CLSAG signatures per input
    pub clsag_sigs: Vec<ClsagProof>,
}

impl RctSigPrunable {
    pub fn new(
        commitments: Vec<[u8; 32]>,
        encrypted_amounts: Vec<[u8; 8]>,
        bulletproofs: Vec<Bulletproof>,
        clsag_sigs: Vec<ClsagProof>,
    ) -> Self {
        Self { commitments, encrypted_amounts, bulletproofs, clsag_sigs }
    }

    /// 序列化 prunable (BIP-compatible with XMR wire format)
    /// 格式: varint commitments_count + commitments + varint encrypted_amounts_count + encrypted + varint clsag_sigs_count + clsag
    /// bulletproofs 在最后 (per-output BP for type=2, 或单个 aggregated BP for type=3)
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        // commitments
        crate::chain::xmr::transaction::encode_varint(&mut out, self.commitments.len() as u64);
        for c in &self.commitments {
            out.extend_from_slice(c);
        }
        // encrypted_amounts
        crate::chain::xmr::transaction::encode_varint(
            &mut out,
            self.encrypted_amounts.len() as u64,
        );
        for a in &self.encrypted_amounts {
            out.extend_from_slice(a);
        }
        // bulletproofs (variable size, written via Write trait)
        let mut bp_buf = Vec::new();
        for bp in &self.bulletproofs {
            let mut single = Vec::new();
            bp.write(&mut single)
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
            bp_buf.extend_from_slice(&single);
        }
        crate::chain::xmr::transaction::encode_varint(&mut out, bp_buf.len() as u64);
        out.extend_from_slice(&bp_buf);
        // clsag_sigs
        crate::chain::xmr::transaction::encode_varint(&mut out, self.clsag_sigs.len() as u64);
        for clsag in &self.clsag_sigs {
            let bytes = clsag.to_bytes().to_vec();
            crate::chain::xmr::transaction::encode_varint(&mut out, bytes.len() as u64);
            out.extend_from_slice(&bytes);
        }
        Ok(out)
    }
}

/// Complete RctSig (Base + Prunable)
#[derive(Clone, Debug)]
pub struct RctSig {
    pub base: RctSigBase,
    pub prunable: RctSigPrunable,
}

impl RctSig {
    pub fn new(base: RctSigBase, prunable: RctSigPrunable) -> Self {
        Self { base, prunable }
    }

    /// 序列化完整 RctSig
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut out = self.base.serialize();
        let prunable_bytes = self.prunable.serialize()?;
        out.extend_from_slice(&prunable_bytes);
        Ok(out)
    }
}

/// 构造一个 Pedersen commitment (mask, amount)
pub fn make_commitment(mask: &Scalar, amount: u64) -> MoneroCommitment {
    MoneroCommitment::new(*mask, amount)
}

/// 构造 commitment points (VarInt count + 32 bytes each) — XMR wire format
pub fn serialize_commitments(commitments: &[MoneroCommitment]) -> Vec<u8> {
    let mut out = Vec::new();
    crate::chain::xmr::transaction::encode_varint(&mut out, commitments.len() as u64);
    for c in commitments {
        // Commitment::commit() returns Point (monero-ed25519::Point)
        let point = c.commit();
        let compressed = point.compress();
        out.extend_from_slice(&compressed.to_bytes());
    }
    out
}

/// Generate Bulletproofs+ for a list of commitments (RingCTType 2/3 aggregated)
///
/// **输入**:
/// - `rng`: 密码学安全 RNG
/// - `commitments`: Pedersen commitment 列表 (每 output 一个)
///
/// **输出**: Bulletproof (Plus 类型, 聚合多个 commitments)
///
/// **限制**: commitments.len() <= MAX_COMMITMENTS (16)
pub fn prove_bulletproofs_plus<R: RngCore + CryptoRng>(
    rng: &mut R,
    commitments: Vec<MoneroCommitment>,
) -> Result<Bulletproof> {
    if commitments.is_empty() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    if commitments.len() > MAX_COMMITMENTS {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    Bulletproof::prove_plus(rng, commitments)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))
}

/// Verify Bulletproofs+ for given commitment points (32 bytes each)
///
/// **输入**:
/// - `rng`: 密码学安全 RNG
/// - `bp`: Bulletproof (Plus 类型)
/// - `commitments`: compressed points (32 bytes each) for verification
///
/// **输出**: true if valid
pub fn verify_bulletproofs_plus<R: RngCore + CryptoRng>(
    rng: &mut R,
    bp: &Bulletproof,
    commitments: &[CompressedPoint],
) -> bool {
    bp.verify(rng, commitments)
}

/// Generate pseudo output commitment: C' = Commitment(pseudo_mask, 0)
///
/// pseudo_outs[i] 用于让 sum_input_commitments = sum_output_commitments + fee*G.
/// C' amount = 0 (范围在 BP+ 范围内), 但 mask 是 pseudo_mask.
pub fn pseudo_out_commitment(pseudo_mask: &Scalar) -> [u8; 32] {
    let c = MoneroCommitment::new(*pseudo_mask, 0);
    let point = c.commit();
    point.compress().to_bytes()
}

/// 单元测试
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::chain::xmr::reduce_scalar::reduce_scalar;
    use alloc::string::String;
    use rand_core::OsRng;
    use std::eprintln;

    fn hex_encode(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&alloc::format!("{:02x}", byte));
        }
        s
    }

    /// RctSigBase 序列化
    #[test]
    fn rct_sig_base_serialize() {
        let base = RctSigBase::new(
            rct_type::BULLETPROOFS_PLUS,
            100_000_000, // 0.0001 XMR
            vec![[0xab; 32], [0xcd; 32]],
        );
        let bytes = base.serialize();
        // type=3, varint(fee), varint(2 pseudo_outs), 2x32 bytes
        assert_eq!(bytes[0], rct_type::BULLETPROOFS_PLUS);
        eprintln!(
            "RctSigBase ({} bytes): {}",
            bytes.len(),
            hex_encode(&bytes)
        );
    }

    /// Pedersen commitment 构造
    #[test]
    fn commitment_construction() {
        let scalar_bytes = reduce_scalar(&[0x55u8; 32]).unwrap();
        let mask = {
    let bytes = crate::curve_primitive::ed25519::scalar_to_bytes(&scalar_bytes);
    let mut cursor = crate::chain::xmr::transaction::Read32Cursor(bytes);
    Scalar::read(&mut cursor).expect("reduced scalar")
};
        let amount: u64 = 1000;
        let c = make_commitment(&mask, amount);
        let point = c.commit();
        let compressed = point.compress();
        assert_eq!(compressed.to_bytes().len(), 32);
        eprintln!("Commitment({} piconero): {}", amount, hex_encode(&compressed.to_bytes()));
    }

    /// Pseudo output commitment
    #[test]
    fn pseudo_out() {
        let scalar_bytes = reduce_scalar(&[0x77u8; 32]).unwrap();
        let pseudo_mask = {
    let bytes = crate::curve_primitive::ed25519::scalar_to_bytes(&scalar_bytes);
    let mut cursor = crate::chain::xmr::transaction::Read32Cursor(bytes);
    Scalar::read(&mut cursor).expect("reduced scalar")
};
        let bytes = pseudo_out_commitment(&pseudo_mask);
        assert_eq!(bytes.len(), 32);
        eprintln!("Pseudo out: {}", hex_encode(&bytes));
    }

    /// Bulletproofs+ 范围证明 (1 commitment)
    #[test]
    fn bulletproof_plus_single() {
        let mut rng = OsRng;
        let scalar_bytes = reduce_scalar(&[0x33u8; 32]).unwrap();
        let mask = {
    let bytes = crate::curve_primitive::ed25519::scalar_to_bytes(&scalar_bytes);
    let mut cursor = crate::chain::xmr::transaction::Read32Cursor(bytes);
    Scalar::read(&mut cursor).expect("reduced scalar")
};
        let commitments = vec![MoneroCommitment::new(mask, 100_000_000)];
        let bp = prove_bulletproofs_plus(&mut rng, commitments).unwrap();

        // Verify with commitments
        let verify_mask_bytes = reduce_scalar(&[0x33u8; 32]).unwrap();
        let verify_mask = crate::chain::xmr::transaction::bytes_to_monerod_scalar(&crate::curve_primitive::ed25519::scalar_to_bytes(&verify_mask_bytes));
        let verify_commitment = MoneroCommitment::new(verify_mask, 100_000_000);
        let compressed = verify_commitment.commit().compress();
        let commitments_for_verify = vec![CompressedPoint::from(compressed.to_bytes())];
        assert!(verify_bulletproofs_plus(&mut rng, &bp, &commitments_for_verify));

        // BP serialize
        let mut bp_bytes = Vec::new();
        bp.write(&mut bp_bytes).unwrap();
        eprintln!("BP+ single ({} bytes)", bp_bytes.len());
    }

    /// Bulletproofs+ 多个 commitment (aggregated)
    #[test]
    fn bulletproof_plus_aggregated() {
        let mut rng = OsRng;
        let mut commitments = Vec::new();
        for i in 0u64..4 {
            let scalar_bytes = reduce_scalar(&[i as u8 + 1; 32]).unwrap();
            let mask = {
    let bytes = crate::curve_primitive::ed25519::scalar_to_bytes(&scalar_bytes);
    let mut cursor = crate::chain::xmr::transaction::Read32Cursor(bytes);
    Scalar::read(&mut cursor).expect("reduced scalar")
};
            commitments.push(MoneroCommitment::new(mask, (i + 1) * 1000));
        }

        let bp = prove_bulletproofs_plus(&mut rng, commitments.clone()).unwrap();

        // Verify
        let mut compressed_pts = Vec::new();
        for c in &commitments {
            let cp = c.commit().compress();
            compressed_pts.push(CompressedPoint::from(cp.to_bytes()));
        }
        assert!(verify_bulletproofs_plus(&mut rng, &bp, &compressed_pts));

        eprintln!("BP+ aggregated (4 commitments): ok");
    }

    /// Bulletproofs+ empty commitments → Err
    #[test]
    fn bulletproof_plus_empty() {
        let mut rng = OsRng;
        let result = prove_bulletproofs_plus(&mut rng, vec![]);
        assert!(result.is_err());
    }

    /// Bulletproofs+ too many commitments → Err
    #[test]
    fn bulletproof_plus_too_many() {
        let mut rng = OsRng;
        let mut commitments = Vec::new();
        for i in 0u64..=MAX_COMMITMENTS as u64 {
            // MAX_COMMITMENTS+1 = 17, 应失败
            let scalar_bytes = reduce_scalar(&[i as u8; 32]).unwrap();
            let mask = {
    let bytes = crate::curve_primitive::ed25519::scalar_to_bytes(&scalar_bytes);
    let mut cursor = crate::chain::xmr::transaction::Read32Cursor(bytes);
    Scalar::read(&mut cursor).expect("reduced scalar")
};
            commitments.push(MoneroCommitment::new(mask, i));
        }
        let result = prove_bulletproofs_plus(&mut rng, commitments);
        assert!(result.is_err());
    }

    /// RctSigBase 完整 round-trip
    #[test]
    fn rct_sig_base_round_trip() {
        let base = RctSigBase::new(rct_type::BULLETPROOFS_PLUS, 100, vec![[0x42; 32]]);
        let bytes = base.serialize();
        assert_eq!(bytes[0], rct_type::BULLETPROOFS_PLUS);
        // 然后 decode — 简化: 验证 byte structure
        let mut pos = 1;
        let fee = crate::chain::xmr::transaction::monero_decode_varint(&bytes, &mut pos).unwrap();
        assert_eq!(fee, 100);
        let n = crate::chain::xmr::transaction::monero_decode_varint(&bytes, &mut pos).unwrap();
        assert_eq!(n, 1);
        let p: [u8; 32] = bytes[pos..pos + 32].try_into().unwrap();
        assert_eq!(p, [0x42; 32]);
        assert_eq!(pos + 32, bytes.len());
    }

    /// CLSAG round-trip (单 input, BP+ 0 outputs, no RCT)
    /// — 最小化 demo: 仅验证 clsag.sign + 输出的 ClsagProof 可 serialize
    #[test]
    fn clsag_minimal_demo() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use curve25519_dalek::Scalar as DScalar;
        let mut rng = OsRng;

        // 1. 构造 ring (real + 1 decoy)
        let real_sk_arr = crate::curve_primitive::ed25519::scalar_to_bytes(&reduce_scalar(&[0x11u8; 32]).unwrap());
        
        let real_sk_dalek = DScalar::from_bytes_mod_order(real_sk_arr);
        let real_pub_point: curve25519_dalek::EdwardsPoint =
            ED25519_BASEPOINT_TABLE * &real_sk_dalek;
        let real_pub_bytes = real_pub_point.compress().to_bytes();
        let real_pub = CompressedPoint::from(real_pub_bytes);

        let decoy_sk_arr = crate::curve_primitive::ed25519::scalar_to_bytes(&reduce_scalar(&[0x22u8; 32]).unwrap());
        let decoy_sk_dalek = DScalar::from_bytes_mod_order(decoy_sk_arr);
        let decoy_pub_point: curve25519_dalek::EdwardsPoint =
            ED25519_BASEPOINT_TABLE * &decoy_sk_dalek;
        let decoy_pub_bytes = decoy_pub_point.compress().to_bytes();
        let decoy_pub = CompressedPoint::from(decoy_pub_bytes);

        let real_mask_bytes = reduce_scalar(&[0x33u8; 32]).unwrap();
        let real_mask = crate::chain::xmr::transaction::bytes_to_monerod_scalar(&crate::curve_primitive::ed25519::scalar_to_bytes(&real_mask_bytes));
        let real_commit = MoneroCommitment::new(real_mask, 1000);

        let decoy_mask_bytes = reduce_scalar(&[0x44u8; 32]).unwrap();
        let decoy_mask = crate::chain::xmr::transaction::bytes_to_monerod_scalar(&crate::curve_primitive::ed25519::scalar_to_bytes(&decoy_mask_bytes));
        let decoy_commit = MoneroCommitment::new(decoy_mask, 1000);

        let ring = vec![
            (real_pub, real_commit.commit().compress().to_bytes().into()),
            (decoy_pub, decoy_commit.commit().compress().to_bytes().into()),
        ];

        // 2. 构造 pseudo_mask (different from real_mask)
        let pseudo_mask_bytes = reduce_scalar(&[0x55u8; 32]).unwrap();
        let pseudo_mask = crate::curve_primitive::ed25519::scalar_to_bytes(&pseudo_mask_bytes);
        let msg_hash: [u8; 32] = [0x99u8; 32];

        // 3. Call v8 clsag.sign
        let real_mask_arr = crate::curve_primitive::ed25519::scalar_to_bytes(&real_mask_bytes);
        let sign_result = clsag_mod::sign(
            &real_sk_arr,
            &ring,
            0, // real index
            &real_mask_arr,
            1000, // amount
            &pseudo_mask,
            &msg_hash,
            &mut rng,
        );

        let (clsag_proof, key_image, _pseudo_out) = sign_result.unwrap();

        // 4. Serialize ClsagProof bytes
        let clsag_bytes = clsag_proof.to_bytes().to_vec();
        assert!(clsag_bytes.len() >= 32 + 64);

        // 5. RctSigPrunable 包装 (无 BP+, 单 input CLSAG)
        let commitments_prunable: Vec<[u8; 32]> = vec![real_commit.commit().compress().to_bytes()];
        let encrypted_amounts_prunable: Vec<[u8; 8]> = vec![[0u8; 8]];
        let prunable = RctSigPrunable::new(
            commitments_prunable,
            encrypted_amounts_prunable,
            vec![], // 无 BP+ — 仅 CLSAG demo
            vec![clsag_proof],
        );
        let prunable_bytes = prunable.serialize().unwrap();
        assert!(prunable_bytes.len() > 32);

        eprintln!(
            "CLSAG demo: clsag_bytes={}, prunable={}, ki={}",
            clsag_bytes.len(),
            prunable_bytes.len(),
            hex_encode(&key_image.to_bytes())
        );
    }

    /// RctSig 完整序列化 (Base + Prunable) — minimal
    #[test]
    fn rct_sig_serialize_minimal() {
        let base = RctSigBase::new(rct_type::BULLETPROOFS_PLUS, 100, vec![[0x11; 32]]);
        let prunable = RctSigPrunable::new(
            vec![[0x22; 32]],
            vec![[0x33; 8]],
            vec![],
            vec![],
        );
        let sig = RctSig::new(base, prunable);
        let bytes = sig.serialize().unwrap();
        eprintln!("RctSig ({} bytes): {}", bytes.len(), hex_encode(&bytes));
    }
}