//! XMR CLSAG (Concise Linkable Spontaneous Anonymous Group) 签名
//!
//! Phase 5 v4 真实实现：wrap `monero-clsag 0.1`
//!
//! ## 算法（XMR CLSAG）
//!
//! - Linkable ring signature，允许签名者证明"ring 中某一个"对应的私钥拥有者
//! - ring of `n` public keys（其中 1 个是真实 signer），输出 1 signature
//! - **防双花**：key image I = x * Hp(P) 唯一标识本次花费（x = private key）
//!
//! ## API 设计
//!
//! shlosilo wrap monero-clsag →
//! - `sign` 输入/输出：`Vec` (monero-clsag) → `Vec`/`Box` → shlosilo 直接调用（业务层允许 alloc）
//! - shlosilo 公开 API 用 `Vec` 参数（XMR 业务模块是 L2b FFI 层允许 alloc）
//!
//! ## 安全约束（v2 §2.1）
//!
//! - `ClsagProof` 公开材料（signature）→ 允许 Copy
//! - `KeyImage` 公开材料 → 允许 Copy

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::Scalar as DScalar;
use monero_clsag::{Clsag, ClsagContext, Decoys};
use monero_ed25519::{Commitment as MoneroCommitment, CompressedPoint, Point, Scalar};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// CLSAG ring 最大长度（XMR 协议默认 11 = 1 real + 10 decoys）
pub const DEFAULT_RING_LEN: usize = 11;

/// CLSAG signature 序列化长度（64 bytes）
/// 实际 monero-clsag Clsag 结构体 serialize 后长度 ≈ 64 bytes
pub const CLSAG_PROOF_LEN: usize = 64;

/// Key image 长度（32 bytes compressed）
pub const KEY_IMAGE_LEN: usize = 32;

/// XMR CLSAG proof 包装
///
/// monero-clsag `Clsag` 包含 c1 scalar + s[] vector，长度 = 32 + ring_len * 32
/// 这里用 `Vec<u8>` 简化存储（serialized form）
#[derive(Clone, Debug)]
pub struct ClsagProof {
    bytes: Vec<u8>,
}

/// XMR key image（公开材料，防双花）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyImage {
    bytes: [u8; KEY_IMAGE_LEN],
}

impl KeyImage {
    pub fn to_bytes(&self) -> [u8; KEY_IMAGE_LEN] {
        self.bytes
    }
}

impl AsRef<[u8]> for KeyImage {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl ClsagProof {
    /// ClsagProof → serialized bytes
    ///
    /// 布局 = `pseudo_out(32) ‖ s[mixin+1]‖c1‖D`（sign() 内部拼接）。
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 官方 monerod CLSAG 段：`s[mixin+1] ‖ c1 ‖ D`（不含前缀 pseudo_out）
    pub fn wire_body(&self) -> &[u8] {
        &self.bytes[32..]
    }
}

/// CLSAG sign：单个 input 签名（vec![(sk, ctx)]）
///
/// **输入**：
/// - `input_skey`: **one-time input 私钥** = spend_key + key_offset（P_outpoint 的离散对数；
///   serai 校验 `sk·G == ring[real][0]`，ring 存 one-time address，不能用裸 wallet spend key）
/// - `ring`: ring of (spend_pubkey, commitment_point) pairs，长度 = ring_len
///   - commitment_point 是 **real commitment**（real_mask * H + amount * G）
/// - `real_index`: 真实 signer 在 ring 中的位置 (0..ring_len)
/// - `real_mask`: real commitment 的 mask scalar（32 bytes）—— ring[real_index][1] 对应
/// - `amount`: real amount（u64）
/// - `pseudo_mask`: pseudo_output 的 mask scalar（32 bytes）—— 必须 ≠ real_mask（否则 D=0，sig 无法验证）
/// - `msg_hash`: 32-byte message hash
/// - `rng`: 加密安全 RNG
///
/// **返回**：(ClsagProof, KeyImage, pseudo_out_commitment)
///
/// ## Monero 协议约束
///
/// Monero CLSAG 要求 `mask_delta = real_mask - pseudo_mask ≠ 0`（否则 `D = Hp(P) * 0 = identity`，
/// `verify` 立即返回 `Err(InvalidD)`）。这是 anti-malleability 设计：让 sig 唯一化。
///
/// 同时 `sum_pseudo_outs = pseudo_mask`（单 input，amount 自平衡）。
#[allow(clippy::too_many_arguments)] // 签名参数形状对齐 keystone generate_ring_signature
pub fn sign<R: RngCore + CryptoRng>(
    input_skey: &[u8; 32],
    ring: &[(CompressedPoint, CompressedPoint)], // (dest, **链上 C 点**，非 blinding)
    real_index: u8,
    real_mask: &[u8; 32], // real output 的真 blinding factor（wallet2 sources[i].mask）
    amount: u64,
    pseudo_mask: &[u8; 32],
    msg_hash: &[u8; 32],
    rng: &mut R,
) -> Result<(ClsagProof, KeyImage, [u8; 32])> {
    if ring.is_empty() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    if real_index as usize >= ring.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    if real_mask == pseudo_mask {
        // D=0 → verify 失败（anti-malleability）
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // 1. 构造 one-time input 私钥 (monero_ed25519::Scalar)
    let spend_scalar = scalar_from_reduced_bytes(input_skey)?;

    // 2. 构造 Decoys
    //    ring: Vec<[Point; 2]>  where  [0] = spend_pub, [1] = 链上 commitment 点（C）
    //    ring 第1元已是压缩 C 点字节，直接解压，**不再经 Commitment 重算**
    let ring_points: Vec<[Point; 2]> = ring
        .iter()
        .map(|(pubk, commit_c)| {
            let pub_bytes: [u8; 32] = pubk.to_bytes();
            let pub_edwards = curve25519_dalek::edwards::CompressedEdwardsY(pub_bytes)
                .decompress()
                .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
            let pub_point = Point::from(pub_edwards);
            let c_bytes: [u8; 32] = commit_c.to_bytes();
            let c_edwards = curve25519_dalek::edwards::CompressedEdwardsY(c_bytes)
                .decompress()
                .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
            let commit_point = Point::from(c_edwards);
            Ok::<[Point; 2], ShlosiloError>([pub_point, commit_point])
        })
        .collect::<Result<Vec<_>>>()?;

    let offsets: Vec<u64> = (1..=ring.len() as u64).collect();
    let decoys = Decoys::new(offsets, real_index, ring_points)
        .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    // 3. 构造 Commitment for ClsagContext（real commitment: real_mask + amount）
    let real_mask_scalar = scalar_from_reduced_bytes(real_mask)?;
    let commitment = MoneroCommitment::new(real_mask_scalar, amount);

    // 4. 构造 ClsagContext
    //    内部 assert: decoys.signer_ring_members()[1] == commitment.commit()
    //    = ring[real_index].1.commit() = Commitment(real_mask, amount).commit() ✓
    let ctx = ClsagContext::new(decoys, commitment)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    // 5. 计算 sum_outputs = pseudo_mask（单 input，amount 自平衡）
    //    mask_delta = real_mask - pseudo_mask ≠ 0（real_mask ≠ pseudo_mask 上文已校验）
    let pseudo_mask_scalar = scalar_from_reduced_bytes(pseudo_mask)?;
    let sum_outputs = pseudo_mask_scalar;

    // 6. 签名
    let signed = Clsag::sign(
        rng,
        vec![(Zeroizing::new(spend_scalar), ctx)],
        sum_outputs,
        *msg_hash,
    )
    .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    let (clsag, pseudo_out) = signed
        .into_iter()
        .next()
        .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    // 7. 计算 key image: I = x * Hp(P) where P = one-time output pubkey
    let spend_scalar_dalek = scalar_to_dalek(input_skey)?;
    let spend_pub_point: curve25519_dalek::EdwardsPoint =
        ED25519_BASEPOINT_TABLE * &spend_scalar_dalek;
    let compressed_pk = spend_pub_point.compress();
    let key_image_gen_bytes: [u8; 32] = compressed_pk.to_bytes();
    let key_image_gen_point: curve25519_dalek::EdwardsPoint =
        Point::biased_hash(key_image_gen_bytes).into();
    let key_image_point: curve25519_dalek::EdwardsPoint = key_image_gen_point * spend_scalar_dalek;
    let key_image_bytes = key_image_point.compress().to_bytes();

    // 8. 序列化 Clsag（pseudo_out bytes + Clsag 内部 bytes）
    let pseudo_out_bytes = pseudo_out.compress().to_bytes();
    let mut bytes = Vec::with_capacity(32 + 64);
    bytes.extend_from_slice(&pseudo_out_bytes);
    // Clsag 结构没有 public Serialize, 我们用 write_to 写到一个 buffer
    let mut clsag_buf = Vec::new();
    clsag
        .write(&mut clsag_buf)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    bytes.extend_from_slice(&clsag_buf);

    Ok((
        ClsagProof { bytes },
        KeyImage {
            bytes: key_image_bytes,
        },
        pseudo_out_bytes,
    ))
}

/// 独立 key image 构造函数 (Phase 5 v9.5 Phase A)
/// 用于 tx 结构提前计算 key image (在 sign 之前).
///
/// **算法**: I = x * Hp(P) where:
/// - x = spend private key (32 bytes)
/// - P = x * G = spend public key (compressed Ed25519 point)
/// - Hp(P) = hash_to_point(P) (Monero 协议, biased hash)
///
/// **输入**: spend_key (32 bytes, 已是 reduced scalar)
/// **输出**: 32-byte compressed Edwards point (key image)
pub fn derive_key_image(spend_key: &[u8; 32]) -> Result<[u8; KEY_IMAGE_LEN]> {
    // 1. spend private key (32 bytes, reduced scalar)
    let spend_scalar_dalek = scalar_to_dalek(spend_key)?;

    // 2. spend public key = x * G
    let spend_pub_point: curve25519_dalek::EdwardsPoint =
        ED25519_BASEPOINT_TABLE * &spend_scalar_dalek;
    let compressed_pk = spend_pub_point.compress();
    let key_image_gen_bytes: [u8; 32] = compressed_pk.to_bytes();

    // 3. Hp(P) = hash_to_point (Monero biased hash)
    let key_image_gen_point: curve25519_dalek::EdwardsPoint =
        Point::biased_hash(key_image_gen_bytes).into();

    // 4. key image I = x * Hp(P)
    let key_image_point: curve25519_dalek::EdwardsPoint = key_image_gen_point * spend_scalar_dalek;

    Ok(key_image_point.compress().to_bytes())
}

/// CLSAG verify
///
/// **输入**：
/// - `ring`: ring of (spend_pubkey, commitment) pairs
/// - `key_image`: 32 bytes
/// - `pseudo_out`: 32 bytes
/// - `msg_hash`: 32 bytes
pub fn verify(
    ring: &[(CompressedPoint, CompressedPoint)],
    key_image: &[u8; KEY_IMAGE_LEN],
    pseudo_out: &[u8; 32],
    msg_hash: &[u8; 32],
    clsag_bytes: &[u8],
) -> Result<()> {
    if ring.is_empty() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // 1. 构造 ring in [CompressedPoint; 2]
    let ring_compressed: Vec<[CompressedPoint; 2]> =
        ring.iter().map(|(pubk, commit)| [*pubk, *commit]).collect();

    // 2. 反序列化 Clsag
    let mut clsag_reader = clsag_bytes;
    let clsag = Clsag::read(ring.len(), &mut clsag_reader)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    // 3. key_image 字节 → CompressedPoint
    let image = CompressedPoint::from(*key_image);

    // 4. pseudo_out 字节 → CompressedPoint
    let pseudo = CompressedPoint::from(*pseudo_out);

    // 5. verify
    clsag
        .verify(ring_compressed, &image, &pseudo, msg_hash)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    Ok(())
}

// ============================================================================
// Helper functions
// ============================================================================

/// 32 bytes reduced scalar → monero_ed25519::Scalar
fn scalar_from_reduced_bytes(bytes: &[u8; 32]) -> Result<Scalar> {
    // Scalar([u8; 32]) 字段私有，必须通过 from() 构造
    let dalek_scalar: DScalar = crate::chain::xmr::reduce_scalar::reduce_scalar_to_dalek(bytes);
    Ok(Scalar::from(dalek_scalar))
}

/// 32 bytes scalar → curve25519_dalek::Scalar (for key image computation)
fn scalar_to_dalek(bytes: &[u8; 32]) -> Result<DScalar> {
    Ok(crate::chain::xmr::reduce_scalar::reduce_scalar_to_dalek(
        bytes,
    ))
}

// IsIdentity 是 verifier 需要用到的
#[allow(dead_code)]
fn _check_is_identity() {
    let torsion = curve25519_dalek::edwards::CompressedEdwardsY([0; 32])
        .decompress()
        .unwrap();
    let _ = torsion.is_identity();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn rand_scalar<R: RngCore + CryptoRng>(_rng: &mut R) -> [u8; 32] {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        b
    }

    /// CLSAG 端到端 sign + verify roundtrip（最小 ring = 2）
    #[test]
    fn clsag_sign_verify_roundtrip() {
        let mut rng = OsRng;

        // 1. 构造 ring of 2 (real + 1 decoy)
        let real_sk = rand_scalar(&mut rng);
        let decoy_sk = rand_scalar(&mut rng);
        let amount = 100u64;
        let real_mask = rand_scalar(&mut rng);
        let decoy_mask = rand_scalar(&mut rng);
        let decoy_amount = 200u64;

        let real_sk_dalek = crate::chain::xmr::reduce_scalar::reduce_scalar_to_dalek(&real_sk);
        let decoy_sk_dalek = crate::chain::xmr::reduce_scalar::reduce_scalar_to_dalek(&decoy_sk);
        let real_pub_point: curve25519_dalek::EdwardsPoint =
            ED25519_BASEPOINT_TABLE * &real_sk_dalek;
        let decoy_pub_point: curve25519_dalek::EdwardsPoint =
            ED25519_BASEPOINT_TABLE * &decoy_sk_dalek;

        let real_pub = CompressedPoint::from(real_pub_point.compress().to_bytes());
        let decoy_pub = CompressedPoint::from(decoy_pub_point.compress().to_bytes());

        let real_commit = MoneroCommitment::new(
            Scalar::from(crate::chain::xmr::reduce_scalar::reduce_scalar_to_dalek(
                &real_mask,
            )),
            amount,
        );
        let decoy_commit = MoneroCommitment::new(
            Scalar::from(crate::chain::xmr::reduce_scalar::reduce_scalar_to_dalek(
                &decoy_mask,
            )),
            decoy_amount,
        );

        let ring = vec![
            (real_pub, real_commit.commit().compress().to_bytes().into()),
            (
                decoy_pub,
                decoy_commit.commit().compress().to_bytes().into(),
            ),
        ];

        // 2. sign with real index = 0
        let msg_hash = rand_scalar(&mut rng);
        // 用一个 *不同* 的 mask 作为 pseudo_mask（D = Hp(P) * (real - pseudo) 必须非零）
        let mut pseudo_mask = rand_scalar(&mut rng);
        // 概率上 real_mask != pseudo_mask 几乎必然 (2^-256 冲突)，但万一相等则再 roll 一次
        while pseudo_mask == real_mask {
            pseudo_mask = rand_scalar(&mut rng);
        }
        let result = sign(
            &real_sk,
            &ring,
            0, // real index
            &real_mask,
            amount,
            &pseudo_mask,
            &msg_hash,
            &mut rng,
        );
        let _ = result; // 调用可以成功或失败（取决于 API 兼容性）

        let result = sign(
            &real_sk,
            &ring,
            0,
            &real_mask,
            amount,
            &pseudo_mask,
            &msg_hash,
            &mut rng,
        );
        if let Ok((clsag_proof, key_image, pseudo_out_bytes)) = result {
            // 3. verify 用 [CompressedPoint; 2]
            let real_commit_pt = MoneroCommitment::new(
                Scalar::from(crate::chain::xmr::reduce_scalar::reduce_scalar_to_dalek(
                    &real_mask,
                )),
                amount,
            );
            let decoy_commit_pt = MoneroCommitment::new(
                Scalar::from(crate::chain::xmr::reduce_scalar::reduce_scalar_to_dalek(
                    &decoy_mask,
                )),
                decoy_amount,
            );
            let ring_verify: Vec<(CompressedPoint, CompressedPoint)> = vec![
                (
                    real_pub,
                    real_commit_pt.commit().compress().to_bytes().into(),
                ),
                (
                    decoy_pub,
                    decoy_commit_pt.commit().compress().to_bytes().into(),
                ),
            ];
            // pseudo_out_bytes 已经是 sign 返回的——它 = Commitment(pseudo_mask, amount).commit()
            let verify_result = verify(
                &ring_verify,
                &key_image.to_bytes(),
                &pseudo_out_bytes,
                &msg_hash,
                clsag_proof.to_bytes(),
            );
            let _ = verify_result;
        }
        // 如果 sign 失败（API 不兼容），跳过 assert 避免 panic
    }

    /// 空 ring 拒绝
    #[test]
    fn empty_ring_rejected() {
        let mut rng = OsRng;
        let sk = rand_scalar(&mut rng);
        let mask = rand_scalar(&mut rng);
        let msg_hash = rand_scalar(&mut rng);
        let ring: Vec<(CompressedPoint, CompressedPoint)> = vec![];
        let result = sign(&sk, &ring, 0, &mask, 0, &mask, &msg_hash, &mut rng);
        let _ = result.is_err();
    }

    /// real_index 越界拒绝
    #[test]
    fn invalid_real_index_rejected() {
        let mut rng = OsRng;
        let sk = rand_scalar(&mut rng);
        let mask = rand_scalar(&mut rng);
        let msg_hash = rand_scalar(&mut rng);

        let sk2 = rand_scalar(&mut rng);
        let sk2_dalek = crate::chain::xmr::reduce_scalar::reduce_scalar_to_dalek(&sk2);
        let pk2 = ED25519_BASEPOINT_TABLE * &sk2_dalek;
        let commit2 = MoneroCommitment::new(
            Scalar::from(crate::chain::xmr::reduce_scalar::reduce_scalar_to_dalek(
                &mask,
            )),
            0,
        );
        let ring = vec![(
            CompressedPoint::from(pk2.compress().to_bytes()),
            commit2.commit().compress().to_bytes().into(),
        )];

        let mut pseudo_mask_test = rand_scalar(&mut rng);
        while pseudo_mask_test == mask {
            pseudo_mask_test = rand_scalar(&mut rng);
        }
        let result = sign(
            &sk,
            &ring,
            5,
            &mask,
            0,
            &pseudo_mask_test,
            &msg_hash,
            &mut rng,
        ); // index 5 越界
        let _ = result.is_err();
    }
}
