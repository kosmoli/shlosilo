//! P1-06 真实签名路径：unsigned_txset → signed tx
//!
//! 对齐 keystone transfer.rs::construct_tx + transfer_key.rs + monero wallet2 genRctSimple：
//! 1. tx_key = 随机标量 r；有 subaddress 输出时 tx_pub = r·B_sub（keystone transaction_keys）
//! 2. per-output: ECDH → shared_key = Hs(8Ra || varint(o))；
//!    mask = Hs("commitment_mask" || shared_key)；amount 加密 = Hs("amount"||shared_key)[..8] XOR
//! 3. extra = txpub (+ r·B_sub 若 subaddress 且无 additional keys) + payment_id XOR(change)
//! 4. BP+ over output commitments（bp_version=4 → RCTTypeBulletproofPlus, wire type=6）
//! 5. pseudo_out_i：pseudo_mask = sum_out_masks − real_mask_i，CLSAG 签名
//! 6. 组 prefix → msg_hash = keccak(prefix) → CLSAG → 完整 tx

extern crate alloc;

use crate::chain::xmr::rct_sig::prove_bulletproofs_plus;
use alloc::vec::Vec;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use monero_ed25519::CompressedPoint;
use rand_core::{CryptoRng, RngCore};

use crate::chain::xmr::clsag::{self as clsag_mod};
use crate::chain::xmr::subaddress::hash_to_scalar;
use crate::chain::xmr::transaction::{
    bytes_to_monerod_scalar, monero_encode_varint, monerod_scalar_to_bytes, TransactionPrefix, TxExtra, TxInput, TxOutput,
};
use crate::chain::xmr::unsigned_txset::{TxConstructionData, TxDestinationEntry};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

// monero-ed25519 Pedersen commitment（与 tx_builder 同一类型）
type MonCommitment = monero_ed25519::Commitment;

/// RingCT wire type：对齐 monero genRctSimple，bp_version∈{0,4} → BulletproofPlus(6)，
/// 3 → CLSAG/Bulletproof(5)。keystone construct_tx 同样在 bp4 用 prove_plus。
pub fn resolve_rct_type(bp_version: u64) -> Result<u8> {
    match bp_version {
        0 | 4 => Ok(6), // RCTTypeBulletproofPlus
        3 => Ok(5),     // RCTTypeCLSAG
        _ => Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)),
    }
}

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

fn bytes_to_scalar(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

/// per-output 派生（shared key + mask + encrypted amount）——keystone commitments_and_encrypted_amounts
struct OutputDerivation {
    /// 8Ra = r·A_v·8（或 change: view_sec·tx_pub·8）
    #[allow(dead_code)] // 预留给 P2 后续输出验证
    shared_key: [u8; 32],
    commitment_mask: [u8; 32],
    encrypted_amount: [u8; 8],
    stealth_address: [u8; 32],
    additional_tx_key: Option<[u8; 32]>,
    view_tag: u8,
}

/// 推导单个 output 的 ECDH 与 shared_key 等派生值
///
/// 对齐 keystone transfer_key.rs::ecdhs + serai output_derivations：
/// - 非 change 且非子地址：ecdh = r · A_v(dest)
/// - 非 change 且子地址：ecdh = r_i · A_v_sub（r_i 是 additional key；shlosilo 单
///   additional-key 模式 = 主 r 复用，见 tx_builder resolve_tx_output 注释）
/// - change（回自己）：ecdh = view_sec · TxPub（接收方视角推导，Keystone is_change_dest 分支）
fn derive_output(
    r: &Scalar,
    _view_sec: &[u8; 32],
    dest: &TxDestinationEntry,
    _tx_pub: &[u8; 32],
    index: usize,
) -> Result<OutputDerivation> {
    // ecdh 点
    let a_v_point: curve25519_dalek::EdwardsPoint = CompressedPoint::from(dest.view_public_key)
        .decompress()
        .ok_or_else(err)?
        .into();

    let ecdh_point = if dest.is_subaddress {
        // keystone: additional_keys.get(i).unwrap_or(tx_key)；单 input 无 add keys 时用 r
        a_v_point * *r
    } else {
        a_v_point * *r
    };

    // 8Ra = ecdh · cofactor(8)，压缩后 || varint(index)
    let eight_ra_pt = ecdh_point.mul_by_cofactor();
    let eight_ra = eight_ra_pt.compress().to_bytes();

    let mut od_data = Vec::with_capacity(33);
    od_data.extend_from_slice(&eight_ra);
    monero_encode_varint(&mut od_data, index as u64);

    let shared_key = hash_to_scalar(&od_data)?;

    // mask = Hs("commitment_mask" || shared_key)
    let mut mask_data = Vec::with_capacity(16 + 32);
    mask_data.extend_from_slice(b"commitment_mask");
    mask_data.extend_from_slice(&shared_key);
    let commitment_mask = hash_to_scalar(&mask_data)?;

    // enc amount = amount XOR Hs("amount"||shared_key)[..8] (LE)
    let mut amt_data = Vec::with_capacity(6 + 32);
    amt_data.extend_from_slice(b"amount");
    amt_data.extend_from_slice(&shared_key);
    let amt_mask = crate::encoding::keccak256::hash(&amt_data)?;
    let mut mask8 = [0u8; 8];
    mask8.copy_from_slice(&amt_mask[..8]);
    let xor_val = u64::from_le_bytes(mask8);
    let encrypted_amount = (dest.amount ^ xor_val).to_le_bytes();

    // stealth = B_dest + Hs(8Ra||varint(idx))·G（monero one-time address，仅非 change 需要）
    // 对 subaddress 的 B 已是 B_sub；change 也一样走标准公式
    let hs_out = hash_to_scalar(&od_data)?; // 同 shared_key（Hs(8Ra||o) 即 derivation split）
    let hs_scalar = bytes_to_scalar(&hs_out);
    let b_dest: curve25519_dalek::EdwardsPoint = CompressedPoint::from(dest.spend_public_key)
        .decompress()
        .ok_or_else(err)?
        .into();
    let stealth_pt = b_dest + ED25519_BASEPOINT_TABLE * &hs_scalar;
    let stealth_address = stealth_pt.compress().to_bytes();

    // view tag = keccak("view_tag" || 8Ra || varint(o))[0]
    let mut vt_data = Vec::with_capacity(9 + 33);
    vt_data.extend_from_slice(b"view_tag");
    vt_data.extend_from_slice(&eight_ra);
    monero_encode_varint(&mut vt_data, index as u64);
    let vtag_full = crate::encoding::keccak256::hash(&vt_data)?;
    let view_tag = vtag_full[0];

    // 子地址时 additional key = r·B_sub（keystone should_use_additional_keys=false 路径：
    // tx_pub 本身 = r·B_sub。这里采用 shlosilo tx_builder 惯例：additional key 记录 r·B_sub）
    let additional_tx_key = if dest.is_subaddress {
        let b_sub: curve25519_dalek::EdwardsPoint =
            CompressedPoint::from(dest.spend_public_key)
                .decompress()
                .ok_or_else(err)?
                .into();
        Some((b_sub * *r).compress().to_bytes())
    } else {
        None
    };

    Ok(OutputDerivation {
        shared_key,
        commitment_mask,
        encrypted_amount,
        stealth_address,
        additional_tx_key,
        view_tag,
    })
}

/// payment_id_xor = keccak(8Ra || 0x8d)[..8]
fn payment_id_xor(ecdh_view_times_tx_pub: &[u8; 32]) -> [u8; 8] {
    let mut data = Vec::with_capacity(33);
    data.extend_from_slice(ecdh_view_times_tx_pub);
    data.push(0x8d);
    let h = crate::encoding::keccak256::hash(&data).unwrap_or([0u8; 32]);
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}

/// 从 TxConstructionData 构造并签名完整交易（P1-06 核心入口）
///
/// **输入**:
/// - tx_data: 解析后的 unsigned tx 构造数据（一个 tx）
/// - spend_sec / view_sec: 派生出的钱包密钥
/// - rng: 随机源（L3 注入；真机 = TRNG）
///
/// **输出**: 完整签名的 Transaction（wire 格式直接可用）
pub fn sign_tx_from_construction<R: RngCore + CryptoRng + Clone>(
    tx_data: &TxConstructionData,
    spend_sec: &[u8; 32],
    view_sec: &[u8; 32],
    rng: &mut R,
) -> Result<Vec<u8>> {
    // 便捷包装：r 现场随机生成（§B.5 目的子域由调用方决定时用 _with_rngs 版本）。
    // 单一 rng 时按顺序消费：先 32B 给 r，剩余流供 BP+/CLSAG（兼容旧行为）。
    let mut r_bytes = [0u8; 32];
    rng.fill_bytes(&mut r_bytes);
    let r = Scalar::from_bytes_mod_order(r_bytes);
    let mut rng2 = rng.clone();
    sign_tx_from_construction_with_rngs(tx_data, spend_sec, view_sec, &r, rng, &mut rng2)
}

/// 核心签名（§B.5 定案）：tx_key r 由调用方注入（purpose 子域派生），
/// bp_rng 供 Bulletproof+，clsag_rng 供 CLSAG（per-input 子域在调用方拆分；
/// v1 单输入时传入 Clsag(0) 派生流即可）。
pub fn sign_tx_from_construction_with_rngs<B: RngCore + CryptoRng, C: RngCore + CryptoRng>(
    tx_data: &TxConstructionData,
    spend_sec: &[u8; 32],
    view_sec: &[u8; 32],
    r: &Scalar,
    bp_rng: &mut B,
    clsag_rng: &mut C,
) -> Result<Vec<u8>> {
    if tx_data.splitted_dsts.is_empty() || tx_data.sources.is_empty() {
        return Err(err());
    }
    let rct_type = resolve_rct_type(tx_data.rct_config.bp_version)?;

    // r 由调用方注入（§B.5：TxKey purpose 子域派生）
    // 有 subaddress 输出且无 additional keys 时：tx_pub = r·B_sub
    // （keystone transaction_keys has_payments_to_subaddresses 分支）
    let has_subaddress_dest = tx_data.splitted_dsts.iter().any(|d| d.is_subaddress);
    let tx_pub_point = if has_subaddress_dest {
        // keystone 用第一个 subaddress 输出的 B
        let b_sub_bytes = tx_data
            .splitted_dsts
            .iter()
            .find(|d| d.is_subaddress)
            .map(|d| d.spend_public_key)
            .unwrap();
        let b_sub: curve25519_dalek::EdwardsPoint = CompressedPoint::from(b_sub_bytes)
            .decompress()
            .ok_or_else(err)?
            .into();
        b_sub * r
    } else {
        ED25519_BASEPOINT_TABLE * r
    };
    let tx_pub = tx_pub_point.compress().to_bytes();

    // ---- 2. per-output 派生（keystone commitments_and_encrypted_amounts）----
    // change_dts 是"回自己"——ecdh = view_sec · TxPub（is_change_dest 分支）
    let change_ecdh_pt = {
        let v_scalar = bytes_to_scalar(view_sec);
        tx_pub_point * v_scalar
    };
    let change_eight_ra = change_ecdh_pt.mul_by_cofactor().compress().to_bytes();

    let mut outs: Vec<OutInfo> = Vec::with_capacity(tx_data.splitted_dsts.len());

    for (i, dest) in tx_data.splitted_dsts.iter().enumerate() {
        let is_change = dest.amount == tx_data.change_dts.amount
            && dest.spend_public_key == tx_data.change_dts.spend_public_key;
        if is_change {
            // change 走 view_sec·TxPub 路径：手工派生（derive_output 的 r·A_v 不适用）
            let shared_key = {
                let mut od = Vec::with_capacity(33);
                od.extend_from_slice(&change_eight_ra);
                monero_encode_varint(&mut od, i as u64);
                hash_to_scalar(&od)?
            };
            let commitment_mask = {
                let mut md = Vec::with_capacity(48);
                md.extend_from_slice(b"commitment_mask");
                md.extend_from_slice(&shared_key);
                hash_to_scalar(&md)?
            };
            let encrypted_amount = {
                let mut ad = Vec::with_capacity(38);
                ad.extend_from_slice(b"amount");
                ad.extend_from_slice(&shared_key);
                let h = crate::encoding::keccak256::hash(&ad)?;
                let m8 = u64::from_le_bytes(h[..8].try_into().unwrap());
                (dest.amount ^ m8).to_le_bytes()
            };
            // stealth（change 也输出 onetime address）
            let hs_scalar = bytes_to_scalar(&shared_key);
            let b_dest: curve25519_dalek::EdwardsPoint =
                CompressedPoint::from(dest.spend_public_key)
                    .decompress()
                    .ok_or_else(err)?
                    .into();
            let stealth_address =
                (b_dest + ED25519_BASEPOINT_TABLE * &hs_scalar).compress().to_bytes();
            // view tag
            let mut vt = Vec::with_capacity(42);
            vt.extend_from_slice(b"view_tag");
            vt.extend_from_slice(&change_eight_ra);
            monero_encode_varint(&mut vt, i as u64);
            let vt_full = crate::encoding::keccak256::hash(&vt)?;
            outs.push(OutInfo {
                deriv: OutputDerivation {
                    shared_key,
                    commitment_mask,
                    encrypted_amount,
                    stealth_address,
                    additional_tx_key: None,
                    view_tag: vt_full[0],
                },
                is_change: true,
                dest: dest.clone(),
                eight_ra_for_pid: Some(change_eight_ra),
            });
        } else {
            let deriv = derive_output(r, view_sec, dest, &tx_pub, i)?;
            outs.push(OutInfo {
                deriv,
                is_change: false,
                dest: dest.clone(),
                eight_ra_for_pid: None,
            });
        }
    }

    // ---- 3. extra（txpub + additional keys + payment_id XOR(change)）----
    let mut extra = TxExtra::new().with_tx_pub_key(tx_pub);
    for o in &outs {
        if !o.is_change {
            if let Some(add) = o.deriv.additional_tx_key {
                extra = extra.with_additional_pub_key(add);
            }
        }
    }
    // splitted_dsts.len()==2 且有 change → 加密 payment_id 进 extra（keystone extra()）
    // fixture 里 change 是主地址，其 payment_id_xors 来自 view_sec·TxPub 的 8Ra XOR 全零 pid
    if tx_data.splitted_dsts.len() == 2 {
        if let Some(o) = outs.iter().find(|o| o.is_change) {
            if let Some(e8ra) = o.eight_ra_for_pid {
                let xor = payment_id_xor(&e8ra);
                let zero_pid = [0u8; 8];
                let enc_pid = zero_pid
                    .iter()
                    .zip(xor.iter())
                    .map(|(a, b)| a ^ b)
                    .collect::<Vec<u8>>();
                let mut enc8 = [0u8; 8];
                enc8.copy_from_slice(&enc_pid);
                extra = extra.with_encrypted_payment_id(enc8);
            }
        }
    }

    // ---- 4. outputs ----
    let mut tx_outputs = Vec::with_capacity(outs.len());
    for o in &outs {
        tx_outputs.push(TxOutput::new_tagged(
            0, // RCT 交易 wire/prefix 中 vout amount 一律 0（真实金额在 ecdhInfo）
            o.deriv.stealth_address,
            o.deriv.view_tag,
        ));
    }

    // ---- 5. inputs: key_offsets(relative) + key images ----
    let mut tx_inputs = Vec::with_capacity(tx_data.sources.len());
    let mut input_real_masks: Vec<[u8; 32]> = Vec::with_capacity(tx_data.sources.len());
    let mut rings: Vec<Vec<(CompressedPoint, CompressedPoint)>> =
        Vec::with_capacity(tx_data.sources.len());
    let mut input_key_offsets: Vec<[u8; 32]> = Vec::with_capacity(tx_data.sources.len());
    for src in &tx_data.sources {
        // key offsets：绝对→相对（monero absolute_output_offsets_to_relative，升序差分）
        let mut offs: Vec<u64> = src.outputs.iter().map(|o| o.index).collect();
        offs.sort_unstable();
        for i in (1..offs.len()).rev() {
            offs[i] -= offs[i - 1];
        }
        let (key_image, key_offset) = crate::chain::xmr::subaddress::derive_input_from_source(
            view_sec,
            spend_sec,
            src,
            tx_data.subaddr_account,
            &tx_data.subaddr_indices,
        )?;
        tx_inputs.push(TxInput::new(offs.clone(), key_image));
        input_real_masks.push(src.mask); // TxSourceEntry.mask = real output 的真 blinding factor
        // （OutputEntry.mask 是链上 C 点；real_entry.mask 被当作 blinding 重算是错的）
        input_key_offsets.push(key_offset);
        // ring members：(dest 一次性地址, 链上 commitment C 点字节)。
        // OutputEntry.mask = 链上 outPk commitment（不是 blinding factor），直接当点用，
        // monerod verify 时也从链上取同样的 C——两侧输入必须逐字节一致。
        let ring: Vec<(CompressedPoint, CompressedPoint)> = src
            .outputs
            .iter()
            .map(|o| (CompressedPoint::from(o.dest), CompressedPoint::from(o.mask)))
            .collect();
        rings.push(ring);
    }

    // ---- 6. prefix hash（CLSAG message 还需叠加 rct base + BP 元素，见 step 8）----
    let prefix = TransactionPrefix::new(0, tx_inputs.clone(), tx_outputs.clone(), extra.clone());
    // Serialize once and reuse these exact bytes for both the CLSAG message and
    // final wire. This invariant is consensus-critical: even a valid field
    // omitted only from the hash-side serializer makes the signature unverifiable.
    let prefix_bytes = prefix.serialize();
    let prefix_hash = crate::encoding::keccak256::hash(&prefix_bytes)?;

    // ---- 7. BP+ over output commitments ----
    let commitments: Vec<MonCommitment> = outs
        .iter()
        .map(|o| {
            MonCommitment::new(
                bytes_to_monerod_scalar(&o.deriv.commitment_mask),
                o.dest.amount,
            )
        })
        .collect();
    let bp = prove_bulletproofs_plus(bp_rng, commitments.clone())?;
    // Σ out masks：curve25519_dalek 标量域算术，再转回 monero 字节
    let mut sum_out_masks = curve25519_dalek::Scalar::from_bytes_mod_order(
        monerod_scalar_to_bytes(&bytes_to_monerod_scalar(&outs[0].deriv.commitment_mask)),
    );
    for o in &outs[1..] {
        let m = curve25519_dalek::Scalar::from_bytes_mod_order(monerod_scalar_to_bytes(
            &bytes_to_monerod_scalar(&o.deriv.commitment_mask),
        ));
        sum_out_masks += m;
    }

    // ---- 8. full_message = H(prefix_hash ‖ H(rct_base) ‖ H(BP+ fields)) ----
    // 官方 get_pre_mlsag_hash 先按 A,A1,B,r1,s1,d1,L*,R* 拼接并哈希 BP+，
    // 再对三个 32B hash 做最终 cn_fast_hash；signature_write 提供无 count 的字段串。
    let rct_base_bytes = {
        let mut b = Vec::new();
        b.push(rct_type);
        monero_encode_varint(&mut b, compute_fee(tx_data));
        for o in &outs {
            b.extend_from_slice(&o.deriv.encrypted_amount);
        }
        for o in &outs {
            let c = MonCommitment::new(
                bytes_to_monerod_scalar(&o.deriv.commitment_mask),
                o.dest.amount,
            );
            b.extend_from_slice(&c.commit().compress().to_bytes());
        }
        b
    };
    let rct_base_hash = crate::encoding::keccak256::hash(&rct_base_bytes)?;
    let mut bp_sig_bytes = Vec::new();
    bp.signature_write(&mut bp_sig_bytes).map_err(|_| {
        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
    })?;
    // get_pre_mlsag_hash hashes the flattened BP+ fields first, then hashes
    // exactly three 32-byte keys: prefix hash, base hash, and BP+ fields hash.
    let bp_sig_hash = crate::encoding::keccak256::hash(&bp_sig_bytes)?;
    let mut full_msg_in = Vec::with_capacity(96);
    full_msg_in.extend_from_slice(&prefix_hash);
    full_msg_in.extend_from_slice(&rct_base_hash);
    full_msg_in.extend_from_slice(&bp_sig_hash);
    let msg_hash = crate::encoding::keccak256::hash(&full_msg_in)?;

    // ---- 9. CLSAG per input：pseudo_mask = Σout_masks（monero-clsag sum_outputs 语义）----
    let mut clsag_wire: Vec<Vec<u8>> = Vec::with_capacity(tx_data.sources.len());
    let mut pseudo_outs_arr: Vec<[u8; 32]> = Vec::with_capacity(tx_data.sources.len());

    // P1-06 范围：单输入（fixture 即单输入）；多输入排期后续
    if tx_data.sources.len() != 1 {
        return Err(err());
    }
    for (i, (src, ring)) in tx_data.sources.iter().zip(rings.iter()).enumerate() {
        // 单输入：monero-clsag sign(sum_outputs) 语义 = Σ output masks；
        // 最后一个 input 的 pseudo_mask 由库计算为 sum_outputs − Σprev ⇒ 单输入时 = Σout_masks。
        // （官方 genRctSimple: a[last] = Σout_masks − Σprev_pseudo；balance 自然成立）
        let pseudo_mask_bytes: [u8; 32] = sum_out_masks.to_bytes();
        let real_mask_bytes = input_real_masks[i];

        // CLSAG 签名私钥 = one-time input sk（spend + key_offset），非裸 spend key
        let input_sk =
            crate::chain::xmr::subaddress::derive_input_spend_key(spend_sec, &input_key_offsets[i])?;
        let (clsag_proof, _ki, pseudo_out_bytes) = clsag_mod::sign(
            &input_sk,
            ring,
            src.real_output as u8,
            &real_mask_bytes,
            src.amount,
            &pseudo_mask_bytes,
            &msg_hash,
            clsag_rng,
        )?;
        // proof.bytes 布局 = pseudo_out(32) ‖ s[mixin+1] ‖ c1(32) ‖ D(32)
        let body: Vec<u8> = clsag_proof.wire_body().to_vec();
        debug_assert_eq!(clsag_proof.to_bytes().len(), 32 + rings[i].len() * 32 + 64);
        clsag_wire.push(body);
        pseudo_outs_arr.push(pseudo_out_bytes);
    }

    // ---- 10. 官方 monerod wire 序列化 ----
    let bp_buf = {
        let mut b = Vec::new();
        bp.write(&mut b)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
        b
    };
    build_official_wire(
        &prefix_bytes,
        &rct_base_bytes,
        &bp_buf,
        &clsag_wire,
        &pseudo_outs_arr,
    )
}

/// fee = inputs − splitted outputs（change 在 splitted 里已含）
fn compute_fee(tx_data: &TxConstructionData) -> u64 {
    let input_sum: u64 = tx_data.sources.iter().map(|s| s.amount).sum();
    let out_sum: u64 = tx_data.splitted_dsts.iter().map(|d| d.amount).sum();
    input_sum.saturating_sub(out_sum)
}

struct OutInfo {
    deriv: OutputDerivation,
    is_change: bool,
    dest: TxDestinationEntry,
    eight_ra_for_pid: Option<[u8; 32]>,
}

/// 组装官方 monerod wire 格式交易（P1-06 oracle 驱动逆向确认的 binary_archive 布局）
///
/// 层次：`prefix ‖ rct_base ‖ prunable`，无总长前缀；ecdhInfo/outPk/CLSAGs/pseudoOuts
/// 数组均**无 count 前缀**（binary_archive `begin_array()` 无参重载）；vin 有 variant
/// tag 0x02 与 VARINT amount；vout amount 用 VARINT。
fn build_official_wire(
    prefix_bytes: &[u8],
    rct_base_bytes: &[u8],
    bp_buf: &[u8],
    clsag_wire: &[Vec<u8>],
    pseudo_outs: &[[u8; 32]],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(4096);
    // ---- prefix ----
    // These are the same bytes used above to compute prefix_hash.
    out.extend_from_slice(prefix_bytes);
    // ---- rct base ----
    // These are likewise the exact bytes hashed into rct_base_hash.
    out.extend_from_slice(rct_base_bytes);
    // ---- prunable ----
    // BP+: nbp(varint) + raw proof bytes
    monero_encode_varint(&mut out, 1); // 单个聚合 BP+
    out.extend_from_slice(bp_buf);
    // CLSAGs（无 count，元素由 mixin+1 推断）：s[16]‖c1‖D
    for w in clsag_wire {
        out.extend_from_slice(w);
    }
    // pseudoOuts（无 count）
    for po in pseudo_outs {
        out.extend_from_slice(po);
    }
    Ok(out)
}
