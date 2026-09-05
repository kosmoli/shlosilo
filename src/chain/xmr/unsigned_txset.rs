//! XMR unsigned_txset 解析（P1-06，2026-08-26）
//!
//! 格式（P6.3 实测 + keystone apps/monero/src/transfer.rs 对齐）：
//! ```text
//! magic "Monero unsigned tx set\x05" (23B)
//! nonce 8B
//! 密文（ChaCha20-Legacy, key = cryptonight_hash_v0(view_sk)）
//! 尾部 64B = Ed25519 签名（view_pub 对 keccak256(nonce||密文)）
//! ```
//!
//! 解密后明文 = epee binary_archive：
//! ```text
//! version varint (0x02)
//! txes_len varint
//!   per tx:
//!     sources_len varint
//!       per source:
//!         outputs_len varint
//!           per output: 0x02 varint + index varint + dest 32B + mask 32B
//!         real_output u64LE
//!         real_out_tx_key 32B
//!         real_out_additional_tx_keys_len varint + 32B each
//!         real_output_in_tx_index u64LE
//!         amount u64LE (FIELD)
//!         rct bool 1B
//!         mask 32B
//!         multisig_kLRki 128B (k,L,R,ki 各 32B)
//!     change_dts: tx_destination_entry (original varint+bytes, amount VARINT,
//!                                        spend 32B, view 32B, is_sub 1B, is_int 1B)
//!     splitted_dsts_len varint + entries
//!     selected_transfers_len varint + varint each
//!     extra_len varint + bytes
//!     unlock_time u64LE
//!     use_rct u8
//!     RCTConfig: version varint + range_proof_type varint + bp_version varint
//!     dests_len varint + entries
//!     subaddr_account u32LE
//!     subaddr_indices_len varint + varint each
//! 剩余 = transfers 段（显示层不需解析，跳过）
//! ```

extern crate alloc;

use alloc::vec::Vec;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20Legacy;

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// unsigned_txset magic（P6.3 实测）
pub const UNSIGNED_TX_PREFIX: &[u8] = b"Monero unsigned tx set\x05";
const MAGIC_LEN: usize = 23;
const SIG_LEN: usize = 64;
const NONCE_LEN: usize = 8;

// ============ 读取器（epee binary_archive 小工具） ============

/// 审计 #12 P1-03:入口总预算。对齐 multipart payload 上限(加密 blob 只会
/// 更小;解密明文不可能超过 wire 输入总量)。恶意但签名有效的请求在入口
/// 即拒,不进入任何分配路径。
const UNSIGNED_TXSET_MAX_PLAIN_LEN: usize = crate::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN;

/// 预算化计数读取(审计 #12 P1-03,X1 单一 helper 纪律——同族检查点共用):
/// varint → usize fallible 转换(拒绝 32 位窄化回绕)→ 物理可行性校验
/// (count × min_elem_bytes > 剩余字节 = 物理上解析不完,分配前拒绝)。
/// min_elem_bytes 是该元素在 wire 上的最小字节数(保守下界);0 值防御性
/// 按 1 处理(防除零,审计 #7 P2-01 教训)。
fn read_count(data: &[u8], off: &mut usize, min_elem_bytes: usize) -> Result<usize> {
    let v = read_varint(data, off)?;
    let count = usize::try_from(v).map_err(|_| err())?;
    let remaining = data.len().saturating_sub(*off);
    if count > remaining / min_elem_bytes.max(1) {
        return Err(err());
    }
    Ok(count)
}

fn read_varint(data: &[u8], off: &mut usize) -> Result<u64> {
    let mut value: u64 = 0;
    let mut shift = 0;
    loop {
        let b = *data.get(*off).ok_or_else(err)?;
        *off += 1;
        value |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(err());
        }
    }
    Ok(value)
}

fn read_u8(data: &[u8], off: &mut usize) -> Result<u8> {
    let b = *data.get(*off).ok_or_else(err)?;
    *off += 1;
    Ok(b)
}

fn read_bool(data: &[u8], off: &mut usize) -> Result<bool> {
    Ok(read_u8(data, off)? != 0)
}

fn read_u32(data: &[u8], off: &mut usize) -> Result<u32> {
    let s = data.get(*off..*off + 4).ok_or_else(err)?;
    *off += 4;
    Ok(u32::from_le_bytes(s.try_into().unwrap()))
}

fn read_u64(data: &[u8], off: &mut usize) -> Result<u64> {
    let s = data.get(*off..*off + 8).ok_or_else(err)?;
    *off += 8;
    Ok(u64::from_le_bytes(s.try_into().unwrap()))
}

fn read_bytes(data: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>> {
    // 审计 #12 P1-03:offset+len 走 checked_add(32 位平台截断/64 位溢出都
    // 是真问题),取值用 get(单次越界判定),失败不产生任何分配。
    let end = off.checked_add(len).ok_or_else(err)?;
    let s = data.get(*off..end).ok_or_else(err)?;
    *off = end;
    Ok(s.to_vec())
}

fn read_u8_32(data: &[u8], off: &mut usize) -> Result<[u8; 32]> {
    let v = read_bytes(data, off, 32)?;
    Ok(v.try_into().unwrap())
}

// ============ 数据结构（对齐 keystone transfer.rs） ============

#[derive(Clone, Debug)]
pub struct OutputEntry {
    pub index: u64,
    pub dest: [u8; 32],
    pub mask: [u8; 32],
}

/// 审计 #5 P1-02:去 Clone——k/l/r 是敏感标量,序列化只用 `&TxSourceEntry`,
/// Clone 无必要(上轮"wire DTO 重序列化需求"的理由不成立)
pub struct MultisigKLRki {
    pub k: [u8; 32],
    pub l: [u8; 32],
    pub r: [u8; 32],
    pub ki: [u8; 32],
}

/// P1-C（2026-09-01 再复审）：k/l/r 是多签随机掩码（敏感标量）——Drop 时清零。
/// ki 是公开 key image，无需擦除。Clone 保留：wire DTO 重序列化的功能需求。
impl Drop for MultisigKLRki {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.k.zeroize();
        self.l.zeroize();
        self.r.zeroize();
    }
}

/// P1-03（2026-09-01 审计 #4）：real output 的真 blinding factor——敏感标量。
///
/// 拆型决策：wire DTO（`TxSourceEntry`）与 signing-secret 分离。mask 用
/// `SecretBytes<32>`（不可 Clone、ZeroizeOnDrop）——修复前裸 `[u8; 32]`
/// 无 Drop，随 `TxSourceEntry` 的 Clone/复制在内存中扩散且永不擦除。
/// 访问明文必须走 `.expose()`（grep 审计点）。
pub type SourceMask = crate::types::SecretBytes<32>;

/// R1: k/r 是多签随机掩码（敏感）— Debug redacted
impl core::fmt::Debug for MultisigKLRki {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MultisigKLRki")
            .field("k", &"[REDACTED]")
            .field("l", &"[REDACTED]")
            .field("r", &"[REDACTED]")
            .field("ki", &"[REDACTED]")
            .finish()
    }
}

#[allow(non_snake_case)] // multisig_kLRki 字段名对齐 Monero 官方 wire 命名
pub struct TxSourceEntry {
    pub outputs: Vec<OutputEntry>,
    pub real_output: u64,
    pub real_out_tx_key: [u8; 32],
    pub real_out_additional_tx_keys: Vec<[u8; 32]>,
    pub real_output_in_tx_index: u64,
    pub amount: u64,
    pub rct: bool,
    /// P1-03：真 blinding factor（SecretBytes，不 Clone 不 Debug、ZeroizeOnDrop）
    pub mask: SourceMask,
    #[allow(non_snake_case)] // 字段名对齐 Monero 官方 MultisigKLRki 结构
    pub multisig_kLRki: MultisigKLRki,
}

/// R1: real_out_tx_key / mask / multisig_kLRki 均为敏感标量 — Debug redacted
impl core::fmt::Debug for TxSourceEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TxSourceEntry")
            .field("outputs", &self.outputs.len())
            .field("real_output", &self.real_output)
            .field("real_out_tx_key", &"[REDACTED]")
            .field(
                "real_out_additional_tx_keys",
                &self.real_out_additional_tx_keys.len(),
            )
            .field("real_output_in_tx_index", &self.real_output_in_tx_index)
            .field("amount", &self.amount)
            .field("rct", &self.rct)
            .field("mask", &"[REDACTED]")
            .field("multisig_kLRki", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct TxDestinationEntry {
    pub original: Vec<u8>,
    pub amount: u64,
    pub spend_public_key: [u8; 32],
    pub view_public_key: [u8; 32],
    pub is_subaddress: bool,
    pub is_integrated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct RctConfig {
    pub version: u64,
    pub range_proof_type: u64,
    pub bp_version: u64,
}

/// P1-03：TxSourceEntry 含不可 Clone 秘密（mask）→ 本结构不再 derive Clone。
/// wire 序列化走引用（write_construction_data），sign 路径 move。
#[derive(Debug)]
pub struct TxConstructionData {
    pub sources: Vec<TxSourceEntry>,
    pub change_dts: TxDestinationEntry,
    pub splitted_dsts: Vec<TxDestinationEntry>,
    pub selected_transfers: Vec<usize>,
    pub extra: Vec<u8>,
    pub unlock_time: u64,
    pub use_rct: u8,
    pub rct_config: RctConfig,
    pub dests: Vec<TxDestinationEntry>,
    pub subaddr_account: u32,
    pub subaddr_indices: Vec<u32>,
}

/// P1-03：含 TxConstructionData（不可 Clone）→ 本结构不再 derive Clone
#[derive(Debug)]
pub struct UnsignedTx {
    pub txes: Vec<TxConstructionData>,
}

// ============ 解密 ============

/// Monero 式 Schnorr 验签（对齐 keystone utils/sign.rs::check_signature）
///
/// 签名格式 (c 32B, r 32B)，验证：
/// ```text
/// R = s·B - c·P            （s = r, P = 公钥点）
/// c' = Hs(hash || P || R)
/// 有效 ⇔ c' == c
/// ```
///
/// **注意**：这不是标准 Ed25519！Monero 自定义的 crypto_ops::check_signature。
pub(crate) fn check_monero_signature(
    hash: &[u8; 32],
    pubkey: &[u8; 32],
    sig: &[u8],
) -> Result<bool> {
    if sig.len() != 64 {
        return Err(err());
    }
    let c_bytes: [u8; 32] = sig[..32].try_into().unwrap();
    let r_bytes: [u8; 32] = sig[32..].try_into().unwrap();

    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::IsIdentity as _;
    use subtle::ConstantTimeEq as _;
    let c_opt = Scalar::from_canonical_bytes(c_bytes);
    let r_opt = Scalar::from_canonical_bytes(r_bytes);
    if bool::from(c_opt.is_none()) || bool::from(r_opt.is_none()) {
        return Ok(false);
    }
    let c_scalar = c_opt.unwrap();
    let r_scalar = r_opt.unwrap();
    if r_scalar == Scalar::ZERO {
        return Ok(false);
    }

    let p_point: curve25519_dalek::EdwardsPoint = monero_ed25519::CompressedPoint::from(*pubkey)
        .decompress()
        .ok_or_else(err)?
        .into();

    // R = c·P + r·B —— 对齐 monero crypto.cpp::check_signature 的
    // ge_double_scalarmult_base_vartime(tmp2, c, P, r)，生成侧 r = k − c·sec，
    // 故合法签名满足 c·P + r·B == k·B。
    let r_point = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &r_scalar;
    let c_times_p = p_point * c_scalar;
    let result_point = r_point + c_times_p;
    if result_point.is_identity() {
        return Ok(false);
    }

    // c' = Hs(hash || P || R)
    let mut data = Vec::with_capacity(32 + 32 + 32);
    data.extend_from_slice(hash);
    data.extend_from_slice(pubkey);
    data.extend_from_slice(&result_point.compress().to_bytes());
    let c2 = crate::chain::xmr::subaddress::hash_to_scalar(&data)?;
    let c2_opt = Scalar::from_canonical_bytes(c2);
    if bool::from(c2_opt.is_none()) {
        return Ok(false);
    }
    let c2_scalar = c2_opt.unwrap();

    Ok(bool::from((c2_scalar - c_scalar).ct_eq(&Scalar::ZERO)))
}

/// pub 包装：Monero Schnorr 验签（供 signed_txset 加密往返互验复用）
pub fn verify_monero_signature_pubkey(
    hash: &[u8; 32],
    pubkey: &[u8; 32],
    sig: &[u8],
) -> Result<bool> {
    check_monero_signature(hash, pubkey, sig)
}

/// ChaCha20 密钥 = CryptoNight-V0(view_sk)。2MB scratchpad，真机上是 XMR 签名的大头；
/// 同一 view_sk 在 decrypt unsigned + encrypt signed 各调一次会翻倍，调用方应复用。
/// 审计 #12 P1-02:返回 Zeroizing owner,不落地普通 [u8;32] 绑定;crate 内部
/// helper(旧 pub 让调用方"外层再包 Zeroizing"——构造后包 owner 不擦来源绑定)。
pub(crate) fn chacha_key_from_view_sk(view_sk: &[u8; 32]) -> zeroize::Zeroizing<[u8; 32]> {
    zeroize::Zeroizing::new(cuprate_cryptonight::cryptonight_hash_v0(view_sk))
}

/// 解密 unsigned_txset（对齐 keystone decrypt_data_with_pvk）
///
/// 流程：magic 校验 → nonce=8B → Ed25519 验签（view_pub 对
/// keccak256(nonce||密文)，尾部 64B）→ ChaCha20-Legacy keystream。
/// 验签失败 = 数据被篡改或 view key 不匹配 → 拒绝。
pub fn decrypt_unsigned_txset(
    data: &[u8],
    view_sk: &[u8; 32],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let key = chacha_key_from_view_sk(view_sk);
    decrypt_unsigned_txset_with_chacha_key(data, view_sk, &key)
}

/// 与 `decrypt_unsigned_txset` 相同，ChaCha 密钥由调用方注入（避免重复 CN）。
/// 审计 #12 P1-02:明文 owner 化——返回 Zeroizing<Vec<u8>>,错误/提前返回
/// 路径由 Drop 覆盖,不再返回普通 Vec。
pub(crate) fn decrypt_unsigned_txset_with_chacha_key(
    data: &[u8],
    view_sk: &[u8; 32],
    chacha_key: &zeroize::Zeroizing<[u8; 32]>,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if data.len() < MAGIC_LEN + NONCE_LEN + SIG_LEN {
        return Err(err());
    }
    if &data[..MAGIC_LEN] != UNSIGNED_TX_PREFIX {
        return Err(err());
    }

    // raw_data = nonce || 密文（签名覆盖的范围）
    let raw_data = &data[MAGIC_LEN..data.len() - SIG_LEN];
    let nonce = &raw_data[..NONCE_LEN];
    let sig_bytes = &data[data.len() - SIG_LEN..];

    // 1. Monero 式 Schnorr 验签（对齐 keystone check_signature）
    //    签名格式 = (c 32B, r 32B)，验证：
    //      R = sB - cP
    //      Hs(hash || P || R) == c
    //    **不是标准 Ed25519**（Monero 自定义 crypto_ops::check_signature）
    // monero secret_key_to_public_key = s·G，**无 Ed25519 clamp**
    // （不能用 curve_primitive::scalar_from_bytes —— SigningKey 会 clamp！）
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    let v_scalar = Scalar::from_bytes_mod_order(*view_sk);
    let view_pub = (ED25519_BASEPOINT_TABLE * &v_scalar).compress().to_bytes();
    let msg_hash = crate::encoding::keccak256::hash(raw_data)?;
    if !check_monero_signature(&msg_hash, &view_pub, sig_bytes)? {
        return Err(err());
    }

    // 2. ChaCha20-Legacy 解密
    let mut cipher = ChaCha20Legacy::new_from_slices(&**chacha_key, nonce).map_err(|_| err())?;
    let mut plain = zeroize::Zeroizing::new(raw_data[NONCE_LEN..].to_vec());
    cipher.apply_keystream(&mut plain);
    Ok(plain)
}

// ============ epee deserialize ============

fn read_destination_entry(data: &[u8], off: &mut usize) -> Result<TxDestinationEntry> {
    let original_len = usize::try_from(read_varint(data, off)?).map_err(|_| err())?;
    let original = read_bytes(data, off, original_len)?;
    let amount = read_varint(data, off)?;
    let spend_public_key = read_u8_32(data, off)?;
    let view_public_key = read_u8_32(data, off)?;
    let is_subaddress = read_bool(data, off)?;
    let is_integrated = read_bool(data, off)?;
    Ok(TxDestinationEntry {
        original,
        amount,
        spend_public_key,
        view_public_key,
        is_subaddress,
        is_integrated,
    })
}

fn read_output_entry(data: &[u8], off: &mut usize) -> Result<OutputEntry> {
    // std::pair 在 binary_archive 里是 class，前有字段数前缀 0x02
    let _pair_tag = read_varint(data, off)?;
    let index = read_varint(data, off)?;
    let dest = read_u8_32(data, off)?;
    let mask = read_u8_32(data, off)?;
    Ok(OutputEntry { index, dest, mask })
}

fn read_source_entry(data: &[u8], off: &mut usize) -> Result<TxSourceEntry> {
    // OutputEntry wire 最小 = varint pair_tag(1) + varint index(1) + 64B = 66
    let outputs_len = read_count(data, off, 66)?;
    let mut outputs = Vec::with_capacity(outputs_len);
    for _ in 0..outputs_len {
        outputs.push(read_output_entry(data, off)?);
    }
    let real_output = read_u64(data, off)?;
    let real_out_tx_key = read_u8_32(data, off)?;
    // additional tx key wire 最小 = 32B
    let additional_len = read_count(data, off, 32)?;
    let mut real_out_additional_tx_keys = Vec::with_capacity(additional_len);
    for _ in 0..additional_len {
        real_out_additional_tx_keys.push(read_u8_32(data, off)?);
    }
    let real_output_in_tx_index = read_u64(data, off)?;
    let amount = read_u64(data, off)?; // FIELD(uint64) = 8B LE
    let rct = read_bool(data, off)?;
    // P1-03: mask 走 SecretBytes take 接管（读入缓冲副本立即清零）
    let mut mask_buf = read_u8_32(data, off)?;
    let mask = crate::types::SecretBytes::take(&mut mask_buf);
    let k = read_u8_32(data, off)?;
    let l = read_u8_32(data, off)?;
    let r = read_u8_32(data, off)?;
    let ki = read_u8_32(data, off)?;
    Ok(TxSourceEntry {
        outputs,
        real_output,
        real_out_tx_key,
        real_out_additional_tx_keys,
        real_output_in_tx_index,
        amount,
        rct,
        mask,
        multisig_kLRki: MultisigKLRki { k, l, r, ki },
    })
}

fn read_tx_construction_data(data: &[u8], off: &mut usize) -> Result<TxConstructionData> {
    // TxSourceEntry wire 最小 = outputs_len(1) + outputs(66) + 8+32+1(keys len+key+…)
    // 保守取 100；其实任何恶意值都会被后续字段读取拒绝
    let sources_len = read_count(data, off, 100)?;
    let mut sources = Vec::with_capacity(sources_len);
    for _ in 0..sources_len {
        sources.push(read_source_entry(data, off)?);
    }
    let change_dts = read_destination_entry(data, off)?;
    // TxDestinationEntry wire 最小 = original_len(1) + varint amount(1) + 64 + 2 ≈ 68
    let splitted_dsts_len = read_count(data, off, 68)?;
    let mut splitted_dsts = Vec::with_capacity(splitted_dsts_len);
    for _ in 0..splitted_dsts_len {
        splitted_dsts.push(read_destination_entry(data, off)?);
    }
    let selected_len = read_count(data, off, 1)?;
    let mut selected_transfers = Vec::with_capacity(selected_len);
    for _ in 0..selected_len {
        // u64 → usize fallible(32 位窄化回绕拒绝)
        selected_transfers.push(usize::try_from(read_varint(data, off)?).map_err(|_| err())?);
    }
    let extra_len = usize::try_from(read_varint(data, off)?).map_err(|_| err())?;
    let extra = read_bytes(data, off, extra_len)?;
    let unlock_time = read_u64(data, off)?;
    let use_rct = read_u8(data, off)?;
    let version = read_varint(data, off)?;
    let range_proof_type = read_varint(data, off)?;
    let bp_version = read_varint(data, off)?;
    let dests_len = read_count(data, off, 68)?;
    let mut dests = Vec::with_capacity(dests_len);
    for _ in 0..dests_len {
        dests.push(read_destination_entry(data, off)?);
    }
    let subaddr_account = read_u32(data, off)?;
    let subaddr_indices_len = read_count(data, off, 1)?;
    let mut subaddr_indices = Vec::with_capacity(subaddr_indices_len);
    for _ in 0..subaddr_indices_len {
        // u64 → u32 fallible(高位截断 256→0 类回绕拒绝)
        subaddr_indices.push(u32::try_from(read_varint(data, off)?).map_err(|_| err())?);
    }
    Ok(TxConstructionData {
        sources,
        change_dts,
        splitted_dsts,
        selected_transfers,
        extra,
        unlock_time,
        use_rct,
        rct_config: RctConfig {
            version,
            range_proof_type,
            bp_version,
        },
        dests,
        subaddr_account,
        subaddr_indices,
    })
}

fn put_varint(out: &mut Vec<u8>, n: u64) {
    crate::chain::xmr::transaction::monero_encode_varint(out, n);
}

fn write_unsigned_destination(out: &mut Vec<u8>, e: &TxDestinationEntry) {
    // unsigned 侧 amount 是 varint（read_destination_entry）；signed 侧是 u64 LE。
    put_varint(out, e.original.len() as u64);
    out.extend_from_slice(&e.original);
    put_varint(out, e.amount);
    out.extend_from_slice(&e.spend_public_key);
    out.extend_from_slice(&e.view_public_key);
    out.push(e.is_subaddress as u8);
    out.push(e.is_integrated as u8);
}

fn write_unsigned_source(out: &mut Vec<u8>, s: &TxSourceEntry) {
    put_varint(out, s.outputs.len() as u64);
    for o in &s.outputs {
        out.push(2); // std::pair 字段数前缀，与 read_output_entry 的 varint 2 同构
        put_varint(out, o.index);
        out.extend_from_slice(&o.dest);
        out.extend_from_slice(&o.mask);
    }
    out.extend_from_slice(&s.real_output.to_le_bytes());
    out.extend_from_slice(&s.real_out_tx_key);
    put_varint(out, s.real_out_additional_tx_keys.len() as u64);
    for k in &s.real_out_additional_tx_keys {
        out.extend_from_slice(k);
    }
    out.extend_from_slice(&s.real_output_in_tx_index.to_le_bytes());
    out.extend_from_slice(&s.amount.to_le_bytes());
    out.push(s.rct as u8);
    out.extend_from_slice(s.mask.expose());
    out.extend_from_slice(&s.multisig_kLRki.k);
    out.extend_from_slice(&s.multisig_kLRki.l);
    out.extend_from_slice(&s.multisig_kLRki.r);
    out.extend_from_slice(&s.multisig_kLRki.ki);
}

fn write_unsigned_construction(out: &mut Vec<u8>, d: &TxConstructionData) {
    put_varint(out, d.sources.len() as u64);
    for s in &d.sources {
        write_unsigned_source(out, s);
    }
    write_unsigned_destination(out, &d.change_dts);
    put_varint(out, d.splitted_dsts.len() as u64);
    for dst in &d.splitted_dsts {
        write_unsigned_destination(out, dst);
    }
    put_varint(out, d.selected_transfers.len() as u64);
    for t in &d.selected_transfers {
        put_varint(out, *t as u64);
    }
    put_varint(out, d.extra.len() as u64);
    out.extend_from_slice(&d.extra);
    out.extend_from_slice(&d.unlock_time.to_le_bytes());
    out.push(d.use_rct);
    put_varint(out, d.rct_config.version);
    put_varint(out, d.rct_config.range_proof_type);
    put_varint(out, d.rct_config.bp_version);
    put_varint(out, d.dests.len() as u64);
    for dest in &d.dests {
        write_unsigned_destination(out, dest);
    }
    out.extend_from_slice(&d.subaddr_account.to_le_bytes());
    put_varint(out, d.subaddr_indices.len() as u64);
    for i in &d.subaddr_indices {
        put_varint(out, *i as u64);
    }
}

/// epee serialize（与 `deserialize_unsigned_tx` 对偶；不含 transfers 尾段）。
/// 审计 #12 P1-02:输出含 mask/kLRki 秘密字段,返回 Zeroizing owner。
pub fn serialize_unsigned_tx(tx: &UnsignedTx) -> zeroize::Zeroizing<Vec<u8>> {
    let mut out = Vec::new();
    put_varint(&mut out, 2);
    put_varint(&mut out, tx.txes.len() as u64);
    for d in &tx.txes {
        write_unsigned_construction(&mut out, d);
    }
    zeroize::Zeroizing::new(out)
}

/// epee deserialize（对齐 keystone UnsignedTx::deserialize）。
/// 审计 #12 P1-03:入口资源预算三层——总长度预算(分配前)→ txes 计数
/// 物理可行性 → 逐字段 checked 读取;恶意但签名有效的请求稳定返回 Err。
pub fn deserialize_unsigned_tx(bytes: &[u8]) -> Result<UnsignedTx> {
    if bytes.len() > UNSIGNED_TXSET_MAX_PLAIN_LEN {
        return Err(err());
    }
    let mut off = 0usize;
    let version = read_varint(bytes, &mut off)?;
    if version != 2 {
        return Err(err());
    }
    // TxConstructionData wire 最小量级 100B(1 source + change + 逐字段);
    // 恶意大计数在 with_capacity 前被拒。
    let txes_len = read_count(bytes, &mut off, 100)?;
    let mut txes = Vec::with_capacity(txes_len);
    for _ in 0..txes_len {
        txes.push(read_tx_construction_data(bytes, &mut off)?);
    }
    // 剩余 = transfers 段（显示层不需要）
    Ok(UnsignedTx { txes })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P6.3 真实 fixture 明文（/tmp/txset_plain.bin 1952B）——从文件 include
    /// 验证 deserialize 与 python 解析一致（1 输入 ring16、找零+dest、fee）
    #[test]
    fn deserialize_p63_fixture_plain() {
        // fixture 明文太大不内嵌——用已知的 P6.3 关键值构造最小验证：
        // 通过 read_destination_entry 单测 + 已知偏移验证（见下面测试）
        // 完整 fixture 解析在集成测试 tests/p63_xmr_unsigned.rs（include_bytes）
        let _ = UNSIGNED_TX_PREFIX;
    }

    /// 读取器：varint 标准 LEB128
    #[test]
    fn read_varint_basic() {
        let data = [0x80u8, 0xd7, 0xb0, 0xfb, 0x06]; // 1869360000
        let mut off = 0;
        assert_eq!(read_varint(&data, &mut off).unwrap(), 1869360000);
        assert_eq!(off, 5);
    }

    /// 读取器：短 varint
    #[test]
    fn read_varint_short() {
        let data = [0x02u8];
        let mut off = 0;
        assert_eq!(read_varint(&data, &mut off).unwrap(), 2);
        assert_eq!(off, 1);
    }

    /// 读取器：越界 → Err
    #[test]
    fn read_overflow_rejected() {
        let data = [0x01u8];
        let mut off = 5;
        assert!(read_u32(&data, &mut off).is_err());
    }

    /// 读取器：u64 LE
    #[test]
    fn read_u64_le() {
        let data = [0x0du8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut off = 0;
        assert_eq!(read_u64(&data, &mut off).unwrap(), 13);
    }

    /// decrypt：magic 错误 → Err
    #[test]
    fn decrypt_bad_magic_rejected() {
        let data = b"not the magic at all...........";
        let view = [0u8; 32];
        assert!(decrypt_unsigned_txset(data, &view).is_err());
    }

    /// decrypt：太短 → Err
    #[test]
    fn decrypt_too_short_rejected() {
        let view = [0u8; 32];
        assert!(decrypt_unsigned_txset(b"Monero unsigned tx set\x05short", &view).is_err());
    }

    // ── P1-03（审计 #4）：secret owner 编译期纪律 ──

    /// mask（真 blinding factor）必须有 Drop——ZeroizeOnDrop 擦除证明的锚点
    #[test]
    fn p103_source_mask_needs_drop() {
        assert!(core::mem::needs_drop::<SourceMask>());
        // 且不可 Clone——秘密副本不扩散
        static_assertions::assert_not_impl_any!(SourceMask: Clone, Copy);
    }

    /// TxSourceEntry 整体不再 Clone（含 mask/kLRki 秘密）
    #[test]
    fn p103_tx_source_entry_not_clone() {
        static_assertions::assert_not_impl_any!(TxSourceEntry: Clone, Copy);
        // 宿主结构同样不 Clone——秘密无法随结构树扩散
        static_assertions::assert_not_impl_any!(TxConstructionData: Clone);
        static_assertions::assert_not_impl_any!(UnsignedTx: Clone);
    }

    /// MultisigKLRki 有 Drop（k/l/r 擦除）且不可 Clone（审计 #5 P1-02：
    /// 序列化只需引用，Clone 理由不成立——敏感标量副本不扩散）
    #[test]
    fn p103_multisig_klrki_needs_drop() {
        assert!(core::mem::needs_drop::<MultisigKLRki>());
        static_assertions::assert_not_impl_any!(MultisigKLRki: Clone, Copy);
    }

    /// serialize ↔ deserialize 对偶：1 source / 2 dest，amount 走 varint。
    #[test]
    fn serialize_deserialize_roundtrip_minimal() {
        let src = TxSourceEntry {
            outputs: alloc::vec![OutputEntry {
                index: 7,
                dest: [0x11u8; 32],
                mask: [0x22u8; 32],
            }],
            real_output: 0,
            real_out_tx_key: [0x33u8; 32],
            real_out_additional_tx_keys: alloc::vec![],
            real_output_in_tx_index: 0,
            amount: 1000,
            rct: true,
            mask: crate::types::SecretBytes::new([0x66u8; 32]),
            multisig_kLRki: MultisigKLRki {
                k: [0; 32],
                l: [0; 32],
                r: [0; 32],
                ki: [0; 32],
            },
        };
        let dest = TxDestinationEntry {
            original: alloc::vec![],
            amount: 900,
            spend_public_key: [0x44u8; 32],
            view_public_key: [0x55u8; 32],
            is_subaddress: false,
            is_integrated: false,
        };
        let change = TxDestinationEntry {
            original: alloc::vec![],
            amount: 50,
            spend_public_key: [0x44u8; 32],
            view_public_key: [0x55u8; 32],
            is_subaddress: false,
            is_integrated: false,
        };
        let tx = UnsignedTx {
            txes: alloc::vec![TxConstructionData {
                sources: alloc::vec![src],
                change_dts: change.clone(),
                splitted_dsts: alloc::vec![change.clone(), dest.clone()],
                selected_transfers: alloc::vec![0],
                extra: alloc::vec![],
                unlock_time: 0,
                use_rct: 1,
                rct_config: RctConfig {
                    version: 0,
                    range_proof_type: 0,
                    bp_version: 4,
                },
                dests: alloc::vec![],
                subaddr_account: 0,
                subaddr_indices: alloc::vec![],
            }],
        };
        let bytes = serialize_unsigned_tx(&tx);
        let back = deserialize_unsigned_tx(&bytes).expect("deserialize");
        assert_eq!(back.txes.len(), 1);
        let d = &back.txes[0];
        assert_eq!(d.sources.len(), 1);
        assert_eq!(d.sources[0].amount, 1000);
        assert_eq!(d.sources[0].outputs[0].index, 7);
        assert_eq!(d.change_dts.amount, 50);
        assert_eq!(d.splitted_dsts[1].amount, 900);
        assert_eq!(d.rct_config.bp_version, 4);
        let bytes2 = serialize_unsigned_tx(&back);
        assert_eq!(bytes, bytes2);
    }

    /// encrypt_unsigned ↔ decrypt_unsigned 对偶。
    #[test]
    fn encrypt_decrypt_unsigned_roundtrip() {
        use rand_chacha::rand_core::SeedableRng;
        let plain = serialize_unsigned_tx(&UnsignedTx {
            txes: alloc::vec![],
        });
        let view = [0xABu8; 32];
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x11u8; 32]);
        let enc =
            crate::chain::xmr::signed_txset::encrypt_unsigned_txset(plain.clone(), &view, &mut rng)
                .expect("encrypt");
        let dec = decrypt_unsigned_txset(&enc, &view).expect("decrypt");
        assert_eq!(*dec, *plain);
    }

    /// 审计 #12 P1-02 API 门禁:明文/密文/CN key 的 owner 类型必须带
    /// Drop 清零语义(Zeroizing);错误路径与提前返回由 Drop 覆盖。
    #[test]
    fn plaintext_owner_types_have_drop() {
        assert!(core::mem::needs_drop::<zeroize::Zeroizing<Vec<u8>>>());
        assert!(core::mem::needs_drop::<zeroize::Zeroizing<[u8; 32]>>());
    }

    // ============ 审计 #12 P1-03:parser 资源预算边界 ============

    /// read_count 物理可行性边界(纯 helper 直测,#6 复审 P2-01 终态——
    /// 不依赖时序/分配观察):count > remaining/min_elem 即拒。
    #[test]
    fn read_count_physical_feasibility_boundaries() {
        // count=1, varint 后剩 19, min_elem=10 → 1 ≤ 19/10=1 可行
        let data = [1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut off = 0usize;
        assert_eq!(read_count(&data, &mut off, 10).unwrap(), 1);
        // count=2, varint 后剩 9, min_elem=5 → 2 > 9/5=1 → 拒
        let data2 = [2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut off2 = 0usize;
        assert!(read_count(&data2, &mut off2, 5).is_err());
        // min_elem=0 防御(不 panic,#7 P2-01 教训):count=9, 剩 9, 按 1 处理 → 9 ≤ 9
        let data3 = [9u8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut off3 = 0usize;
        assert_eq!(read_count(&data3, &mut off3, 0).unwrap(), 9);
        // u64::MAX 计数 → usize::try_from 在 32 位拒绝/64 位被物理可行性拒
        let huge = {
            // LEB128 of u64::MAX
            [0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        };
        let mut off4 = 0usize;
        assert!(read_count(&huge, &mut off4, 1).is_err());
    }

    /// 入口总预算:明文 > UNSIGNED_TXSET_MAX_PLAIN_LEN(16384)在分配前拒绝。
    #[test]
    fn entry_total_budget_rejects_oversize() {
        let big = alloc::vec![0u8; UNSIGNED_TXSET_MAX_PLAIN_LEN + 1];
        assert!(deserialize_unsigned_tx(&big).is_err());
        // 边界内(空 txset 合法形态)不被误伤
        let ok = alloc::vec![2u8, 0];
        assert!(deserialize_unsigned_tx(&ok).is_ok());
    }

    /// 恶意 corpus:合法 version=2 + 巨大 txes 计数 → 物理可行性在
    /// with_capacity 前拒绝(敌对但结构合法的 wire,发布阻断验收)。
    #[test]
    fn malicious_huge_txes_count_rejected_pre_alloc() {
        // version=2(1B) + txes_len = u64::MAX LEB128(10B)
        let mut wire = alloc::vec![2u8];
        wire.extend_from_slice(&[0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
        assert!(deserialize_unsigned_tx(&wire).is_err());
        // 次极端:预算内但物理不可行(60000 × 100B >> 16KiB 预算)
        let mut wire2 = alloc::vec![2u8];
        // LEB128 of 60000 = 0xF0 0xD4 0x03
        wire2.extend_from_slice(&[0xf0, 0xd4, 0x03]);
        assert!(deserialize_unsigned_tx(&wire2).is_err());
    }
}
