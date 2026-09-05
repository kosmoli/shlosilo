//! P1-06 真实签名路径：unsigned_txset → signed tx
//!
//! 对齐 keystone transfer.rs::construct_tx + transfer_key.rs + monero wallet2 genRctSimple：
//! 1. tx_key = 随机标量 r；有 subaddress 输出时 tx_pub = r·B_sub（keystone transaction_keys）
//! 2. per-output: ECDH → shared_key = Hs(8Ra || varint(o))；
//!    mask = Hs("commitment_mask" || shared_key)；amount 加密 = Hs("amount"||shared_key)[..8] XOR
//! 3. extra = txpub (+ r·B_sub 若 subaddress 且无 additional keys) + payment_id XOR(change)
//! 4. BP+ over output commitments（bp_version=4 → RCTTypeBulletproofPlus, wire type=6）
//! 5. pseudo_out_i：genRctSimple 链 `a[i]=rng (i<last), a[last]=Σout_masks−Σprev`；单输入 = Σout_masks
//! 6. 组 prefix → msg_hash = keccak(prefix) → CLSAG → 完整 tx

extern crate alloc;

use crate::chain::xmr::rct_sig::prove_bulletproofs_plus;
use alloc::vec::Vec;
use monero_ed25519::CompressedPoint;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// real mask 工作集合的 Drop guard——秘密清零的唯一责任方。
/// guard 从建立时刻起持续持有 Vec 到函数离开(正常返回或任何 `?` 路径),
/// Drop 统一擦除;读取只经 `get()` 只读借用,不存在取走数据的 API
/// (审计 #6 复审 P1-01:曾用 into_inner 在 CLSAG 段前解包,导致最后
/// 一段错误路径跳过清零——已按复审建议消除)。
struct ZeroizingMaskGuard {
    masks: Vec<[u8; 32]>,
    /// 审计 #9 P2-01:owner 身份标签——影子记录携带 kind,测试可精确归因
    /// (解决"全局 latest slot 无法区分 input_sk/real_mask"的归因缺口)
    #[cfg(test)]
    kind: &'static str,
}
impl ZeroizingMaskGuard {
    #[allow(unused_variables)] // kind 仅 cfg(test) 影子观察使用
    fn new(kind: &'static str) -> Self {
        Self {
            masks: Vec::new(),
            #[cfg(test)]
            kind,
        }
    }
    /// 接管语义:复制进 owner 后**立即清零调用方缓冲**——审计 #8 P1-01,
    /// 消除"[u8;32] Copy 导致的第二存活副本"
    fn push_take(&mut self, mask: &mut [u8; 32]) {
        self.masks.push(*mask);
        mask.zeroize();
    }
    /// 只读借用——不取走数据,秘密的清零完全由 Drop 负责
    /// (审计 #6 复审 P1-01:into_inner 会在最后一段错误路径前解除保护)
    fn get(&self, idx: usize) -> Option<&[u8; 32]> {
        self.masks.get(idx)
    }
}
/// 审计 #7 Gate2 #1:测试影子缓冲——Drop 清零后的真实 backing 拷贝落点。
/// 仅测试编译存在;静态生命周期让"guard 消费后观察 Drop 效果"无 UB。
#[cfg(test)]
mod shadow {
    // 测试环境 = host(std feature),no_std crate 内按既有惯例局部引入 std
    extern crate std;
    use std::sync::{Mutex, MutexGuard};
    pub struct ShadowRecord {
        pub kind: &'static str,
        pub masks: alloc::vec::Vec<[u8; 32]>,
    }
    pub static SHADOW_RECORDS: Mutex<alloc::vec::Vec<ShadowRecord>> =
        Mutex::new(alloc::vec::Vec::new());
    static SHADOW_TX_LOCK: Mutex<()> = Mutex::new(());

    /// 审计 #12 P2-01 事务隔离:begin = 调用前清空 + 持事务锁;返回的
    /// Invocation 在 Drop 前一直持有锁(并行测试串行进入各自事务);
    /// take_last = 调用后消费标记(记录被取走,不可重复消费)。
    pub struct Invocation {
        _lock: MutexGuard<'static, ()>,
    }

    impl Invocation {
        /// 取走本事务内最后一条匹配 kind 的记录(消费式)。
        pub fn take_last(self, kind: &str) -> Option<ShadowRecord> {
            let mut v = SHADOW_RECORDS.lock().unwrap_or_else(|e| e.into_inner());
            let idx = v.iter().rposition(|r| r.kind == kind)?;
            Some(v.remove(idx))
            // self drop 时释放事务锁
        }
    }

    pub fn begin_invocation() -> Invocation {
        let lock = SHADOW_TX_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        SHADOW_RECORDS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        Invocation { _lock: lock }
    }
}

/// 官方 genRctSimple 伪输出掩码链:
/// `a[i] = random` (i < last), `a[last] = Σout_masks − Σ_{j<last} a[j]`。
/// 单输入 ⇒ last=0 ⇒ a[0] = Σout_masks,与既有 `sum_outputs` 语义逐字节一致,
/// 不额外消费 rng(锁单输入确定性)。
fn derive_pseudo_masks<R: RngCore>(
    n_in: usize,
    sum_out_masks: &crate::types::secret_scalar::SecretScalar,
    rng: &mut R,
) -> Result<ZeroizingMaskGuard> {
    if n_in == 0 {
        return Err(err());
    }
    let mut dest = ZeroizingMaskGuard::new("pseudo_mask");
    let mut sum_prev = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order([0u8; 32]);
    for i in 0..n_in {
        let mask = if i + 1 == n_in {
            sum_out_masks.sub_secret(&sum_prev)
        } else {
            let mut raw = zeroize::Zeroizing::new([0u8; 32]);
            rng.fill_bytes(raw.as_mut());
            let m = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(*raw);
            sum_prev = sum_prev.add_secret(&m);
            m
        };
        let mut bytes = mask.to_bytes();
        dest.push_take(&mut bytes);
    }
    sum_prev.zeroize_now();
    Ok(dest)
}

impl Drop for ZeroizingMaskGuard {
    fn drop(&mut self) {
        for m in self.masks.iter_mut() {
            m.zeroize();
        }
        // 审计 #7 Gate2 #1:测试可见性——清零后的真实 backing 拷入静态影子,
        // 测试在事务内(begin_invocation 持锁 + 调用前清空)按 kind 消费式
        // 取记录 = 观察真实 Drop 效果,无 UB、无并行覆盖(审计 #12 P2-01)
        #[cfg(test)]
        {
            shadow::SHADOW_RECORDS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(shadow::ShadowRecord {
                    kind: self.kind,
                    masks: self.masks.clone(),
                });
        }
    }
}

use crate::chain::xmr::clsag::{self as clsag_mod};
use crate::chain::xmr::subaddress::hash_to_scalar;
use crate::chain::xmr::transaction::{
    bytes_to_monerod_scalar, monero_encode_varint, monerod_scalar_to_bytes, TransactionPrefix,
    TxExtra, TxInput, TxOutput,
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

#[cfg(test)]
fn bytes_to_scalar(bytes: &[u8; 32]) -> curve25519_dalek::scalar::Scalar {
    curve25519_dalek::scalar::Scalar::from_bytes_mod_order(*bytes)
}

/// per-output 派生（shared key + mask + encrypted amount）——keystone commitments_and_encrypted_amounts
///
/// 审计 #9 P1-03:shared_key/commitment_mask 是 ECDH 派生秘密——字段直接用
/// SecretBytes owner(ZeroizeOnDrop),从产生即受保护(构造前 ? 与 Copy 来源
/// 副本问题一并消除)。encrypted_amount/stealth/view_tag/additional_tx_key
/// 是链上可见数据,非秘密,不擦除。
struct OutputDerivation {
    /// 8Ra = r·A_v·8（或 change: view_sec·tx_pub·8）
    /// 审计 #9 P1-03:秘密字段从产生即 SecretBytes owner(ZeroizeOnDrop;
    /// 此前普通 [u8;32] Copy 字段 + 构造时复制,构造前 ? 与来源副本均无擦除)
    #[allow(dead_code)] // 预留给 P2 后续输出验证
    shared_key: crate::types::SecretBytes<32>,
    commitment_mask: crate::types::SecretBytes<32>,
    encrypted_amount: [u8; 8],
    stealth_address: [u8; 32],
    /// 链上可见数据(公开点),非秘密——无需 owner(审计 #9 复核:
    /// 上一轮把手写 Drop 也擦它属过度擦除,恢复数组类型)
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
    r: &crate::types::secret_scalar::SecretScalar,
    _view_sec: &[u8; 32],
    dest: &TxDestinationEntry,
    _tx_pub: &[u8; 32],
    index: usize,
) -> Result<OutputDerivation> {
    // ecdh = r · A_v(两分支当前同式;additional-key 派生排期后续)
    // 审计 #10 P1-03:白名单点乘——r 不暴露 &Scalar,内部完成解压/点乘
    let ecdh_bytes = r.mul_point(&dest.view_public_key)?;
    let ecdh_point: curve25519_dalek::EdwardsPoint = CompressedPoint::from(ecdh_bytes)
        .decompress()
        .ok_or_else(err)?
        .into();

    // 8Ra = ecdh · cofactor(8)，压缩后 || varint(index)
    let eight_ra_pt = ecdh_point.mul_by_cofactor();
    let eight_ra = eight_ra_pt.compress().to_bytes();

    // 审计 #8 P0-01:临时缓冲从创建即进 Zeroizing(避免人工收尾顺序
    // 影响协议语义——此前 od_data 在消费者之前被清零,stealth 用了
    // Hs(empty),输出地址错误;zeroize 对 Vec = clear + 擦 capacity)
    let mut od_data = zeroize::Zeroizing::new(Vec::with_capacity(33));
    od_data.extend_from_slice(&eight_ra);
    monero_encode_varint(&mut od_data, index as u64);

    let shared_key = crate::types::SecretBytes::new(hash_to_scalar(&od_data)?);

    // mask = Hs("commitment_mask" || shared_key)
    let mut mask_data = zeroize::Zeroizing::new(Vec::with_capacity(16 + 32));
    mask_data.extend_from_slice(b"commitment_mask");
    mask_data.extend_from_slice(shared_key.expose());
    let commitment_mask = crate::types::SecretBytes::new(hash_to_scalar(&mask_data)?);

    // enc amount = amount XOR Hs("amount"||shared_key)[..8] (LE)
    let mut amt_data = zeroize::Zeroizing::new(Vec::with_capacity(6 + 32));
    amt_data.extend_from_slice(b"amount");
    amt_data.extend_from_slice(shared_key.expose());
    let amt_mask = zeroize::Zeroizing::new(crate::encoding::keccak256::hash(&amt_data)?);
    let mask8 = zeroize::Zeroizing::new(<[u8; 8]>::try_from(&amt_mask[..8]).unwrap());
    let xor_val = u64::from_le_bytes(*mask8);
    let encrypted_amount = (dest.amount ^ xor_val).to_le_bytes();

    // stealth = B_dest + Hs(8Ra||varint(idx))·G(monero one-time address)
    // 审计 #8 P0-01:Hs(8Ra||o) = shared_key(同一哈希),直接复用
    // 审计 #11 P1-02:Hs(shared_key) 进 SecretScalar owner(上一版
    // hs_z = hs_scalar 只清 Copy 副本,且解压 ? 在清零前——两个缺口);
    // spend key 解压前移到任何秘密派生之前,全部 ? 由 owner Drop 覆盖
    let b_dest: curve25519_dalek::EdwardsPoint = CompressedPoint::from(dest.spend_public_key)
        .decompress()
        .ok_or_else(err)?
        .into();
    let hs = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(*shared_key.expose());
    let stealth_address = hs.mul_basepoint_add_point(&b_dest);

    // view tag = keccak("view_tag" || 8Ra || varint(o))[0]
    let mut vt_data = zeroize::Zeroizing::new(Vec::with_capacity(9 + 33));
    vt_data.extend_from_slice(b"view_tag");
    vt_data.extend_from_slice(&eight_ra);
    monero_encode_varint(&mut vt_data, index as u64);
    let vtag_full = zeroize::Zeroizing::new(crate::encoding::keccak256::hash(&vt_data)?);
    let view_tag = vtag_full[0];

    // 子地址时 additional key = r·B_sub（keystone should_use_additional_keys=false 路径：
    // tx_pub 本身 = r·B_sub。这里采用 shlosilo tx_builder 惯例：additional key 记录 r·B_sub）
    let additional_tx_key = if dest.is_subaddress {
        // r·B_sub——dest.spend_public_key 即 B_sub 压缩字节
        Some(r.mul_point(&dest.spend_public_key)?)
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
    // 审计 #7 Gate1 #3:r 是 Monero transaction secret key——Zeroizing 全路径
    let mut r_bytes = zeroize::Zeroizing::new([0u8; 32]);
    rng.fill_bytes(r_bytes.as_mut());
    // 审计 #8 P1-02:r 不再物化为普通 Copy Scalar——_with_rngs 改收
    // Zeroizing 字节 owner,内部使用点按需转 Scalar(临时,不落地)
    let mut rng2 = rng.clone();
    sign_tx_from_construction_with_rngs(tx_data, spend_sec, view_sec, &r_bytes, rng, &mut rng2)
}

/// 核心签名（§B.5 定案）：tx_key r 由调用方注入（purpose 子域派生），
/// bp_rng 供 Bulletproof+，clsag_rng 供 CLSAG（per-input 子域在调用方拆分；
/// v1 单输入时传入 Clsag(0) 派生流即可）。
pub fn sign_tx_from_construction_with_rngs<B: RngCore + CryptoRng, C: RngCore + CryptoRng>(
    tx_data: &TxConstructionData,
    spend_sec: &[u8; 32],
    view_sec: &[u8; 32],
    r_bytes: &zeroize::Zeroizing<[u8; 32]>,
    bp_rng: &mut B,
    clsag_rng: &mut C,
) -> Result<Vec<u8>> {
    // 审计 #9 P1-02:r 是 transaction secret key——SecretScalar owner
    // (dalek Scalar 是 Copy 且无 Drop,普通绑定在 ? 路径不会清零);
    // 消费点经 with_scalar 借用,外层无普通 Scalar 绑定
    let r = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(**r_bytes);
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
        // 白名单点乘直接收压缩字节——无需解压
        r.mul_point(&b_sub_bytes)?
    } else {
        r.mul_basepoint()
    };
    let tx_pub = tx_pub_point; // mul_point/mul_basepoint 已返回压缩字节

    // ---- 2. per-output 派生（keystone commitments_and_encrypted_amounts）----
    // change_dts 是"回自己"——ecdh = view_sec · TxPub（is_change_dest 分支）
    // 审计 #9 P1-02 + #10 P1-04:v_scalar 是长期 view secret 派生——白名单点乘
    let change_ecdh_pt = {
        let v_scalar = crate::types::secret_scalar::SecretScalar::from_slice(view_sec);
        let pt_bytes = v_scalar.mul_point(&tx_pub_point)?;
        let decompressed: curve25519_dalek::EdwardsPoint = CompressedPoint::from(pt_bytes)
            .decompress()
            .ok_or_else(err)?
            .into();
        decompressed
    };
    let change_eight_ra = change_ecdh_pt.mul_by_cofactor().compress().to_bytes();

    let mut outs: Vec<OutInfo> = Vec::with_capacity(tx_data.splitted_dsts.len());

    for (i, dest) in tx_data.splitted_dsts.iter().enumerate() {
        let is_change = dest.amount == tx_data.change_dts.amount
            && dest.spend_public_key == tx_data.change_dts.spend_public_key;
        if is_change {
            // change 走 view_sec·TxPub 路径：手工派生（derive_output 的 r·A_v 不适用）
            // 审计 #8 P1-02:change 分支临时缓冲与主分支同纪律(Zeroizing owner)
            // 审计 #11 P1-03:哈希产生处直接进 owner(不再落地普通数组)
            let shared_key = {
                let mut od = zeroize::Zeroizing::new(Vec::with_capacity(33));
                od.extend_from_slice(&change_eight_ra);
                monero_encode_varint(&mut od, i as u64);
                crate::types::SecretBytes::new(hash_to_scalar(&od)?)
            };
            let commitment_mask = {
                let mut md = zeroize::Zeroizing::new(Vec::with_capacity(48));
                md.extend_from_slice(b"commitment_mask");
                md.extend_from_slice(shared_key.expose());
                crate::types::SecretBytes::new(hash_to_scalar(&md)?)
            };
            let encrypted_amount = {
                let mut ad = zeroize::Zeroizing::new(Vec::with_capacity(38));
                ad.extend_from_slice(b"amount");
                ad.extend_from_slice(shared_key.expose());
                let h = crate::encoding::keccak256::hash(&ad)?;
                let m8 = u64::from_le_bytes(h[..8].try_into().unwrap());
                (dest.amount ^ m8).to_le_bytes()
            };
            // stealth(change 也输出 onetime address)——审计 #11 P1-03:
            // hs 进 SecretScalar owner;解压前移,全部 ? 由 owner Drop 覆盖
            let b_dest: curve25519_dalek::EdwardsPoint =
                CompressedPoint::from(dest.spend_public_key)
                    .decompress()
                    .ok_or_else(err)?
                    .into();
            let hs = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(
                *shared_key.expose(),
            );
            let stealth_address = hs.mul_basepoint_add_point(&b_dest);
            // view tag
            let mut vt = zeroize::Zeroizing::new(Vec::with_capacity(42));
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
            let deriv = derive_output(&r, view_sec, dest, &tx_pub, i)?;
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
    // 审计 #6 复审 Gate1 #4:空 sources 已在函数入口拒绝;n>=1 即进入秘密
    // owner 建立。多输入走 genRctSimple 链,不再在此硬拒绝。
    let mut input_real_masks = ZeroizingMaskGuard::new("real_mask");
    let mut rings: Vec<Vec<(CompressedPoint, CompressedPoint)>> =
        Vec::with_capacity(tx_data.sources.len());
    // 审计 #7 Gate1 #4:key_offset 是构造 one-time spend key 的秘密——
    // 不落地 Vec,循环内立即派生 input_sk 进 ZeroizingGuard(owner 持有到底)
    let mut input_sks = ZeroizingMaskGuard::new("input_sk");
    for src in &tx_data.sources {
        // key offsets：绝对→相对（monero absolute_output_offsets_to_relative，升序差分）
        let mut offs: Vec<u64> = src.outputs.iter().map(|o| o.index).collect();
        offs.sort_unstable();
        for i in (1..offs.len()).rev() {
            offs[i] -= offs[i - 1];
        }
        // 审计 #9 P1-01:tuple 直接绑 mut——`let mut x = x` shadow 是一次
        // Copy,旧绑定(不可变)无法擦除;绑定处声明 mut 才能原地清零
        let (key_image, mut key_offset) = crate::chain::xmr::subaddress::derive_input_from_source(
            view_sec,
            spend_sec,
            src,
            tx_data.subaddr_account,
            &tx_data.subaddr_indices,
        )?;
        tx_inputs.push(TxInput::new(offs.clone(), key_image));
        // key_offset 即用即派生(不经过中间 Vec);push_take 后原地清零
        let mut input_sk =
            crate::chain::xmr::subaddress::derive_input_spend_key(spend_sec, &key_offset)?;
        input_sks.push_take(&mut input_sk); // input_sk 原地接管进 owner
        key_offset.zeroize(); // 原地(绑定处 mut,无 shadow Copy)
                              // P1-03 + 审计 #8 P1-01:mask 写入本地缓冲后 push_take 原地接管
                              // (push 后调用方缓冲立即清零,不存在存活的第二副本)
        let mut mask_copy = [0u8; 32];
        src.mask.write_into(&mut mask_copy);
        input_real_masks.push_take(&mut mask_copy); // TxSourceEntry.mask = real output 的真 blinding factor
                                                    // （OutputEntry.mask 是链上 C 点；real_entry.mask 被当作 blinding 重算是错的）
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
                bytes_to_monerod_scalar(o.deriv.commitment_mask.expose()),
                o.dest.amount,
            )
        })
        .collect();
    // 审计 #7 Gate1 #5:commitment 是链上公开数据(Pedersen 承诺随 tx 广播,不含
    // mask 明文),clone 非秘密复制问题——但本体此后无消费,直接 move 消除复制
    let bp = prove_bulletproofs_plus(bp_rng, commitments)?;
    // Σ out masks：curve25519_dalek 标量域算术，再转回 monero 字节
    // 审计 #9 P1-02:blinding mask 之和——SecretScalar owner(错误路径 Drop 清零;
    // loop 内 m 用后即擦,不落地普通绑定)
    let mut sum_out_masks =
        crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(monerod_scalar_to_bytes(
            &bytes_to_monerod_scalar(outs[0].deriv.commitment_mask.expose()),
        ));
    for o in &outs[1..] {
        // 审计 #12 P1-01:累加项从产生即 owner(旧写法 m 为普通 Scalar 绑定,
        // 经 add_assign(&Scalar) 参与且仅靠手工 zeroize 收尾——? 提前返回
        // 或未来重构都会漏擦;SecretScalar Drop 全路径覆盖)
        let m = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(
            monerod_scalar_to_bytes(&bytes_to_monerod_scalar(o.deriv.commitment_mask.expose())),
        );
        sum_out_masks.add_assign(&m);
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
                bytes_to_monerod_scalar(o.deriv.commitment_mask.expose()),
                o.dest.amount,
            );
            b.extend_from_slice(&c.commit().compress().to_bytes());
        }
        b
    };
    let rct_base_hash = crate::encoding::keccak256::hash(&rct_base_bytes)?;
    let mut bp_sig_bytes = Vec::new();
    bp.signature_write(&mut bp_sig_bytes)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    // get_pre_mlsag_hash hashes the flattened BP+ fields first, then hashes
    // exactly three 32-byte keys: prefix hash, base hash, and BP+ fields hash.
    let bp_sig_hash = crate::encoding::keccak256::hash(&bp_sig_bytes)?;
    let mut full_msg_in = Vec::with_capacity(96);
    full_msg_in.extend_from_slice(&prefix_hash);
    full_msg_in.extend_from_slice(&rct_base_hash);
    full_msg_in.extend_from_slice(&bp_sig_hash);
    let msg_hash = crate::encoding::keccak256::hash(&full_msg_in)?;

    // 审计 #6 复审 Gate1 #1:guard 不解包,持续持有 Vec 到函数离开——
    // CLSAG 段的所有 ? (derive_input_spend_key / clsag sign)失败时
    // Drop 仍会擦除全部 mask(复审证据:into_inner 后 3 类提前返回跳过清零)

    // ---- 9. CLSAG per input：pseudo_mask 走 genRctSimple 链 ----
    // 官方: a[i]=skGen (i<last); a[last]=Σout_masks−Σprev_pseudo。
    // 单输入 ⇒ 不消费 rng,a[0]=Σout_masks,与既有 monero-clsag sum_outputs 语义一致。
    // 每输入再调 clsag::sign(sum_outputs=该 input 的 a[i])——单元素列表下
    // 库把 sum_outputs 当 last mask,等价于直接使用我们算好的 a[i]。
    let pseudo_masks = derive_pseudo_masks(tx_data.sources.len(), &sum_out_masks, clsag_rng)?;
    let mut clsag_wire: Vec<Vec<u8>> = Vec::with_capacity(tx_data.sources.len());
    let mut pseudo_outs_arr: Vec<[u8; 32]> = Vec::with_capacity(tx_data.sources.len());

    for (i, (src, ring)) in tx_data.sources.iter().zip(rings.iter()).enumerate() {
        // 审计 #7 Gate1 #5:pseudo_mask 是 blinding scalar——owner 持有到底
        let pseudo_mask_bytes: &[u8; 32] = pseudo_masks.get(i).ok_or_else(err)?;
        // Gate1 #2:只读借用,不产生普通栈副本
        let real_mask_bytes: &[u8; 32] = input_real_masks.get(i).ok_or_else(err)?;

        // CLSAG 签名私钥 = one-time input sk(spend + key_offset)——已在收集
        // 循环派生入 ZeroizingMaskGuard,此处只读借用(审计 #7 Gate1 #4)
        let input_sk_bytes: &[u8; 32] = input_sks.get(i).ok_or_else(err)?;
        let (clsag_proof, _ki, pseudo_out_bytes) = clsag_mod::sign(
            input_sk_bytes,
            ring,
            src.real_output as u8,
            real_mask_bytes,
            src.amount,
            pseudo_mask_bytes,
            &msg_hash,
            clsag_rng,
        )?;
        // proof.bytes 布局 = pseudo_out(32) ‖ s[mixin+1] ‖ c1(32) ‖ D(32)
        let body: Vec<u8> = clsag_proof.wire_body().to_vec();
        debug_assert_eq!(clsag_proof.to_bytes().len(), 32 + rings[i].len() * 32 + 64);
        clsag_wire.push(body);
        pseudo_outs_arr.push(pseudo_out_bytes);
    }

    // 审计 #6 复审:mask 清零唯一责任方 = ZeroizingMaskGuard::drop,
    // 函数离开(正常返回或任何 ? 路径)时自动执行,无手工收尾点。

    // 审计 #7 Gate1 #5 + #9 P1-02:sum_out_masks 是输出 blinding 之和——
    // CLSAG 循环后即无消费,显式清零;错误路径由 SecretScalar Drop 覆盖
    // (dalek Scalar 本体 Copy 无 Drop——上一轮注释是错误安全声明)
    sum_out_masks.zeroize_now();

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

#[cfg(test)]
mod guard_tests {
    use super::*;

    /// Drop 清零可观察性:同模块直接读 guard.masks——drop 后全零。
    /// (GPT 复审 Gate1 #5:错误注入锚点必须测 owner 的 Drop 路径,
    /// 而非只验证最终错误码)
    /// 审计 #7 Gate2 #1:真实 Drop 观察——guard Drop 清零自身 backing 后,
    /// 拷贝落入静态影子缓冲 SHADOW_POST_DROP;guard 被 Box::into_raw +
    /// drop_in_place 真实消费,测试读静态影子断言全零(无 UB:影子生命周期
    /// 独立于 guard)。此前版本的缺陷(复审 P1-01):只对手工 Vec 跑 zeroize
    /// 循环,从未触发真实 Drop。
    #[test]
    fn guard_drop_zeroizes_real_backing() {
        // 审计 #8 P1-03 修订:普通 Box drop(g) 消费 guard——Drop 内 zeroize +
        // 拷贝进同步 Mutex 影子;之后读影子即观察真实 Drop 效果,无 UB、
        // 无泄漏、并行安全(Miri --test-threads=2 通过)。原始指针/故意泄漏
        // 结构体的旧写法已删(Miri 泄漏检查失败)。
        let invocation = shadow::begin_invocation();
        let g = {
            let mut g = ZeroizingMaskGuard::new("test");
            let mut a = [0xAAu8; 32];
            g.push_take(&mut a);
            let mut b = [0x55u8; 32];
            g.push_take(&mut b);
            g
        };
        drop(g); // 真实 Drop:zeroize + Mutex 影子拷贝
        let shadow = invocation
            .take_last("test")
            .expect("shadow must be populated by guard Drop in this invocation");
        assert_eq!(
            shadow.masks.len(),
            2,
            "shadow must capture the dropped guard's masks"
        );
        assert!(
            shadow.masks.iter().all(|m| m.iter().all(|&b| b == 0)),
            "real guard Drop must zeroize its own backing"
        );
    }

    /// 审计 #7 Gate1 #4:owner 类型断言——不可 Clone/不可 Copy,needs_drop 为真
    #[test]
    fn guard_owner_type_invariants() {
        assert!(core::mem::needs_drop::<ZeroizingMaskGuard>());
        static_assertions::assert_not_impl_any!(ZeroizingMaskGuard: Clone, Copy);
        // OutputDerivation 同样是秘密 owner(含 shared_key/commitment_mask)
        assert!(core::mem::needs_drop::<OutputDerivation>());
        static_assertions::assert_not_impl_any!(OutputDerivation: Clone, Copy);
    }

    /// get() 只读借用:返回数据引用但不转移所有权(guard 仍持有、仍负责清零)
    #[test]
    fn guard_get_is_borrow_not_take() {
        let mut g = ZeroizingMaskGuard::new("test");
        let mut c = [0x42u8; 32];
        g.push_take(&mut c);
        {
            let borrowed = g.get(0).expect("idx 0 must exist");
            assert_eq!(borrowed[0], 0x42);
        }
        // guard 仍持有数据(get 后)
        assert_eq!(g.masks.len(), 1);
        assert_eq!(g.masks[0][0], 0x42);
    }

    /// genRctSimple:单输入 a[0] = Σout,且不消费 rng(锁既有确定性)。
    #[test]
    fn pseudo_mask_chain_single_equals_sum_and_consumes_no_rng() {
        use rand_chacha::rand_core::{RngCore, SeedableRng};
        let mut sum_bytes = [0u8; 32];
        sum_bytes[0] = 7;
        let sum = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(sum_bytes);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x11u8; 32]);
        let mut rng_clone = rng.clone();
        let g = derive_pseudo_masks(1, &sum, &mut rng).expect("n=1");
        assert_eq!(g.get(0).expect("mask 0"), &sum.to_bytes());
        assert_eq!(g.masks.len(), 1);
        // 不消费 rng:再 fill 一次应与从未被 derive 碰过的 clone 一致
        let mut a = [0u8; 8];
        let mut b = [0u8; 8];
        rng.fill_bytes(&mut a);
        rng_clone.fill_bytes(&mut b);
        assert_eq!(a, b, "n=1 must not consume clsag rng");
    }

    /// genRctSimple:n=2 时 a[0] 来自 rng,a[1] = Σout − a[0],Σa = Σout。
    #[test]
    fn pseudo_mask_chain_two_last_equals_sum_minus_first() {
        use curve25519_dalek::Scalar;
        use rand_chacha::rand_core::{RngCore, SeedableRng};
        let mut sum_bytes = [0u8; 32];
        sum_bytes[0] = 9;
        let sum = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(sum_bytes);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x22u8; 32]);
        let mut rng_expect = rng.clone();
        let g = derive_pseudo_masks(2, &sum, &mut rng).expect("n=2");
        let mut raw = [0u8; 32];
        rng_expect.fill_bytes(&mut raw);
        let first = Scalar::from_bytes_mod_order(raw);
        let last = Scalar::from_bytes_mod_order(sum.to_bytes()) - first;
        assert_eq!(g.get(0).expect("mask 0"), &first.to_bytes());
        assert_eq!(g.get(1).expect("mask 1"), &last.to_bytes());
        let total = first + last;
        assert_eq!(total.to_bytes(), sum.to_bytes());
    }

    /// genRctSimple:任意 n,Σa[i] = Σout_masks(balance 的标量形式)。
    #[test]
    fn pseudo_mask_chain_n3_sums_to_sum_out() {
        use curve25519_dalek::Scalar;
        use rand_chacha::rand_core::SeedableRng;
        let mut sum_bytes = [0u8; 32];
        sum_bytes[0] = 11;
        let sum = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(sum_bytes);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x33u8; 32]);
        let g = derive_pseudo_masks(3, &sum, &mut rng).expect("n=3");
        assert_eq!(g.masks.len(), 3);
        let mut acc = Scalar::ZERO;
        for i in 0..3 {
            acc += Scalar::from_bytes_mod_order(*g.get(i).expect("mask"));
        }
        assert_eq!(acc.to_bytes(), sum.to_bytes());
    }

    /// n=0 拒绝(形状,任何秘密 owner 建立前)。
    #[test]
    fn pseudo_mask_chain_zero_inputs_rejected() {
        use rand_chacha::rand_core::SeedableRng;
        let sum = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order([1u8; 32]);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x44u8; 32]);
        assert!(derive_pseudo_masks(0, &sum, &mut rng).is_err());
    }

    /// 审计 #11 P0-01(第二层):敌对 destination view key([0x02;32]
    /// 不可解压)通过公开 signer——必须返回 Err,不 panic(复审 PoC
    /// 以 catch_unwind 观察到 panic;panic=abort 真机上是整机 DoS)。
    #[test]
    fn hostile_destination_point_returns_err_not_panic() {
        use crate::chain::xmr::unsigned_txset::{
            OutputEntry, RctConfig, TxDestinationEntry, TxSourceEntry,
        };
        use crate::types::SecretBytes;

        let test_seed = [0x42u8; 64];
        let path = crate::derivation::monero_reduce_scalar::MoneroPath::mainnet(0);
        let kp = crate::derivation::monero_reduce_scalar::derive(&test_seed, &path).unwrap();
        let spend_sec = crate::curve_primitive::ed25519::scalar_to_bytes(kp.spend_priv());
        let view_sec = crate::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv());

        let source = TxSourceEntry {
            outputs: alloc::vec![OutputEntry {
                index: 0,
                dest: [0x33u8; 32],
                mask: [0x33u8; 32],
            }],
            real_output: 0,
            real_out_tx_key: [0; 32],
            real_out_additional_tx_keys: alloc::vec![],
            real_output_in_tx_index: 0,
            amount: 1000,
            rct: true,
            mask: SecretBytes::new([0x66u8; 32]),
            multisig_kLRki: crate::chain::xmr::unsigned_txset::MultisigKLRki {
                k: [0; 32],
                l: [0; 32],
                r: [0; 32],
                ki: [0; 32],
            },
        };
        // 敌对 destination:view_public_key = [0x02;32](复审 PoC 编码)
        let dest = TxDestinationEntry {
            original: Vec::new(),
            amount: 900,
            spend_public_key: [0x02u8; 32],
            view_public_key: [0x02u8; 32],
            is_subaddress: false,
            is_integrated: false,
        };
        let tx_data = crate::chain::xmr::unsigned_txset::TxConstructionData {
            sources: alloc::vec![source],
            change_dts: dest.clone(),
            splitted_dsts: alloc::vec![dest],
            selected_transfers: alloc::vec![0],
            extra: alloc::vec![],
            unlock_time: 0,
            use_rct: 1,
            rct_config: RctConfig::default(),
            dests: alloc::vec![],
            subaddr_account: 0,
            subaddr_indices: alloc::vec![],
        };

        use rand_chacha::rand_core::SeedableRng;
        let rng = rand_chacha::ChaCha20Rng::from_seed([0x77u8; 32]);
        let mut bp_rng = rng.clone();
        let mut clsag_rng = rng.clone();
        let r_bytes = zeroize::Zeroizing::new([0x77u8; 32]);
        let result = sign_tx_from_construction_with_rngs(
            &tx_data,
            &spend_sec,
            &view_sec,
            &r_bytes,
            &mut bp_rng,
            &mut clsag_rng,
        );
        // 敌对输入 → Err(不 panic——本测试存活即证明)
        let e = result.unwrap_err();
        assert_eq!(e.kind, ShlosiloErrorKind::EncodingInvalidFormat);
    }
}

#[cfg(test)]
fn test_wallet_keys() -> ([u8; 32], [u8; 32]) {
    let test_seed = [0x42u8; 64];
    let path = crate::derivation::monero_reduce_scalar::MoneroPath::mainnet(0);
    let kp = crate::derivation::monero_reduce_scalar::derive(&test_seed, &path).unwrap();
    (
        crate::curve_primitive::ed25519::scalar_to_bytes(kp.spend_priv()),
        crate::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv()),
    )
}

#[cfg(test)]
fn point_of(n: u64) -> [u8; 32] {
    (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &curve25519_dalek::Scalar::from(n))
        .compress()
        .to_bytes()
}

#[cfg(test)]
fn mask_of(b: u8) -> [u8; 32] {
    [b; 32]
}

#[cfg(test)]
fn test_dest(amount: u64, pt: [u8; 32], is_subaddress: bool) -> TxDestinationEntry {
    TxDestinationEntry {
        original: Vec::new(),
        amount,
        spend_public_key: pt,
        view_public_key: pt,
        is_subaddress,
        is_integrated: false,
    }
}

/// 构造归属当前钱包的 source:real dest = (spend+offset)·G,real C = Commit(mask, amount)。
#[cfg(test)]
fn owned_source(
    spend_sec: &[u8; 32],
    view_sec: &[u8; 32],
    amount: u64,
    real_mask: [u8; 32],
    tx_pub: [u8; 32],
    decoy_k: u64,
) -> crate::chain::xmr::unsigned_txset::TxSourceEntry {
    use crate::chain::xmr::unsigned_txset::{OutputEntry, TxSourceEntry};
    use crate::types::SecretBytes;
    let key_offset =
        crate::chain::xmr::subaddress::calc_output_key_offset(view_sec, &tx_pub, 0, 0, 0).unwrap();
    let spend_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(*spend_sec);
    let offset_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(key_offset);
    let wallet_dest = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
        * &(spend_scalar + offset_scalar))
        .compress()
        .to_bytes();
    let c_real = MonCommitment::new(bytes_to_monerod_scalar(&real_mask), amount)
        .commit()
        .compress()
        .to_bytes();
    TxSourceEntry {
        outputs: alloc::vec![
            OutputEntry {
                index: 0,
                dest: wallet_dest,
                mask: c_real,
            },
            OutputEntry {
                index: 100,
                dest: point_of(decoy_k),
                mask: point_of(decoy_k + 10),
            },
        ],
        real_output: 0,
        real_out_tx_key: tx_pub,
        real_out_additional_tx_keys: alloc::vec![],
        real_output_in_tx_index: 0,
        amount,
        rct: true,
        mask: SecretBytes::new(real_mask),
        multisig_kLRki: crate::chain::xmr::unsigned_txset::MultisigKLRki {
            k: [0; 32],
            l: [0; 32],
            r: [0; 32],
            ki: [0; 32],
        },
    }
}

/// 官方 verRctSemanticsSimple:ΣpseudoOuts = ΣoutPk + fee·H。
#[cfg(test)]
fn assert_rct_simple_balance(wire: &[u8], expect_fee: u64) {
    use crate::chain::xmr::transaction::monero_decode_varint;
    use curve25519_dalek::traits::Identity;
    let mut pos = 0;
    let prefix = TransactionPrefix::deserialize(wire, &mut pos).expect("prefix");
    let n_in = prefix.inputs.len();
    let n_out = prefix.outputs.len();
    assert!(n_in >= 1);
    assert!(n_out >= 1);
    pos += 1; // rct type
    let fee = monero_decode_varint(wire, &mut pos).expect("fee");
    assert_eq!(fee, expect_fee);
    pos += n_out * 8; // ecdhInfo
    let mut sum_out = curve25519_dalek::EdwardsPoint::identity();
    for _ in 0..n_out {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&wire[pos..pos + 32]);
        pos += 32;
        sum_out += curve25519_dalek::edwards::CompressedEdwardsY(pk)
            .decompress()
            .expect("outPk");
    }
    let fee_bytes = MonCommitment::new(bytes_to_monerod_scalar(&[0u8; 32]), fee)
        .commit()
        .compress()
        .to_bytes();
    sum_out += curve25519_dalek::edwards::CompressedEdwardsY(fee_bytes)
        .decompress()
        .expect("fee·H");
    let pseudo_start = wire.len() - n_in * 32;
    let mut sum_pseudo = curve25519_dalek::EdwardsPoint::identity();
    for i in 0..n_in {
        let off = pseudo_start + i * 32;
        let mut po = [0u8; 32];
        po.copy_from_slice(&wire[off..off + 32]);
        sum_pseudo += curve25519_dalek::edwards::CompressedEdwardsY(po)
            .decompress()
            .expect("pseudoOut");
    }
    assert_eq!(
        sum_pseudo.compress().to_bytes(),
        sum_out.compress().to_bytes(),
        "ΣpseudoOuts must equal ΣoutPk + fee·H"
    );
}

/// 审计 #9 P2-03 原「多输入拒绝」反转:真实 2-input signer 必须成功,
/// 且 ΣpseudoOuts = ΣoutPk + fee·H(官方 verRctSemanticsSimple)。
/// 手工构造 TxConstructionData,不依赖 env。不放 guard_tests:含 BP+ 证明,
/// Miri `guard_` 子集跑不完。
#[test]
fn multi_input_signer_succeeds_and_balances() {
    let (spend_sec, view_sec) = test_wallet_keys();
    let dest_pt = point_of(1);
    let dest = test_dest(2500, dest_pt, false);
    let change = test_dest(400, dest_pt, false);
    let tx_data = crate::chain::xmr::unsigned_txset::TxConstructionData {
        sources: alloc::vec![
            owned_source(&spend_sec, &view_sec, 1000, mask_of(0x66), point_of(5), 2),
            owned_source(&spend_sec, &view_sec, 2000, mask_of(0x77), point_of(6), 3),
        ],
        change_dts: change.clone(),
        splitted_dsts: alloc::vec![change, dest],
        selected_transfers: alloc::vec![0, 1],
        extra: alloc::vec![],
        unlock_time: 0,
        use_rct: 1,
        rct_config: crate::chain::xmr::unsigned_txset::RctConfig::default(),
        dests: alloc::vec![],
        subaddr_account: 0,
        subaddr_indices: alloc::vec![],
    };

    use rand_chacha::rand_core::SeedableRng;
    let rng = rand_chacha::ChaCha20Rng::from_seed([0x77u8; 32]);
    let mut bp_rng = rng.clone();
    let mut clsag_rng = rng.clone();
    let r_bytes = zeroize::Zeroizing::new([0x77u8; 32]);
    let wire = sign_tx_from_construction_with_rngs(
        &tx_data,
        &spend_sec,
        &view_sec,
        &r_bytes,
        &mut bp_rng,
        &mut clsag_rng,
    )
    .expect("2-input signer must succeed");
    assert_rct_simple_balance(&wire, 100);
}

/// 审计 #8 Gate0 #2:output derivation KAT——不依赖外部密钥的逐字节
/// 公式锁定,进普通测试(此前 XMR 输出正确性无普通门禁,P0-01 回归
/// 未被发现)。向量 = 实现按协议公式推导的快照;真实 oracle 交叉验证
/// 在 p63(ignored,需 env)。
#[test]
fn output_derivation_kat() {
    // 固定输入:r = 0x11.., dest view/spend = 0x22/0x33.., amount = 12345
    let r = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order([0x11u8; 32]);
    let dest = TxDestinationEntry {
        original: Vec::new(),
        amount: 12_345,
        spend_public_key: [0x33u8; 32],
        view_public_key: [0x22u8; 32],
        is_subaddress: false,
        is_integrated: false,
    };
    let d = derive_output(&r, &[0u8; 32], &dest, &[0u8; 32], 0).unwrap();

    // 8Ra 点 = 8·(r·A_v);独立重算(KAT 是验证方——直接用 dalek 数学)
    let a_v: curve25519_dalek::EdwardsPoint = CompressedPoint::from([0x22u8; 32])
        .decompress()
        .unwrap()
        .into();
    let r_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order([0x11u8; 32]);
    let eight_ra = (a_v * r_scalar).mul_by_cofactor().compress().to_bytes();
    // shared_key = Hs(8Ra || varint(0)) — varint(0) = [0]
    let mut expect_od = alloc::vec::Vec::new();
    expect_od.extend_from_slice(&eight_ra);
    expect_od.push(0);
    let expect_shared = hash_to_scalar(&expect_od).unwrap();
    assert_eq!(d.shared_key.expose(), &expect_shared);

    // stealth = B_dest + Hs(8Ra||0)·G —— 与 shared_key 同一哈希(P0-01 锚点)
    let hs_scalar = bytes_to_scalar(&expect_shared);
    let b_dest: curve25519_dalek::EdwardsPoint = CompressedPoint::from([0x33u8; 32])
        .decompress()
        .unwrap()
        .into();
    let expect_stealth = (b_dest
        + curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &hs_scalar)
        .compress()
        .to_bytes();
    assert_eq!(d.stealth_address, expect_stealth);

    // enc amount = amount XOR Hs("amount"||shared_key)[..8]
    let mut amt = alloc::vec::Vec::new();
    amt.extend_from_slice(b"amount");
    amt.extend_from_slice(&expect_shared);
    let h = crate::encoding::keccak256::hash(&amt).unwrap();
    let m8 = u64::from_le_bytes(h[..8].try_into().unwrap());
    assert_eq!(d.encrypted_amount, (12_345u64 ^ m8).to_le_bytes());

    // view_tag = keccak("view_tag"||8Ra||0)[0]
    let mut vt = alloc::vec::Vec::new();
    vt.extend_from_slice(b"view_tag");
    vt.extend_from_slice(&eight_ra);
    vt.push(0);
    assert_eq!(
        d.view_tag,
        crate::encoding::keccak256::hash(&vt).unwrap()[0]
    );
}

/// 审计 #8 Gate2 P1-04:signer 级失败注入——复用 GPT 方案 2:
/// 构造天然可达的 clsag 失败点(decoy C 点 [0x99;32] 不可解压;real_output=0
/// 对两元素 ring 合法),让真实 clsag_mod::sign 在 owner(real mask/input
/// sk/rings)全部建立后稳定失败;通过静态影子证明错误路径上 guard Drop
/// 真实执行了清零(影子含 Drop 时的 masks)。
/// 审计 #12 P2-01:影子加 invocation token——测试先 begin_invocation()
/// 领 token,guard Drop 盖当前 token,测试按 token 消费式取记录。
/// 并行测试不再经由单槽互相覆盖(事务隔离,不止于消除数据竞争)。
#[test]
fn signer_clsag_failure_populates_then_drops_owner() {
    use crate::chain::xmr::unsigned_txset::{
        OutputEntry, RctConfig, TxDestinationEntry, TxSourceEntry,
    };
    use crate::types::SecretBytes;

    // 测试自己的钱包 → derive_input_from_source 可成功
    let test_seed = [0x42u8; 64];
    let path = crate::derivation::monero_reduce_scalar::MoneroPath::mainnet(0);
    let kp = crate::derivation::monero_reduce_scalar::derive(&test_seed, &path).unwrap();
    let spend_sec = crate::curve_primitive::ed25519::scalar_to_bytes(kp.spend_priv());
    let view_sec = crate::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv());

    // 有效曲线点(可解压):1·G
    let pt =
        curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &curve25519_dalek::Scalar::from(1u8);
    let pt_bytes = pt.compress().to_bytes();
    // decoy C 点:全 0x99 不可解压——Edwards 解压必失败
    // → clsag sign 在 decoy 解压处 Err——此时 owner 已全部建立
    let bad_c: [u8; 32] = [0x99u8; 32];
    // real output dest 必须通过归属校验:dest = (spend + offset)·G,
    // offset = calc_output_key_offset(view_sec, tx_pub, 0, 0, 0)
    let tx_pub_bytes: [u8; 32] = pt_bytes; // real_out_tx_key(点,可解压即可)
    let key_offset =
        crate::chain::xmr::subaddress::calc_output_key_offset(&view_sec, &tx_pub_bytes, 0, 0, 0)
            .unwrap();
    let spend_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(spend_sec);
    let offset_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(key_offset);
    let wallet_dest = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
        * &(spend_scalar + offset_scalar))
        .compress()
        .to_bytes();
    let mk_output = move |i: u64, c: [u8; 32], d: [u8; 32]| OutputEntry {
        index: i * 100,
        dest: d,
        mask: c, // 链上 C 点
    };

    let source = TxSourceEntry {
        outputs: alloc::vec![
            mk_output(0, pt_bytes, wallet_dest), // real:归属校验通过
            mk_output(1, bad_c, pt_bytes),       // decoy:C 点无效 → clsag 失败
        ],
        real_output: 0, // real 合法(derive_input_from_source 通过)
        real_out_tx_key: tx_pub_bytes,
        real_out_additional_tx_keys: alloc::vec![],
        real_output_in_tx_index: 0,
        amount: 1000,
        rct: true,
        mask: SecretBytes::new([0x66u8; 32]), // 真实 mask(会被 guard 建立)
        multisig_kLRki: crate::chain::xmr::unsigned_txset::MultisigKLRki {
            k: [0; 32],
            l: [0; 32],
            r: [0; 32],
            ki: [0; 32],
        },
    };
    let dest = TxDestinationEntry {
        original: Vec::new(),
        amount: 900,
        spend_public_key: pt_bytes,
        view_public_key: pt_bytes,
        is_subaddress: false,
        is_integrated: false,
    };
    // change 用不同 amount/keys——is_change 判定不误伤,输出走非 change
    // 分支(与 inputs/guard 同在 CLSAG 前的正确路径上)
    let change_dest = TxDestinationEntry {
        original: Vec::new(),
        amount: 1,
        spend_public_key: [0x77u8; 32],
        view_public_key: [0x77u8; 32],
        is_subaddress: false,
        is_integrated: false,
    };
    let tx_data = crate::chain::xmr::unsigned_txset::TxConstructionData {
        sources: alloc::vec![source],
        change_dts: change_dest,
        splitted_dsts: alloc::vec![dest],
        selected_transfers: alloc::vec![0],
        extra: alloc::vec![],
        unlock_time: 0,
        use_rct: 1,
        rct_config: RctConfig::default(),
        dests: alloc::vec![],
        subaddr_account: 0,
        subaddr_indices: alloc::vec![],
    };

    use rand_chacha::rand_core::SeedableRng;
    let invocation = shadow::begin_invocation();
    let rng = rand_chacha::ChaCha20Rng::from_seed([0x77u8; 32]);
    let mut bp_rng = rng.clone();
    let mut clsag_rng = rng.clone();
    let r_bytes = zeroize::Zeroizing::new([0x77u8; 32]);
    let result = sign_tx_from_construction_with_rngs(
        &tx_data,
        &spend_sec,
        &view_sec,
        &r_bytes,
        &mut bp_rng,
        &mut clsag_rng,
    );
    // 失败必须发生(fault point = decoy commitment 解压,real_output=0
    // 对两元素 ring 合法);关键证据在下方影子断言
    assert!(
        result.is_err(),
        "invalid decoy commitment must fail at clsag decompression"
    );

    // 按事务消费式取记录 = 本测试自己的 guard Drop(审计 #12 P2-01 事务
    // 隔离);kind 精确归因——距失败点最近的 owner 是 real_mask guard
    // (decoy C 点不可解压 → clsag sign 解压失败)
    let inner = invocation
        .take_last("real_mask")
        .expect("guard Drop must have populated shadow in this invocation");
    assert_eq!(
        inner.kind, "real_mask",
        "shadow must attribute to the real-mask owner (P2-01)"
    );
    assert_eq!(
        inner.masks.len(),
        1,
        "guard must have held 1 real mask when clsag sign failed"
    );
    assert!(
        inner.masks[0].iter().all(|&b| b == 0),
        "error-path guard Drop must zeroize the real mask"
    );
}

/// 多输入失败路径:第二输入 decoy C 不可解压 → Err,且 real_mask owner 已持有 2 个并被 Drop 清零。
#[test]
fn multi_input_clsag_failure_drops_all_owners() {
    use crate::chain::xmr::unsigned_txset::{OutputEntry, RctConfig, TxSourceEntry};
    use crate::types::SecretBytes;

    let (spend_sec, view_sec) = test_wallet_keys();
    let dest_pt = point_of(1);
    let dest = test_dest(900, dest_pt, false);
    let good = owned_source(&spend_sec, &view_sec, 1000, mask_of(0x66), point_of(5), 2);

    // 本测试的事务在任何 guard Drop 前开启(调用前清空 + 持锁)
    let invocation = shadow::begin_invocation();

    let tx_pub = point_of(6);
    let key_offset =
        crate::chain::xmr::subaddress::calc_output_key_offset(&view_sec, &tx_pub, 0, 0, 0).unwrap();
    let spend_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(spend_sec);
    let offset_scalar = curve25519_dalek::Scalar::from_bytes_mod_order(key_offset);
    let wallet_dest = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
        * &(spend_scalar + offset_scalar))
        .compress()
        .to_bytes();
    let c_real = MonCommitment::new(bytes_to_monerod_scalar(&mask_of(0x77)), 2000)
        .commit()
        .compress()
        .to_bytes();
    let bad = TxSourceEntry {
        outputs: alloc::vec![
            OutputEntry {
                index: 0,
                dest: wallet_dest,
                mask: c_real,
            },
            OutputEntry {
                index: 100,
                dest: point_of(3),
                mask: [0x99u8; 32], // 不可解压 → clsag 失败
            },
        ],
        real_output: 0,
        real_out_tx_key: tx_pub,
        real_out_additional_tx_keys: alloc::vec![],
        real_output_in_tx_index: 0,
        amount: 2000,
        rct: true,
        mask: SecretBytes::new(mask_of(0x77)),
        multisig_kLRki: crate::chain::xmr::unsigned_txset::MultisigKLRki {
            k: [0; 32],
            l: [0; 32],
            r: [0; 32],
            ki: [0; 32],
        },
    };
    let tx_data = crate::chain::xmr::unsigned_txset::TxConstructionData {
        sources: alloc::vec![good, bad],
        change_dts: dest.clone(),
        splitted_dsts: alloc::vec![dest],
        selected_transfers: alloc::vec![0, 1],
        extra: alloc::vec![],
        unlock_time: 0,
        use_rct: 1,
        rct_config: RctConfig::default(),
        dests: alloc::vec![],
        subaddr_account: 0,
        subaddr_indices: alloc::vec![],
    };
    use rand_chacha::rand_core::SeedableRng;
    let rng = rand_chacha::ChaCha20Rng::from_seed([0x77u8; 32]);
    let mut bp_rng = rng.clone();
    let mut clsag_rng = rng.clone();
    let r_bytes = zeroize::Zeroizing::new([0x77u8; 32]);
    let result = sign_tx_from_construction_with_rngs(
        &tx_data,
        &spend_sec,
        &view_sec,
        &r_bytes,
        &mut bp_rng,
        &mut clsag_rng,
    );
    assert!(result.is_err(), "invalid decoy on input 1 must fail");
    let inner = invocation
        .take_last("real_mask")
        .expect("guard Drop must have populated shadow in this invocation");
    assert_eq!(inner.kind, "real_mask");
    assert_eq!(
        inner.masks.len(),
        2,
        "both real masks must be in the owner when clsag fails"
    );
    assert!(
        inner.masks.iter().all(|m| m.iter().all(|&b| b == 0)),
        "error-path Drop must zeroize all real masks"
    );
}

/// change 分支 KAT:ecdh = view_sec · TxPub,stealth = B + Hs(8Ra||varint(i))·G。
#[test]
fn change_output_derivation_kat() {
    let (spend_sec, view_sec) = test_wallet_keys();
    let dest_pt = point_of(1);
    let change_pt = point_of(4);
    let dest = test_dest(900, dest_pt, false);
    let change = test_dest(100, change_pt, false);
    let tx_data = crate::chain::xmr::unsigned_txset::TxConstructionData {
        sources: alloc::vec![owned_source(
            &spend_sec,
            &view_sec,
            1100,
            mask_of(0x66),
            point_of(5),
            2
        )],
        change_dts: change.clone(),
        splitted_dsts: alloc::vec![change.clone(), dest],
        selected_transfers: alloc::vec![0],
        extra: alloc::vec![],
        unlock_time: 0,
        use_rct: 1,
        rct_config: crate::chain::xmr::unsigned_txset::RctConfig::default(),
        dests: alloc::vec![],
        subaddr_account: 0,
        subaddr_indices: alloc::vec![],
    };
    use rand_chacha::rand_core::SeedableRng;
    let rng = rand_chacha::ChaCha20Rng::from_seed([0x55u8; 32]);
    let mut bp_rng = rng.clone();
    let mut clsag_rng = rng.clone();
    let r_bytes = zeroize::Zeroizing::new([0x11u8; 32]);
    let wire = sign_tx_from_construction_with_rngs(
        &tx_data,
        &spend_sec,
        &view_sec,
        &r_bytes,
        &mut bp_rng,
        &mut clsag_rng,
    )
    .expect("1-input change path must succeed");
    let mut pos = 0;
    let prefix = TransactionPrefix::deserialize(&wire, &mut pos).expect("prefix");
    assert_eq!(prefix.outputs.len(), 2);

    // 独立重算 change(index=0):8Ra = 8·(view·tx_pub);tx_pub = r·G
    let r = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order(*r_bytes);
    let tx_pub = r.mul_basepoint();
    let v = crate::types::secret_scalar::SecretScalar::from_slice(&view_sec);
    let ecdh = v.mul_point(&tx_pub).unwrap();
    let ecdh_pt: curve25519_dalek::EdwardsPoint =
        CompressedPoint::from(ecdh).decompress().unwrap().into();
    let eight_ra = ecdh_pt.mul_by_cofactor().compress().to_bytes();
    let mut od = alloc::vec::Vec::new();
    od.extend_from_slice(&eight_ra);
    od.push(0); // varint(0)
    let shared = hash_to_scalar(&od).unwrap();
    let hs = bytes_to_scalar(&shared);
    let b_change: curve25519_dalek::EdwardsPoint = CompressedPoint::from(change_pt)
        .decompress()
        .unwrap()
        .into();
    let expect_stealth = (b_change + curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &hs)
        .compress()
        .to_bytes();
    assert_eq!(
        prefix.outputs[0].stealth_address, expect_stealth,
        "change stealth must use view_sec·TxPub, not r·A_v"
    );
}

/// subaddress 输出 KAT:additional_tx_key = r·B_sub。
#[test]
fn subaddress_output_derivation_kat() {
    let r = crate::types::secret_scalar::SecretScalar::from_bytes_mod_order([0x11u8; 32]);
    let dest = TxDestinationEntry {
        original: Vec::new(),
        amount: 12_345,
        spend_public_key: [0x33u8; 32],
        view_public_key: [0x22u8; 32],
        is_subaddress: true,
        is_integrated: false,
    };
    let d = derive_output(&r, &[0u8; 32], &dest, &[0u8; 32], 0).unwrap();
    let expect_add = r.mul_point(&dest.spend_public_key).unwrap();
    assert_eq!(
        d.additional_tx_key
            .expect("subaddress must emit additional key"),
        expect_add
    );
    // 非子地址路径不发 additional key(对照,防止恒真)
    let dest_main = TxDestinationEntry {
        is_subaddress: false,
        ..dest
    };
    let d_main = derive_output(&r, &[0u8; 32], &dest_main, &[0u8; 32], 0).unwrap();
    assert!(d_main.additional_tx_key.is_none());
}
