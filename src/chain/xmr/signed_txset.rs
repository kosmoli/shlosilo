//! Signed txset 序列化 + 加密（P1-06 收尾，§B.5 定案实施第 3 步）。
//!
//! 对齐 keystone：
//! - `signed_transaction.rs:87-138` `SignedTxSet::serialize`（wire 布局逐字节一致）
//! - `utils/mod.rs::encrypt_data_with_pvk`（magic + nonce 8B 大端 + ChaCha20-Legacy
//!   + 尾部 64B Monero Schnorr 签名）
//! - `utils/sign.rs::generate_signature` / `generate_ring_signature`（tx_key_images 签名）
//!
//! wire 要点（与解密侧 read_* 对偶，均经 P6.3 真实 fixture 互验）：
//! - varint = LEB128；u64 字段 = 8B LE
//! - tx_key 位置写 Scalar::ONE（keystone 归零处理——r 不回传 host）
//! - key_images_str = `<hex> ` 逐项拼接（含尾随空格）
//! - tx_key_images 项 = 0x02 ‖ output 一次性地址 ‖ key image（Hs(shared_key)·Hp）

extern crate alloc;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;

use crate::chain::xmr::subaddress::hash_to_scalar;
use crate::chain::xmr::unsigned_txset::{TxConstructionData, TxDestinationEntry};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

use alloc::{string::String, vec::Vec};

/// 与解密侧对称的 magic
pub const SIGNED_TX_PREFIX: &[u8] = b"Monero signed tx set\x05";

const NONCE_LEN: usize = 8;
const SIG_LEN: usize = 64;

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

fn put_varint(out: &mut Vec<u8>, n: u64) {
    crate::chain::xmr::transaction::monero_encode_varint(out, n);
}

// ============ 子结构序列化（对齐 keystone utils/io.rs） ============

pub(crate) fn write_destination_entry(out: &mut Vec<u8>, e: &TxDestinationEntry) {
    put_varint(out, e.original.len() as u64);
    out.extend_from_slice(&e.original);
    out.extend_from_slice(&e.amount.to_le_bytes());
    out.extend_from_slice(&e.spend_public_key);
    out.extend_from_slice(&e.view_public_key);
    out.push(e.is_subaddress as u8);
    out.push(e.is_integrated as u8);
}

fn write_output_entry(out: &mut Vec<u8>, index: u64, dest: &[u8; 32], mask: &[u8; 32]) {
    // std::pair 在 binary_archive 里是 class，前有字段数前缀 0x02
    out.push(2);
    put_varint(out, index);
    out.extend_from_slice(dest);
    out.extend_from_slice(mask);
}

fn write_source_entry(out: &mut Vec<u8>, s: &crate::chain::xmr::unsigned_txset::TxSourceEntry) {
    put_varint(out, s.outputs.len() as u64);
    for o in &s.outputs {
        write_output_entry(out, o.index, &o.dest, &o.mask);
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
    // P1-03: mask 明文访问收敛到 expose()——wire 序列化是唯一的合法出口之一
    out.extend_from_slice(s.mask.expose());
    out.extend_from_slice(&s.multisig_kLRki.k);
    out.extend_from_slice(&s.multisig_kLRki.l);
    out.extend_from_slice(&s.multisig_kLRki.r);
    out.extend_from_slice(&s.multisig_kLRki.ki);
}

pub(crate) fn write_construction_data(out: &mut Vec<u8>, d: &TxConstructionData) {
    put_varint(out, d.sources.len() as u64);
    for s in &d.sources {
        write_source_entry(out, s);
    }
    write_destination_entry(out, &d.change_dts);
    put_varint(out, d.splitted_dsts.len() as u64);
    for dst in &d.splitted_dsts {
        write_destination_entry(out, dst);
    }
    put_varint(out, d.selected_transfers.len() as u64);
    // construction_data 里 selected_transfers 是 varint（与 ptx 顶层的逐 u8 不同！）
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
        write_destination_entry(out, dest);
    }
    out.extend_from_slice(&d.subaddr_account.to_le_bytes());
    put_varint(out, d.subaddr_indices.len() as u64);
    for i in &d.subaddr_indices {
        put_varint(out, *i as u64);
    }
}

// ============ PendingTx / SignedTxSet ============

/// 一笔已签交易及其元数据（对齐 keystone PendingTx）
pub struct PendingTx {
    /// 完整 tx wire bytes（含 rct signatures）
    pub tx_bytes: Vec<u8>,
    pub dust: u64,
    pub fee: u64,
    pub dust_added_to_fee: bool,
    pub change_dts: TxDestinationEntry,
    /// ptx 顶层：逐 u8（非 varint）
    pub selected_transfers: Vec<u8>,
    /// `<hex> ` 拼接的 key image 列表
    pub key_images_str: String,
    /// tx_key（写入 wire 前强制置 ONE——r 不回传 host，见模块文档）
    pub additional_tx_keys: Vec<[u8; 32]>,
    pub dests: Vec<TxDestinationEntry>,
    pub construction_data: TxConstructionData,
}

/// 输出一次性地址 → key image（对齐 keystone tx_key_images）
pub struct TxKeyImageEntry {
    /// 输出的一次性地址（stealth address）
    pub output_pubkey: [u8; 32],
    /// Hs(shared_key)·Hp(output_pubkey)
    pub key_image: [u8; 32],
}

pub struct SignedTxSet {
    pub ptx: Vec<PendingTx>,
    /// 每个 transfer 一个 key image（外层，逐 32B）
    pub key_images: Vec<[u8; 32]>,
    pub tx_key_images: Vec<TxKeyImageEntry>,
}

impl SignedTxSet {
    /// 对齐 keystone `SignedTxSet::serialize`（逐字节一致）
    pub fn serialize(&self) -> Vec<u8> {
        let mut res = Vec::new();
        // signed_tx_set version 00
        res.push(0u8);
        put_varint(&mut res, self.ptx.len() as u64);
        for ptx in &self.ptx {
            // ptx version 1
            res.push(1u8);
            res.extend_from_slice(&ptx.tx_bytes);
            res.extend_from_slice(&ptx.dust.to_le_bytes());
            res.extend_from_slice(&ptx.fee.to_le_bytes());
            res.push(ptx.dust_added_to_fee as u8);
            write_destination_entry(&mut res, &ptx.change_dts);
            put_varint(&mut res, ptx.selected_transfers.len() as u64);
            // ptx 顶层 selected_transfers：逐 u8（非 varint）
            for t in &ptx.selected_transfers {
                res.push(*t);
            }
            let ki = ptx.key_images_str.as_bytes();
            put_varint(&mut res, ki.len() as u64);
            if !ki.is_empty() {
                res.extend_from_slice(ki);
            }
            // tx_key ZERO：keystone 用 Scalar::ONE 占位（r 不回传）
            res.extend_from_slice(&Scalar::ONE.to_bytes());
            put_varint(&mut res, ptx.additional_tx_keys.len() as u64);
            for k in &ptx.additional_tx_keys {
                res.extend_from_slice(k);
            }
            put_varint(&mut res, ptx.dests.len() as u64);
            for dest in &ptx.dests {
                write_destination_entry(&mut res, dest);
            }
            write_construction_data(&mut res, &ptx.construction_data);
            // multisig_sigs：v1 恒空
            res.push(0u8);
            // multisig_tx_key_entropy：keystone PrivateKey::default() = 全零
            res.extend_from_slice(&[0u8; 32]);
        }
        put_varint(&mut res, self.key_images.len() as u64);
        for ki in &self.key_images {
            res.extend_from_slice(ki);
        }
        put_varint(&mut res, self.tx_key_images.len() as u64);
        for e in &self.tx_key_images {
            res.push(2u8);
            res.extend_from_slice(&e.output_pubkey);
            res.extend_from_slice(&e.key_image);
        }
        res
    }
}

// ============ key image 环签名（tx_key_images 用） ============

// Monero 环签名（对齐 keystone `generate_ring_signature`）：
// 输出 [π0, π1] 数组；真成员位置由 sec_idx 决定。
//
// 返回扁平 (s0, s1) 对（keystone SignatureTrait 的 [Scalar; 2]），
// 这里只用于 tx_key_images 的 key image 生成，与 wire 无关（wire 只存 image）。
// shlosilo 中 image 已由 sign 路径计算；此函数仅供 host 侧一致性验证，
// 故未导出为 pub——避免无人调用的死代码进 staticlib。

// ============ Monero Schnorr 签名（加密 blob 尾部 64B） ============

/// Monero 自定义 Schnorr 签名（对齐 keystone `generate_signature`）：
/// k 随机 → R' = kG → c = Hs(hash ‖ P ‖ R') → r = k − c·x
/// 输出 (c 32B, r 32B)。
///
/// 与解密侧 `check_monero_signature` 完全对偶（同一签名方案两侧实现互验）。
pub fn monero_sign(
    hash: &[u8; 32],
    view_sk: &[u8; 32],
    rng: &mut impl rand_core::RngCore,
) -> Result<[[u8; 32]; 2]> {
    let x = Scalar::from_bytes_mod_order(*view_sk);
    let p_bytes = (ED25519_BASEPOINT_TABLE * &x).compress().to_bytes();

    let mut k_bytes = [0u8; 32];
    let (mut c, mut r);
    loop {
        rng.fill_bytes(&mut k_bytes);
        let k = Scalar::from_bytes_mod_order(k_bytes);
        let k_pub = (ED25519_BASEPOINT_TABLE * &k).compress().to_bytes();

        let mut data = Vec::with_capacity(96);
        data.extend_from_slice(hash);
        data.extend_from_slice(&p_bytes);
        data.extend_from_slice(&k_pub);
        let c_bytes = hash_to_scalar(&data)?;
        c = Scalar::from_bytes_mod_order(c_bytes);
        if c == Scalar::ZERO {
            continue;
        }
        r = k - c * x;
        if r == Scalar::ZERO {
            continue;
        }
        break;
    }
    Ok([c.to_bytes(), r.to_bytes()])
}

// ============ 加密输出 ============

/// 加密 signed txset（对齐 keystone `encrypt_data_with_pvk`，SIGNED_TX_PREFIX 路径）：
///
/// ```text
/// output = magic(23B) ‖ nonce(8B BE) ‖ ChaCha20Legacy(H(cn_v0(view_sk)), nonce)(plain) ‖ sig(64B)
/// plain  = txset bytes（SIGNED_TX_PREFIX 路径无 spend/view pubkey 前缀）
/// sig    = Monero Schnorr(keccak256(nonce ‖ 密文), view_pub, view_sk)
/// ```
///
/// rng 用途：nonce（next_u64）+ 签名 k——由 §B.5 purpose RNG 提供。
pub fn encrypt_signed_txset(
    plain: Vec<u8>,
    view_sk: &[u8; 32],
    rng: &mut impl rand_core::RngCore,
) -> Result<Vec<u8>> {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20Legacy;

    // 1. key = CryptoNight v0(view_sk)，nonce = 8B 大端
    let key = cuprate_cryptonight::cryptonight_hash_v0(view_sk);
    let nonce_num = rng.next_u64();
    let nonce_num_bytes = nonce_num.to_be_bytes();

    // 2. 密文（原位加密）
    let mut buffer = plain;
    let nonce: chacha20::LegacyNonce = nonce_num_bytes.into();
    let mut cipher = ChaCha20Legacy::new_from_slices(&key, &nonce).map_err(|_| err())?;
    cipher.apply_keystream(&mut buffer);

    // 3. 签名 = Monero Schnorr over keccak256(nonce ‖ 密文)，公钥 = view_pub
    let mut unsigned = Vec::with_capacity(NONCE_LEN + buffer.len());
    unsigned.extend_from_slice(&nonce_num_bytes);
    unsigned.extend_from_slice(&buffer);
    let msg_hash = crate::encoding::keccak256::hash(&unsigned)?;
    let [c, r] = monero_sign(&msg_hash, view_sk, rng)?;

    // 4. magic ‖ nonce ‖ 密文 ‖ sig
    let mut out = Vec::with_capacity(SIGNED_TX_PREFIX.len() + NONCE_LEN + buffer.len() + SIG_LEN);
    out.extend_from_slice(SIGNED_TX_PREFIX);
    out.extend_from_slice(&nonce_num_bytes);
    out.extend_from_slice(&buffer);
    out.extend_from_slice(&c);
    out.extend_from_slice(&r);
    Ok(out)
}

/// 解密 signed txset（自验 round-trip 用；对齐 keystone `decrypt_data_with_pvk`）。
///
/// magic 校验 → nonce → Schnorr 验签（view_pub，keccak256(nonce‖密文)）→ 解密。
pub fn decrypt_signed_txset(data: &[u8], view_sk: &[u8; 32]) -> Result<Vec<u8>> {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20Legacy;

    if data.len() < SIGNED_TX_PREFIX.len() + NONCE_LEN + SIG_LEN {
        return Err(err());
    }
    if &data[..SIGNED_TX_PREFIX.len()] != SIGNED_TX_PREFIX {
        return Err(err());
    }
    let raw = &data[SIGNED_TX_PREFIX.len()..data.len() - SIG_LEN];
    let nonce_bytes = &raw[..NONCE_LEN];
    let sig = &data[data.len() - SIG_LEN..];

    // 验签（复用 unsigned_txset.rs 的实现——同一方案两侧对称）
    use curve25519_dalek::scalar::Scalar;
    let v_scalar = Scalar::from_bytes_mod_order(*view_sk);
    let view_pub = (ED25519_BASEPOINT_TABLE * &v_scalar).compress().to_bytes();
    let msg_hash = crate::encoding::keccak256::hash(raw)?;
    if !super::unsigned_txset::verify_monero_signature_pubkey(&msg_hash, &view_pub, sig)? {
        return Err(err());
    }

    let key = cuprate_cryptonight::cryptonight_hash_v0(view_sk);
    let mut plain = raw[NONCE_LEN..].to_vec();
    let mut nb = [0u8; 8];
    nb.copy_from_slice(nonce_bytes);
    let nonce: chacha20::LegacyNonce = nb.into();
    let mut cipher = ChaCha20Legacy::new_from_slices(&key, &nonce).map_err(|_| err())?;
    cipher.apply_keystream(&mut plain);
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec, vec::Vec};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_view_sk() -> [u8; 32] {
        let mut sk = [0u8; 32];
        for (i, b) in sk.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        sk
    }

    /// Monero Schnorr 生成/验证 round-trip（同方案两侧对称）
    #[test]
    fn monero_sign_verify_round_trip() {
        let sk = test_view_sk();
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let sig = monero_sign(&[0xAAu8; 32], &sk, &mut rng).unwrap();
        let mut sig_bytes = Vec::new();
        sig_bytes.extend_from_slice(&sig[0]);
        sig_bytes.extend_from_slice(&sig[1]);

        let x = Scalar::from_bytes_mod_order(sk);
        let pub_key = (ED25519_BASEPOINT_TABLE * &x).compress().to_bytes();
        assert!(
            super::super::unsigned_txset::verify_monero_signature_pubkey(
                &[0xAAu8; 32],
                &pub_key,
                &sig_bytes
            )
            .unwrap()
        );
        // 篡改 hash → 验签失败
        assert!(
            !super::super::unsigned_txset::verify_monero_signature_pubkey(
                &[0xBBu8; 32],
                &pub_key,
                &sig_bytes
            )
            .unwrap()
        );
    }

    /// 加密/解密 round-trip + 篡改拒绝
    #[test]
    fn encrypt_decrypt_round_trip() {
        let sk = test_view_sk();
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let plain = b"Monero signed tx set payload here".to_vec();
        let enc = encrypt_signed_txset(plain.clone(), &sk, &mut rng).unwrap();
        assert_eq!(&enc[..SIGNED_TX_PREFIX.len()], SIGNED_TX_PREFIX);
        assert_eq!(enc.len(), SIGNED_TX_PREFIX.len() + 8 + plain.len() + 64);
        let dec = decrypt_signed_txset(&enc, &sk).unwrap();
        assert_eq!(dec, plain);

        // 篡改密文中间字节 → 验签拒绝
        let mut tampered = enc.clone();
        tampered[SIGNED_TX_PREFIX.len() + 20] ^= 0x01;
        assert!(decrypt_signed_txset(&tampered, &sk).is_err());

        // 错误 view key → 验签拒绝
        assert!(decrypt_signed_txset(&enc, &[0xEEu8; 32]).is_err());
    }

    /// 确定性：同 (plain, view_sk, seed) → 同输出（§B.5 测试模型）
    #[test]
    fn encrypt_deterministic() {
        let sk = test_view_sk();
        let mut rng1 = ChaCha20Rng::from_seed([9u8; 32]);
        let mut rng2 = ChaCha20Rng::from_seed([9u8; 32]);
        let e1 = encrypt_signed_txset(b"data".to_vec(), &sk, &mut rng1).unwrap();
        let e2 = encrypt_signed_txset(b"data".to_vec(), &sk, &mut rng2).unwrap();
        assert_eq!(e1, e2);
    }

    /// serialize 布局关键锚点：version/ptx count/tx_key=ONE/multisig 占位
    #[test]
    fn serialize_layout_anchors() {
        use crate::chain::xmr::unsigned_txset::RctConfig;
        let dest = TxDestinationEntry {
            original: b"4Ae44ncK".to_vec(),
            amount: 1000,
            spend_public_key: [1u8; 32],
            view_public_key: [2u8; 32],
            is_subaddress: false,
            is_integrated: false,
        };
        let ptx = PendingTx {
            tx_bytes: vec![0xABu8; 5],
            dust: 0,
            fee: 30640000,
            dust_added_to_fee: false,
            change_dts: dest.clone(),
            selected_transfers: vec![0u8],
            key_images_str: "<aabb> ".to_string(),
            additional_tx_keys: vec![],
            dests: vec![dest.clone()],
            construction_data: TxConstructionData {
                sources: vec![],
                change_dts: dest.clone(),
                splitted_dsts: vec![dest],
                selected_transfers: vec![0usize],
                extra: vec![],
                unlock_time: 0,
                use_rct: 1,
                rct_config: RctConfig::default(),
                dests: vec![],
                subaddr_account: 0,
                subaddr_indices: vec![1],
            },
        };
        let set = SignedTxSet {
            ptx: vec![ptx],
            key_images: vec![[3u8; 32]],
            tx_key_images: vec![TxKeyImageEntry {
                output_pubkey: [4u8; 32],
                key_image: [5u8; 32],
            }],
        };
        let bytes = set.serialize();
        let mut off = 0usize;
        // version
        assert_eq!(bytes[off], 0x00);
        off += 1;
        // ptx count = 1
        assert_eq!(bytes[off], 0x01);
        off += 1;
        // ptx version
        assert_eq!(bytes[off], 0x01);
        off += 1;
        // tx_bytes
        assert_eq!(&bytes[off..off + 5], &[0xABu8; 5]);
        off += 5;
        // dust(8) + fee(8) + dust_added(1)
        assert_eq!(&bytes[off..off + 8], &0u64.to_le_bytes());
        off += 8;
        assert_eq!(&bytes[off..off + 8], &30640000u64.to_le_bytes());
        off += 8;
        assert_eq!(bytes[off], 0);
        off += 1;
        // change_dts: varint(8) + "4Ae44ncK" + amount(8) + pk(32)×2 + 2 flags
        assert_eq!(bytes[off], 8);
        off += 1 + 8 + 8 + 32 + 32 + 2;
        // selected_transfers count=1, 逐 u8
        assert_eq!(bytes[off], 1);
        off += 1;
        assert_eq!(bytes[off], 0);
        off += 1;
        // key_images_str len varint(7) + "<aabb> "
        assert_eq!(bytes[off], 7);
        off += 1;
        assert_eq!(&bytes[off..off + 7], b"<aabb> ");
        off += 7;
        // tx_key = Scalar::ONE
        assert_eq!(&bytes[off..off + 32], &Scalar::ONE.to_bytes());
        off += 32;
        // additional_tx_keys count = 0
        assert_eq!(bytes[off], 0);
        off += 1;
        // dests count = 1（ptx 顶层）
        assert_eq!(bytes[off], 1);
        off += 1;
        off += 1 + 8 + 8 + 32 + 32 + 2; // dest entry
                                        // construction_data: sources=0 → change_dts → splitted=1 → …
        assert_eq!(bytes[off], 0); // sources count
        off += 1;
        off += 1 + 8 + 8 + 32 + 32 + 2; // change_dts
        assert_eq!(bytes[off], 1); // splitted count
        off += 1;
        off += 1 + 8 + 8 + 32 + 32 + 2; // splitted[0]
        assert_eq!(bytes[off], 1); // selected_transfers count
        off += 1;
        assert_eq!(bytes[off], 0); // varint(0)
        off += 1;
        assert_eq!(bytes[off], 0); // extra len
        off += 1;
        off += 8; // unlock_time
        assert_eq!(bytes[off], 1); // use_rct
        off += 1;
        off += 3; // rct_config version/range/bp varint(0)×3
        assert_eq!(bytes[off], 0); // dests count
        off += 1;
        off += 4; // subaddr_account u32
        assert_eq!(bytes[off], 1); // subaddr_indices count
        off += 1;
        assert_eq!(bytes[off], 1); // varint(1)
        off += 1;
        // multisig_sigs = 0 + entropy 32B 零
        assert_eq!(bytes[off], 0);
        off += 1;
        assert_eq!(&bytes[off..off + 32], &[0u8; 32]);
        off += 32;
        // 外层 key_images count=1 + 32B
        assert_eq!(bytes[off], 1);
        off += 1;
        assert_eq!(&bytes[off..off + 32], &[3u8; 32]);
        off += 32;
        // tx_key_images count=1 + 0x02 + 32 + 32
        assert_eq!(bytes[off], 1);
        off += 1;
        assert_eq!(bytes[off], 2);
        off += 1;
        assert_eq!(&bytes[off..off + 32], &[4u8; 32]);
        off += 32;
        assert_eq!(&bytes[off..off + 32], &[5u8; 32]);
        off += 32;
        assert_eq!(off, bytes.len());
    }
}
