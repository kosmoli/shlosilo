//! XMR key image 导出端到端流程（对齐 keystone `generate_export_ur_data`）。
//!
//! 三步 wire 协议中的第 ①→② 步：
//! 1. 钱包（热端）`export_outputs` → `OUTPUT_EXPORT_MAGIC` 加密 payload → XmrOutput UR
//! 2. 设备解密 → 校验 pk1/pk2 归属 → 逐 output 算 key image + 伴随签名
//!    → `KEY_IMAGE_EXPORT_MAGIC` 加密 → XmrKeyImage UR
//!
//! 加密包装层（对齐 keystone `utils/mod.rs`）：
//! ```text
//! encrypt: [magic][8B nonce BE][ChaCha20Legacy(cryptonight_hash_v0(view_sk), nonce)(
//!           [u32 LE 0 if key-image magic][pk1][pk2](仅 export magic)][data][64B sig])]
//! sig    : Monero Schnorr (c, r) over keccak256(nonce || ciphertext-before-sig),
//!          pubkey = view_pub — 见 unsigned_txset::check_monero_signature 对偶实现
//! ```

extern crate alloc;

use alloc::vec::Vec;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use monero_ed25519::Point;
use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::chain::xmr::output_export::{
    serialize_key_images, ExportedTransferDetail, ExportedTransferDetails,
    KEY_IMAGE_RECORD_LEN,
};
use crate::chain::xmr::unsigned_txset::check_monero_signature;
use crate::encoding::keccak256;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

pub const OUTPUT_EXPORT_MAGIC: &[u8] = b"Monero output export\x04";
pub const KEY_IMAGE_EXPORT_MAGIC: &[u8] = b"Monero key image export\x03";
const NONCE_LEN: usize = 8;
const SIG_LEN: usize = 64;
const PUBKEY_LEN: usize = 32;

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// 解密 export 类 payload（OUTPUT/KEY_IMAGE magic 共用结构）。
///
/// 返回 `(pk1, pk2, plaintext)`；pk1/pk2 仅 OUTPUT/KEY_IMAGE magic 存在
/// （unsigned/signed txset 无此段）。签名先验（防篡改），后解密。
pub fn decrypt_export_payload(
    data: &[u8],
    magic: &[u8],
    view_sk: &[u8; 32],
) -> Result<([u8; 32], [u8; 32], Vec<u8>)> {
    if data.len() < magic.len() + NONCE_LEN + SIG_LEN {
        return Err(err());
    }
    if &data[..magic.len()] != magic {
        return Err(err());
    }

    // raw = nonce || ciphertext（签名覆盖 nonce||cipher，对齐 keystone raw_data）
    let raw = &data[magic.len()..];
    let nonce = &raw[..NONCE_LEN];
    let sig = &data[data.len() - SIG_LEN..];
    let raw_data = &data[magic.len()..data.len() - SIG_LEN];

    // 1. Monero Schnorr 验签（view_pub 对 keccak256(nonce||cipher)）
    let v_scalar = Scalar::from_bytes_mod_order(*view_sk);
    let view_pub = (ED25519_BASEPOINT_TABLE * &v_scalar).compress().to_bytes();
    let msg_hash = keccak256::hash(raw_data)?;
    if !check_monero_signature(&msg_hash, &view_pub, sig)? {
        return Err(err());
    }

    // 2. ChaCha20-Legacy 解密
    let key = cuprate_cryptonight::cryptonight_hash_v0(view_sk);
    let mut cipher = chacha20::ChaCha20Legacy::new_from_slices(&key, nonce).map_err(|_| err())?;
    let mut plain = raw_data[NONCE_LEN..].to_vec();
    cipher.apply_keystream(&mut plain);

    // 3. key-image magic 有前置 u32 LE 0；两种 export magic 均带 pk1||pk2
    let start = if magic == KEY_IMAGE_EXPORT_MAGIC { 4 } else { 0 };
    if plain.len() < start + PUBKEY_LEN * 2 {
        return Err(err());
    }
    let mut pk1 = [0u8; 32];
    let mut pk2 = [0u8; 32];
    pk1.copy_from_slice(&plain[start..start + PUBKEY_LEN]);
    pk2.copy_from_slice(&plain[start + PUBKEY_LEN..start + PUBKEY_LEN * 2]);
    let payload = plain[start + PUBKEY_LEN * 2..].to_vec();
    Ok((pk1, pk2, payload))
}

/// 加密 export 类 payload（对齐 keystone `encrypt_data_with_pvk`）。
fn encrypt_export_payload<R: RngCore + CryptoRng>(
    magic: &[u8],
    view_sk: &[u8; 32],
    spend_pub: &[u8; 32],
    view_pub: &[u8; 32],
    data: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let key = cuprate_cryptonight::cryptonight_hash_v0(view_sk);
    let nonce_num = rng.next_u64().to_be_bytes();
    let mut cipher = chacha20::ChaCha20Legacy::new_from_slices(&key, &nonce_num).map_err(|_| err())?;

    // 明文段：key-image magic 前置 u32 LE 0；export magic 带 pk1||pk2
    let mut buffer = Vec::with_capacity(4 + 64 + data.len());
    if magic == KEY_IMAGE_EXPORT_MAGIC {
        buffer.extend_from_slice(&0u32.to_le_bytes());
    }
    buffer.extend_from_slice(spend_pub);
    buffer.extend_from_slice(view_pub);
    buffer.extend_from_slice(data);
    cipher.apply_keystream(&mut buffer);

    // 签名：Monero Schnorr over keccak256(nonce || ciphertext)，key = view_sk
    let v_scalar = Scalar::from_bytes_mod_order(*view_sk);
    let v_point = ED25519_BASEPOINT_TABLE * &v_scalar;
    debug_assert_eq!(v_point.compress().to_bytes(), *view_pub);

    let mut signed = Vec::with_capacity(NONCE_LEN + buffer.len());
    signed.extend_from_slice(&nonce_num);
    signed.extend_from_slice(&buffer);
    let msg_hash = keccak256::hash(&signed)?;
    let sig = generate_monero_signature(&msg_hash, &v_scalar, rng)?;
    let _ = v_point; // view_pub 已由调用方保证一致

    let mut out = Vec::with_capacity(magic.len() + signed.len() + SIG_LEN);
    out.extend_from_slice(magic);
    out.extend_from_slice(&signed);
    out.extend_from_slice(&sig);
    Ok(out)
}

/// Monero Schnorr 生成侧（对齐 keystone `generate_signature`）：
/// k 随机 → K = k·B → c = Hs(hash || P || K) → r = k − c·x。
/// 验证侧 `check_monero_signature`：c·P + r·B == K。
pub fn generate_monero_signature<R: RngCore + CryptoRng>(
    hash: &[u8; 32],
    sec: &Scalar,
    rng: &mut R,
) -> Result<[u8; 64]> {
    loop {
        // 64B 随机 → mod_order_wide（对齐 keystone generate_random_scalar）
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        let k = Scalar::from_bytes_mod_order_wide(&wide);
        let kb = (ED25519_BASEPOINT_TABLE * &k).compress().to_bytes();
        let pub_b = (ED25519_BASEPOINT_TABLE * sec).compress().to_bytes();

        let mut data = Vec::with_capacity(32 + 32 + 32);
        data.extend_from_slice(hash);
        data.extend_from_slice(&pub_b);
        data.extend_from_slice(&kb);
        let c_bytes = crate::chain::xmr::subaddress::hash_to_scalar(&data)?;
        let c = Scalar::from_bytes_mod_order(c_bytes);
        if c == Scalar::ZERO {
            continue;
        }
        let r = k - c * sec;
        if r == Scalar::ZERO {
            continue;
        }
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&c.to_bytes());
        sig[32..].copy_from_slice(&r.to_bytes());
        return Ok(sig);
    }
}

/// key image 伴随签名（对齐 keystone `generate_ring_signature`，ring=1）。
///
/// 单元素环签名（MLSAG 特例）：h = Hs(prefix || k·B || k·Hp(P))，
/// c = h，r = k − c·x。验证侧重算 Hs(prefix || r·B + c·P || r·Hp(P) + c·I)。
/// `prefix_hash` = key image 本身（keystone 传 image.compress().0）。
fn generate_key_image_signature<R: RngCore + CryptoRng>(
    prefix_hash: &[u8; 32],
    input_sk: &Scalar,
    rng: &mut R,
) -> Result<[u8; 64]> {
    use curve25519_dalek::EdwardsPoint;
    // P = x·G；I = x·Hp(P)
    let p_point: EdwardsPoint = ED25519_BASEPOINT_TABLE * input_sk;
    let p_bytes = p_point.compress().to_bytes();
    let i_point: EdwardsPoint = Point::biased_hash(p_bytes).into();

    let k = {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        Scalar::from_bytes_mod_order_wide(&wide)
    };
    let kb = (ED25519_BASEPOINT_TABLE * &k).compress().to_bytes();
    let khp = (k * i_point).compress().to_bytes();

    let mut buff = Vec::with_capacity(32 + 64);
    buff.extend_from_slice(prefix_hash);
    buff.extend_from_slice(&kb);
    buff.extend_from_slice(&khp);
    let h_bytes = crate::chain::xmr::subaddress::hash_to_scalar(&buff)?;
    let h = Scalar::from_bytes_mod_order(h_bytes);
    let c = h;
    let r = k - c * input_sk;

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&c.to_bytes());
    sig[32..].copy_from_slice(&r.to_bytes());
    Ok(sig)
}

/// 端到端：XmrOutput payload → XmrKeyImage payload（keystone generate_export_ur_data 同构）。
///
/// `view_sk`/`spend_sk` 由调用方以 Zeroizing 持有；本函数只收借用（v2-安全 §2），
/// 不产生额外副本。只对 `is_key_image_request()` 的 output 计算（keystone 全算，
/// 但 flags bit5 语义即"需要 key image"——保持全量对齐，参数开关留将来）。
pub fn generate_key_image_export<R: RngCore + CryptoRng>(
    view_sk: &[u8; 32],
    spend_sk: &[u8; 32],
    request_payload: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    // 1. 解密 OUTPUT_EXPORT payload，校验 pk1/pk2 归属
    let (pk1, pk2, plain) =
        decrypt_export_payload(request_payload, OUTPUT_EXPORT_MAGIC, view_sk)?;

    let spend_sk_scalar = Scalar::from_bytes_mod_order(*spend_sk);
    let spend_pub = (ED25519_BASEPOINT_TABLE * &spend_sk_scalar).compress().to_bytes();
    let v_scalar = Scalar::from_bytes_mod_order(*view_sk);
    let view_pub = (ED25519_BASEPOINT_TABLE * &v_scalar).compress().to_bytes();

    // 归属校验（keystone 用 panic——我们返回错误码，签名器不容 panic）
    if pk1 != spend_pub || pk2 != view_pub {
        return Err(err());
    }

    // 2. 解析 outputs
    let details = ExportedTransferDetails::from_bytes(&plain)?;

    // 3. 逐 output 算 key image + 伴随签名
    let spend_sk_z = Zeroizing::new(*spend_sk);
    let _ = spend_sk_z; // Zeroizing 生命周期挂到函数尾
    let mut records = Vec::with_capacity(details.details.len() * KEY_IMAGE_RECORD_LEN);
    for detail in &details.details {
        let rec = compute_key_image_with_signature(view_sk, &spend_sk_scalar, detail, rng)?;
        records.push(rec);
    }

    // 4. KEY_IMAGE_EXPORT_MAGIC 加密
    let wire = serialize_key_images(&records);
    encrypt_export_payload(KEY_IMAGE_EXPORT_MAGIC, view_sk, &spend_pub, &view_pub, &wire, rng)
}

/// 单 output key image + 签名（对齐 keystone `generate_key_image`）。
fn compute_key_image_with_signature<R: RngCore + CryptoRng>(
    view_sk: &[u8; 32],
    spend_sk: &Scalar,
    detail: &ExportedTransferDetail,
    rng: &mut R,
) -> Result<([u8; 32], [u8; 64])> {
    // additional key 语义：子地址 output 用 per-output additional tx key
    let key_to_use: [u8; 32] = if detail.major != 0 || detail.minor != 0 {
        match detail.additional_tx_keys.len() {
            1 => detail.additional_tx_keys[0],
            n if n > 1 => {
                let idx = detail.internal_output_index as usize;
                *detail
                    .additional_tx_keys
                    .get(idx)
                    .ok_or_else(err)?
            }
            _ => detail.tx_pubkey,
        }
    } else {
        detail.tx_pubkey
    };

    // key_offset = Hs((view·tx_pub)·8 || varint(idx)) + m(major,minor)
    let offset = crate::chain::xmr::subaddress::calc_output_key_offset(
        view_sk,
        &key_to_use,
        detail.internal_output_index,
        detail.major,
        detail.minor,
    )?;

    // input_sk = spend_sk + offset；验证 input_sk·G == output_pubkey
    let input_sk = spend_sk + Scalar::from_bytes_mod_order(offset);
    let input_pub = (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes();
    if input_pub != detail.pubkey {
        return Err(err());
    }

    // I = input_sk · Hp(P)
    let image: [u8; 32] = {
        let point: curve25519_dalek::EdwardsPoint = Point::biased_hash(detail.pubkey).into();
        (point * input_sk).compress().to_bytes()
    };

    // 伴随签名：prefix = image 本身
    let sig = generate_key_image_signature(&image, &input_sk, rng)?;
    Ok((image, sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::xmr::output_export::deserialize_key_images;
    use rand_chacha::rand_core::SeedableRng;

    fn rng_from(seed: u64) -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::seed_from_u64(seed)
    }

    fn make_keypair(seed: u8) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        let sk = Scalar::from_bytes_mod_order([seed; 32]);
        let sk_b = sk.to_bytes();
        let pk = (ED25519_BASEPOINT_TABLE * &sk).compress().to_bytes();
        (sk_b, pk, sk_b, pk) // (spend_sk, spend_pub, view_sk, view_pub)
    }

    #[test]
    fn export_encrypt_decrypt_round_trip() {
        let mut rng = rng_from(1);
        let (_, spend_pub, view_sk, view_pub) = make_keypair(1);
        let data = b"hello wire";

        let enc = encrypt_export_payload(
            OUTPUT_EXPORT_MAGIC, &view_sk, &spend_pub, &view_pub, data, &mut rng,
        )
        .unwrap();
        let (pk1, pk2, plain) =
            decrypt_export_payload(&enc, OUTPUT_EXPORT_MAGIC, &view_sk).unwrap();
        assert_eq!(pk1, spend_pub);
        assert_eq!(pk2, view_pub);
        assert_eq!(plain, data.to_vec());
    }

    #[test]
    fn wrong_magic_rejected() {
        let mut rng = rng_from(2);
        let (_, spend_pub, view_sk, view_pub) = make_keypair(2);
        let enc = encrypt_export_payload(
            OUTPUT_EXPORT_MAGIC, &view_sk, &spend_pub, &view_pub, b"x", &mut rng,
        )
        .unwrap();
        assert!(decrypt_export_payload(&enc, KEY_IMAGE_EXPORT_MAGIC, &view_sk).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut rng = rng_from(3);
        let (_, spend_pub, view_sk, view_pub) = make_keypair(3);
        let mut enc = encrypt_export_payload(
            OUTPUT_EXPORT_MAGIC, &view_sk, &spend_pub, &view_pub, b"payload", &mut rng,
        )
        .unwrap();
        let last = enc.len() - 1;
        enc[last] ^= 0x01;
        assert!(decrypt_export_payload(&enc, OUTPUT_EXPORT_MAGIC, &view_sk).is_err());
    }

    #[test]
    fn wrong_view_key_rejected() {
        let mut rng = rng_from(4);
        let (_, spend_pub, view_sk, view_pub) = make_keypair(4);
        let enc = encrypt_export_payload(
            OUTPUT_EXPORT_MAGIC, &view_sk, &spend_pub, &view_pub, b"payload", &mut rng,
        )
        .unwrap();
        let (_, _, other_view, _) = make_keypair(99);
        assert!(decrypt_export_payload(&enc, OUTPUT_EXPORT_MAGIC, &other_view).is_err());
    }

    #[test]
    fn key_image_export_end_to_end() {
        // 端到端：构造 output export（含 1 个主地址 output）→ 全流程 → 解密验证
        let mut rng = rng_from(5);
        let (spend_sk, spend_pub, view_sk, view_pub) = make_keypair(5);

        // 构造明文 ExportedTransferDetails（主地址 output: major=0,minor=0）
        let mut plain = Vec::new();
        plain.extend_from_slice(&[0x01]); // has_transfers
        plain.extend_from_slice(&[0x00]); // offset
        plain.extend_from_slice(&[0x01]); // transfer_count
        plain.extend_from_slice(&[0x00]); // blob size
        // detail: version, pubkey, idx, gidx, tx_pubkey, flags, amount, keys, major, minor
        plain.extend_from_slice(&[0x01]); // version
        // output pubkey = input_sk·G，input_sk = spend + offset(0)
        let offset = crate::chain::xmr::subaddress::calc_output_key_offset(
            &view_sk, &[0x22u8; 32], 0, 0, 0,
        )
        .unwrap();
        let input_sk = Scalar::from_bytes_mod_order(spend_sk)
            + Scalar::from_bytes_mod_order(offset);
        let out_pub = (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes();
        plain.extend_from_slice(&out_pub);
        plain.extend_from_slice(&[0x00]); // idx=0
        plain.extend_from_slice(&[0x64]); // gidx=100
        plain.extend_from_slice(&[0x22u8; 32]); // tx_pubkey
        plain.push(0b0001_0100); // rct + key_image_request
        plain.extend_from_slice(&[0x80, 0x89, 0x2f]); // amount varint-ish
        plain.extend_from_slice(&[0x00]); // no additional keys
        plain.extend_from_slice(&[0x00, 0x00]); // major=0 minor=0

        let enc_req = encrypt_export_payload(
            OUTPUT_EXPORT_MAGIC, &view_sk, &spend_pub, &view_pub, &plain, &mut rng,
        )
        .unwrap();

        // 设备侧全流程
        let enc_resp = generate_key_image_export(
            &view_sk, &spend_sk, &enc_req, &mut rng,
        )
        .unwrap();

        // 热端解密（用 monero 解密路径验证）
        let (_, _, resp_plain) =
            decrypt_export_payload(&enc_resp, KEY_IMAGE_EXPORT_MAGIC, &view_sk).unwrap();
        let records = deserialize_key_images(&resp_plain);
        assert_eq!(records.len(), 1);

        // key image 独立重算交叉验证
        let (image, sig) = &records[0];
        let expected: [u8; 32] = {
            let hp: curve25519_dalek::EdwardsPoint =
                Point::biased_hash(out_pub).into();
            (hp * input_sk).compress().to_bytes()
        };
        assert_eq!(*image, expected);

        // 伴随签名验证（单环重算 Hs）
        let i_point: curve25519_dalek::EdwardsPoint =
            Point::biased_hash(out_pub).into();
        let c = Scalar::from_canonical_bytes(sig[..32].try_into().unwrap()).unwrap();
        let r = Scalar::from_canonical_bytes(sig[32..].try_into().unwrap()).unwrap();
        let lhs = (ED25519_BASEPOINT_TABLE * &r)
            + (ED25519_BASEPOINT_TABLE * &c);
        let rhs = (r * i_point) + (c * i_point);
        // 期望：Hs(prefix || r·B + c·P || r·I + c·I) == c，其中 P = input_sk·G = out_pub
        // P 点：input_sk·G
        let p_point = ED25519_BASEPOINT_TABLE * &input_sk;
        let rb = (ED25519_BASEPOINT_TABLE * &r).compress().to_bytes();
        let r_p = (&r * p_point).compress().to_bytes();
        let _ = lhs;
        let _ = rhs;
        let _ = r_p;
        let _ = rb;
        // 完整验证：重算 challenge
        let mut buff = Vec::new();
        buff.extend_from_slice(image);
        // k·B 不可重算（k 丢失）→ 验证式：Hs(prefix || r·B + c·P || r·I + c·I) == c
        //   r·B + c·P（P=input_sk·G=out_pub）
        let s1 = (ED25519_BASEPOINT_TABLE * &r) + (&c * p_point);
        //   r·Hp(P) + c·I = (r + c·input_sk)·Hp(P)
        let s2 = (&r + &c * &input_sk) * i_point;
        let mut vbuf = Vec::new();
        vbuf.extend_from_slice(image);
        vbuf.extend_from_slice(&s1.compress().to_bytes());
        vbuf.extend_from_slice(&s2.compress().to_bytes());
        let h = crate::chain::xmr::subaddress::hash_to_scalar(&vbuf).unwrap();
        assert_eq!(h, c.to_bytes());
    }
}


