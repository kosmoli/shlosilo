//! XMR key image 导出反向交叉验证（shlosilo encrypt → keystone decrypt）。
//!
//! 流程：shlosilo 生成 OUTPUT_EXPORT 加密 payload + 端到端 key image 导出，
//! 把 KEY_IMAGE_EXPORT 加密产物写到 `/tmp/xmr_shlosilo_ki_fixture.bin`；
//! keystone fork 侧测试读取并用 `decrypt_data_with_pvk` 消费（见
//! keystone3-firmware/rust/apps/monero src/utils/mod.rs `shlosilo_ki_fixture_test`）。
//!
//! 依赖：先跑本测试产出 fixture，再跑 keystone 侧测试。
#![cfg(test)]

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use shlosilo::chain::xmr::key_image_export::{
    decrypt_export_payload, generate_key_image_export, OUTPUT_EXPORT_MAGIC,
};
use shlosilo::chain::xmr::output_export::ExportedTransferDetails;
use shlosilo::chain::xmr::subaddress::calc_output_key_offset;

const SPEND_SK: [u8; 32] = [5u8; 32];
const VIEW_SK: [u8; 32] = [5u8; 32];

fn point(sk: &[u8; 32]) -> [u8; 32] {
    (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*sk))
        .compress()
        .to_bytes()
}

#[test]
fn generate_shlosilo_keyimage_fixture_for_keystone() {
    let mut rng = ChaCha20Rng::seed_from_u64(2026);

    // 真实 output：input_sk = spend + offset(view, tx_pub, 0, 0, 0)
    // tx_pub 必须是合法曲线点(真实交易里=一次性输出密钥)
    let tx_pub = (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order([0x42u8; 32]))
        .compress()
        .to_bytes();
    let offset = calc_output_key_offset(&VIEW_SK, &tx_pub, 0, 0, 0).unwrap();
    let input_sk = Scalar::from_bytes_mod_order(SPEND_SK) + Scalar::from_bytes_mod_order(offset);
    let out_pub = (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes();

    // ExportedTransferDetails 明文（主地址 output）
    let mut plain = Vec::new();
    plain.extend_from_slice(&[0x01, 0x00, 0x01, 0x00]); // has_transfers, offset, count, blob_size
    plain.extend_from_slice(&[0x01]); // version
    plain.extend_from_slice(&out_pub);
    plain.extend_from_slice(&[0x00]); // internal_output_index
    plain.extend_from_slice(&[0x64]); // global_output_index = 100
    plain.extend_from_slice(&tx_pub);
    plain.push(0b0001_0100); // rct | key_image_request
    plain.extend_from_slice(&[0x80, 0x96, 0x98, 0x91, 0x04]); // amount varint ~ 1.0 XMR
    plain.extend_from_slice(&[0x00, 0x00, 0x00]); // no add keys, major=0, minor=0

    // 自检：shlosilo 自己能解析
    let details = ExportedTransferDetails::from_bytes(&plain).unwrap();
    assert_eq!(details.details.len(), 1);
    assert!(details.details[0].is_key_image_request());

    // shlosilo encrypt（模拟 Feather 热端加密 output export）
    let spend_pub = point(&SPEND_SK);
    let view_pub = point(&VIEW_SK);

    // 端到端：需要 OUTPUT_EXPORT 加密输入。公开 API 未暴露 encrypt，
    // 本测试先固定 nonce 复刻 keystone encrypt 逻辑（与 utils/mod.rs encrypt_data_with_pvk 一致），
    // 这段逻辑在 keystone 侧测试中独立复刻解密，双方各自实现同一 wire 规范即交叉验证。
    let enc_req = shlosilo_encrypt_export_for_test(&plain, &spend_pub, &view_pub, &mut rng);

    // shlosilo 端到端 → KEY_IMAGE_EXPORT 加密产物
    let enc_resp =
        generate_key_image_export(&VIEW_SK, &SPEND_SK, &enc_req, &mut rng).unwrap();

    // 自检：shlosilo 自己解密回环
    let (_, _, resp_plain) =
        decrypt_export_payload(&enc_resp, shlosilo::chain::xmr::key_image_export::KEY_IMAGE_EXPORT_MAGIC, &VIEW_SK)
            .unwrap();
    assert!(!resp_plain.is_empty());

    // 写 fixture 给 keystone 侧消费
    std::fs::write("/tmp/xmr_shlosilo_ki_fixture.bin", &enc_resp).unwrap();
    std::fs::write("/tmp/xmr_shlosilo_ki_viewkey.hex", hex(&VIEW_SK)).unwrap();
}

fn shlosilo_encrypt_export_for_test<R: rand_chacha::rand_core::RngCore + rand_chacha::rand_core::CryptoRng>(
    plain: &[u8],
    spend_pub: &[u8; 32],
    view_pub: &[u8; 32],
    rng: &mut R,
) -> Vec<u8> {
    // 复刻 keystone encrypt_data_with_pvk（OUTPUT magic: 无 u32 前缀，带 pk1||pk2）
    // 加密 key = cryptonight_hash_v0(view_sk)；sig = Monero Schnorr(keccak(nonce||ct), view_sk)
    // 注：shlosilo lib 内部同逻辑已由单测覆盖；此处为集成层构造输入。
    let mut nonce8 = [0u8; 8];
    rng.fill_bytes(&mut nonce8);

    let key: [u8; 32] = cuprate_cryptonight::cryptonight_hash_v0(&VIEW_SK);
    use chacha20::cipher::KeyIvInit as _;
    let mut cipher = chacha20::ChaCha20Legacy::new_from_slices(&key, &nonce8).unwrap();
    use chacha20::cipher::StreamCipher;
    let mut buffer = Vec::with_capacity(64 + plain.len());
    buffer.extend_from_slice(spend_pub);
    buffer.extend_from_slice(view_pub);
    buffer.extend_from_slice(plain);
    cipher.apply_keystream(&mut buffer);

    let mut signed = Vec::with_capacity(8 + buffer.len());
    signed.extend_from_slice(&nonce8);
    signed.extend_from_slice(&buffer);
    let hash = shlosilo::encoding::keccak256::hash(&signed).unwrap();
    let v_scalar = Scalar::from_bytes_mod_order(VIEW_SK);
    let sig = shlosilo::chain::xmr::key_image_export::generate_monero_signature(
        &hash, &v_scalar, rng,
    )
    .unwrap();

    let mut out = Vec::new();
    out.extend_from_slice(OUTPUT_EXPORT_MAGIC);
    out.extend_from_slice(&signed);
    out.extend_from_slice(&sig);
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
