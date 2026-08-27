//! XMR ↔ keystone3-firmware Cross-Validation Test Module (v9.12)
//!
//! ## 目的
//! 把 keystone3-firmware monero app 的测试 fixture 搬过来，作为 shlosilo 的 oracle。
//! oracle 失败 = shlosilo bug，必须修。
//!
//! ## 范围 (Phase 5 §7.2 v9.12)
//! 1. cn_fast_hash (Keccak-256) — `apps/monero/src/utils/hash.rs`
//! 2. subaddress derivation (calc_subaddress_m) — `apps/monero/src/key.rs`
//! 3. subaddress spend/view pub — `apps/monero/src/key.rs` + `address.rs`
//! 4. key image (hash_to_point Hp) — `apps/monero/src/key.rs` (moneroinflation vector)
//!
//! ## 来源
//! Fixtures 从 `/home/komo/works/keystone3-firmware/rust/apps/monero/src/` 提取。
//! keystone = 已审计 + 部署在硬件钱包，是 shlosilo 的 oracle。
#![cfg(test)]
extern crate alloc;

// ============================================================================
// Helper: hex decode
// ============================================================================

fn hex_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).unwrap();
        let lo = (bytes[i + 1] as char).to_digit(16).unwrap();
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    out
}

fn hex_decode_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let v = hex_decode(s);
    out.copy_from_slice(&v);
    out
}

// ============================================================================
// 1. cn_fast_hash (Keccak-256) 跨验证
// ============================================================================
//
// Monero `cn_fast_hash` = Keccak-256（不是 SHA3-256）。keystone 用 cryptoxide
// Keccak256，shlosilo 用 tiny_keccak。两者都对齐标准 Keccak-256 向量。

#[test]
fn keystone_xmr_cn_fast_hash_matches() {
    use shlosilo::encoding::keccak256::hash;
    // Keccak-256("") 标准向量（= Monero cn_fast_hash("")）
    let h = hash(b"").unwrap();
    let expected = hex_decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    assert_eq!(&h[..], &expected[..], "cn_fast_hash (Keccak-256) must match standard vector");
}

// ============================================================================
// 2. subaddress derivation scalar m (calc_subaddress_m)
// ============================================================================
//
// Source: keystone key.rs::test_monero_subadd_keys
//   seed = "key stone ... success" → keypair (major=0)
//   keypair.view.to_bytes() = 17921dbd...  (view private key)
//   calc_subaddress_m(view_sec, major=0, minor=1) = 42654349...
//
// m = Hs("SubAddr" || 0x00 || view_sec || major_LE || minor_LE)

#[test]
fn keystone_xmr_calc_subaddress_m() {
    use shlosilo::chain::xmr::subaddress::calc_subaddress_m;
    let view_sec = hex_decode_32("17921dbd51b4a1af0b4049bc13dc7048ace1dcd8be9b8669de95b8430924ea09");
    let m = calc_subaddress_m(&view_sec, 0, 1).unwrap();
    let expected = hex_decode_32("426543494cfc94803177f4ccffaee54275d9accb3f54a2caafa753ff62e8b400");
    assert_eq!(&m[..], &expected[..], "calc_subaddress_m must match keystone oracle (m = Hs(\"SubAddr\"||0||a||major||minor))");
}

// ============================================================================
// 3. subaddress spend / view public key
// ============================================================================
//
// Source: keystone key.rs::test_monero_keys + test_monero_subadd_keys
//   main_spend_pub = 12f38162...  (spend_sec 6c3895c1... * G)
//   main_view_pub  = e18a5360...  (view_sec 17921dbd... * G)
//   sub (0,1) spend_pub = 3dca7526...
//   sub (0,1) view_pub  = 33f3f7b3...
//
// 算法 (Monero 官方 MRL-0006):
//   sub_spend_pub = main_spend_pub + m*G
//   sub_view_pub  = sub_spend_pub * view_sec

#[test]
fn keystone_xmr_subaddress_spend_pub() {
    use shlosilo::chain::xmr::subaddress::derive_subaddress;
    let main_spend_sec = hex_decode_32("6c3895c1dfd7c3ed22be481ed5ec7f40e3d8ded84f0a3d65a542915475ca6f0e");
    let main_view_sec = hex_decode_32("17921dbd51b4a1af0b4049bc13dc7048ace1dcd8be9b8669de95b8430924ea09");
    let main_spend_pub = hex_decode_32("12f38162635cf3aecf081d96158022b2a1517993100e54d62b17057f2443e749");
    let main_view_pub = hex_decode_32("e18a5360ae4b2ff71bf91c5a626e14fc2395608375b750526bc0962ed27237a1");

    let sub = derive_subaddress(
        &main_spend_sec,
        &main_view_sec,
        &main_spend_pub,
        &main_view_pub,
        0,
        1,
    )
    .unwrap();

    let expected_spend = hex_decode_32("3dca752621e394b068c3bde78951d029778d822aee481a2b08dc21589a3c6693");
    assert_eq!(
        &sub.spend_pub[..],
        &expected_spend[..],
        "subaddress spend pub must match keystone oracle"
    );
}

#[test]
fn keystone_xmr_subaddress_view_pub() {
    use shlosilo::chain::xmr::subaddress::derive_subaddress;
    let main_spend_sec = hex_decode_32("6c3895c1dfd7c3ed22be481ed5ec7f40e3d8ded84f0a3d65a542915475ca6f0e");
    let main_view_sec = hex_decode_32("17921dbd51b4a1af0b4049bc13dc7048ace1dcd8be9b8669de95b8430924ea09");
    let main_spend_pub = hex_decode_32("12f38162635cf3aecf081d96158022b2a1517993100e54d62b17057f2443e749");
    let main_view_pub = hex_decode_32("e18a5360ae4b2ff71bf91c5a626e14fc2395608375b750526bc0962ed27237a1");

    let sub = derive_subaddress(
        &main_spend_sec,
        &main_view_sec,
        &main_spend_pub,
        &main_view_pub,
        0,
        1,
    )
    .unwrap();

    let expected_view = hex_decode_32("33f3f7b3628e0587f23abec549a071fb420783de74858a1fba0d9e49f3c193f7");
    assert_eq!(
        &sub.view_pub[..],
        &expected_view[..],
        "subaddress view pub must match keystone oracle (sub_spend_pub * view_sec)"
    );
}

// ============================================================================
// 4. key image (hash_to_point Hp + point mul)
// ============================================================================
//
// Source: keystone key.rs::test_generate_keyimages_prvkey_pair
//   https://www.moneroinflation.com/ring_signatures
//   x  = 09321db3...  (spend secret)
//   P  = xG = cd48cd05...
//   Hp(P) = c530057d...
//   KI = x * Hp(P) = d9a248bf...

#[test]
fn keystone_xmr_key_image() {
    use shlosilo::chain::xmr::clsag::derive_key_image;
    let spend_sec = hex_decode_32("09321db315661e54fe0d606faffc2437506d6594db804cddd5b5ce27970f2e09");
    let ki = derive_key_image(&spend_sec).unwrap();
    let expected = hex_decode_32("d9a248bf031a2157a5a63991c00848a5879e42b7388458b4716c836bb96d96c0");
    assert_eq!(&ki[..], &expected[..], "key image must match moneroinflation (keystone) oracle");
}

// ============================================================================
// 5. output key 恢复 → key image (完整链路)
// ============================================================================
//
// Source: keystone key_images.rs::test_include_additional_keys
//   验证 Monero "识别 output → 计算 key image" 的完整链路：
//     recv_derivation = (view_sec * tx_pubkey) * 8   (ECDH + mul_by_cofactor)
//     key_offset      = Hs(recv_derivation_compressed || varint(output_index))
//     x               = spend_sec + key_offset         (mod L)
//     key image       = x * Hp(x*G)
//   (major=0, minor=0，故不加 subaddress m；output_index=1 → varint=0x01)

#[test]
fn keystone_xmr_output_key_image() {
    use shlosilo::chain::xmr::subaddress::hash_to_scalar;
    use shlosilo::chain::xmr::clsag::derive_key_image;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    let sec_s = hex_decode_32("a57cfb517deb1c35a4b8208847f8e5d54a3a54bc82e72f1b6d21e849934e9e06");
    let sec_v = hex_decode_32("c665da45f363a80a637740721e97b0c8249fe2599c14eeac73131438c0b92503");
    let tx_pubkey = hex_decode_32("3e2ebe8773322defc39251cdb18f0500398e525b6720815e95aced3b24375fcc");

    // 1. recv_derivation = (view_sec * tx_pubkey) * 8
    let view_scalar = Scalar::from_bytes_mod_order(sec_v);
    let tx_pubkey_point = CompressedEdwardsY(tx_pubkey).decompress().expect("valid point");
    let recv_derivation = (tx_pubkey_point * view_scalar).mul_by_cofactor();

    // 2. key_offset = Hs(recv_derivation_compressed || varint(1)=0x01)
    let mut data = Vec::new();
    data.extend_from_slice(&recv_derivation.compress().to_bytes());
    data.push(0x01u8);
    let key_offset_bytes = hash_to_scalar(&data).unwrap();
    let key_offset = Scalar::from_bytes_mod_order(key_offset_bytes);

    // 3. x = spend_sec + key_offset (mod L)
    let spend_scalar = Scalar::from_bytes_mod_order(sec_s);
    let x = spend_scalar + key_offset;
    let x_bytes: [u8; 32] = x.to_bytes();

    // 4. key image = x * Hp(x*G)
    let ki = derive_key_image(&x_bytes).unwrap();

    let expected = hex_decode_32("bd4054a880249da808cf609472f4341b5303cd63fb208f1791492bdd7d7c2a8b");
    assert_eq!(
        &ki[..],
        &expected[..],
        "output key image must match keystone test_include_additional_keys"
    );
}

// ============================================================================
// 6. keypair 派生 (BIP32 secp256k1 → hash_to_scalar → spend/view key)
// ============================================================================
//
// Source: keystone key.rs::test_monero_keys
//   链路：
//     sk    = BIP32(seed, "m/44'/128'/0'/0/0")   (secp256k1 私钥)
//     spend = Hs(sk)                              (hash_to_scalar)
//     view  = Hs(spend)                           (hash_to_scalar)
//     spend_pub = spend * G, view_pub = view * G  (ed25519, 无 clamp)
//   keystone 用 rust-bitcoin BIP32，shlosilo 用 bip32 crate，都是标准 BIP32。

#[test]
fn keystone_xmr_keypair_from_seed() {
    use shlosilo::chain::xmr::subaddress::hash_to_scalar;
    use shlosilo::curve_primitive::secp256k1::scalar_to_bytes;
    use shlosilo::derivation::bip32_secp256k1::derive_from_seed;
    use shlosilo::derivation::path::DerivationPath;
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;

    let seed = hex_decode("45a5056acbe881d7a5f2996558b303e08b4ad1daffacf6ffb757ff2a9705e6b9f806cffe3bd90ff8e3f8e8b629d9af78bcd2ed23e8c711f238308e65b62aa5f0");

    // 1. BIP32 派生 secp256k1 私钥
    let path = DerivationPath::parse("m/44'/128'/0'/0/0").unwrap();
    let scalar = derive_from_seed(&seed, &path).unwrap();
    let secp_priv = scalar_to_bytes(&scalar);

    // 2. spend = Hs(secp256k1 私钥)
    let spend = hash_to_scalar(&secp_priv).unwrap();
    let expected_spend = hex_decode_32("6c3895c1dfd7c3ed22be481ed5ec7f40e3d8ded84f0a3d65a542915475ca6f0e");
    assert_eq!(&spend[..], &expected_spend[..], "spend key must match keystone test_monero_keys");

    // 3. view = Hs(spend)
    let view = hash_to_scalar(&spend).unwrap();
    let expected_view = hex_decode_32("17921dbd51b4a1af0b4049bc13dc7048ace1dcd8be9b8669de95b8430924ea09");
    assert_eq!(&view[..], &expected_view[..], "view key must match keystone test_monero_keys");

    // 4. spend_pub = spend * G (无 clamp，curve25519_dalek)
    let spend_pub = (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(spend))
        .compress()
        .to_bytes();
    let expected_spend_pub = hex_decode_32("12f38162635cf3aecf081d96158022b2a1517993100e54d62b17057f2443e749");
    assert_eq!(&spend_pub[..], &expected_spend_pub[..], "spend pub must match keystone");

    // 5. view_pub = view * G
    let view_pub = (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(view))
        .compress()
        .to_bytes();
    let expected_view_pub = hex_decode_32("e18a5360ae4b2ff71bf91c5a626e14fc2395608375b750526bc0962ed27237a1");
    assert_eq!(&view_pub[..], &expected_view_pub[..], "view pub must match keystone");
}
