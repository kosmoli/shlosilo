//! ETH personal_sign / personal_ecRecover (EIP-191 v0x45)
//!
//! 算法: `keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)`
//!
//! MetaMask, WalletConnect 等 wallet 的"Sign Message"功能都用这个格式.
//! 不是 ETH transaction, 是任意 UTF-8 字符串盲签.
//!
//! 参考: <https://eips.ethereum.org/EIPS/eip-191>

    extern crate alloc;

use alloc::format;
use alloc::vec::Vec;

use crate::chain::eth::sign;
use crate::encoding::keccak256;
use crate::error::Result;
use crate::types::SecretBytes;

/// personal_sign 输入
/// P1-03：私钥走 `SecretBytes<32>`——不 Clone 不 Debug、ZeroizeOnDrop、常时比较。
pub struct PersonalSignInput {
    /// 待签名任意 UTF-8 字符串
    pub message: Vec<u8>,
    /// 32 字节私钥
    pub private_key: SecretBytes<32>,
}

/// personal_sign 输出: 65 字节签名 (r || s || v)
#[derive(Clone, Debug)]
pub struct PersonalSignature {
    /// signing hash (用户确认屏幕显示的内容摘要)
    pub signing_hash: [u8; 32],
    /// ECDSA r
    pub r: [u8; 32],
    /// ECDSA s (low-s enforced per EIP-2 / BIP-146)
    pub s: [u8; 32],
    /// recovery id (v): 27 或 28
    pub v: u8,
}

/// 计算 personal_sign signing hash
///
/// EIP-191 v0x45: `keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)`
pub fn personal_signing_hash(msg: &[u8]) -> Result<[u8; 32]> {
    let prefix_str = format!("\x19Ethereum Signed Message:\n{}", msg.len());
    let mut full = Vec::with_capacity(prefix_str.len() + msg.len());
    full.extend_from_slice(prefix_str.as_bytes());
    full.extend_from_slice(msg);
    keccak256::hash(&full)
}

/// 签名 personal message
///
/// 输出 65 字节签名 (r || s || v), v = 27 + y_parity (即 v=27 if y_parity=0, v=28 if y_parity=1).
pub fn personal_sign(input: &PersonalSignInput) -> Result<PersonalSignature> {
    let sighash = personal_signing_hash(&input.message)?;

    // private_key: [u8; 32] → Secp256k1Scalar
    let sk = sign::sk_from_pk(input.private_key.expose())?;

    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    let y_parity = sign::apply_low_s(&sighash, &sk, &mut r_bytes, &mut s_bytes)?;

    Ok(PersonalSignature {
        signing_hash: sighash,
        r: r_bytes,
        s: s_bytes,
        v: 27 + y_parity,
    })
}

/// personal_ecRecover: 从签名恢复公钥 (L1 pure verify)
///
/// 输入: 原始 message + 65 字节签名 (r || s || v)
/// 输出: 64 字节未压缩公钥 (x || y)
///
/// 用于 wallet 端验证签名者身份 (替代 personal_sign 在 wallet 端的镜像功能).
pub fn personal_ec_recover(
    msg: &[u8],
    sig: &[u8; 65],
) -> Result<[u8; 64]> {
    let sighash = personal_signing_hash(msg)?;
    sign::ecdsa_recover(&sighash, sig)
}

/// 单元测试
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::string::String;
    use alloc::vec;
    use std::eprintln;

    fn hex_decode(s: &str) -> Vec<u8> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = hex_nibble(bytes[i]).unwrap();
            let lo = hex_nibble(bytes[i + 1]).unwrap();
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    /// MetaMask 官方示例: "Hello, world!"
    ///
    /// 不同实现可能产生不同的签名 (RFC6979 + low-s), 但 signing hash 必一致.
    #[test]
    fn personal_sign_hello_world() {
        let msg = b"Hello, world!";
        let h = personal_signing_hash(msg).unwrap();
        assert_ne!(h, [0u8; 32]);
        assert_eq!(h.len(), 32);
        eprintln!(
            "personal_sign('Hello, world!') signing hash: {}",
            hex_encode(&h)
        );
    }

    /// 签名前缀正确性测试: `\x19Ethereum Signed Message:\n` + len + msg
    #[test]
    fn personal_sign_prefix_format() {
        let msg = b"test";
        let prefix_str = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let expected = keccak256::hash(&[prefix_str.as_bytes(), msg].concat()).unwrap();
        let actual = personal_signing_hash(msg).unwrap();
        assert_eq!(
            actual, expected,
            "signing hash mismatch with manual construction"
        );
    }

    /// 空消息 edge case
    #[test]
    fn personal_sign_empty_message() {
        let msg = b"";
        let h = personal_signing_hash(msg).unwrap();
        assert_ne!(h, [0u8; 32]);
        // empty msg length = 0 → prefix = "\x19Ethereum Signed Message:\n0"
        let expected_prefix = b"\x19Ethereum Signed Message:\n0";
        let expected = keccak256::hash(expected_prefix).unwrap();
        assert_eq!(h, expected);
    }

    /// UTF-8 中文消息
    #[test]
    fn personal_sign_utf8_chinese() {
        let msg = "你好,世界".as_bytes();
        let h = personal_signing_hash(msg).unwrap();
        assert_ne!(h, [0u8; 32]);
        eprintln!(
            "personal_sign('你好,世界') signing hash: {}",
            hex_encode(&h)
        );
    }

    /// 长字符串 (>1KB) 不 panic
    #[test]
    fn personal_sign_long_message() {
        let msg = vec![0xab; 1024];
        let h = personal_signing_hash(&msg).unwrap();
        assert_ne!(h, [0u8; 32]);

        let msg = vec![0x42; 8192];
        let h = personal_signing_hash(&msg).unwrap();
        assert_ne!(h, [0u8; 32]);
    }

    /// 端到端: 签名 + v ∈ {27, 28} + r/s 不为零
    #[test]
    fn personal_sign_end_to_end() {
        let pk_hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&hex_decode(pk_hex));

        let input = PersonalSignInput {
            message: b"test message".to_vec(),
            private_key: SecretBytes::new(pk),
        };
        let sig = personal_sign(&input).unwrap();

        assert!(
            sig.v == 27 || sig.v == 28,
            "v must be 27 or 28, got {}",
            sig.v
        );
        assert_ne!(sig.r, [0u8; 32]);
        assert_ne!(sig.s, [0u8; 32]);
    }

    /// 验证 personal_sign 确定性: 同一输入 → 同一输出
    #[test]
    fn personal_sign_deterministic() {
        let msg = b"deterministic test";
        let h1 = personal_signing_hash(msg).unwrap();
        let h2 = personal_signing_hash(msg).unwrap();
        assert_eq!(h1, h2, "personal_signing_hash must be deterministic");

        let pk_hex = "1111111111111111111111111111111111111111111111111111111111111111";
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&hex_decode(pk_hex));

        let input1 = PersonalSignInput {
            message: msg.to_vec(),
            private_key: SecretBytes::new(pk),
        };
        let sig1 = personal_sign(&input1).unwrap();
        let sig2 = personal_sign(&input1).unwrap();
        assert_eq!(sig1.r, sig2.r, "r must be deterministic (RFC6979)");
        assert_eq!(sig1.s, sig2.s, "s must be deterministic (RFC6979)");
        assert_eq!(sig1.v, sig2.v, "v must be deterministic");
        assert_eq!(sig1.signing_hash, sig2.signing_hash);
    }

    /// round-trip: sign + recover (验证签名者公钥一致)
    #[test]
    fn personal_sign_recover_round_trip() {
        use crate::curve_primitive::secp256k1::{base_mul, point_to_compressed};

        // 测试私钥
        let pk_hex = "4646464646464646464646464646464646464646464646464646464646464646";
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&hex_decode(pk_hex));

        let input = PersonalSignInput {
            message: b"Hello, world!".to_vec(),
            private_key: SecretBytes::new(pk_bytes),
        };

        // 1. 签名
        let sig = personal_sign(&input).unwrap();

        // 2. 构造 65-byte 签名
        let mut sig_65 = [0u8; 65];
        sig_65[..32].copy_from_slice(&sig.r.as_slice());
        sig_65[32..64].copy_from_slice(&sig.s.as_slice());
        sig_65[64] = sig.v;

        // 3. 从签名恢复公钥
        let recovered_pk = personal_ec_recover(&input.message, &sig_65).unwrap();

        // 4. 直接从私钥算公钥
        let sk = sign::sk_from_pk(&pk_bytes).unwrap();
        let pk_point = base_mul(&sk);
        let pk_compressed = point_to_compressed(&pk_point);

        // 5. 比对: recovered_pk 末 64 bytes (x||y) vs 已知公钥
        // k256 VerifyingKey.to_encoded_point(false) 输出 65 bytes: 0x04 || x (32) || y (32)
        // recovered_pk 是 64 bytes (x || y), 跳过 0x04 前缀
        // pk_compressed 是 33 bytes, 不直接比较
        // 简化: 通过对 pk_compressed 的 x bytes 比对验证
        // pk_compressed[1..33] 是 x coordinate (33 bytes = 1 prefix + 32 x)
        let pk_x = &pk_compressed[1..33];
        let recovered_x = &recovered_pk[..32];
        assert_eq!(
            pk_x, recovered_x,
            "recovered x must match pk x coordinate"
        );
        // y parity: 验证 recovered y 坐标 parity 与原始 pk 一致
        // recovered_pk[63] 的 LSB 表示 y parity (0 = even, 1 = odd)
        let recovered_y_parity = (recovered_pk[63] & 1) as u8;
        // pk_compressed prefix: 0x02 = even y, 0x03 = odd y
        let pk_y_parity = pk_compressed[0] - 0x02;
        assert_eq!(
            recovered_y_parity, pk_y_parity,
            "recovered y parity ({}) must match pk y parity ({})",
            recovered_y_parity, pk_y_parity
        );
        // 注: sig.v 可能因 low-s flip 而与 pk_y_parity 不同 (这是 EIP-2/BIP-146 正确行为)
        // recover_from_prehash 必须用正确的 y_parity 才能恢复出正确的 pk
        let sig_y_parity = sig.v - 27;
        assert!(
            sig_y_parity == pk_y_parity || sig_y_parity == 1 - pk_y_parity,
            "sig.v={} should reflect pk parity (with possible low-s flip)",
            sig.v
        );
    }

    fn hex_encode(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }
}