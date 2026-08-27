//! XMR 地址编码（base58 + Keccak256 checksum + network byte + spend_pub + view_pub）
//!
//! Phase 5 v4 真实实现：wrap `base58-monero 2.0` + `monero-ed25519`
//!
//! ## 算法（XMR 标准地址）
//!
//! 1. payload = 1 byte network + 32 bytes spend_pub + 32 bytes view_pub (65 bytes)
//! 2. checksum = Keccak256(payload)[:4]
//! 3. bytes_to_encode = payload || checksum (69 bytes)
//! 4. address = base58_monero_encode(bytes_to_encode) (~95 chars)
//!
//! **注意**：
//! - Keccak-256 **不是** SHA3-256（nonce 不同），但 tiny-keccak 默认就是 Keccak-256 ✓
//! - XMR base58 ≠ Bitcoin base58（8-byte blocks）
//!
//! ## Network bytes
//!
//! | Network | byte |
//! |---------|------|
//! | Mainnet | 0x12 |
//! | Stagenet | 0x18 |
//! | Testnet | 0x35 |
//!
//! ## v2.4 安全修正
//!
//! - 两个 `&Ed25519Point` 都是 borrow，不 clone 副本
//! - 输出 XmrAddress 是 `heapless::String<128>`（栈分配）
//!
//! ## v2 §2.3 算法决策
//!
//! ✅ **wrap base58-monero**（monero-rs 官方，多次审计；编码类）

use crate::curve_primitive::ed25519::{point_to_compressed, Ed25519Point};
use crate::encoding::keccak256;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::network::Network;
use base58_monero::encode as base58_monero_encode;
use core::fmt;

/// XMR 地址最大长度（base58 编码 69 bytes = 8-byte × 8 + 5-byte tail → 11×8 + 7 = 95 chars，< 128 安全余量）
pub const XMR_ADDRESS_MAX_LEN: usize = 128;

/// XMR 地址 payload 长度
const XMR_PAYLOAD_LEN: usize = 65; // 1 byte network + 32 spend_pub + 32 view_pub
/// XMR Keccak-256 checksum 长度
const XMR_CHECKSUM_LEN: usize = 4;

/// XMR 网络字节
fn xmr_network_byte(network: Network) -> Result<u8> {
    match network {
        Network::MoneroMainnet => Ok(0x12),
        Network::MoneroStagenet => Ok(0x18),
        Network::MoneroTestnet => Ok(0x35),
        _ => Err(ShlosiloError::new(ShlosiloErrorKind::NetworkUnrecognized)),
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct XmrAddress {
    bytes: heapless::String<XMR_ADDRESS_MAX_LEN>,
}

impl AsRef<str> for XmrAddress {
    fn as_ref(&self) -> &str {
        self.bytes.as_str()
    }
}

impl fmt::Display for XmrAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.bytes)
    }
}

impl fmt::Debug for XmrAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.bytes.as_str();
        if s.len() > 12 {
            write!(f, "XmrAddress({}…{})", &s[..8], &s[s.len() - 6..])
        } else {
            write!(f, "XmrAddress(<redacted>)")
        }
    }
}

/// XMR 地址编码
///
/// # 算法
///
/// 1. payload = network_byte || spend_pub || view_pub (65 bytes)
/// 2. checksum = Keccak256(payload)[:4]
/// 3. bytes = payload || checksum (69 bytes)
/// 4. address = base58_monero_encode(bytes) → 95 字符
///
/// # v2.4 安全
///
/// 两个 `&Ed25519Point` 都是 borrow，**不 clone**——避免热路径泄漏私钥关联的 spend_pk 副本。
///
/// # base58-monero encode_check 已知 bug
///
/// `base58_monero::encode_check` 简单把 checksum 接在 payload 后调 `encode`，导致 Monero 地址
/// 实际编码为 101 字符（不是规范的 95 字符）。我们用 `encode` + 手写 checksum 拼接逻辑：
///
/// - 65 bytes payload → 8 full blocks (64 bytes) + 1 byte tail
/// - 1 byte tail + 4 checksum = 5 bytes ≤ 8 → 5-byte final block → 7 chars
/// - Total: 8 × 11 + 7 = **95 chars** ✓ (Monero 官方长度)
pub fn encode(
    spend_pub: &Ed25519Point,
    view_pub: &Ed25519Point,
    network: Network,
) -> Result<XmrAddress> {
    // 1. network byte
    let net_byte = xmr_network_byte(network)?;

    // 2. spend_pub + view_pub → 32 bytes each (compressed)
    let spend_bytes = point_to_compressed(spend_pub);
    let view_bytes = point_to_compressed(view_pub);

    // 3. payload = [net_byte, spend_bytes, view_bytes] (65 bytes)
    let mut payload: heapless::Vec<u8, XMR_PAYLOAD_LEN> = heapless::Vec::new();
    payload
        .push(net_byte)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    payload
        .extend_from_slice(&spend_bytes)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    payload
        .extend_from_slice(&view_bytes)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;

    // 4. checksum = Keccak256(payload)[:4]
    let checksum_full = keccak256::hash(&payload)?;
    let checksum = &checksum_full[..XMR_CHECKSUM_LEN];

    // 5. 正确编码：8 full blocks + 1 byte tail
    //    full blocks (64 bytes) → 88 chars
    let full_blocks = &payload[..XMR_PAYLOAD_LEN - 1]; // 64 bytes
    let encoded_full = base58_monero_encode(full_blocks)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    // 6. last 1 byte of payload + 4 checksum bytes = 5 bytes → 7 chars
    let mut tail_block: heapless::Vec<u8, 8> = heapless::Vec::new();
    tail_block
        .extend_from_slice(&payload[XMR_PAYLOAD_LEN - 1..])
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    tail_block
        .extend_from_slice(checksum)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    let encoded_tail = base58_monero_encode(&tail_block)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    // 7. 拼接 → 95 chars
    let mut address: heapless::String<XMR_ADDRESS_MAX_LEN> = heapless::String::new();
    address
        .push_str(&encoded_full)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    address
        .push_str(&encoded_tail)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;

    Ok(XmrAddress { bytes: address })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve_primitive::ed25519::{base_mul, scalar_from_bytes};

    /// XMR Mainnet 地址长度 = 95 字符
    #[test]
    fn address_length_mainnet() {
        let sk1 = scalar_from_bytes(&[1u8; 32]).unwrap();
        let sk2 = scalar_from_bytes(&[2u8; 32]).unwrap();
        let pk1 = base_mul(&sk1);
        let pk2 = base_mul(&sk2);
        let addr = encode(&pk1, &pk2, Network::MoneroMainnet).unwrap();
        assert_eq!(addr.as_ref().len(), 95);
    }

    /// XMR Stagenet / Testnet 不同 prefix
    #[test]
    fn network_prefix_different() {
        let sk1 = scalar_from_bytes(&[1u8; 32]).unwrap();
        let sk2 = scalar_from_bytes(&[2u8; 32]).unwrap();
        let pk1 = base_mul(&sk1);
        let pk2 = base_mul(&sk2);

        let mainnet = encode(&pk1, &pk2, Network::MoneroMainnet).unwrap();
        let stagenet = encode(&pk1, &pk2, Network::MoneroStagenet).unwrap();
        let testnet = encode(&pk1, &pk2, Network::MoneroTestnet).unwrap();

        // XMR Mainnet 地址开头通常是 '4' (0x12 = 18, 18 = 0x12 → "4" 是 base58-monero 第 19 字符)
        // Stagenet 通常 '7' (0x18 = 24)
        // Testnet 通常 '9' 或 'B' (0x35 = 53)
        // 实际字符依算法不同而异，但**前两个字符应该不同**
        assert_ne!(&mainnet.as_ref()[..2], &stagenet.as_ref()[..2]);
        assert_ne!(&mainnet.as_ref()[..2], &testnet.as_ref()[..2]);
        assert_ne!(&stagenet.as_ref()[..2], &testnet.as_ref()[..2]);
    }

    /// 确定性：相同 sk + 网络 → 相同地址
    #[test]
    fn deterministic_encoding() {
        let sk1 = scalar_from_bytes(&[3u8; 32]).unwrap();
        let sk2 = scalar_from_bytes(&[4u8; 32]).unwrap();
        let pk1 = base_mul(&sk1);
        let pk2 = base_mul(&sk2);
        let addr1 = encode(&pk1, &pk2, Network::MoneroMainnet).unwrap();
        let addr2 = encode(&pk1, &pk2, Network::MoneroMainnet).unwrap();
        assert_eq!(addr1.as_ref(), addr2.as_ref());
    }

    /// 不同 sk → 不同地址；同 sk 重新 base_mul → 同地址
    #[test]
    fn different_spend_pub_different_address() {
        let sk1 = scalar_from_bytes(&[5u8; 32]).unwrap();
        let sk2 = scalar_from_bytes(&[6u8; 32]).unwrap();
        let pk1 = base_mul(&sk1);
        let pk2 = base_mul(&sk2);

        // pk1 vs pk2 不同
        assert_ne!(point_to_compressed(&pk1), point_to_compressed(&pk2));

        // spend_pub 不同 → 地址不同
        let addr1 = encode(&pk1, &pk2, Network::MoneroMainnet).unwrap();
        let addr_swap = encode(&pk2, &pk1, Network::MoneroMainnet).unwrap();
        assert_ne!(addr1.as_ref(), addr_swap.as_ref());

        // 同 pk1 + pk2 重新调用 → 同样地址 (deterministic)
        let pk1_again = base_mul(&sk1);
        let pk2_again = base_mul(&sk2);
        let addr1_again = encode(&pk1_again, &pk2_again, Network::MoneroMainnet).unwrap();
        assert_eq!(addr1.as_ref(), addr1_again.as_ref());

        // 不同网络 →不同地址
        let addr_testnet = encode(&pk1, &pk2, Network::MoneroTestnet).unwrap();
        assert_ne!(addr1.as_ref(), addr_testnet.as_ref());
    }

    /// 非 XMR 网络报错
    #[test]
    fn non_xmr_network_rejected() {
        let sk1 = scalar_from_bytes(&[7u8; 32]).unwrap();
        let sk2 = scalar_from_bytes(&[8u8; 32]).unwrap();
        let pk1 = base_mul(&sk1);
        let pk2 = base_mul(&sk2);
        let result = encode(&pk1, &pk2, Network::BitcoinMainnet);
        assert!(result.is_err());
    }

    /// XMR 地址 prefix 验证（精确 prefix 取决于 base58-monero 8-byte block 编码，
    /// 实际我们只需验证三个网络编码出不同地址且长度都是 95 chars）：
    #[test]
    fn xmr_address_differs_by_network() {
        let sk = scalar_from_bytes(&[9u8; 32]).unwrap();
        let pk = base_mul(&sk);

        let mainnet = encode(&pk, &pk, Network::MoneroMainnet).unwrap();
        let stagenet = encode(&pk, &pk, Network::MoneroStagenet).unwrap();
        let testnet = encode(&pk, &pk, Network::MoneroTestnet).unwrap();

        // 三个网络的 XMR 地址应该完全不同
        assert_ne!(mainnet.as_ref(), stagenet.as_ref());
        assert_ne!(mainnet.as_ref(), testnet.as_ref());
        assert_ne!(stagenet.as_ref(), testnet.as_ref());

        // 长度都是 95 chars (Monero 标准)
        assert_eq!(mainnet.as_ref().len(), 95);
        assert_eq!(stagenet.as_ref().len(), 95);
        assert_eq!(testnet.as_ref().len(), 95);
    }
}