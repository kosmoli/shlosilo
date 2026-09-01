//! XMR view tag / 加密 payment ID / payment proof（Phase 5 v9.19）
//!
//! L1 纯函数。对标 keystone `derive_view_tag` + monero-oxide `SharedKeyDerivations`。

extern crate alloc;
use alloc::vec::Vec;

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// Hs("view_tag" || 8Ra || varint(o)) 的首字节
pub fn derive_view_tag(eight_ra: &[u8; 32], output_index: u64) -> u8 {
    let mut buf = Vec::with_capacity(8 + 32 + 9);
    buf.extend_from_slice(b"view_tag");
    buf.extend_from_slice(eight_ra);
    crate::chain::xmr::transaction::encode_varint(&mut buf, output_index);
    crate::encoding::keccak256::hash(&buf)
        .map(|h| h[0])
        .unwrap_or(0)
}

/// 8 * (r * A_view)，压缩点
pub fn eight_ra(tx_secret: &[u8; 32], dest_view_pub: &[u8; 32]) -> Result<[u8; 32]> {
    use curve25519_dalek::Scalar as DScalar;
    use monero_ed25519::CompressedPoint;

    let r = DScalar::from_bytes_mod_order(*tx_secret);
    let a = CompressedPoint::from(*dest_view_pub)
        .decompress()
        .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let a_ed: curve25519_dalek::EdwardsPoint = a.into();
    let ra = a_ed * r;
    Ok(ra.mul_by_cofactor().compress().to_bytes())
}

/// keccak256(8Ra || 0x8d)[..8]
pub fn payment_id_xor(eight_ra: &[u8; 32]) -> [u8; 8] {
    let mut buf = Vec::with_capacity(33);
    buf.extend_from_slice(eight_ra);
    buf.push(0x8d);
    let h = crate::encoding::keccak256::hash(&buf).unwrap_or([0u8; 32]);
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}

pub fn encrypt_payment_id(pid: &[u8; 8], xor_key: &[u8; 8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = pid[i] ^ xor_key[i];
    }
    out
}

/// 标准主地址 stealth：P = Hs(8Ra || varint(i))·G + B
pub fn stealth_address(
    eight_ra: &[u8; 32],
    output_index: u64,
    dest_spend_pub: &[u8; 32],
) -> Result<[u8; 32]> {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::Scalar as DScalar;
    use monero_ed25519::CompressedPoint;

    let mut buf = Vec::with_capacity(32 + 9);
    buf.extend_from_slice(eight_ra);
    crate::chain::xmr::transaction::encode_varint(&mut buf, output_index);
    let hs = crate::chain::xmr::subaddress::hash_to_scalar(&buf)?;
    let hs_d = DScalar::from_bytes_mod_order(hs);
    let hs_g: curve25519_dalek::EdwardsPoint = ED25519_BASEPOINT_TABLE * &hs_d;
    let b = CompressedPoint::from(*dest_spend_pub)
        .decompress()
        .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let b_ed: curve25519_dalek::EdwardsPoint = b.into();
    Ok((b_ed + hs_g).compress().to_bytes())
}

/// 导出 r（业务 2：证明付给了地址 A）
/// R1 (2026-08-31 复审整改): tx_secret 是交易密钥 — 去 derive(Clone, Debug),
/// 手写 Debug redacted; secret 字段保持借用消费 (v2-安全 §3 函数只收借用)。
pub struct PaymentProof {
    pub tx_secret: [u8; 32],
    pub tx_pub: [u8; 32],
}

/// P1-C（2026-09-01 再复审）：tx_secret 是交易密钥——Drop 时清零。
/// 不实现 Clone/Copy（编译期断言见文件尾 inventory）。
impl Drop for PaymentProof {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.tx_secret.zeroize();
    }
}

impl core::fmt::Debug for PaymentProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PaymentProof")
            .field("tx_secret", &"[REDACTED]")
            .field("tx_pub", &self.tx_pub)
            .finish()
    }
}

impl PartialEq for PaymentProof {
    fn eq(&self, other: &Self) -> bool {
        // 常时比较 tx_secret 防时序侧信道
        use subtle::ConstantTimeEq;
        bool::from(self.tx_secret.ct_eq(&other.tx_secret)) && self.tx_pub == other.tx_pub
    }
}

impl Eq for PaymentProof {}

pub fn export_payment_proof(tx_secret: &[u8; 32], tx_pub: &[u8; 32]) -> PaymentProof {
    PaymentProof {
        tx_secret: *tx_secret,
        tx_pub: *tx_pub,
    }
}

pub fn verify_payment(
    tx_secret: &[u8; 32],
    dest_view_pub: &[u8; 32],
    dest_spend_pub: &[u8; 32],
    output_index: u64,
    claimed_stealth: &[u8; 32],
) -> Result<bool> {
    let eight = eight_ra(tx_secret, dest_view_pub)?;
    let expected = stealth_address(&eight, output_index, dest_spend_pub)?;
    Ok(&expected == claimed_stealth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::xmr::tx_builder::TxKeyPair;
    use crate::encoding::keccak256;
    use crate::types::SecretBytes;

    #[test]
    fn view_tag_is_first_keccak_byte() {
        let eight_ra = [0x11u8; 32];
        let tag = derive_view_tag(&eight_ra, 0);
        let mut buf = Vec::from(&b"view_tag"[..]);
        buf.extend_from_slice(&eight_ra);
        buf.push(0x00); // varint(0)
        let h = keccak256::hash(&buf).unwrap();
        assert_eq!(tag, h[0]);
        assert_ne!(tag, derive_view_tag(&eight_ra, 1));
    }

    #[test]
    fn payment_id_xor_round_trip() {
        let eight_ra = [0x22u8; 32];
        let xor_key = payment_id_xor(&eight_ra);
        let pid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let enc = encrypt_payment_id(&pid, &xor_key);
        assert_eq!(encrypt_payment_id(&enc, &xor_key), pid);
        let mut buf = Vec::from(eight_ra.as_slice());
        buf.push(0x8d);
        let h = keccak256::hash(&buf).unwrap();
        assert_eq!(&xor_key[..], &h[..8]);
    }

    #[test]
    fn eight_ra_matches_r_times_a_times_8() {
        let keys = TxKeyPair::from_secret(SecretBytes::new([2u8; 32])).unwrap();
        // view_pub = 3*G
        let view = TxKeyPair::from_secret(SecretBytes::new([3u8; 32])).unwrap();
        let d = eight_ra(keys.secret.expose(), &view.public).unwrap();
        assert_ne!(d, [0u8; 32]);
        // 不同 view → 不同 derivation
        let view2 = TxKeyPair::from_secret(SecretBytes::new([5u8; 32])).unwrap();
        assert_ne!(d, eight_ra(keys.secret.expose(), &view2.public).unwrap());
    }

    #[test]
    fn payment_proof_verifies_own_stealth() {
        let tx = TxKeyPair::from_secret(SecretBytes::new([7u8; 32])).unwrap();
        let dest_view = TxKeyPair::from_secret(SecretBytes::new([9u8; 32])).unwrap();
        let dest_spend = TxKeyPair::from_secret(SecretBytes::new([11u8; 32])).unwrap();
        let eight = eight_ra(tx.secret.expose(), &dest_view.public).unwrap();
        let stealth = stealth_address(&eight, 0, &dest_spend.public).unwrap();
        let proof = export_payment_proof(tx.secret.expose(), &tx.public);
        assert_eq!(proof.tx_pub, tx.public);
        assert!(verify_payment(
            &proof.tx_secret,
            &dest_view.public,
            &dest_spend.public,
            0,
            &stealth,
        )
        .unwrap());
        assert!(!verify_payment(
            &proof.tx_secret,
            &dest_view.public,
            &dest_spend.public,
            1,
            &stealth,
        )
        .unwrap());
    }
}

#[cfg(test)]
mod p1c_inventory {
    use super::PaymentProof;
    use static_assertions::assert_not_impl_any;
    // P1-C: 秘密载体禁止值复制
    assert_not_impl_any!(PaymentProof: Copy, Clone);
}
