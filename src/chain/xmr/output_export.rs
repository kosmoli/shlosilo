//! XMR output export 解析（keystone XmrOutput request 侧）。
//!
//! 对齐 keystone `apps/monero/src/outputs.rs` 的 `ExportedTransferDetails::from_bytes`
//! （epee binary_archive 变体，Feather export_outputs 格式）。
//!
//! wire 格式（解密后 plaintext）：
//! ```text
//! [varint has_transfers]  — 0 = 无转账，直接结束
//! [varint offset]
//! [varint transfer_count]
//! [varint details_blob_size]  ← 未消费（keystone 同样忽略）
//! per transfer:
//!   [varint ignored_version]
//!   [32B output_pubkey]
//!   [varint internal_output_index]
//!   [varint global_output_index]
//!   [32B tx_pubkey]
//!   [1B flags]
//!   [varint amount]
//!   [varint additional_tx_keys_count] + count × [32B key]
//!   [varint major]
//!   [varint minor]
//! ```
//!
//! v2-安全 §2 约束：纯解析（L1），无副作用；敏感字段（additional_tx_keys）
//! 保留为普通字节——本结构为**公开材料**（output pubkey/索引/金额均上链或可公开），
//! 仅 spend/view 私钥属敏感，本模块不接触。

extern crate alloc;

use alloc::vec::Vec;

use crate::chain::xmr::transaction::encode_varint;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// 单笔 transfer detail（对齐 keystone `ExportedTransferDetail`）。
#[derive(Debug, Clone)]
pub struct ExportedTransferDetail {
    pub pubkey: [u8; 32],
    pub internal_output_index: u64,
    pub global_output_index: u64,
    pub tx_pubkey: [u8; 32],
    pub flags: u8,
    pub amount: u64,
    pub additional_tx_keys: Vec<[u8; 32]>,
    pub major: u32,
    pub minor: u32,
}

impl ExportedTransferDetail {
    /// flags 位语义（keystone outputs.rs，全 u8 bit）。
    pub fn is_spent(&self) -> bool {
        self.flags & 0b0000_0001 != 0
    }
    pub fn is_frozen(&self) -> bool {
        self.flags & 0b0000_0010 != 0
    }
    pub fn is_rct(&self) -> bool {
        self.flags & 0b0000_0100 != 0
    }
    pub fn is_key_image_known(&self) -> bool {
        self.flags & 0b0000_1000 != 0
    }
    pub fn is_key_image_request(&self) -> bool {
        self.flags & 0b0001_0000 != 0
    }
    pub fn is_key_image_partial(&self) -> bool {
        self.flags & 0b0010_0000 != 0
    }
}

/// 解析后的完整 export（对齐 keystone `ExportedTransferDetails`）。
#[derive(Debug, Clone, Default)]
pub struct ExportedTransferDetails {
    pub offset: u64,
    pub size: u64,
    pub details: Vec<ExportedTransferDetail>,
}

/// `flags & 0b0001_0000` — 只对需要 key image 的 output 计算并导出。
pub fn wants_key_image(detail: &ExportedTransferDetail) -> bool {
    detail.is_key_image_request()
}

fn read_varint(data: &[u8], off: &mut usize) -> Result<u64> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        let b = *data
            .get(*off)
            .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
        *off += 1;
        // Monero/keystone varint: 7 bits per byte, high bit = continue
        // (LEB128, 对齐 keystone varinteger::decode_with_offset)
        value |= u64::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
    }
    Ok(value)
}

fn read_u8_32(data: &[u8], off: &mut usize) -> Result<[u8; 32]> {
    if data.len() < *off + 32 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data[*off..*off + 32]);
    *off += 32;
    Ok(out)
}

impl ExportedTransferDetails {
    /// 对齐 keystone `ExportedTransferDetails::from_bytes`。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut off = 0usize;
        let has_transfers = read_varint(bytes, &mut off)?;
        if has_transfers == 0 {
            return Ok(Self::default());
        }
        let offset = read_varint(bytes, &mut off)?;
        // transfers.size()
        let _value_offset = read_varint(bytes, &mut off)?;
        // details blob size — keystone 读出后未消费，保持同构
        let _value_size = read_varint(bytes, &mut off)?;

        let mut details = Vec::new();
        for _ in 0.._value_offset {
            // version 字段忽略
            let _version = read_varint(bytes, &mut off)?;
            let pubkey = read_u8_32(bytes, &mut off)?;
            let internal_output_index = read_varint(bytes, &mut off)?;
            let global_output_index = read_varint(bytes, &mut off)?;
            let tx_pubkey = read_u8_32(bytes, &mut off)?;
            let flags = *bytes
                .get(off)
                .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
            off += 1;
            let amount = read_varint(bytes, &mut off)?;
            let keys_num = read_varint(bytes, &mut off)? as usize;
            let mut additional_tx_keys = Vec::with_capacity(keys_num.min(16));
            for _ in 0..keys_num {
                additional_tx_keys.push(read_u8_32(bytes, &mut off)?);
            }
            let major = read_varint(bytes, &mut off)? as u32;
            let minor = read_varint(bytes, &mut off)? as u32;

            details.push(ExportedTransferDetail {
                pubkey,
                internal_output_index,
                global_output_index,
                tx_pubkey,
                flags,
                amount,
                additional_tx_keys,
                major,
                minor,
            });
        }

        Ok(Self {
            offset,
            size: _value_offset,
            details,
        })
    }
}

/// key image 伴随签名的 wire：连续 `[32B image][64B signature]` 记录流，
/// 对齐 keystone `KeyImages::to_bytes` / `From<&Vec<u8>>`（96B 步长）。
pub const KEY_IMAGE_RECORD_LEN: usize = 96;

/// 序列化 `[(image, sig)]` → keystone `KeyImages::to_bytes` 同构。
pub fn serialize_key_images(images: &[([u8; 32], [u8; 64])]) -> Vec<u8> {
    let mut data = Vec::with_capacity(images.len() * KEY_IMAGE_RECORD_LEN);
    for (image, sig) in images {
        data.extend_from_slice(image);
        data.extend_from_slice(sig);
    }
    data
}

/// 反序列化 96B 记录流（对齐 keystone `From<&Vec<u8>>`：尾部不足 96B 的残段丢弃）。
pub fn deserialize_key_images(data: &[u8]) -> Vec<([u8; 32], [u8; 64])> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while data.len() >= i + KEY_IMAGE_RECORD_LEN {
        let mut image = [0u8; 32];
        let mut sig = [0u8; 64];
        image.copy_from_slice(&data[i..i + 32]);
        sig.copy_from_slice(&data[i + 32..i + 96]);
        out.push((image, sig));
        i += KEY_IMAGE_RECORD_LEN;
    }
    out
}

/// re-export encode_varint 供导出端组包使用（keystone write_varinteger 同构）。
pub fn write_varint(value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    encode_varint(&mut out, value);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn encode_varint_leb(v: u64) -> Vec<u8> {
        // 独立实现用于 fixture 构造（不依赖 transaction::encode_varint，交叉验证）
        let mut out = Vec::new();
        let mut v = v;
        loop {
            let b = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        }
        out
    }

    fn make_detail_bytes(idx: u64, with_key_image_request: bool) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&encode_varint_leb(1)); // version
        b.extend_from_slice(&[0x11u8; 32]); // output pubkey
        b.extend_from_slice(&encode_varint_leb(idx)); // internal_output_index
        b.extend_from_slice(&encode_varint_leb(idx + 1000)); // global_output_index
        b.extend_from_slice(&[0x22u8; 32]); // tx_pubkey
        let flags: u8 = if with_key_image_request {
            0b0001_0100
        } else {
            0b0000_0100
        };
        b.push(flags);
        b.extend_from_slice(&encode_varint_leb(123_456_789)); // amount piconero
        b.extend_from_slice(&encode_varint_leb(1)); // 1 additional key
        b.extend_from_slice(&[0x33u8; 32]);
        b.extend_from_slice(&encode_varint_leb(1)); // major (subaddress)
        b.extend_from_slice(&encode_varint_leb(2)); // minor
        b
    }

    #[test]
    fn parse_single_detail() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&encode_varint_leb(1)); // has_transfers
        bytes.extend_from_slice(&encode_varint_leb(0)); // offset
        bytes.extend_from_slice(&encode_varint_leb(1)); // transfer_count
        bytes.extend_from_slice(&encode_varint_leb(999)); // blob size (ignored)
        bytes.extend_from_slice(&make_detail_bytes(0, false));

        let parsed = ExportedTransferDetails::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.details.len(), 1);
        let d = &parsed.details[0];
        assert_eq!(d.pubkey, [0x11u8; 32]);
        assert_eq!(d.tx_pubkey, [0x22u8; 32]);
        assert_eq!(d.internal_output_index, 0);
        assert_eq!(d.global_output_index, 1000);
        assert_eq!(d.amount, 123_456_789);
        assert!(d.is_rct());
        assert!(!d.is_key_image_request());
        assert_eq!(d.major, 1);
        assert_eq!(d.minor, 2);
        assert_eq!(d.additional_tx_keys.len(), 1);
        assert_eq!(d.additional_tx_keys[0], [0x33u8; 32]);
    }

    #[test]
    fn parse_multiple_details() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&encode_varint_leb(1));
        bytes.extend_from_slice(&encode_varint_leb(42));
        bytes.extend_from_slice(&encode_varint_leb(3));
        bytes.extend_from_slice(&encode_varint_leb(0));
        bytes.extend_from_slice(&make_detail_bytes(0, true));
        bytes.extend_from_slice(&make_detail_bytes(1, true));
        bytes.extend_from_slice(&make_detail_bytes(2, false));

        let parsed = ExportedTransferDetails::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.offset, 42);
        assert_eq!(parsed.details.len(), 3);
        assert!(parsed.details[0].is_key_image_request());
        assert!(parsed.details[1].is_key_image_request());
        assert!(!parsed.details[2].is_key_image_request());
    }

    #[test]
    fn no_transfers_short_form() {
        let parsed = ExportedTransferDetails::from_bytes(&[0x00]).unwrap();
        assert!(parsed.details.is_empty());
    }

    #[test]
    fn truncated_input_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&encode_varint_leb(1));
        bytes.extend_from_slice(&encode_varint_leb(0));
        bytes.extend_from_slice(&encode_varint_leb(1));
        bytes.extend_from_slice(&encode_varint_leb(0));
        bytes.extend_from_slice(&make_detail_bytes(0, false));
        // 截断 pubkey
        bytes.truncate(bytes.len() - 10);
        assert!(ExportedTransferDetails::from_bytes(&bytes).is_err());
    }

    #[test]
    fn key_images_round_trip() {
        let records = vec![([0xAAu8; 32], [0xBBu8; 64]), ([0xCCu8; 32], [0xDDu8; 64])];
        let bytes = serialize_key_images(&records);
        assert_eq!(bytes.len(), 2 * KEY_IMAGE_RECORD_LEN);
        let back = deserialize_key_images(&bytes);
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].0, [0xAAu8; 32]);
        assert_eq!(back[1].1, [0xDDu8; 64]);
    }

    #[test]
    fn key_images_partial_tail_dropped() {
        // keystone From<&Vec<u8>>: while (data.len() - i) > 64 → 尾部残段丢弃
        let mut bytes = serialize_key_images(&[([0xAAu8; 32], [0xBBu8; 64])]);
        bytes.extend_from_slice(&[0xFFu8; 50]);
        let back = deserialize_key_images(&bytes);
        assert_eq!(back.len(), 1);
    }
}
