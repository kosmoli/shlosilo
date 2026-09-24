//! XMR output export parsing (the keystone XmrOutput request side).
//!
//! Aligned with keystone `apps/monero/src/outputs.rs` `ExportedTransferDetails::from_bytes`
//! (the epee binary_archive variant, the Feather export_outputs format).
//!
//! Wire format (decrypted plaintext):
//! ```text
//! [varint has_transfers]  — 0 = no transfers, end directly
//! [varint offset]
//! [varint transfer_count]
//! [varint details_blob_size]  ← unconsumed (keystone also ignores it)
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
//! v2-security §2 constraint: pure parsing (L1), no side effects; sensitive fields (additional_tx_keys)
//! are kept as ordinary bytes — this structure is **public material** (output pubkey/index/amount are on-chain or public);
//! only spend/view private keys are sensitive, and this module never touches them.

extern crate alloc;

use alloc::vec::Vec;

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::types::SliceVec;

/// A single transfer detail (aligned with keystone `ExportedTransferDetail`).
#[derive(Clone, Default)]
pub struct ExportedTransferDetail {
    pub pubkey: [u8; 32],
    pub internal_output_index: u64,
    pub global_output_index: u64,
    pub tx_pubkey: [u8; 32],
    pub flags: u8,
    pub amount: u64,
    /// v2-security §2 (module docs) marks this sensitive; wire-adjacent usage reads like
    /// tx pubkeys — zeroize-wrapped defensively either way (Z2.1 S3, 2026-09-24).
    /// Z2.3 C3b-1: element-level `Zeroizing` over a capped heapless leaf (drop zeroizes
    /// every key; no collection-level Zeroize impl exists for heapless).
    pub additional_tx_keys:
        heapless::Vec<zeroize::Zeroizing<[u8; 32]>, { crate::types::caps::EXTRA_KEYS_MAX }>,
    pub major: u32,
    pub minor: u32,
}

/// Z2.1 S3 (2026-09-24): manual Debug — `Zeroizing` has no Debug impl; the sensitive
/// `additional_tx_keys` field is redacted (R1-style, cf. TxSourceEntry).
impl core::fmt::Debug for ExportedTransferDetail {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExportedTransferDetail")
            .field("pubkey", &self.pubkey)
            .field("internal_output_index", &self.internal_output_index)
            .field("global_output_index", &self.global_output_index)
            .field("tx_pubkey", &self.tx_pubkey)
            .field("flags", &self.flags)
            .field("amount", &self.amount)
            .field("additional_tx_keys", &"[REDACTED]")
            .field("major", &self.major)
            .field("minor", &self.minor)
            .finish()
    }
}

impl ExportedTransferDetail {
    /// flags bit semantics (keystone outputs.rs, all u8 bits).
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

/// The parsed full export (aligned with keystone `ExportedTransferDetails`).
/// Z2.3 C3b-1 (2026-09-24, option 2): `details` is a caller-storage SliceVec.
#[derive(Debug)]
pub struct ExportedTransferDetails<'a> {
    pub offset: u64,
    pub size: u64,
    pub details: SliceVec<'a, ExportedTransferDetail>,
}

/// `flags & 0b0001_0000` — compute and export only for outputs that need a key image.
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
        // (LEB128, aligned with keystone varinteger::decode_with_offset)
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

impl ExportedTransferDetails<'_> {
    /// Aligned with keystone `ExportedTransferDetails::from_bytes`.
    /// Z2.3 C3b-1 (2026-09-24, option 2): parse-into — the details list lives in a
    /// caller-provided slice (capacity is a deployment parameter, over-cap is explicit Err).
    pub fn from_bytes<'a>(
        bytes: &[u8],
        details_out: &'a mut [ExportedTransferDetail],
    ) -> Result<ExportedTransferDetails<'a>> {
        let mut off = 0usize;
        let has_transfers = read_varint(bytes, &mut off)?;
        if has_transfers == 0 {
            return Ok(ExportedTransferDetails {
                offset: 0,
                size: 0,
                details: SliceVec::new(details_out),
            });
        }
        let offset = read_varint(bytes, &mut off)?;
        // transfers.size()
        let _value_offset = read_varint(bytes, &mut off)?;
        // details blob size — keystone reads it without consuming; kept isomorphic
        let _value_size = read_varint(bytes, &mut off)?;

        let mut details = SliceVec::new(details_out);
        for _ in 0.._value_offset {
            // version field ignored
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
            // Z2.3 C3b-1: fallible count + element-zeroized leaf cap (no `as usize` truncation).
            let keys_num = read_varint(bytes, &mut off)?;
            if keys_num > crate::types::caps::EXTRA_KEYS_MAX as u64 {
                return Err(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall));
            }
            let mut additional_tx_keys = heapless::Vec::new();
            for _ in 0..keys_num {
                additional_tx_keys
                    .push(zeroize::Zeroizing::new(read_u8_32(bytes, &mut off)?))
                    .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
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
            })?;
        }

        Ok(ExportedTransferDetails {
            offset,
            size: _value_offset,
            details,
        })
    }
}

/// The wire of key-image-with-signature: a continuous stream of `[32B image][64B signature]` records,
/// aligned with keystone `KeyImages::to_bytes` / `From<&Vec<u8>>` (96B stride).
pub const KEY_IMAGE_RECORD_LEN: usize = 96;

/// Serialize `[(image, sig)]` — isomorphic to keystone `KeyImages::to_bytes`.
pub fn serialize_key_images(images: &[([u8; 32], [u8; 64])]) -> Vec<u8> {
    let mut data = Vec::with_capacity(images.len() * KEY_IMAGE_RECORD_LEN);
    for (image, sig) in images {
        data.extend_from_slice(image);
        data.extend_from_slice(sig);
    }
    data
}

/// Deserialize a stream of 96B records (aligned with keystone `From<&Vec<u8>>`: a trailing segment shorter than 96B is dropped).
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

/// Export-side varint writer — isomorphic to keystone `write_varinteger` = Monero LEB128
/// (Z2.4d-1 follow-up: it previously delegated to the BTC-style CompactSize `encode_varint`,
/// contradicting its own doc; parse side `read_varint` was always LEB128).
pub fn write_varint(value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    crate::chain::xmr::transaction::monero_encode_varint(&mut out, value);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn encode_varint_leb(v: u64) -> Vec<u8> {
        // Independent implementation for fixture construction (does not depend on transaction::encode_varint; cross-validated)
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

        let mut pool: [ExportedTransferDetail; 4] =
            core::array::from_fn(|_| ExportedTransferDetail::default());
        let parsed = ExportedTransferDetails::from_bytes(&bytes, &mut pool).unwrap();
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
        assert_eq!(*d.additional_tx_keys[0], [0x33u8; 32]);
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

        let mut pool: [ExportedTransferDetail; 4] =
            core::array::from_fn(|_| ExportedTransferDetail::default());
        let parsed = ExportedTransferDetails::from_bytes(&bytes, &mut pool).unwrap();
        assert_eq!(parsed.offset, 42);
        assert_eq!(parsed.details.len(), 3);
        assert!(parsed.details[0].is_key_image_request());
        assert!(parsed.details[1].is_key_image_request());
        assert!(!parsed.details[2].is_key_image_request());
    }

    #[test]
    fn no_transfers_short_form() {
        let mut pool: [ExportedTransferDetail; 4] =
            core::array::from_fn(|_| ExportedTransferDetail::default());
        let parsed = ExportedTransferDetails::from_bytes(&[0x00], &mut pool).unwrap();
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
        // Truncated pubkey
        bytes.truncate(bytes.len() - 10);
        let mut pool: [ExportedTransferDetail; 4] =
            core::array::from_fn(|_| ExportedTransferDetail::default());
        assert!(ExportedTransferDetails::from_bytes(&bytes, &mut pool).is_err());
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
        // keystone From<&Vec<u8>>: while (data.len() - i) > 64 → the trailing remnant is dropped
        let mut bytes = serialize_key_images(&[([0xAAu8; 32], [0xBBu8; 64])]);
        bytes.extend_from_slice(&[0xFFu8; 50]);
        let back = deserialize_key_images(&bytes);
        assert_eq!(back.len(), 1);
    }
}
