//! Monero Transaction full serialization (Phase 5 v9.5 Phase A)
//!
//! Implements:
//! - XMR tx structure: `Transaction` / `TransactionPrefix` / `TxInput` / `TxOutput` / `extra`
//! - tx serialization (varint encoding)
//! - Round-trip tests
//! - Key image construction (reuses the v8 CLSAG `derive_key_image`)
//!
//! **Not implemented (later in Phase B + C)**:
//! - RingCT signatures (rctSigBase + rctSigPrunable) — Phase B
//! - Bulletproofs+ generation — Phase B
//! - CLSAG sign integration — Phase B
//! - encrypted_amounts (epee) — Phase B
//! - End-to-end construct → sign → serialize → verify — Phase C
//!
//! ## Algorithm
//!
//! Monero tx format (BIP-style v2, post hard-fork):
//! ```text
//! TransactionPrefix {
//!   u8 version,         // always 2
//!   varint unlock_time,
//!   varint input_count,
//!   TxInput[input_count] {
//!     key_offsets: relative_output_indexes,  // ring members
//!     key_image: 32 bytes
//!   },
//!   varint output_count,
//!   TxOutput[output_count] {
//!     amount: u64,     // 0 for RingCT
//!     type: u8,        // 0x02 for TxOutToTaggedKey, 0x03 for TxOutToKey
//!     stealth_address: 32 bytes
//!   },
//!   varint extra_size,
//!   extra_bytes,
//! }
//! + rct_signatures: { type, txnFee, pseudoOuts, ... }
//! ```
//!
//! **Note**: shlosilo implements version=2 only (RingCT mandatory). Pre-RingCT (version=1) has been deprecated on mainnet.
//!
//! **Reference**: <https://github.com/monero-project/monero/blob/master/src/cryptonote_basic/cryptonote_format_utils.cpp>

extern crate alloc;
use alloc::vec::Vec;

use crate::chain::xmr::clsag::derive_key_image;
use crate::curve_primitive::ed25519::{scalar_to_bytes, Ed25519Scalar as ShlosiloScalar};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::types::caps::{RING_MAX, TX_EXTRA_NONCE_MAX, TX_EXTRA_PUBKEYS_MAX};
use monero_ed25519::{CompressedPoint, Scalar};

/// XMR tx version: 2 = RingCT (post-fork, only valid in mainnet)
pub const TX_VERSION: u8 = 2;

/// P1-02 discipline (2026-09-24 T-01): wire u64 -> usize fallible conversion —
/// silently truncating `as usize` on 32-bit targets would desync the parser.
fn wire_len(n: u64) -> Result<usize> {
    usize::try_from(n).map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))
}

/// Monero tx input (ring member + key image)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxInput {
    /// ring members' offsets (relative to actual spend)
    /// Z2.3 (2026-09-24, option 2): leaf collection, protocol-hard cap RING_MAX.
    pub key_offsets: heapless::Vec<u64, RING_MAX>,
    /// key image (32 bytes, Ed25519 compressed point)
    pub key_image: [u8; 32],
}

impl TxInput {
    /// Construct a RingCT `txin_to_key` input.
    pub fn new(key_offsets: heapless::Vec<u64, RING_MAX>, key_image: [u8; 32]) -> Self {
        Self {
            key_offsets,
            key_image,
        }
    }

    /// Exact serialized length (pairs with `serialize_into`).
    pub fn serialized_len(&self) -> usize {
        2 + monero_varint_len(self.key_offsets.len() as u64)
            + self
                .key_offsets
                .iter()
                .map(|o| monero_varint_len(*o))
                .sum::<usize>()
            + 32
    }

    /// Serialize into a caller buffer (Z2.4d C-class). Byte-identical to `serialize`.
    pub fn serialize_into(&self, out: &mut [u8], n: &mut usize) -> Result<()> {
        use crate::types::push::push_slice;
        push_slice(out, n, &[0x02])?; // txin_to_key variant tag
        monero_encode_varint_at(out, n, 0)?; // RingCT input amount
        monero_encode_varint_at(out, n, self.key_offsets.len() as u64)?;
        for offset in &self.key_offsets {
            monero_encode_varint_at(out, n, *offset)?;
        }
        push_slice(out, n, &self.key_image)
    }

    /// Serialize a `txin_to_key` input as it appears in a transaction prefix.
    ///
    /// - variant tag `0x02`
    /// - varint amount (`0` for RingCT v2 transactions)
    /// - varint key_offsets.len
    /// - varint key_offsets[i]
    /// - 32 bytes key_image
    ///
    /// Test/legacy convenience (allocates). Production writes through `serialize_into`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x02); // txin_to_key variant tag
        monero_encode_varint(&mut out, 0); // RingCT input amount
        monero_encode_varint(&mut out, self.key_offsets.len() as u64);
        for offset in &self.key_offsets {
            monero_encode_varint(&mut out, *offset);
        }
        out.extend_from_slice(&self.key_image);
        out
    }

    pub fn deserialize(bytes: &[u8], pos: &mut usize) -> Result<Self> {
        if *pos >= bytes.len() || bytes[*pos] != 0x02 {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        *pos += 1;
        let amount = monero_decode_varint(bytes, pos)?;
        if amount != 0 {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let n = monero_decode_varint(bytes, pos)?;
        // Z2.3 (2026-09-24, option 2): leaf cap RING_MAX (protocol-hard) — over-cap
        // ring offsets are consensus-invalid; explicit Err, never truncation.
        let mut key_offsets: heapless::Vec<u64, RING_MAX> = heapless::Vec::new();
        for _ in 0..n {
            key_offsets
                .push(monero_decode_varint(bytes, pos)?)
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
        }
        if *pos + 32 > bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let mut key_image = [0u8; 32];
        key_image.copy_from_slice(&bytes[*pos..*pos + 32]);
        *pos += 32;
        Ok(Self {
            key_offsets,
            key_image,
        })
    }
}

/// TxOut type (BIP format, used in TransactionOutput)
pub mod out_type {
    /// Legacy (pre-RingCT, deprecated)
    pub const TX_OUT_GEN: u8 = 0x00;
    /// TxOutToKey: standard stealth output (RingCT compatible)
    pub const TX_OUT_TO_KEY: u8 = 0x02;
    /// TxOutToTaggedKey: tagged-key output (subaddress)
    pub const TX_OUT_TO_TAGGED_KEY: u8 = 0x03;
}

/// Monero tx output (stealth address + amount)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutput {
    /// amount (0 for RingCT — actual amount hidden in encrypted_amounts)
    pub amount: u64,
    /// output type (see `out_type`)
    pub output_type: u8,
    /// stealth address / tagged key (32 bytes Ed25519 compressed point)
    pub stealth_address: [u8; 32],
    /// view tag (1 byte when type 0x03; None for type 0x02)
    pub view_tag: Option<u8>,
}

impl TxOutput {
    /// Construct a P2WPKH-style output
    pub fn new(amount: u64, stealth_address: [u8; 32]) -> Self {
        Self {
            amount,
            output_type: out_type::TX_OUT_TO_KEY,
            stealth_address,
            view_tag: None,
        }
    }

    /// Construct a tagged-key output (with view tag)
    pub fn new_tagged(amount: u64, stealth_address: [u8; 32], view_tag: u8) -> Self {
        Self {
            amount,
            output_type: out_type::TX_OUT_TO_TAGGED_KEY,
            stealth_address,
            view_tag: Some(view_tag),
        }
    }

    /// Exact serialized length (pairs with `serialize_into`).
    pub fn serialized_len(&self) -> usize {
        monero_varint_len(self.amount)
            + 1
            + 32
            + usize::from(self.output_type == out_type::TX_OUT_TO_TAGGED_KEY)
    }

    /// Serialize into a caller buffer (Z2.4d C-class). Byte-identical to `serialize`.
    pub fn serialize_into(&self, out: &mut [u8], n: &mut usize) -> Result<()> {
        use crate::types::push::{push_byte, push_slice};
        monero_encode_varint_at(out, n, self.amount)?;
        push_byte(out, n, self.output_type)?;
        push_slice(out, n, &self.stealth_address)?;
        if self.output_type == out_type::TX_OUT_TO_TAGGED_KEY {
            push_byte(out, n, self.view_tag.unwrap_or(0))?;
        }
        Ok(())
    }

    /// Serialize the output (official binary_archive: amount is a VARINT, not 8B LE)
    ///
    /// - varint(amount) + type + stealth_address [+ view_tag]
    ///
    /// Test/legacy convenience (allocates). Production writes through `serialize_into`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        monero_encode_varint(&mut out, self.amount);
        out.push(self.output_type);
        out.extend_from_slice(&self.stealth_address);
        if self.output_type == out_type::TX_OUT_TO_TAGGED_KEY {
            out.push(self.view_tag.unwrap_or(0));
        }
        out
    }

    pub fn deserialize(bytes: &[u8], pos: &mut usize) -> Result<Self> {
        let amount = monero_decode_varint(bytes, pos)?;
        // T-01-class hardening (found by fuzz smoke 2026-09-25): every field read
        // is bounds-checked before indexing/slicing — a truncated wire must Err,
        // never a range panic (panic=abort on device = DoS).
        if *pos >= bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let output_type = bytes[*pos];
        *pos += 1;
        if *pos + 32 > bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let mut stealth_address = [0u8; 32];
        stealth_address.copy_from_slice(&bytes[*pos..*pos + 32]);
        *pos += 32;
        let view_tag = if output_type == out_type::TX_OUT_TO_TAGGED_KEY {
            if *pos >= bytes.len() {
                return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            let t = bytes[*pos];
            *pos += 1;
            Some(t)
        } else {
            None
        };
        Ok(Self {
            amount,
            output_type,
            stealth_address,
            view_tag,
        })
    }
}

/// extra field (BIP format, Monero protocol set)
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TxExtra {
    /// tx public key (transaction extra field tag 0x01, length 32)
    pub tx_pub_key: Option<[u8; 32]>,
    /// additional public keys (tag 0x04, each varint length + 32 bytes)
    /// Z2.3 (2026-09-24, option 2): leaf cap TX_EXTRA_PUBKEYS_MAX (soft, Err on overflow).
    pub additional_pub_keys: heapless::Vec<[u8; 32], TX_EXTRA_PUBKEYS_MAX>,
    /// payment ID (tag 0x02 or 0x07 for encrypted/integrated)
    pub payment_id: Option<[u8; 8]>,
    /// Encrypted payment ID (extra nonce: tag 0x02, 9 bytes = 0x01 || enc[8])
    pub encrypted_payment_id: Option<[u8; 8]>,
    /// nonce (raw bytes, optional field)
    /// Z2.3 (2026-09-24, option 2): leaf cap TX_EXTRA_NONCE_MAX (soft, Err on overflow).
    pub nonce: Option<heapless::Vec<u8, TX_EXTRA_NONCE_MAX>>,
}

impl TxExtra {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tx_pub_key(mut self, pk: [u8; 32]) -> Self {
        self.tx_pub_key = Some(pk);
        self
    }

    pub fn with_additional_pub_key(mut self, pk: [u8; 32]) -> Result<Self> {
        self.additional_pub_keys
            .push(pk)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
        Ok(self)
    }

    pub fn with_encrypted_payment_id(mut self, enc: [u8; 8]) -> Self {
        self.encrypted_payment_id = Some(enc);
        self
    }

    /// Exact serialized length (pairs with `serialize_into`).
    pub fn serialized_len(&self) -> usize {
        let mut len = 0usize;
        if self.tx_pub_key.is_some() {
            len += 1 + 32;
        }
        if !self.additional_pub_keys.is_empty() {
            len += 1
                + monero_varint_len(self.additional_pub_keys.len() as u64)
                + 32 * self.additional_pub_keys.len();
        }
        if self.encrypted_payment_id.is_some() {
            len += 3 + 8;
        } else if self.payment_id.is_some() {
            len += 2 + 8;
        }
        if let Some(n) = &self.nonce {
            len += 1 + monero_varint_len(n.len() as u64) + n.len();
        }
        len
    }

    /// Serialize into a caller buffer (Z2.4d C-class). Byte-identical to `serialize`.
    pub fn serialize_into(&self, out: &mut [u8], n: &mut usize) -> Result<()> {
        use crate::types::push::{push_byte, push_slice};
        if let Some(pk) = &self.tx_pub_key {
            push_byte(out, n, 0x01)?;
            push_slice(out, n, pk)?;
        }
        if !self.additional_pub_keys.is_empty() {
            push_byte(out, n, 0x04)?;
            monero_encode_varint_at(out, n, self.additional_pub_keys.len() as u64)?;
            for pk in &self.additional_pub_keys {
                push_slice(out, n, pk)?;
            }
        }
        if let Some(enc) = &self.encrypted_payment_id {
            push_slice(out, n, &[0x02, 9, 0x01])?;
            push_slice(out, n, enc)?;
        } else if let Some(pid) = &self.payment_id {
            push_slice(out, n, &[0x02, 8])?;
            push_slice(out, n, pid)?;
        }
        if let Some(nb) = &self.nonce {
            push_byte(out, n, 0x05)?;
            monero_encode_varint_at(out, n, nb.len() as u64)?;
            push_slice(out, n, nb)?;
        }
        Ok(())
    }

    /// Test/legacy convenience (allocates). Production writes through `serialize_into`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // tx_pub_key: tag 0x01 + 32B raw (official tx_extra_pub_key has no length field)
        if let Some(pk) = &self.tx_pub_key {
            out.push(0x01);
            out.extend_from_slice(pk);
        }
        // additional_pub_keys: tag 0x04 + varint count + N×32B (FIELD(vector) carries a count)
        if !self.additional_pub_keys.is_empty() {
            out.push(0x04);
            monero_encode_varint(&mut out, self.additional_pub_keys.len() as u64);
            for pk in &self.additional_pub_keys {
                out.extend_from_slice(pk);
            }
        }
        // payment_id (tag 0x02 for plaintext, varint len=8, 8 bytes)
        // payment_id plaintext (tag 0x02, len=8) — mutually exclusive with encrypted; encrypted takes priority
        if let Some(enc) = &self.encrypted_payment_id {
            out.push(0x02);
            out.push(9);
            out.push(0x01);
            out.extend_from_slice(enc);
        } else if let Some(pid) = &self.payment_id {
            out.push(0x02);
            out.push(8);
            out.extend_from_slice(pid);
        }
        // nonce (tag 0x05, varint len, raw bytes)
        if let Some(n) = &self.nonce {
            out.push(0x05);
            monero_encode_varint(&mut out, n.len() as u64);
            out.extend_from_slice(n);
        }
        out
    }

    pub fn deserialize(bytes: &[u8], pos: &mut usize) -> Result<Self> {
        let mut extra = Self::new();
        while *pos < bytes.len() {
            let tag = bytes[*pos];
            *pos += 1;
            // Official format: 32B bare key directly after tx_extra_pub_key(0x01), no length field;
            // the other fields have a varint length prefix
            if tag == 0x01 {
                if *pos + 32 > bytes.len() {
                    return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&bytes[*pos..*pos + 32]);
                extra.tx_pub_key = Some(pk);
                *pos += 32;
                continue;
            }
            // P0-01-class hardening (2026-09-24 T-01): fallible u64 -> usize +
            // checked_add — a wire u64::MAX must yield Err, never an
            // addition-overflow panic (panic=abort on device = DoS) or a wrapped
            // bounds check followed by a slice panic. `len` is a byte length for
            // every tag except 0x04 (key count, bounded precisely in that arm).
            let len = wire_len(monero_decode_varint(bytes, pos)?)?;
            if (*pos)
                .checked_add(len)
                .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?
                > bytes.len()
            {
                return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            match tag {
                0x04 => {
                    // additional_pub_keys: len is the **key count** (FIELD(vector)'s count), not a byte count
                    let keys_bytes = len.checked_mul(32).ok_or_else(|| {
                        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
                    })?;
                    if (*pos).checked_add(keys_bytes).ok_or_else(|| {
                        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
                    })? > bytes.len()
                    {
                        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
                    }
                    for _ in 0..len {
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(&bytes[*pos..*pos + 32]);
                        extra
                            .additional_pub_keys
                            .push(pk)
                            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
                        *pos += 32;
                    }
                }
                0x02 if len == 8 => {
                    let mut pid = [0u8; 8];
                    pid.copy_from_slice(&bytes[*pos..*pos + 8]);
                    extra.payment_id = Some(pid);
                    *pos += 8;
                }
                0x02 if len == 9 => {
                    let data = &bytes[*pos..*pos + 9];
                    *pos += 9;
                    if data[0] == 0x01 {
                        let mut enc = [0u8; 8];
                        enc.copy_from_slice(&data[1..]);
                        extra.encrypted_payment_id = Some(enc);
                    }
                }
                0x05 => {
                    let data = heapless::Vec::from_slice(&bytes[*pos..*pos + len])
                        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
                    extra.nonce = Some(data);
                    *pos += len;
                }
                // unknown tag — skip
                _ => {
                    *pos += len;
                }
            }
        }
        Ok(extra)
    }
}

/// Monero transaction prefix (BIP format, before RCT signatures)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionPrefix {
    /// version (always 2)
    pub version: u8,
    /// unlock_time (block height or timestamp; 0 = no lock)
    pub unlock_time: u64,
    /// inputs
    pub inputs: Vec<TxInput>,
    /// outputs
    pub outputs: Vec<TxOutput>,
    /// extra field
    pub extra: TxExtra,
}

impl TransactionPrefix {
    pub fn new(
        unlock_time: u64,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        extra: TxExtra,
    ) -> Self {
        Self {
            version: TX_VERSION,
            unlock_time,
            inputs,
            outputs,
            extra,
        }
    }

    /// Exact serialized length (pairs with `serialize_into`).
    pub fn serialized_len(&self) -> usize {
        1 + monero_varint_len(self.unlock_time)
            + monero_varint_len(self.inputs.len() as u64)
            + self
                .inputs
                .iter()
                .map(|i| i.serialized_len())
                .sum::<usize>()
            + monero_varint_len(self.outputs.len() as u64)
            + self
                .outputs
                .iter()
                .map(|o| o.serialized_len())
                .sum::<usize>()
            + monero_varint_len(self.extra.serialized_len() as u64)
            + self.extra.serialized_len()
    }

    /// Serialize into a caller buffer (Z2.4d C-class). Byte-identical to `serialize`.
    pub fn serialize_into(&self, out: &mut [u8], n: &mut usize) -> Result<()> {
        use crate::types::push::push_byte;
        push_byte(out, n, self.version)?;
        monero_encode_varint_at(out, n, self.unlock_time)?;
        monero_encode_varint_at(out, n, self.inputs.len() as u64)?;
        for input in &self.inputs {
            input.serialize_into(out, n)?;
        }
        monero_encode_varint_at(out, n, self.outputs.len() as u64)?;
        for output in &self.outputs {
            output.serialize_into(out, n)?;
        }
        monero_encode_varint_at(out, n, self.extra.serialized_len() as u64)?;
        self.extra.serialize_into(out, n)?;
        Ok(())
    }

    /// Test/legacy convenience (allocates). Production writes through `serialize_into`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        monero_encode_varint(&mut out, self.unlock_time);
        monero_encode_varint(&mut out, self.inputs.len() as u64);
        for input in &self.inputs {
            let bytes = input.serialize();
            out.extend_from_slice(&bytes);
        }
        monero_encode_varint(&mut out, self.outputs.len() as u64);
        for output in &self.outputs {
            let bytes = output.serialize();
            out.extend_from_slice(&bytes);
        }
        let extra_bytes = self.extra.serialize();
        monero_encode_varint(&mut out, extra_bytes.len() as u64);
        out.extend_from_slice(&extra_bytes);
        out
    }

    pub fn deserialize(bytes: &[u8], pos: &mut usize) -> Result<Self> {
        if *pos >= bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let version = bytes[*pos];
        *pos += 1;
        if version != TX_VERSION {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let unlock_time = monero_decode_varint(bytes, pos)?;
        // P0-01-class hardening (2026-09-24 T-01): bound the count by wire
        // feasibility before preallocation (min serialized input = varint
        // offsets count + one offset varint + 32B key image = 34B) — a malicious
        // count must Err, never reach with_capacity (capacity-overflow abort).
        let n_inputs = monero_decode_varint(bytes, pos)?;
        if n_inputs > (bytes.len().saturating_sub(*pos) / 34) as u64 {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let mut inputs = Vec::with_capacity(wire_len(n_inputs)?);
        for _ in 0..n_inputs {
            inputs.push(TxInput::deserialize(bytes, pos)?);
        }
        // Same feasibility bound as inputs (min serialized output = varint amount
        // + type byte + 32B stealth address = 34B).
        let n_outputs = monero_decode_varint(bytes, pos)?;
        if n_outputs > (bytes.len().saturating_sub(*pos) / 34) as u64 {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let mut outputs = Vec::with_capacity(wire_len(n_outputs)?);
        for _ in 0..n_outputs {
            outputs.push(TxOutput::deserialize(bytes, pos)?);
        }
        // P0-01-class hardening (2026-09-24 T-01): fallible u64 -> usize + checked_add.
        let extra_len = wire_len(monero_decode_varint(bytes, pos)?)?;
        let extra_end = (*pos)
            .checked_add(extra_len)
            .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
        if extra_end > bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let extra = TxExtra::deserialize(&bytes[*pos..extra_end], &mut 0)?;
        *pos = extra_end;
        Ok(Self {
            version,
            unlock_time,
            inputs,
            outputs,
            extra,
        })
    }
}

/// Complete Monero transaction (prefix + RCT signatures placeholder)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub prefix: TransactionPrefix,
    /// rct_signatures bytes (Phase B/C will populate with actual RctSigBase + Prunable)
    /// Phase A: set to an empty Vec (no RCT, but this is an invalid mainnet tx; for structural tests only)
    pub rct_signatures: Vec<u8>,
}

impl Transaction {
    pub fn new(prefix: TransactionPrefix) -> Self {
        Self {
            prefix,
            rct_signatures: Vec::new(),
        }
    }

    /// Construct transaction with pre-serialized RCT signatures bytes
    pub fn new_with_rct(prefix: TransactionPrefix, rct_signatures: Vec<u8>) -> Self {
        Self {
            prefix,
            rct_signatures,
        }
    }

    /// Serialize complete tx
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.prefix.serialize();
        // RCT signatures serialized as varint len + bytes
        // Even when empty, we need varint(0) marker
        monero_encode_varint(&mut out, self.rct_signatures.len() as u64);
        out.extend_from_slice(&self.rct_signatures);
        out
    }

    pub fn deserialize(bytes: &[u8], pos: &mut usize) -> Result<Self> {
        let prefix = TransactionPrefix::deserialize(bytes, pos)?;
        // P0-01-class hardening (2026-09-24 T-01): fallible u64 -> usize + checked_add.
        let rct_len = wire_len(monero_decode_varint(bytes, pos)?)?;
        let rct_end = (*pos)
            .checked_add(rct_len)
            .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
        if rct_end > bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let rct_signatures = bytes[*pos..rct_end].to_vec();
        *pos = rct_end;
        Ok(Self {
            prefix,
            rct_signatures,
        })
    }
}

/// T-01 (2026-09-24) regression: malicious wire lengths must yield Err — never an
/// addition-overflow / slice panic (panic=abort DoS) or a capacity-overflow abort.
#[cfg(test)]
mod wire_hardening_tests {
    use super::*;

    /// Fuzz smoke regression (2026-09-25): output-entry field reads were
    /// unguarded — a truncated wire must Err at each cut, never panic.
    #[test]
    fn output_entry_truncated_rejected() {
        // amount(0) + type(0x02) + 32B stealth — every strict prefix must Err.
        let mut wire = alloc::vec![0x00u8, 0x02];
        wire.extend_from_slice(&[0x42u8; 32]);
        for cut in 0..wire.len() {
            let mut pos = 0usize;
            assert!(
                TxOutput::deserialize(&wire[..cut], &mut pos).is_err(),
                "cut {cut} must Err"
            );
        }
        // complete wire parses
        let mut pos = 0usize;
        assert!(TxOutput::deserialize(&wire, &mut pos).is_ok());
    }

    /// extra tag 0x05 (nonce) declaring u64::MAX length
    #[test]
    fn extra_huge_len_rejected() {
        let mut extra = alloc::vec![0x05u8];
        monero_encode_varint(&mut extra, u64::MAX);
        extra.extend_from_slice(&[0u8; 8]);
        assert!(TxExtra::deserialize(&extra, &mut 0).is_err());
    }

    /// extra tag 0x04 declaring a u64::MAX key COUNT (len is count, not bytes)
    #[test]
    fn extra_huge_key_count_rejected() {
        let mut extra = alloc::vec![0x04u8];
        monero_encode_varint(&mut extra, u64::MAX);
        extra.extend_from_slice(&[0u8; 40]);
        assert!(TxExtra::deserialize(&extra, &mut 0).is_err());
    }

    /// prefix with a huge input count must Err before any preallocation
    #[test]
    fn prefix_huge_input_count_rejected() {
        let mut p = alloc::vec![TX_VERSION];
        monero_encode_varint(&mut p, 0); // unlock_time
        monero_encode_varint(&mut p, u64::MAX); // n_inputs
        assert!(TransactionPrefix::deserialize(&p, &mut 0).is_err());
    }

    /// prefix with a huge extra_size must Err (no overflow/slice panic)
    #[test]
    fn prefix_huge_extra_len_rejected() {
        let mut p = alloc::vec![TX_VERSION];
        monero_encode_varint(&mut p, 0); // unlock_time
        monero_encode_varint(&mut p, 0); // n_inputs
        monero_encode_varint(&mut p, 0); // n_outputs
        monero_encode_varint(&mut p, u64::MAX); // extra_size
        assert!(TransactionPrefix::deserialize(&p, &mut 0).is_err());
    }

    /// Z2.2: the Vec shape and the slice-cursor core must be byte-identical.
    #[test]
    fn encode_varint_shapes_identical() {
        for n in [
            0u64,
            1,
            0xfc,
            0xfd,
            0xffff,
            0x1_0000,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ] {
            let mut v = alloc::vec::Vec::new();
            encode_varint(&mut v, n);
            let mut buf = [0u8; 9];
            let mut pos = 0usize;
            encode_varint_at(&mut buf, &mut pos, n).unwrap();
            assert_eq!(v.as_slice(), &buf[..pos], "n = {n}");
        }
    }
}

/// Construct key image from a 32-byte spend private key (32 bytes)
///
/// Re-export from clsag module for convenience. Actual implementation in chain/xmr/clsag.rs.
pub fn construct_key_image(spend_key: &[u8; 32]) -> Result<[u8; 32]> {
    derive_key_image(spend_key)
}

/// Convert 32 bytes to monero-ed25519 Scalar
///
/// First reduced via curve25519-dalek's `from_bytes_mod_order` — some scalars in the Monero protocol
/// (e.g. decoy commitment masks) are not guaranteed canonical, and `Scalar::read` would reject them.
pub fn bytes_to_monerod_scalar(bytes: &[u8; 32]) -> Scalar {
    let reduced = curve25519_dalek::Scalar::from_bytes_mod_order(*bytes).to_bytes();
    let mut cursor = Read32Cursor(reduced);
    Scalar::read(&mut cursor).expect("reduced scalar is canonical")
}

/// Convert shlosilo Scalar to monero-ed25519 Scalar
///
/// XMR specific type bridge. Both are 32-byte scalars, but monero-ed25519 Scalar is newtype.
/// shlosilo uses reduced scalars (32 bytes), so we can use `Scalar::read` via Cursor.
pub fn shlosilo_scalar_to_monerod(s: &ShlosiloScalar) -> Scalar {
    let bytes = scalar_to_bytes(s);
    let mut cursor = Read32Cursor(bytes);
    Scalar::read(&mut cursor).expect("shlosilo scalar is reduced")
}

pub struct Read32Cursor(pub [u8; 32]);
impl std_shims::io::Read for Read32Cursor {
    fn read(&mut self, buf: &mut [u8]) -> std_shims::io::Result<usize> {
        let n = buf.len().min(self.0.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = [0u8; 32];
        Ok(n)
    }
}

/// Convert monero-ed25519 CompressedPoint to 32-byte array
pub fn compressed_point_to_bytes(p: &CompressedPoint) -> [u8; 32] {
    p.to_bytes()
}

/// Convert monero-ed25519 Scalar to 32-byte array
pub fn monerod_scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    <[u8; 32]>::from(*s)
}

/// Monero protocol varint encoding (BTC compact size style)
///
/// Z2.2 (2026-09-24): delegates to `encode_varint_at` — the Vec and slice-cursor call
/// shapes share one core and are byte-identical by construction
/// (see `encode_varint_shapes_identical`).
pub fn encode_varint(out: &mut Vec<u8>, n: u64) {
    let mut tmp = [0u8; 9];
    let mut pos = 0usize;
    // 9 bytes is the exact CompactSize maximum (0xff + u64 LE); infallible here.
    let _ = encode_varint_at(&mut tmp, &mut pos, n);
    out.extend_from_slice(&tmp[..pos]);
}

/// Bounded slice-cursor core for the BTC-style CompactSize varint (Z2.2 A-class,
/// zero-heap call shape for stack buffers).
pub fn encode_varint_at(out: &mut [u8], pos: &mut usize, n: u64) -> Result<()> {
    fn put(out: &mut [u8], pos: &mut usize, bytes: &[u8]) -> Result<()> {
        let end = (*pos)
            .checked_add(bytes.len())
            .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
        if end > out.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        out[*pos..end].copy_from_slice(bytes);
        *pos = end;
        Ok(())
    }
    if n < 0xfd {
        put(out, pos, &[n as u8])
    } else if n <= 0xffff {
        put(out, pos, &[0xfd])?;
        put(out, pos, &(n as u16).to_le_bytes())
    } else if n <= 0xffff_ffff {
        put(out, pos, &[0xfe])?;
        put(out, pos, &(n as u32).to_le_bytes())
    } else {
        put(out, pos, &[0xff])?;
        put(out, pos, &n.to_le_bytes())
    }
}

/// Monero (LEB128) varint: 7-bit groups, low byte first, the high bit = continuation flag.
/// Note this differs semantically from `encode_varint` (Bitcoin-style prefix + fixed-width LE, BTC module only);
/// do not mix them — confirmed empirically by the P1-06 oracle.
/// Monero LEB128 varint length in bytes (exact, pairs with `monero_encode_varint_at`).
pub fn monero_varint_len(mut n: u64) -> usize {
    let mut len = 1;
    while n >= 0x80 {
        n >>= 7;
        len += 1;
    }
    len
}

/// Bounded slice-cursor core for the Monero LEB128 varint (Z2.4d, zero-heap call shape).
pub fn monero_encode_varint_at(out: &mut [u8], pos: &mut usize, mut n: u64) -> Result<()> {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        let end = (*pos)
            .checked_add(1)
            .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
        if end > out.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        if n == 0 {
            out[*pos] = b;
            *pos = end;
            return Ok(());
        }
        out[*pos] = b | 0x80;
        *pos = end;
    }
}

/// Vec-delegating convenience (test/legacy); production writes through `monero_encode_varint_at`.
pub fn monero_encode_varint(out: &mut Vec<u8>, mut n: u64) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

/// Monero LEB128 varint decode. Returns (value, new position).
pub fn monero_decode_varint(bytes: &[u8], pos: &mut usize) -> Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let b = bytes[*pos];
        *pos += 1;
        if shift >= 64 {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::string::String;
    use alloc::vec;
    use std::eprintln;

    fn hex_encode(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&alloc::format!("{:02x}", byte));
        }
        s
    }

    /// varint round-trip
    #[test]
    fn varint_round_trip() {
        let mut out = Vec::new();
        monero_encode_varint(&mut out, 0);
        assert_eq!(out, vec![0]);
        let mut pos = 0;
        assert_eq!(monero_decode_varint(&out, &mut pos).unwrap(), 0);
        assert_eq!(pos, 1);

        out.clear();
        monero_encode_varint(&mut out, 100);
        assert_eq!(out, vec![100]);
        let mut pos = 0;
        assert_eq!(monero_decode_varint(&out, &mut pos).unwrap(), 100);

        out.clear();
        monero_encode_varint(&mut out, 1000);
        // 1000 = 0x3e8 → LEB128: low 7 bits 0x68|0x80, high part 0x07
        assert_eq!(out, vec![0xe8, 0x07]);
        let mut pos = 0;
        assert_eq!(monero_decode_varint(&out, &mut pos).unwrap(), 1000);
    }

    /// TxInput serialize round-trip
    #[test]
    fn tx_input_round_trip() {
        let input = TxInput {
            key_offsets: heapless::Vec::from_slice(&[10, 25, 100, 250]).unwrap(),
            key_image: [0x42; 32],
        };
        let bytes = input.serialize();
        assert_eq!(&bytes[..3], &[0x02, 0x00, 0x04]);
        let mut pos = 0;
        let parsed = TxInput::deserialize(&bytes, &mut pos).unwrap();
        assert_eq!(parsed, input);
        assert_eq!(pos, bytes.len());
    }

    /// The bytes hashed as the transaction prefix must include the input
    /// variant tag and RingCT amount. Omitting either makes CLSAG signatures
    /// locally self-consistent but invalid to monerod.
    #[test]
    fn tx_prefix_includes_full_txin_to_key_encoding() {
        let prefix = TransactionPrefix::new(
            0,
            vec![TxInput::new(
                heapless::Vec::from_slice(&[5, 7]).unwrap(),
                [0x11; 32],
            )],
            vec![],
            TxExtra::new(),
        );
        let bytes = prefix.serialize();

        assert_eq!(
            &bytes[..8],
            &[2, 0, 1, 0x02, 0, 2, 5, 7],
            "version, unlock, vin count, variant, amount, offset count, offsets",
        );
    }

    /// TxOutput serialize round-trip
    #[test]
    fn tx_output_round_trip() {
        let output = TxOutput::new(100_000_000_000, [0xab; 32]); // 100 XMR
        let bytes = output.serialize();
        let mut pos = 0;
        let parsed = TxOutput::deserialize(&bytes, &mut pos).unwrap();
        assert_eq!(parsed, output);
        assert_eq!(parsed.output_type, out_type::TX_OUT_TO_KEY);
        assert_eq!(pos, bytes.len());
    }

    /// TxOutput tagged (subaddress)
    #[test]
    fn tx_output_tagged() {
        let output = TxOutput::new_tagged(50_000_000_000, [0xcd; 32], 0xab);
        assert_eq!(output.output_type, out_type::TX_OUT_TO_TAGGED_KEY);
        assert_eq!(output.view_tag, Some(0xab));
        let bytes = output.serialize();
        assert_eq!(bytes[bytes.len() - 1], 0xab);
        let mut pos = 0;
        let parsed = TxOutput::deserialize(&bytes, &mut pos).unwrap();
        assert_eq!(parsed, output);
    }

    /// TxExtra with tx_pub_key + additional pub_keys
    #[test]
    fn tx_extra_round_trip() {
        let extra = TxExtra::new()
            .with_tx_pub_key([0xab; 32])
            .with_additional_pub_key([0xcd; 32])
            .and_then(|e| e.with_additional_pub_key([0xef; 32]))
            .unwrap();
        let bytes = extra.serialize();
        let mut pos = 0;
        let parsed = TxExtra::deserialize(&bytes, &mut pos).unwrap();
        assert_eq!(parsed, extra);
        assert_eq!(pos, bytes.len());
    }

    #[test]
    fn tx_extra_encrypted_payment_id_round_trip() {
        let extra = TxExtra::new()
            .with_tx_pub_key([0x11; 32])
            .with_encrypted_payment_id([0x42; 8]);
        let bytes = extra.serialize();
        let mut pos = 0;
        let parsed = TxExtra::deserialize(&bytes, &mut pos).unwrap();
        assert_eq!(parsed.encrypted_payment_id, Some([0x42; 8]));
        assert!(parsed.payment_id.is_none());
    }

    /// TransactionPrefix round-trip
    #[test]
    fn tx_prefix_round_trip() {
        let prefix = TransactionPrefix::new(
            100, // unlock_time = block 100
            vec![
                TxInput {
                    key_offsets: heapless::Vec::from_slice(&[1, 2, 3]).unwrap(),
                    key_image: [0x11; 32],
                },
                TxInput {
                    key_offsets: heapless::Vec::from_slice(&[4, 5, 6]).unwrap(),
                    key_image: [0x22; 32],
                },
            ],
            vec![
                TxOutput::new(50_000_000_000, [0x33; 32]),
                TxOutput::new(50_000_000_000, [0x44; 32]),
            ],
            TxExtra::new().with_tx_pub_key([0x55; 32]),
        );
        let bytes = prefix.serialize();
        let mut pos = 0;
        let parsed = TransactionPrefix::deserialize(&bytes, &mut pos).unwrap();
        assert_eq!(parsed, prefix);
        assert_eq!(pos, bytes.len());
    }

    /// Transaction (no RCT) round-trip
    #[test]
    fn tx_round_trip_no_rct() {
        let prefix = TransactionPrefix::new(
            0,
            vec![TxInput {
                key_offsets: heapless::Vec::from_slice(&[1]).unwrap(),
                key_image: [0x42; 32],
            }],
            vec![TxOutput::new(1000, [0xab; 32])],
            TxExtra::new().with_tx_pub_key([0xcd; 32]),
        );
        let tx = Transaction::new(prefix);
        let bytes = tx.serialize();
        let mut pos = 0;
        let parsed = Transaction::deserialize(&bytes, &mut pos).unwrap();
        assert_eq!(parsed, tx);
        assert_eq!(parsed.rct_signatures.len(), 0);
    }

    /// Out-of-bounds error handling
    #[test]
    fn tx_empty_deserialize() {
        let bytes = [];
        let mut pos = 0;
        assert!(TransactionPrefix::deserialize(&bytes, &mut pos).is_err());
    }

    /// invalid version
    #[test]
    fn tx_invalid_version() {
        let bytes = vec![0x01]; // version 1 = pre-RingCT, deprecated
        let mut pos = 0;
        assert!(TransactionPrefix::deserialize(&bytes, &mut pos).is_err());
    }

    /// Key image construction
    #[test]
    fn key_image_construction() {
        // dummy spend key (32 bytes)
        let spend_key = [0x42u8; 32];
        let ki = construct_key_image(&spend_key).unwrap();
        assert_eq!(ki.len(), 32);
        eprintln!("key_image: {}", hex_encode(&ki));
    }

    /// shlosilo Scalar → monero-ed25519 Scalar bridge
    #[test]
    fn scalar_bridge() {
        // Use reduce_scalar to ensure the bytes are a reduced scalar
        // (otherwise monero-ed25519 Scalar::read fails: "unreduced scalar")
        use crate::chain::xmr::reduce_scalar::reduce_scalar;
        let shlosilo_scalar = reduce_scalar(&[0x33u8; 32]).unwrap();
        let monerod_scalar = shlosilo_scalar_to_monerod(&shlosilo_scalar);
        let bytes = monerod_scalar_to_bytes(&monerod_scalar);
        // the bytes should equal the shlosilo scalar's 32-byte representation
        let shlosilo_bytes = crate::curve_primitive::ed25519::scalar_to_bytes(&shlosilo_scalar);
        assert_eq!(bytes, shlosilo_bytes);
    }

    /// Encoded prefix byte structure sanity check
    #[test]
    fn prefix_byte_structure() {
        let prefix = TransactionPrefix::new(0, vec![], vec![], TxExtra::new());
        let bytes = prefix.serialize();
        // byte 0: version = 2
        assert_eq!(bytes[0], TX_VERSION);
        // byte 1: varint(unlock_time) = 0
        assert_eq!(bytes[1], 0);
        // byte 2: varint(input_count) = 0
        assert_eq!(bytes[2], 0);
        // byte 3: varint(output_count) = 0
        assert_eq!(bytes[3], 0);
        // byte 4: varint(extra_size) = 0
        assert_eq!(bytes[4], 0);
        assert_eq!(bytes.len(), 5);
    }

    /// Z2.4d: `serialize_into` must be byte-identical to the alloc convenience.
    #[test]
    fn serialize_into_matches_convenience() {
        let mut offs = heapless::Vec::new();
        offs.push(0).unwrap();
        offs.push(300).unwrap();
        let input = TxInput::new(offs, [7u8; 32]);
        let output = TxOutput::new_tagged(12345, [9u8; 32], 0xab);
        let extra = TxExtra::new().with_encrypted_payment_id([5u8; 8]);
        let prefix = TransactionPrefix::new(
            7,
            alloc::vec![input.clone()],
            alloc::vec![output.clone()],
            extra.clone(),
        );

        let mut buf = [0u8; 1024];
        let mut n = 0;
        input.serialize_into(&mut buf, &mut n).unwrap();
        assert_eq!(&buf[..n], input.serialize().as_slice(), "TxInput");
        n = 0;
        output.serialize_into(&mut buf, &mut n).unwrap();
        assert_eq!(&buf[..n], output.serialize().as_slice(), "TxOutput");
        n = 0;
        extra.serialize_into(&mut buf, &mut n).unwrap();
        assert_eq!(&buf[..n], extra.serialize().as_slice(), "TxExtra");
        n = 0;
        prefix.serialize_into(&mut buf, &mut n).unwrap();
        assert_eq!(
            &buf[..n],
            prefix.serialize().as_slice(),
            "TransactionPrefix"
        );
    }
}
