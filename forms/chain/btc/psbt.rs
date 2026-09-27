//! BTC PSBT (Partially Signed Bitcoin Transaction, BIP-174) parsing, signing, serialization
//!
//! **Format overview**:
//! ```text
//! magic: 0x70 0x73 0x62 0x74 0xff  ("psbt" + 0xff)
//! <global-map>     0x00   separator
//! <input-map>*     0x00   separator (one pair per input)
//! <output-map>*    0x00   separator (one pair per output)
//! ```
//!
//! **key-value encoding**: `<keylen><key><valuelen><value>` (compact size varint)
//! - key = `<type-byte><data>` (type-byte 0x00 = separator, value-length is always 0)
//! - value = `<data>`
//!
//! **Key BIP-174 fields** (this implementation covers the minimal P2WPKH 1-input 1-output case):
//!
//! | Type | Field | Scope |
//! |---|---|---|
//! | 0x00 | PSBT_GLOBAL_UNSIGNED_TX | Global |
//! | 0x01 | PSBT_IN_NON_WITNESS_UTXO | Input (legacy) |
//! | 0x02 | PSBT_IN_WITNESS_UTXO | Input (segwit) |
//! | 0x03 | PSBT_IN_PARTIAL_SIG | Input (signature contributed by the signer) |
//! | 0x04 | PSBT_IN_SIGHASH_TYPE | Input (sighash flag) |
//! | 0x05 | PSBT_IN_REDEEM_SCRIPT | Input (P2SH redeemScript) |
//! | 0x06 | PSBT_IN_WITNESS_SCRIPT | Input (P2WSH witnessScript) |
//! | 0x07 | PSBT_IN_BIP32_DERIVATION | Input (HD keypath) |
//! | 0x08 | PSBT_IN_SCRIPTSIG | Input (final scriptSig) |
//! | 0x09 | PSBT_IN_SCRIPTWITNESS | Input (final witness) |
//! | 0x00 | PSBT_GLOBAL_UNSIGNED_TX | Global |
//!
//! **Algorithm**:
//! 1. Parse magic + global-map + each input/output map
//! 2. Locate the input to sign (by witness_utxo or non_witness_utxo)
//! 3. Call the v9.3 sign function (P2WPKH / P2PKH / P2SH-P2WPKH)
//! 4. Inject the signature into the input map: `0x03 || {pubkey} → {DER-sig + sighash-byte}`
//! 5. Serialize the final PSBT
//!
//! **Reference**: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

extern crate alloc;
use alloc::borrow::Cow;
use alloc::vec;
use alloc::vec::Vec;

use crate::chain::btc::p2pkh::sign_p2pkh;
use crate::chain::btc::p2sh::sign_p2sh_p2wpkh;
#[cfg(test)]
use crate::chain::btc::p2wpkh::bt_vec;
use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut};
use crate::encoding::sha256;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::types::push::{CountSink, Sink, SinkCursor};
use crate::types::SecretBytes;

/// PSBT magic bytes: "psbt" + 0xff
pub const PSBT_MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

/// Global map types (BIP-174)
pub mod global_type {
    pub const UNSIGNED_TX: u8 = 0x00;
}

#[allow(dead_code)] // BIP-174 constant set = full contract documentation, not all used
pub(crate) mod input_type {
    //! BIP-174 standard input type numbers.
    //! P6.3 audit fix (2026-08-26): the original constants were all shifted by +1 (NON_WITNESS_UTXO=0x01 etc.),
    //! so they were totally misaligned when interoperating with external implementations like Sparrow/bitcoind — exposed by the real fixture test.psbt.

    pub(crate) const NON_WITNESS_UTXO: u8 = 0x00;
    pub(crate) const WITNESS_UTXO: u8 = 0x01;
    pub(crate) const PARTIAL_SIG: u8 = 0x02;
    pub(crate) const SIGHASH_TYPE: u8 = 0x03;
    pub(crate) const REDEEM_SCRIPT: u8 = 0x04;
    pub(crate) const WITNESS_SCRIPT: u8 = 0x05;
    pub(crate) const BIP32_DERIVATION: u8 = 0x06;
    /// Final scriptSig (for legacy P2PKH + P2SH inputs)
    pub(crate) const FINAL_SCRIPT_SIG: u8 = 0x07;
    /// Final script Witness (for segwit P2WPKH/P2WSH inputs)
    pub(crate) const FINAL_SCRIPTWITNESS: u8 = 0x08;

    // === BIP-371 Taproot PSBT fields ===
    /// 0x13: Taproot key-path signature (key = [0x13], value = 64-byte Schnorr sig)
    pub(crate) const TAP_KEY_SIG: u8 = 0x13;
    /// 0x14: Taproot script-path signature (key = [0x14 || 32-byte leaf_hash], value = 64-byte Schnorr sig || 1-byte sighash)
    pub(crate) const TAP_SCRIPT_SIG: u8 = 0x14;
    /// 0x15: Taproot leaf scripts (key = [0x15 || 32-byte leaf_hash], value = [script || 1-byte leaf_version])
    pub(crate) const TAP_LEAF_SCRIPTS: u8 = 0x15;
    /// 0x16: Taproot BIP-32 derivation (key = [0x16 || 32-byte x-only pubkey], value = bip32 path + fingerprint)
    pub(crate) const TAP_BIP32_DERIVATION: u8 = 0x16;
    /// 0x17: Taproot internal key (key = [], value = 32-byte x-only internal pubkey)
    pub(crate) const TAP_INTERNAL_KEY: u8 = 0x17;
    /// 0x18: Taproot merkle root (key = [], value = 32-byte merkle root; empty = keypath-only)
    pub(crate) const TAP_MERKLE_ROOT: u8 = 0x18;
}

/// Output map types (BIP-174 + BIP-371)
#[allow(dead_code)]
pub(crate) mod output_type {
    pub(crate) const REDEEM_SCRIPT: u8 = 0x00;
    pub(crate) const WITNESS_SCRIPT: u8 = 0x01;
    pub(crate) const BIP32_DERIVATION: u8 = 0x02;

    // === BIP-371 Taproot PSBT output fields ===
    /// 0x65: Taproot internal key (key = [], value = 32-byte x-only internal pubkey)
    pub(crate) const TAP_INTERNAL_KEY: u8 = 0x65;
    /// 0x66: Taproot tree (key = [], value = taproot tree encoding)
    pub(crate) const TAP_TREE: u8 = 0x66;
}

/// Key-value pair in a PSBT map (read view).
///
/// Z4-7b: the map store is a flat pool (POD records + one byte arena, both
/// caller-provided — the SignWs carve in production). Entries are views minted
/// at read time; the Cow fields keep the historical `kv.key` / `kv.value`
/// call shapes working (parsed payloads Borrow, test literals Own).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyValue<'a> {
    pub key: Cow<'a, [u8]>,
    pub value: Cow<'a, [u8]>,
}

/// Z4-7b: one map record — payload offsets in the CONCATENATED address space
/// `[wire bytes][arena bytes]`: parse-time payloads point straight into the
/// wire (zero copies), sign-time additions land in the arena. `off < wire_len`
/// selects the space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KvRec {
    pub key: (u32, u32),
    pub value: (u32, u32),
}

impl KvRec {
    pub const EMPTY: Self = Self {
        key: (0, 0),
        value: (0, 0),
    };
}

/// One map entry as plain slices (the pool's 'a — never a reborrow of a
/// temporary Cow).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KvEntry<'a> {
    pub key: &'a [u8],
    pub value: &'a [u8],
}

/// Read view over one map: the pool backend (production) or a plain entry
/// slice (tests build ad-hoc maps without a pool).
#[derive(Clone, Copy)]
pub enum KvMap<'a> {
    Pool {
        wire: &'a [u8],
        arena: &'a [u8],
        recs: &'a [KvRec],
    },
    Slice(&'a [KeyValue<'a>]),
}

impl<'a> KvMap<'a> {
    /// Ad-hoc map from a plain entry slice (test surface).
    pub fn from_slice(entries: &'a [KeyValue<'a>]) -> Self {
        KvMap::Slice(entries)
    }

    fn pool_slice(wire: &'a [u8], arena: &'a [u8], r: (u32, u32)) -> &'a [u8] {
        let (off, len) = (r.0 as usize, r.1 as usize);
        if off < wire.len() {
            &wire[off..off + len]
        } else {
            let a = off - wire.len();
            &arena[a..a + len]
        }
    }

    pub fn len(&self) -> usize {
        match self {
            KvMap::Pool { recs, .. } => recs.len(),
            KvMap::Slice(e) => e.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = KvEntry<'a>> + '_ {
        let pool = match self {
            KvMap::Pool { wire, arena, recs } => Some((*wire, *arena, *recs)),
            KvMap::Slice(_) => None,
        };
        let slice = match self {
            KvMap::Slice(e) => Some(*e),
            KvMap::Pool { .. } => None,
        };
        pool.into_iter()
            .flat_map(move |(wire, arena, recs)| {
                recs.iter().map(move |r| KvEntry {
                    key: Self::pool_slice(wire, arena, r.key),
                    value: Self::pool_slice(wire, arena, r.value),
                })
            })
            .chain(slice.into_iter().flatten().map(|kv| KvEntry {
                key: kv.key.as_ref(),
                value: kv.value.as_ref(),
            }))
    }

    /// The value's bytes for `key` (one value per key — BIP-174).
    pub fn get(&self, key: &[u8]) -> Option<&'a [u8]> {
        self.iter().find(|e| e.key == key).map(|e| e.value)
    }
}

/// Z4-7b: the PSBT map pool — records + arena + the wire base. Logical map
/// order is `global, inputs…, outputs…`. Capacities are runtime queries
/// (`shlosilo_sign_ws_len`); over-cap is an explicit Err, never truncation.
pub const PSBT_MAPS_MAX: usize = 2 + 16 + 64;

pub struct MapPool<'a> {
    wire: &'a [u8],
    arena: &'a mut [u8],
    arena_used: usize,
    recs: &'a mut [KvRec],
    recs_len: usize,
    maps_started: usize,
    map_lens: [u16; PSBT_MAPS_MAX],
}

impl<'a> MapPool<'a> {
    pub fn new_in(wire: &'a [u8], arena: &'a mut [u8], recs: &'a mut [KvRec]) -> Self {
        Self {
            wire,
            arena,
            arena_used: 0,
            recs,
            recs_len: 0,
            maps_started: 0,
            map_lens: [0; PSBT_MAPS_MAX],
        }
    }

    /// Begin the next map in wire order; returns its index.
    fn start_map(&mut self) -> Result<usize> {
        if self.maps_started >= PSBT_MAPS_MAX {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let idx = self.maps_started;
        self.maps_started += 1;
        Ok(idx)
    }

    pub fn map_count(&self) -> usize {
        self.maps_started
    }

    pub fn map(&self, idx: usize) -> KvMap<'_> {
        let start: usize = self.map_lens[..idx].iter().map(|&l| l as usize).sum();
        let len = self.map_lens[idx] as usize;
        KvMap::Pool {
            wire: self.wire,
            arena: &self.arena[..self.arena_used],
            recs: &self.recs[start..start + len],
        }
    }

    /// Parse-time append (the caller performs the duplicate-key check).
    /// Payload bytes are NOT copied — the record points into the wire.
    fn push_wire(&mut self, idx: usize, key: &'a [u8], value: &'a [u8]) -> Result<()> {
        let cap = ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall);
        if self.recs_len >= self.recs.len() {
            return Err(cap);
        }
        let base = self.wire.len() as u32;
        let k_off = (key.as_ptr() as usize - self.wire.as_ptr() as usize) as u32;
        let v_off = (value.as_ptr() as usize - self.wire.as_ptr() as usize) as u32;
        debug_assert!(k_off < base && v_off < base);
        self.recs[self.recs_len] = KvRec {
            key: (k_off, key.len() as u32),
            value: (v_off, value.len() as u32),
        };
        self.recs_len += 1;
        self.map_lens[idx] += 1;
        Ok(())
    }

    /// Sign-time replace-or-append: payload bytes land in the arena.
    fn set_kv(&mut self, idx: usize, key: &[u8], value: &[u8]) -> Result<()> {
        let cap = ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall);
        let base = self.wire.len() as u32;
        let start: usize = self.map_lens[..idx].iter().map(|&l| l as usize).sum();
        let len = self.map_lens[idx] as usize;
        let place_key = |pool: &mut Self| -> Result<u32> {
            let off = base + pool.arena_used as u32;
            let end = pool.arena_used.checked_add(key.len()).ok_or(cap)?;
            pool.arena[pool.arena_used..end].copy_from_slice(key);
            pool.arena_used = end;
            Ok(off)
        };
        let place_val = |pool: &mut Self| -> Result<u32> {
            let off = base + pool.arena_used as u32;
            let end = pool.arena_used.checked_add(value.len()).ok_or(cap)?;
            pool.arena[pool.arena_used..end].copy_from_slice(value);
            pool.arena_used = end;
            Ok(off)
        };
        // replace an existing key in place (the old payload tail is abandoned —
        // arena space is not reclaimed; capacity is a deployment parameter)
        for i in start..start + len {
            let k = KvMap::pool_slice(self.wire, &self.arena[..self.arena_used], self.recs[i].key);
            if k == key {
                let k_off = place_key(self)?;
                let v_off = place_val(self)?;
                self.recs[i] = KvRec {
                    key: (k_off, key.len() as u32),
                    value: (v_off, value.len() as u32),
                };
                return Ok(());
            }
        }
        // append at the map's end (later records shift right)
        if self.recs_len >= self.recs.len() {
            return Err(cap);
        }
        let k_off = place_key(self)?;
        let v_off = place_val(self)?;
        let at = start + len;
        self.recs.copy_within(at..self.recs_len, at + 1);
        self.recs[at] = KvRec {
            key: (k_off, key.len() as u32),
            value: (v_off, value.len() as u32),
        };
        self.recs_len += 1;
        self.map_lens[idx] += 1;
        Ok(())
    }
}

/// The parsed PSBT: the unsigned tx plus its map pool.
pub struct Psbt<'a> {
    /// unsigned tx (index matches the input/output maps)
    pub unsigned_tx: Transaction<'a>,
    pool: MapPool<'a>,
}

impl<'a> Psbt<'a> {
    /// Read view over map `idx` (0 = global, then inputs, then outputs).
    pub fn map(&self, idx: usize) -> KvMap<'_> {
        self.pool.map(idx)
    }

    pub fn input_map(&self, i: usize) -> KvMap<'_> {
        self.pool.map(1 + i)
    }

    /// Bounds-checked read view (the old `psbt.inputs.get(i)` shape).
    pub fn input_map_checked(&self, i: usize) -> Option<KvMap<'_>> {
        (i < self.unsigned_tx.inputs.len()).then(|| self.input_map(i))
    }

    /// Bounds-checked read view (the old `psbt.outputs.get(i)` shape).
    pub fn output_map_checked(&self, i: usize) -> Option<KvMap<'_>> {
        (i < self.unsigned_tx.outputs.len()).then(|| self.output_map(i))
    }

    pub fn output_map(&self, i: usize) -> KvMap<'_> {
        self.pool.map(1 + self.unsigned_tx.inputs.len() + i)
    }

    /// Replace-or-append one entry of input map `i` (PSBT: one value per key).
    pub fn set_input_kv(&mut self, i: usize, key: &[u8], value: &[u8]) -> Result<()> {
        self.pool.set_kv(1 + i, key, value)
    }

    /// Replace-or-append one entry of output map `i`.
    pub fn set_output_kv(&mut self, i: usize, key: &[u8], value: &[u8]) -> Result<()> {
        let idx = 1 + self.unsigned_tx.inputs.len() + i;
        self.pool.set_kv(idx, key, value)
    }
}

/// Compact size varint encoding (Bitcoin protocol standard), into a sink.
/// Byte-identical to the legacy Vec form (the wire pins hold).
fn put_compact_size(sink: &mut impl Sink, n: u64) -> Result<()> {
    if n < 0xfd {
        sink.put_u8(n as u8)
    } else if n <= 0xffff {
        sink.put(&[0xfd])?;
        sink.put(&(n as u16).to_le_bytes())
    } else if n <= 0xffff_ffff {
        sink.put(&[0xfe])?;
        sink.put(&(n as u32).to_le_bytes())
    } else {
        sink.put(&[0xff])?;
        sink.put(&n.to_le_bytes())
    }
}

/// One map entry (keylen || key || valuelen || value).
fn write_kv<S: Sink>(sink: &mut S, key: &[u8], value: &[u8]) -> Result<()> {
    put_compact_size(sink, key.len() as u64)?;
    sink.put(key)?;
    put_compact_size(sink, value.len() as u64)?;
    sink.put(value)
}

/// Map entries + the 0x00 separator (keylen=0).
fn write_map_entries<S: Sink>(sink: &mut S, map: KvMap<'_>) -> Result<()> {
    for kv in map.iter() {
        write_kv(sink, kv.key, kv.value)?;
    }
    sink.put_u8(0x00)
}

/// P0-01 (2026-09-01 audit #4): PSBT parser resource budget.
///
/// The wire layer\'s CompactSize / element counts are all bounded by this limit — a malicious QR feeding
/// `0xff ‖ u64::MAX` must not trigger an addition-overflow panic (panic=abort on device = DoS)
/// or a `with_capacity(usize::MAX)` capacity-overflow abort.
/// The limit aligns with TxTemplate PAYLOAD_MAX (16 KiB; measured real PSBT is 12 KB) × 4 margin.
pub(crate) const PSBT_WIRE_MAX_LEN: u64 = 64 * 1024;

/// Compact size varint decoding (P0-01 hardened version)
///
/// - Length/count fields > `PSBT_WIRE_MAX_LEN` → error (overflow prevention + OOM preallocation prevention)
/// - Non-canonical encodings rejected (BIP-174/Bitcoin consensus convention: the value following a 0xfd/0xfe/0xff prefix
///   must be the minimal representation for that prefix, preventing parse ambiguity from multiple encodings of the same value)
///
/// Audit #6 re-review P2-01: the physical-feasibility check is extracted into a pure helper — tests can directly assert
/// "Err is returned before capacity is constructed", without relying on timing observation.
/// Minimum wire size per element + 4B locktime margin (inputs/outputs live at the tail of the same unsigned tx).
///
/// Audit #7 P2-01: narrowed to `pub(crate)` — `min_elem_bytes == 0` would panic with division by zero,
/// and a non-total boundary should not be exposed as a public Rust API (parser call sites always pass 41/9).
/// Zero-value semantics: any count > 0 is considered physically infeasible (saturating_sub followed by division by 0
/// panics under usize semantics; defended explicitly here).
pub(crate) fn count_physically_feasible(
    count: usize,
    remaining: usize,
    min_elem_bytes: usize,
) -> bool {
    if min_elem_bytes == 0 {
        return count == 0; // zero-element lower bound = undefined semantics, any non-zero count is infeasible
    }
    let wire_available = remaining.saturating_sub(4); // 4B reserved for locktime
    count <= wire_available / min_elem_bytes
}

fn decode_compact_size(bytes: &[u8], pos: &mut usize) -> Result<u64> {
    if *pos >= bytes.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let first = bytes[*pos];
    *pos += 1;
    match first {
        0xff => {
            if *pos + 8 > bytes.len() {
                return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            let n = u64::from_le_bytes(
                bytes[*pos..*pos + 8]
                    .try_into()
                    .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?,
            );
            *pos += 8;
            // Non-canonical: 8-byte encoding of the minimum value 0x1_0000_0000
            if n < 0x1_0000_0000 || n > PSBT_WIRE_MAX_LEN {
                return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            Ok(n)
        }
        0xfe => {
            if *pos + 4 > bytes.len() {
                return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            let n = u32::from_le_bytes(
                bytes[*pos..*pos + 4]
                    .try_into()
                    .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?,
            ) as u64;
            *pos += 4;
            // Non-canonical: 4-byte encoding of the minimum value 0x1_0000
            if n < 0x1_0000 || n > PSBT_WIRE_MAX_LEN {
                return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            Ok(n)
        }
        0xfd => {
            if *pos + 2 > bytes.len() {
                return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            let n = u16::from_le_bytes(
                bytes[*pos..*pos + 2]
                    .try_into()
                    .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?,
            ) as u64;
            *pos += 2;
            // Non-canonical: 2-byte encoding of the minimum value 0xfd
            if !(0xfd..=PSBT_WIRE_MAX_LEN).contains(&n) {
                return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            Ok(n)
        }
        n if n < 0xfd => Ok(n as u64),
        _ => Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)),
    }
}

/// P0-01: safely take `len` bytes from `bytes[*pos..]` — checked_add + a single bounds check,
/// replacing all bare `pos + len as usize > bytes.len()` checks (a malicious len = usize::MAX overflows and panics).
/// Advances `pos` on success.
fn take_bytes<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = pos
        .checked_add(len)
        .ok_or(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    if end > bytes.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let s = &bytes[*pos..end];
    *pos = end;
    Ok(s)
}

/// Write the unsigned tx (same as P2WPKH.legacy, without marker/flag).
fn write_unsigned_tx<S: Sink>(sink: &mut S, tx: &Transaction) -> Result<()> {
    sink.put(&tx.version.to_le_bytes())?;
    put_compact_size(sink, tx.inputs.len() as u64)?;
    for txin in &tx.inputs {
        sink.put(&txin.prev_out.txid)?;
        sink.put(&txin.prev_out.vout.to_le_bytes())?;
        put_compact_size(sink, txin.script_sig.len() as u64)?;
        sink.put(&txin.script_sig)?;
        sink.put(&txin.sequence.to_le_bytes())?;
    }
    put_compact_size(sink, tx.outputs.len() as u64)?;
    for txout in &tx.outputs {
        sink.put(&txout.value.to_le_bytes())?;
        put_compact_size(sink, txout.script_pubkey.len() as u64)?;
        sink.put(&txout.script_pubkey)?;
    }
    sink.put(&tx.lock_time.to_le_bytes())
}

/// One PSBT: magic || global map || input maps || output maps.
fn write_psbt<S: Sink>(sink: &mut S, psbt: &Psbt<'_>) -> Result<()> {
    sink.put(&PSBT_MAGIC)?;
    // global map: the UNSIGNED_TX entry (value = the serialized unsigned tx)
    put_compact_size(sink, 1)?;
    sink.put(&[global_type::UNSIGNED_TX])?;
    let mut len = CountSink(0);
    write_unsigned_tx(&mut len, &psbt.unsigned_tx)?;
    put_compact_size(sink, len.0 as u64)?;
    write_unsigned_tx(sink, &psbt.unsigned_tx)?;
    sink.put_u8(0x00)?;
    let n_in = psbt.unsigned_tx.inputs.len();
    let n_out = psbt.unsigned_tx.outputs.len();
    for i in 0..n_in {
        write_map_entries(sink, psbt.input_map(i))?;
    }
    for i in 0..n_out {
        write_map_entries(sink, psbt.output_map(i))?;
    }
    Ok(())
}

/// Deserialize unsigned tx (per PSBT format, without marker/flag/witness)
///
/// P0-01 hardening: all length/count fields are validated against the `decode_compact_size` budget,
/// byte fields are taken via `take_bytes` checked_add; counts are clamped before `with_capacity`.
fn deserialize_unsigned_tx(bytes: &[u8]) -> Result<Transaction<'_>> {
    let mut pos = 0;

    // version (4 bytes LE)
    if pos + 4 > bytes.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let version = i32::from_le_bytes(
        bytes[pos..pos + 4]
            .try_into()
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?,
    );
    pos += 4;

    // inputs count (P0-01: count fields bounded by the PSBT_WIRE_MAX_LEN budget)
    let n_inputs = decode_compact_size(bytes, &mut pos)?;
    if n_inputs > PSBT_WIRE_MAX_LEN {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    // Audit #5 P0-01 + #6 re-review P2-01: physical feasibility before allocation (pure helper, unit-testable)
    // Each input wire is at least 41B (txid 32 + vout 4 + script_sig_len >= 1 + seq 4)
    if !count_physically_feasible(n_inputs as usize, bytes.len() - pos, 41) {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut inputs = heapless::Vec::new();
    for _ in 0..n_inputs {
        // txid (32 bytes)
        let txid_bytes = take_bytes(bytes, &mut pos, 32)?;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(txid_bytes);

        // vout (4 bytes)
        let vout_bytes = take_bytes(bytes, &mut pos, 4)?;
        let vout = u32::from_le_bytes(
            vout_bytes
                .try_into()
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?,
        );

        // scriptSig len + bytes
        let script_sig_len = decode_compact_size(bytes, &mut pos)? as usize;
        let script_sig = Cow::Borrowed(take_bytes(bytes, &mut pos, script_sig_len)?);

        // sequence (4 bytes)
        let seq_bytes = take_bytes(bytes, &mut pos, 4)?;
        let sequence = u32::from_le_bytes(
            seq_bytes
                .try_into()
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?,
        );

        inputs
            .push(TxIn {
                prev_out: OutPoint { txid, vout },
                script_sig,
                sequence,
                witness: Vec::new(),
            })
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    }

    // outputs count
    let n_outputs = decode_compact_size(bytes, &mut pos)?;
    if n_outputs > PSBT_WIRE_MAX_LEN {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    // Audit #5 P0-01 + #6 re-review P2-02: same inputs, 9B each (value 8 + spk_len >= 1),
    // the 4B locktime margin is reserved uniformly by the helper (re-review found outputs missing it)
    if !count_physically_feasible(n_outputs as usize, bytes.len() - pos, 9) {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut outputs = heapless::Vec::new();
    for _ in 0..n_outputs {
        // value (8 bytes)
        let value_bytes = take_bytes(bytes, &mut pos, 8)?;
        let value = u64::from_le_bytes(
            value_bytes
                .try_into()
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?,
        );

        // scriptPubKey len + bytes
        let script_pubkey_len = decode_compact_size(bytes, &mut pos)? as usize;
        let script_pubkey = Cow::Borrowed(take_bytes(bytes, &mut pos, script_pubkey_len)?);

        outputs
            .push(TxOut {
                value,
                script_pubkey,
            })
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    }

    // lock_time (4 bytes)
    let lock_bytes = take_bytes(bytes, &mut pos, 4)?;
    let lock_time = u32::from_le_bytes(
        lock_bytes
            .try_into()
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?,
    );

    // Audit #5 P0-02: exact-consumption — the unsigned tx must be consumed exactly,
    // embedded trailing data = hidden semantics (sighash preimage may diverge from the wire)
    if pos != bytes.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    Ok(Transaction {
        version,
        inputs,
        outputs,
        lock_time,
    })
}

/// Parse one encoded map (until separator 0x00) straight into the pool.
///
/// P0-01 hardening: key/value lengths are taken via `take_bytes` checked_add;
/// map entry count is implicitly bounded by bytes.len() (at least 2B per entry).
/// Audit #5 P0-02: **duplicate key rejection** — BIP-174 is one value per key;
/// duplicates are a parser differential vector (first-wins/last-wins).
///
/// Returns the wire slice of the UNSIGNED_TX value when present (map 0) —
/// the tx model borrows the WIRE, never the arena.
fn decode_map_into<'a>(
    pool: &mut MapPool<'a>,
    bytes: &'a [u8],
    pos: &mut usize,
) -> Result<Option<&'a [u8]>> {
    let idx = pool.start_map()?;
    let mut tx_value = None;
    loop {
        if *pos >= bytes.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        // keylen
        let key_len = decode_compact_size(bytes, pos)? as usize;
        if key_len == 0 {
            // separator (0x00 key)
            return Ok(tx_value);
        }
        let key = take_bytes(bytes, pos, key_len)?;
        // valuelen
        let value_len = decode_compact_size(bytes, pos)? as usize;
        let value = take_bytes(bytes, pos, value_len)?;
        // Audit #5: stably reject duplicate keys
        if pool.map(idx).iter().any(|kv| kv.key == key) {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        if idx == 0 && key == &[global_type::UNSIGNED_TX][..] {
            tx_value = Some(value);
        }
        pool.push_wire(idx, key, value)?;
    }
}

/// Test/legacy convenience capacities for the leaking parse below.
const PSBT_TEST_ARENA: usize = 64 * 1024;
const PSBT_TEST_RECS: usize = 128;

/// Parse PSBT bytes into a caller-provided pool — production passes the
/// SignWs carve; tests pass local storage. Same API either way.
///
/// Audit #5 P0-02: exact-consumption — the whole PSBT must be consumed
/// exactly, trailing data = invalid input (may carry unparsed hidden
/// semantics).
pub fn parse_psbt_into<'a>(
    bytes: &'a [u8],
    arena: &'a mut [u8],
    recs: &'a mut [KvRec],
) -> Result<Psbt<'a>> {
    if bytes.len() < 5 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    if bytes[..5] != PSBT_MAGIC {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut pos = 5;
    let mut pool = MapPool::new_in(bytes, arena, recs);

    // global map: carries the unsigned tx (borrowed from the wire)
    let tx_wire = decode_map_into(&mut pool, bytes, &mut pos)?
        .ok_or(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let unsigned_tx = deserialize_unsigned_tx(tx_wire)?;

    // input maps / output maps
    for _ in 0..unsigned_tx.inputs.len() {
        decode_map_into(&mut pool, bytes, &mut pos)?;
    }
    for _ in 0..unsigned_tx.outputs.len() {
        decode_map_into(&mut pool, bytes, &mut pos)?;
    }

    // Audit #5 P0-02: exact-consumption
    if pos != bytes.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    Ok(Psbt { unsigned_tx, pool })
}

/// Test/legacy convenience: build a Psbt from owned map vectors over LEAKED
/// pool storage (the historical `Psbt { inputs: vec![...], outputs: ... }`
/// literal shape). Production parses via `parse_psbt_into` with caller
/// storage. Over-cap panics loudly (test surface only).
pub fn psbt_from_maps_leaky<'a>(
    unsigned_tx: Transaction<'a>,
    inputs: &[Vec<KeyValue<'a>>],
    outputs: &[Vec<KeyValue<'a>>],
) -> Psbt<'a> {
    let arena: &'static mut [u8] =
        alloc::boxed::Box::leak(alloc::vec![0u8; PSBT_TEST_ARENA].into_boxed_slice());
    let recs: &'static mut [KvRec] =
        alloc::boxed::Box::leak(alloc::vec![KvRec::EMPTY; PSBT_TEST_RECS].into_boxed_slice());
    let pool = MapPool::new_in(&[], arena, recs);
    let mut psbt = Psbt { unsigned_tx, pool };
    for (i, m) in inputs.iter().enumerate() {
        for kv in m {
            psbt.set_input_kv(i, kv.key.as_ref(), kv.value.as_ref())
                .expect("test psbt over pool capacity");
        }
    }
    for (i, m) in outputs.iter().enumerate() {
        for kv in m {
            psbt.set_output_kv(i, kv.key.as_ref(), kv.value.as_ref())
                .expect("test psbt over pool capacity");
        }
    }
    psbt
}

/// Test convenience: a LEAKING parse — the pool storage is allocated and
/// never freed. Production MUST pass caller storage via `parse_psbt_into`
/// (the SignWs carve).
pub fn parse_psbt(bytes: &[u8]) -> Result<Psbt<'_>> {
    let arena: &'static mut [u8] =
        alloc::boxed::Box::leak(alloc::vec![0u8; PSBT_TEST_ARENA].into_boxed_slice());
    let recs: &'static mut [KvRec] =
        alloc::boxed::Box::leak(alloc::vec![KvRec::EMPTY; PSBT_TEST_RECS].into_boxed_slice());
    parse_psbt_into(bytes, arena, recs)
}

/// Serialized length — the SAME writer body over an infallible counting
/// sink (no twin length formula to drift).
pub fn serialize_psbt_len(psbt: &Psbt<'_>) -> usize {
    let mut len = CountSink(0);
    write_psbt(&mut len, psbt).expect("counting sink is infallible");
    len.0
}

/// Serialize into a caller buffer; over-capacity is an EXPLICIT error carrying
/// the required length (same shape as the legacy Vec form produced).
pub fn serialize_psbt_into(psbt: &Psbt<'_>, out: &mut [u8]) -> Result<usize> {
    let need = serialize_psbt_len(psbt);
    if out.len() < need {
        return Err(ShlosiloError::with_context(
            ShlosiloErrorKind::BufferTooSmall,
            crate::error::ErrorContext::RequiredLength(need),
        ));
    }
    let mut sink = SinkCursor::new(out);
    write_psbt(&mut sink, psbt)?;
    Ok(sink.pos())
}

/// Test/staging convenience: one sized allocation, same bytes.
pub fn serialize_psbt(psbt: &Psbt<'_>) -> Vec<u8> {
    let mut out = vec![0u8; serialize_psbt_len(psbt)];
    let n = serialize_psbt_into(psbt, &mut out).expect("sized buffer");
    out.truncate(n);
    out
}

/// PSBT signing input (per-input info)
///
/// P1-03: the private key uses `SecretBytes<32>` — no Clone or Debug, ZeroizeOnDrop, constant-time comparison.
pub struct PsbtSignInput {
    /// input index
    pub input_index: usize,
    /// The private key for this input (32 bytes)
    pub private_key: SecretBytes<32>,
    /// pubkey hash (20 bytes) — P2WPKH witness program
    pub pubkey_hash: [u8; 20],
    /// The value of this input (satoshis) — used for the BIP-143 sighash
    pub amount: u64,
}

/// Sign a PSBT P2WPKH input
///
/// Inject into the input map:
/// - 0x03 PARTIAL_SIG: key = `<type-byte 0x03><33-byte compressed pubkey>`, value = `<DER-sig + 0x01 sighash-byte>`
pub fn sign_psbt_p2wpkh(psbt: &mut Psbt<'_>, sign_input: &PsbtSignInput) -> Result<()> {
    let input_idx = sign_input.input_index;
    if input_idx >= psbt.unsigned_tx.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // 2. Z4-3: sign against the unsigned tx READ-ONLY — no clone, no witness
    // staging, no signed-tx serialization (the old flow built all three and
    // threw them away).
    let p2wpkh_input = crate::chain::btc::p2wpkh::P2WPKHSignInput {
        input_index: sign_input.input_index,
        private_key: &sign_input.private_key,
        amount: sign_input.amount,
        pubkey_hash: sign_input.pubkey_hash,
    };
    let (sig_with_sighash, compressed_pk) =
        crate::chain::btc::p2wpkh::sign_p2wpkh_core(&psbt.unsigned_tx, &p2wpkh_input)?;

    // 3. PARTIAL_SIG key = `<0x03><compressed-pubkey>`
    let mut key = Vec::with_capacity(1 + 33);
    key.push(input_type::PARTIAL_SIG);
    key.extend_from_slice(&compressed_pk);

    // value = `<DER-sig + 0x01>`
    let value = sig_with_sighash.to_vec();

    psbt.set_input_kv(input_idx, &key, &value)?;

    Ok(())
}

/// PSBT signing input (P2PKH-specific, no amount needed)
///
/// P1-03: the private key uses `SecretBytes<32>`.
pub struct PsbtP2PKHSignInput {
    pub input_index: usize,
    pub private_key: SecretBytes<32>,
    pub pubkey_hash: [u8; 20],
}

/// PSBT signing input (P2SH-P2WPKH-specific, needs amount)
///
/// P1-03: the private key uses `SecretBytes<32>`.
pub struct PsbtP2SHP2WPKHSignInput {
    pub input_index: usize,
    pub private_key: SecretBytes<32>,
    pub pubkey_hash: [u8; 20],
    pub amount: u64,
}

/// Sign a PSBT P2PKH input
///
/// Unlike P2WPKH: injects FINAL_SCRIPT_SIG (type 0x08) instead of PARTIAL_SIG.
/// The Finalizer extracts FINAL_SCRIPT_SIG into tx.inputs[].scriptSig (final tx).
pub fn sign_psbt_p2pkh(psbt: &mut Psbt<'_>, sign_input: &PsbtP2PKHSignInput) -> Result<()> {
    let input_idx = sign_input.input_index;
    if input_idx >= psbt.unsigned_tx.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // 1. Clone the unsigned tx for sighash computation + scriptSig injection
    let mut tx = psbt.unsigned_tx.clone();

    // 2. Call the v9.3 sign_p2pkh
    let p2pkh_input = crate::chain::btc::p2pkh::P2PKHSignInput {
        input_index: sign_input.input_index,
        private_key: &sign_input.private_key,
        pubkey_hash: sign_input.pubkey_hash,
    };
    let _signed = sign_p2pkh(&mut tx, &p2pkh_input)?;

    // 3. Extract scriptSig → inject FINAL_SCRIPT_SIG (0x08)
    let script_sig = tx.inputs[input_idx].script_sig.clone();

    let key = vec![input_type::FINAL_SCRIPT_SIG];
    let value = script_sig;

    psbt.set_input_kv(input_idx, &key, &value)?;

    Ok(())
}

/// Sign a PSBT P2SH-P2WPKH input
///
/// Inject:
/// - FINAL_SCRIPT_SIG (0x08) = push 22-byte redeemScript
/// - FINAL_SCRIPTWITNESS (0x09) = serialized witness (item count + items)
///
/// Note: FINAL_SCRIPTWITNESS uses the special BIP-174 format; the value is already-serialized witness bytes.
/// shlosilo reuses the witness output (vec![sig, pk]) of the v9.3 sign_p2sh_p2wpkh.
pub fn sign_psbt_p2sh_p2wpkh(
    psbt: &mut Psbt<'_>,
    sign_input: &PsbtP2SHP2WPKHSignInput,
) -> Result<()> {
    let input_idx = sign_input.input_index;
    if input_idx >= psbt.unsigned_tx.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // 1. Clone the unsigned tx
    let mut tx = psbt.unsigned_tx.clone();

    // 2. Call the v9.3 sign_p2sh_p2wpkh
    let p2sh_input = crate::chain::btc::p2sh::P2SHP2WPKHSignInput {
        input_index: sign_input.input_index,
        private_key: &sign_input.private_key,
        pubkey_hash: sign_input.pubkey_hash,
        amount: sign_input.amount,
    };
    let _signed = sign_p2sh_p2wpkh(&mut tx, &p2sh_input)?;

    // 3. Extract scriptSig → FINAL_SCRIPT_SIG
    let script_sig = tx.inputs[input_idx].script_sig.clone();
    let key_script_sig = vec![input_type::FINAL_SCRIPT_SIG];
    let value_script_sig = script_sig;

    // 4. Extract witness → FINAL_SCRIPTWITNESS (serialize witness as bytes)
    let witness = &tx.inputs[input_idx].witness;
    let mut witness_bytes = Vec::new();
    put_compact_size(&mut witness_bytes, witness.len() as u64)?;
    for item in witness {
        put_compact_size(&mut witness_bytes, item.len() as u64)?;
        witness_bytes.extend_from_slice(item);
    }

    let key_witness = vec![input_type::FINAL_SCRIPTWITNESS];
    let value_witness = witness_bytes;

    // 5. Inject into the PSBT input map
    psbt.set_input_kv(input_idx, &key_script_sig, &value_script_sig)?;
    psbt.set_input_kv(input_idx, &key_witness, &value_witness)?;

    Ok(())
}

// === v9.9 P2TR PSBT helpers (BIP-371) ===

/// P2TR sign input (keypath-only)
#[derive(Clone, Debug)]
pub struct PsbtP2TRSignInput {
    pub input_index: usize,
    pub internal_key_x: [u8; 32],
    pub tweaked_schnorr_sig: [u8; 64],
}

/// P2TR sign input (scriptpath)
#[derive(Clone, Debug)]
pub struct PsbtP2TRScriptPathSignInput {
    pub input_index: usize,
    pub internal_key_x: [u8; 32],
    pub leaf_hash: [u8; 32],
    pub schnorr_sig: [u8; 64],
    pub sighash_type: u8,
}

/// Sign PSBT P2TR input (BIP-371 keypath-only).
/// Caller provides pre-computed tweaked Schnorr signature.
/// Injects PSBT_IN_TAP_KEY_SIG (0x13) into input map.
pub fn sign_psbt_p2tr_keypath(psbt: &mut Psbt<'_>, sign_input: &PsbtP2TRSignInput) -> Result<()> {
    let input_idx = sign_input.input_index;
    if input_idx >= psbt.unsigned_tx.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // Verify scriptPubKey of the matching UTXO is a P2TR (OP_1 <0x20> <32-byte-x>).
    // WITNESS_UTXO value = CTxOut: amount(8 LE) || varint(spk_len) || scriptPubKey
    // Audit #5 open-01: utxo retrieval with prev_out binding (txid verification on the NON_WITNESS_UTXO path)
    let prev_out = psbt.unsigned_tx.inputs[input_idx].prev_out.clone();
    let (_amount, spk) = get_utxo_any(psbt.input_map(input_idx), &prev_out)
        .ok_or(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    if decode_p2tr_script_pubkey(&spk).is_err() {
        // 0x51 = OP_1 (witness v1), 0x20 = push 32 bytes
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // Inject TAP_KEY_SIG (0x13) — key = [0x13], value = 64-byte sig
    let key = vec![input_type::TAP_KEY_SIG];
    let value = sign_input.tweaked_schnorr_sig.to_vec();

    // Remove any pre-existing entry
    psbt.set_input_kv(input_idx, &key, &value)?;
    Ok(())
}

/// Sign PSBT P2TR input (BIP-371 scriptpath).
/// Caller provides Schnorr signature for a specific leaf.
/// Injects PSBT_IN_TAP_SCRIPT_SIG (0x14) with key = [0x14 || leaf_hash (32 bytes)].
pub fn sign_psbt_p2tr_scriptpath(
    psbt: &mut Psbt,
    sign_input: &PsbtP2TRScriptPathSignInput,
) -> Result<()> {
    let input_idx = sign_input.input_index;
    if input_idx >= psbt.unsigned_tx.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // Verify scriptPubKey is P2TR. WITNESS_UTXO value = CTxOut format.
    // Audit #5 open-01: utxo retrieval with prev_out binding (txid verification on the NON_WITNESS_UTXO path)
    let prev_out = psbt.unsigned_tx.inputs[input_idx].prev_out.clone();
    let (_amount, spk) = get_utxo_any(psbt.input_map(input_idx), &prev_out)
        .ok_or(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    if decode_p2tr_script_pubkey(&spk).is_err() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // Inject TAP_SCRIPT_SIG (0x14): key = [0x14 || leaf_hash (32)], value = sig(64) || sighash_byte(1)
    let mut key = Vec::with_capacity(33);
    key.push(input_type::TAP_SCRIPT_SIG);
    key.extend_from_slice(&sign_input.leaf_hash);

    let mut value = Vec::with_capacity(65);
    value.extend_from_slice(&sign_input.schnorr_sig);
    value.push(sign_input.sighash_type);

    psbt.set_input_kv(input_idx, &key, &value)?;
    Ok(())
}

/// Decode P2TR scriptPubKey: returns x-only output key (32 bytes)
pub fn decode_p2tr_script_pubkey(script_pubkey: &[u8]) -> Result<[u8; 32]> {
    if script_pubkey.len() != 34 || script_pubkey[0] != 0x51 || script_pubkey[1] != 0x20 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut x = [0u8; 32];
    x.copy_from_slice(&script_pubkey[2..]);
    Ok(x)
}

/// Parse a BIP-174 WITNESS_UTXO value: CTxOut format
/// `<amount (8B LE)> <compact_size spk_len> <scriptPubKey>`
///
/// **Note**: v9.9 once implemented this wrongly as direct concatenation of `amount || spk` (missing the varint length prefix);
/// a real keystone PSBT caught this bug.
///
/// P0-01 hardening (2026-09-01 audit #4): `spk_len` is validated against the budget via
/// decode_compact_size + taken via take_bytes checked_add — the original bare
/// `pos + spk_len` addition overflows and panics on `amount || 0xff || u64::MAX`
/// input (on device = malicious QR DoS).
pub fn decode_witness_utxo<'a>(value: &'a [u8]) -> Result<(u64, Cow<'a, [u8]>)> {
    if value.len() < 8 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let amount = u64::from_le_bytes(
        value[..8]
            .try_into()
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?,
    );
    let mut pos = 8;
    let spk_len = decode_compact_size(value, &mut pos)? as usize;
    let spk = take_bytes(value, &mut pos, spk_len)?;
    // Audit #5 P0-02: exact-consumption — the CTxOut value must be consumed exactly,
    // trailing bytes = non-canonical encoding (tests previously wrongly defined it as "should be accepted")
    if pos != value.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    Ok((amount, Cow::Borrowed(spk)))
}

/// Audit #5 open-01: parse the full transaction of NON_WITNESS_UTXO per BIP-174 semantics:
/// (1) deserialize the full tx (legacy format, no witness — PSBT stores the non-witness serialization)
/// (2) compute txid = dsha256(serialized) (3) compare with OutPoint.txid
/// (4) take CTxOut indexed by vout. Any step failing → None (refuse to sign that input).
fn get_non_witness_utxo_bound<'a>(
    input_map: KvMap<'a>,
    prev_out: &OutPoint,
) -> Option<(u64, Cow<'a, [u8]>)> {
    let value = input_map.get(&[input_type::NON_WITNESS_UTXO])?;
    let full_tx = deserialize_unsigned_tx(value).ok()?;

    // txid binding: serialize back (using the same legacy serialization) → dsha256
    let mut ser = Vec::new();
    write_unsigned_tx(&mut ser, &full_tx).ok()?;
    let txid: [u8; 32] = sha256::hash_twice(&ser).ok()?;

    if txid != prev_out.txid {
        return None; // a malicious full-tx claiming a UTXO that is not its own — reject
    }
    let txout = full_tx.outputs.get(prev_out.vout as usize)?;
    Some((txout.value, txout.script_pubkey.clone()))
}

/// Get the spent output (value, spk) from an input map's WITNESS_UTXO field
pub fn get_witness_utxo<'a>(input_map: KvMap<'a>) -> Option<(u64, Cow<'a, [u8]>)> {
    let value = input_map.get(&[input_type::WITNESS_UTXO])?;
    decode_witness_utxo(value).ok()
}

/// Get the spent output from WITNESS_UTXO (0x02, preferred) or NON_WITNESS_UTXO (0x01).
///
/// Audit #5 open-01: the NON_WITNESS_UTXO path follows BIP-174 semantics — full tx
/// parsing + txid binding + vout indexing, no longer blindly trusting a bare CTxOut as fallback.
/// (The non-standard CTxOut-in-0x01 form from the keystone fixture is no longer supported; affected tests
///   now use the standard WITNESS_UTXO form.)
pub fn get_utxo_any<'a>(input_map: KvMap<'a>, prev_out: &OutPoint) -> Option<(u64, Cow<'a, [u8]>)> {
    // Preferred: WITNESS_UTXO (standard path, CTxOut stored directly)
    if let Some(utxo) = get_witness_utxo(input_map) {
        return Some(utxo);
    }
    // NON_WITNESS_UTXO: full-tx + txid binding + vout indexing
    get_non_witness_utxo_bound(input_map, prev_out)
}

/// Get TAP_INTERNAL_KEY from input map (BIP-371 0x17)
pub fn get_tap_internal_key(input_map: KvMap<'_>) -> Option<[u8; 32]> {
    let kv = input_map
        .iter()
        .find(|kv| kv.key == vec![input_type::TAP_INTERNAL_KEY])?;
    if kv.value.len() != 32 {
        return None;
    }
    let mut x = [0u8; 32];
    x.copy_from_slice(kv.value);
    Some(x)
}

/// Set TAP_INTERNAL_KEY in input map
pub fn set_tap_internal_key(
    input_map: &mut Vec<KeyValue<'_>>,
    internal_key_x: &[u8; 32],
) -> Result<()> {
    let key = vec![input_type::TAP_INTERNAL_KEY];
    input_map.retain(|kv| kv.key != key);
    input_map.push(KeyValue {
        key: key.into(),
        value: internal_key_x.to_vec().into(),
    });
    Ok(())
}

/// Get TAP_MERKLE_ROOT from input map (BIP-371 0x18)
pub fn get_tap_merkle_root(input_map: KvMap<'_>) -> Option<[u8; 32]> {
    let kv = input_map
        .iter()
        .find(|kv| kv.key == vec![input_type::TAP_MERKLE_ROOT])?;
    if kv.value.len() != 32 {
        return None;
    }
    let mut x = [0u8; 32];
    x.copy_from_slice(kv.value);
    Some(x)
}

/// Check if input is P2TR (has P2TR witness UTXO and TAP_INTERNAL_KEY set)
/// WITNESS_UTXO value = CTxOut: amount(8 LE) || varint(spk_len) || scriptPubKey
pub fn is_p2tr_input(input_map: KvMap<'_>) -> bool {
    if get_tap_internal_key(input_map).is_none() {
        return false;
    }
    get_witness_utxo(input_map)
        .map(|(_amount, spk)| decode_p2tr_script_pubkey(&spk).is_ok())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::psbt_from_maps_leaky;
    use super::*;
    use alloc::string::String;
    extern crate std;
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

    fn hex_encode(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&alloc::format!("{:02x}", byte));
        }
        s
    }

    /// magic bytes correct
    #[test]
    fn magic_bytes() {
        assert_eq!(PSBT_MAGIC, [0x70, 0x73, 0x62, 0x74, 0xff]);
    }

    /// compact size round-trip
    #[test]
    fn compact_size_round_trip() {
        let mut out = Vec::new();
        put_compact_size(&mut out, 10).unwrap();
        assert_eq!(out, vec![10]);

        out.clear();
        put_compact_size(&mut out, 0xfd).unwrap();
        assert_eq!(out, vec![0xfd, 0xfd, 0x00]);

        out.clear();
        put_compact_size(&mut out, 0xffff).unwrap();
        assert_eq!(out, vec![0xfd, 0xff, 0xff]);

        out.clear();
        put_compact_size(&mut out, 0x10000).unwrap();
        assert_eq!(&out[..5], &[0xfe, 0x00, 0x00, 0x01, 0x00]);
    }

    /// Full PSBT construction (P2WPKH 1-input 1-output) round-trip
    #[test]
    fn psbt_construction_round_trip() {
        // Simplified P2WPKH test:
        // - 1 input, txid = 0xab...cd, vout = 0
        // - 1 output, value = 100_000, scriptPubKey = P2WPKH program
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        txid[31] = 0xcd;

        let txin = TxIn {
            prev_out: OutPoint { txid, vout: 0 },
            script_sig: vec![].into(),
            sequence: 0xffffffff,
            witness: vec![],
        };

        // P2WPKH scriptPubKey = `0x00 0x14 {20-byte pubkey-hash}`
        let mut pk_hash = [0u8; 20];
        pk_hash[0] = 0x42;
        let mut script_pubkey = Vec::with_capacity(22);
        script_pubkey.push(0x00);
        script_pubkey.push(0x14);
        script_pubkey.extend_from_slice(&pk_hash);

        let txout = TxOut {
            value: 100_000,
            script_pubkey: script_pubkey.into(),
        };

        let unsigned_tx = Transaction {
            version: 2,
            inputs: bt_vec![txin],
            outputs: bt_vec![txout],
            lock_time: 0,
        };

        let psbt = psbt_from_maps_leaky(unsigned_tx.clone(), &[Vec::new()], &[Vec::new()]);

        let bytes = serialize_psbt(&psbt);

        // Verify magic
        assert_eq!(&bytes[..5], &PSBT_MAGIC);

        // Parse back
        let parsed = parse_psbt(&bytes).unwrap();
        assert_eq!(parsed.unsigned_tx.version, unsigned_tx.version);
        assert_eq!(parsed.unsigned_tx.inputs.len(), 1);
        assert_eq!(parsed.unsigned_tx.outputs.len(), 1);
        assert_eq!(parsed.unsigned_tx.inputs[0].prev_out.txid, txid);
        assert_eq!(parsed.unsigned_tx.outputs[0].value, 100_000);
    }

    /// Parse error: magic
    #[test]
    fn psbt_invalid_magic() {
        let bytes = vec![0x00, 0x01, 0x02, 0x03, 0x04];
        assert!(parse_psbt(&bytes).is_err());
    }

    /// Full parse + serialize flow (including input/output map entries)
    #[test]
    fn psbt_full_round_trip() {
        let mut txid = [0u8; 32];
        txid[0] = 0x11;
        let txin = TxIn {
            prev_out: OutPoint { txid, vout: 1 },
            script_sig: vec![].into(),
            sequence: 0xffffffee,
            witness: vec![],
        };
        let mut pk_hash = [0u8; 20];
        pk_hash[0] = 0xab;
        let mut script_pubkey = Vec::with_capacity(22);
        script_pubkey.push(0x00);
        script_pubkey.push(0x14);
        script_pubkey.extend_from_slice(&pk_hash);

        let txout = TxOut {
            value: 50_000,
            script_pubkey: script_pubkey.into(),
        };

        let unsigned_tx = Transaction {
            version: 2,
            inputs: bt_vec![txin],
            outputs: bt_vec![txout],
            lock_time: 12345,
        };

        // Add witness_utxo to the input map
        let witness_utxo = TxOut {
            value: 200_000,
            script_pubkey: {
                let mut s = Vec::with_capacity(22);
                s.push(0x00);
                s.push(0x14);
                s.extend_from_slice(&pk_hash);
                s.into()
            },
        };
        let mut witness_utxo_bytes = Vec::new();
        witness_utxo_bytes.extend_from_slice(&witness_utxo.value.to_le_bytes());
        put_compact_size(
            &mut witness_utxo_bytes,
            witness_utxo.script_pubkey.len() as u64,
        )
        .unwrap();
        witness_utxo_bytes.extend_from_slice(&witness_utxo.script_pubkey);

        let psbt = psbt_from_maps_leaky(
            unsigned_tx.clone(),
            &[vec![KeyValue {
                key: vec![input_type::WITNESS_UTXO].into(),
                value: witness_utxo_bytes.into(),
            }]],
            &[Vec::new()],
        );

        let bytes = serialize_psbt(&psbt);
        let parsed = parse_psbt(&bytes).unwrap();

        // Verify the input map is preserved
        assert_eq!(parsed.unsigned_tx.inputs.len(), 1);
        assert!(parsed
            .input_map(0)
            .iter()
            .any(|kv| kv.key == vec![input_type::WITNESS_UTXO]));
    }

    /// Sign a P2WPKH PSBT input
    #[test]
    fn psbt_sign_p2wpkh() {
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        let txin = TxIn {
            prev_out: OutPoint { txid, vout: 0 },
            script_sig: vec![].into(),
            sequence: 0xffffffff,
            witness: vec![],
        };
        let mut pk_hash = [0u8; 20];
        pk_hash[0] = 0x42;
        let mut script_pubkey = Vec::with_capacity(22);
        script_pubkey.push(0x00);
        script_pubkey.push(0x14);
        script_pubkey.extend_from_slice(&pk_hash);
        let txout = TxOut {
            value: 100_000,
            script_pubkey: script_pubkey.into(),
        };

        let mut psbt = psbt_from_maps_leaky(
            Transaction {
                version: 2,
                inputs: bt_vec![txin],
                outputs: bt_vec![txout],
                lock_time: 0,
            },
            &[Vec::new()],
            &[Vec::new()],
        );

        let private_key_bytes =
            hex_decode("0101010101010101010101010101010101010101010101010101010101010101");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let sign_input = PsbtSignInput {
            input_index: 0,
            private_key,
            pubkey_hash: pk_hash,
            amount: 200_000,
        };

        sign_psbt_p2wpkh(&mut psbt, &sign_input).unwrap();

        // Verify PARTIAL_SIG is injected into the input map
        assert_eq!(psbt.unsigned_tx.inputs.len(), 1);
        let partial_sig = psbt
            .input_map(0)
            .iter()
            .find(|kv| kv.key.starts_with(&[input_type::PARTIAL_SIG]));
        assert!(partial_sig.is_some(), "PARTIAL_SIG must be injected");
        let partial_sig = partial_sig.unwrap();
        // key = 0x03 || compressed_pubkey
        assert_eq!(partial_sig.key[0], input_type::PARTIAL_SIG);
        assert_eq!(partial_sig.key.len(), 1 + 33);
        // The value must end with sighash byte 0x01
        assert_eq!(partial_sig.value[partial_sig.value.len() - 1], 0x01);

        eprintln!(
            "PARTIAL_SIG key: {} value: {}",
            hex_encode(partial_sig.key),
            hex_encode(partial_sig.value)
        );
    }

    /// Out-of-bounds input index
    #[test]
    fn psbt_sign_out_of_bounds() {
        let psbt = psbt_from_maps_leaky(
            Transaction {
                version: 1,
                inputs: bt_vec![],
                outputs: bt_vec![],
                lock_time: 0,
            },
            &[],
            &[],
        );
        let mut psbt = psbt;
        let sign_input = PsbtSignInput {
            input_index: 0,
            private_key: SecretBytes::new([0; 32]),
            pubkey_hash: [0; 20],
            amount: 0,
        };
        assert!(sign_psbt_p2wpkh(&mut psbt, &sign_input).is_err());
    }

    /// Sign a PSBT P2PKH input → FINAL_SCRIPT_SIG
    #[test]
    fn psbt_sign_p2pkh() {
        // Simplified P2PKH test
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        let txin = TxIn {
            prev_out: OutPoint { txid, vout: 0 },
            script_sig: vec![].into(),
            sequence: 0xffffffff,
            witness: vec![],
        };
        // P2PKH scriptPubKey = `0x76a914{20-byte pubkey-hash}88ac`
        let mut pk_hash = [0u8; 20];
        pk_hash[0] = 0x42;
        let mut script_pubkey = Vec::with_capacity(25);
        script_pubkey.push(0x76);
        script_pubkey.push(0xa9);
        script_pubkey.push(0x14);
        script_pubkey.extend_from_slice(&pk_hash);
        script_pubkey.push(0x88);
        script_pubkey.push(0xac);

        let txout = TxOut {
            value: 100_000,
            script_pubkey: script_pubkey.into(),
        };

        let mut psbt = psbt_from_maps_leaky(
            Transaction {
                version: 1,
                inputs: bt_vec![txin],
                outputs: bt_vec![txout],
                lock_time: 0,
            },
            &[Vec::new()],
            &[Vec::new()],
        );

        let private_key_bytes =
            hex_decode("0101010101010101010101010101010101010101010101010101010101010101");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let sign_input = PsbtP2PKHSignInput {
            input_index: 0,
            private_key,
            pubkey_hash: pk_hash,
        };

        sign_psbt_p2pkh(&mut psbt, &sign_input).unwrap();

        // Verify FINAL_SCRIPT_SIG injection
        let final_scriptsig = psbt
            .input_map(0)
            .iter()
            .find(|kv| kv.key == vec![input_type::FINAL_SCRIPT_SIG]);
        assert!(
            final_scriptsig.is_some(),
            "FINAL_SCRIPT_SIG must be injected"
        );
        let final_scriptsig = final_scriptsig.unwrap();
        // The value is the scriptSig: <push sig><push pk>
        assert!(final_scriptsig.value.len() > 33); // sig + compressed pk
                                                   // the scriptSig should end with the compressed pubkey (33 bytes)
        let pk_bytes = &final_scriptsig.value[final_scriptsig.value.len() - 33..];
        assert!(pk_bytes[0] == 0x02 || pk_bytes[0] == 0x03);

        eprintln!(
            "FINAL_SCRIPT_SIG ({} bytes): {}",
            final_scriptsig.value.len(),
            hex_encode(final_scriptsig.value)
        );
    }

    /// P2PKH PSBT out-of-bounds
    #[test]
    fn psbt_sign_p2pkh_out_of_bounds() {
        let psbt = psbt_from_maps_leaky(
            Transaction {
                version: 1,
                inputs: bt_vec![],
                outputs: bt_vec![],
                lock_time: 0,
            },
            &[],
            &[],
        );
        let mut psbt = psbt;
        let sign_input = PsbtP2PKHSignInput {
            input_index: 0,
            private_key: SecretBytes::new([0; 32]),
            pubkey_hash: [0; 20],
        };
        assert!(sign_psbt_p2pkh(&mut psbt, &sign_input).is_err());
    }

    /// Sign a PSBT P2SH-P2WPKH input → FINAL_SCRIPT_SIG + FINAL_SCRIPTWITNESS
    #[test]
    fn psbt_sign_p2sh_p2wpkh() {
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        let txin = TxIn {
            prev_out: OutPoint { txid, vout: 0 },
            script_sig: vec![].into(),
            sequence: 0xffffffff,
            witness: vec![],
        };
        // P2SH scriptPubKey = `0xa914{20-byte-hash}87`
        let mut redeem_hash = [0u8; 20];
        redeem_hash[0] = 0x33;
        let mut script_pubkey = Vec::with_capacity(23);
        script_pubkey.push(0xa9);
        script_pubkey.push(0x14);
        script_pubkey.extend_from_slice(&redeem_hash);
        script_pubkey.push(0x87);

        let txout = TxOut {
            value: 200_000,
            script_pubkey: script_pubkey.into(),
        };

        let mut psbt = psbt_from_maps_leaky(
            Transaction {
                version: 2,
                inputs: bt_vec![txin],
                outputs: bt_vec![txout],
                lock_time: 0,
            },
            &[Vec::new()],
            &[Vec::new()],
        );

        let private_key_bytes =
            hex_decode("0101010101010101010101010101010101010101010101010101010101010101");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let pk_hash = [0x42; 20]; // consistent with sign_p2sh_p2wpkh

        let sign_input = PsbtP2SHP2WPKHSignInput {
            input_index: 0,
            private_key,
            pubkey_hash: pk_hash,
            amount: 300_000,
        };

        sign_psbt_p2sh_p2wpkh(&mut psbt, &sign_input).unwrap();

        // Verify FINAL_SCRIPT_SIG injection
        let final_scriptsig = psbt
            .input_map(0)
            .iter()
            .find(|kv| kv.key == vec![input_type::FINAL_SCRIPT_SIG]);
        assert!(
            final_scriptsig.is_some(),
            "FINAL_SCRIPT_SIG must be injected"
        );
        let final_scriptsig = final_scriptsig.unwrap();
        // scriptSig = push 22 (0x16) + 0x00 + 0x14 + pubkey_hash
        assert_eq!(final_scriptsig.value.len(), 23);
        assert_eq!(final_scriptsig.value[0], 0x16);

        // Verify FINAL_SCRIPTWITNESS injection
        let final_witness = psbt
            .input_map(0)
            .iter()
            .find(|kv| kv.key == vec![input_type::FINAL_SCRIPTWITNESS]);
        assert!(
            final_witness.is_some(),
            "FINAL_SCRIPTWITNESS must be injected"
        );
        let final_witness = final_witness.unwrap();
        // Witness serialization: <item_count><item_len><item_data>*
        // 2 items: signature + pubkey
        assert_eq!(final_witness.value[0], 2); // 2 witness items
                                               // next comes varint(sig_len) + sig
        eprintln!(
            "FINAL_SCRIPTWITNESS ({} bytes): {}",
            final_witness.value.len(),
            hex_encode(final_witness.value)
        );
    }

    /// P2SH-P2WPKH PSBT out-of-bounds
    #[test]
    fn psbt_sign_p2sh_p2wpkh_out_of_bounds() {
        let psbt = psbt_from_maps_leaky(
            Transaction {
                version: 1,
                inputs: bt_vec![],
                outputs: bt_vec![],
                lock_time: 0,
            },
            &[],
            &[],
        );
        let mut psbt = psbt;
        let sign_input = PsbtP2SHP2WPKHSignInput {
            input_index: 0,
            private_key: SecretBytes::new([0; 32]),
            pubkey_hash: [0; 20],
            amount: 0,
        };
        assert!(sign_psbt_p2sh_p2wpkh(&mut psbt, &sign_input).is_err());
    }

    // === v9.9 P2TR PSBT tests ===

    /// Helper: build a P2TR PSBT input (with witness UTXO containing P2TR scriptPubKey)
    fn make_p2tr_input(output_key_x: &[u8; 32]) -> Vec<KeyValue<'_>> {
        let mut input = Vec::new();
        // 1. WITNESS_UTXO: value = CTxOut = amount(8) || varint(spk_len=34=0x22) || spk
        // P2TR scriptPubKey = OP_1 PUSH 32 <x-only-pubkey>
        let mut utxo = Vec::new();
        utxo.extend_from_slice(&100_000u64.to_le_bytes()); // amount
        utxo.push(0x22); // varint: spk len = 34
        utxo.push(0x51); // OP_1
        utxo.push(0x20); // push 32
        utxo.extend_from_slice(output_key_x);
        input.push(KeyValue {
            key: vec![input_type::WITNESS_UTXO].into(),
            value: utxo.into(),
        });
        // 2. TAP_INTERNAL_KEY
        set_tap_internal_key(&mut input, output_key_x).unwrap();
        input
    }

    /// P2TR keypath-only: inject TAP_KEY_SIG (0x13)
    #[test]
    fn psbt_p2tr_keypath_sign() {
        let output_key_x = [0x99u8; 32];
        let input = make_p2tr_input(&output_key_x);

        let mut psbt = psbt_from_maps_leaky(
            Transaction {
                version: 2,
                inputs: bt_vec![crate::chain::btc::p2wpkh::TxIn {
                    prev_out: crate::chain::btc::p2wpkh::OutPoint {
                        txid: [1u8; 32],
                        vout: 0,
                    },
                    script_sig: vec![].into(),
                    sequence: 0xffffffff,
                    witness: vec![],
                }],
                outputs: bt_vec![],
                lock_time: 0,
            },
            &[input],
            &[vec![]],
        );

        let schnorr_sig = [0xabu8; 64];
        let sign_input = PsbtP2TRSignInput {
            input_index: 0,
            internal_key_x: output_key_x,
            tweaked_schnorr_sig: schnorr_sig,
        };

        sign_psbt_p2tr_keypath(&mut psbt, &sign_input).unwrap();

        // Verify TAP_KEY_SIG injected
        let injected = psbt
            .input_map(0)
            .iter()
            .find(|kv| kv.key == vec![input_type::TAP_KEY_SIG])
            .expect("TAP_KEY_SIG not injected");
        assert_eq!(injected.value, schnorr_sig.to_vec());
        assert_eq!(injected.key, vec![0x13u8]);
    }

    /// P2TR scriptpath: inject TAP_SCRIPT_SIG (0x14) with leaf_hash
    #[test]
    fn psbt_p2tr_scriptpath_sign() {
        let output_key_x = [0x88u8; 32];
        let leaf_hash = [0x77u8; 32];
        let input = make_p2tr_input(&output_key_x);

        let mut psbt = psbt_from_maps_leaky(
            Transaction {
                version: 2,
                inputs: bt_vec![crate::chain::btc::p2wpkh::TxIn {
                    prev_out: crate::chain::btc::p2wpkh::OutPoint {
                        txid: [2u8; 32],
                        vout: 0,
                    },
                    script_sig: vec![].into(),
                    sequence: 0xffffffff,
                    witness: vec![],
                }],
                outputs: bt_vec![],
                lock_time: 0,
            },
            &[input],
            &[vec![]],
        );

        let schnorr_sig = [0xccu8; 64];
        let sign_input = PsbtP2TRScriptPathSignInput {
            input_index: 0,
            internal_key_x: output_key_x,
            leaf_hash,
            schnorr_sig,
            sighash_type: 0x00, // SIGHASH_DEFAULT
        };

        sign_psbt_p2tr_scriptpath(&mut psbt, &sign_input).unwrap();

        // Verify TAP_SCRIPT_SIG injected with key = [0x14 || leaf_hash (32)]
        let expected_key_len = 1 + 32;
        let injected = psbt
            .input_map(0)
            .iter()
            .find(|kv| kv.key.len() == expected_key_len && kv.key[0] == input_type::TAP_SCRIPT_SIG)
            .expect("TAP_SCRIPT_SIG not injected");
        assert_eq!(injected.key[1..], leaf_hash);
        assert_eq!(injected.value.len(), 65); // sig(64) + sighash(1)
        assert_eq!(&injected.value[0..64], &schnorr_sig);
        assert_eq!(injected.value[64], 0x00); // sighash byte
    }

    /// P2TR keypath sign should reject non-P2TR input
    #[test]
    fn psbt_p2tr_keypath_rejects_non_p2tr() {
        // Build P2WPKH input (not P2TR)
        let mut input = Vec::new();
        let mut utxo = Vec::new();
        utxo.extend_from_slice(&100_000u64.to_le_bytes());
        utxo.push(0x00); // OP_0
        utxo.push(0x14); // push 20
        utxo.extend_from_slice(&[0x99u8; 20]);
        input.push(KeyValue {
            key: vec![input_type::WITNESS_UTXO].into(),
            value: utxo.into(),
        });

        let mut psbt = psbt_from_maps_leaky(
            Transaction {
                version: 2,
                inputs: bt_vec![crate::chain::btc::p2wpkh::TxIn {
                    prev_out: crate::chain::btc::p2wpkh::OutPoint {
                        txid: [3u8; 32],
                        vout: 0,
                    },
                    script_sig: vec![].into(),
                    sequence: 0xffffffff,
                    witness: vec![],
                }],
                outputs: bt_vec![],
                lock_time: 0,
            },
            &[input],
            &[vec![]],
        );

        let sign_input = PsbtP2TRSignInput {
            input_index: 0,
            internal_key_x: [0x42u8; 32],
            tweaked_schnorr_sig: [0u8; 64],
        };

        let result = sign_psbt_p2tr_keypath(&mut psbt, &sign_input);
        assert!(result.is_err(), "should reject non-P2TR input");
    }

    /// decode_p2tr_script_pubkey round-trip
    #[test]
    fn decode_p2tr_script_pubkey_test() {
        let output_key_x = [0x77u8; 32];
        let mut script_pubkey = Vec::new();
        script_pubkey.push(0x51);
        script_pubkey.push(0x20);
        script_pubkey.extend_from_slice(&output_key_x);

        let decoded = decode_p2tr_script_pubkey(&script_pubkey).unwrap();
        assert_eq!(decoded, output_key_x);

        // Invalid: too short
        assert!(decode_p2tr_script_pubkey(&[0x51, 0x20]).is_err());
        // Invalid: wrong opcode
        assert!(decode_p2tr_script_pubkey(&[0x50, 0x20]).is_err());
    }

    /// is_p2tr_input detection
    #[test]
    fn is_p2tr_input_test() {
        let output_key_x = [0x55u8; 32];
        let p2tr_input = make_p2tr_input(&output_key_x);
        assert!(is_p2tr_input(KvMap::from_slice(&p2tr_input)));

        // Without TAP_INTERNAL_KEY → not P2TR
        let without_tap_key = vec![p2tr_input[0].clone()];
        assert!(!is_p2tr_input(KvMap::from_slice(&without_tap_key)));
    }

    /// TAP_INTERNAL_KEY set/get round-trip
    #[test]
    fn tap_internal_key_round_trip() {
        let mut input = Vec::new();
        let internal_key = [0xabu8; 32];
        set_tap_internal_key(&mut input, &internal_key).unwrap();
        let retrieved = get_tap_internal_key(KvMap::from_slice(&input)).unwrap();
        assert_eq!(retrieved, internal_key);
    }

    /// PSBT_IN_TAP_MERKLE_ROOT encoding
    #[test]
    fn psbt_tap_merkle_root_field() {
        let mut input = vec![KeyValue {
            key: vec![input_type::TAP_MERKLE_ROOT].into(),
            value: [0xaau8; 32].to_vec().into(),
        }];
        // No merkle root → keypath-only
        assert!(get_tap_merkle_root(KvMap::from_slice(&input)).is_some());
        assert_eq!(
            get_tap_merkle_root(KvMap::from_slice(&input)).unwrap(),
            [0xaau8; 32]
        );

        // Empty input → no merkle root
        input.clear();
        assert!(get_tap_merkle_root(KvMap::from_slice(&input)).is_none());
    }

    /// v9.13d end-to-end: keystone PSBT → parse → shlosilo sighash+sign → inject TAP_KEY_SIG → serialize
    ///
    /// Full closed loop:
    /// 1. Parse the real PSBT from the keystone test_taproot_sign
    /// 2. Build the BIP-341 sighash input from unsigned_tx + WITNESS_UTXO → the sighash must equal the oracle value
    /// 3. sign_p2tr_keypath(internal_sk) → Schnorr signature
    /// 4. sign_psbt_p2tr_keypath injects PSBT_IN_TAP_KEY_SIG (0x13)
    /// 5. Serialize back to PSBT → parse again → verify fields exist and the signature verifies
    #[test]
    fn psbt_taproot_end_to_end_keystone_fixture() {
        use crate::chain::btc::taproot::{
            bip341_keypath_sighash, sign_p2tr_keypath, P2TRKeypathSignInput, SpentOutput,
            TaprootSighashInput, SIGHASH_DEFAULT,
        };

        // keystone wrapped_psbt.rs test_taproot_sign fixture (full PSBT hex)
        let psbt_hex = "70736274ff01005e02000000013aee4d6b51da574900e56d173041115bd1e1d01d4697a845784cf716a10c98060000000000ffffffff0100190000000000002251202258f2d4637b2ca3fd27614868b33dee1a242b42582d5474f51730005fa99ce8000000000001012bbc1900000000000022512022f3956cc27a6a9b0e0003a0afc113b04f31b95d5cad222a65476e8440371bd10103040000000001134092864dc9e56b6260ecbd54ec16b94bb597a2e6be7cca0de89d75e17921e0e1528cba32dd04217175c237e1835b5db1c8b384401718514f9443dce933c6ba9c872116b68df382cad577d8304d5a8e640c3cb42d77c10016ab754caa4d6e68b6cb296d190073c5da0a5600008001000080000000800000000002000000011720b68df382cad577d8304d5a8e640c3cb42d77c10016ab754caa4d6e68b6cb296d011820c913dc9a8009a074e7bbc493b9d8b7e741ba137f725f99d44fbce99300b2bb0a0000";
        let psbt_bytes = hex_decode(psbt_hex);
        let mut psbt = parse_psbt(&psbt_bytes).expect("parse keystone PSBT");
        assert_eq!(psbt.unsigned_tx.inputs.len(), 1);
        assert_eq!(psbt.unsigned_tx.inputs[0].sequence, 0xffffffff);

        // 1. Extract Taproot metadata from the input map
        let internal_key_x = get_tap_internal_key(psbt.input_map(0)).unwrap();
        let merkle_root = get_tap_merkle_root(psbt.input_map(0));
        assert_eq!(
            &hex_encode(&internal_key_x),
            "b68df382cad577d8304d5a8e640c3cb42d77c10016ab754caa4d6e68b6cb296d"
        );
        assert_eq!(
            merkle_root.map(|r| hex_encode(&r)).as_deref(),
            Some("c913dc9a8009a074e7bbc493b9d8b7e741ba137f725f99d44fbce99300b2bb0a")
        );
        // After the input_type constant fix (BIP-174 alignment): the fixture\'s UTXO in 0x01 = WITNESS_UTXO (standard),
        // and is_p2tr_input correctly recognizes this P2TR input
        assert!(
            is_p2tr_input(psbt.input_map(0)),
            "standard WITNESS_UTXO(0x01) with P2TR spk must be detected as taproot input"
        );

        // 2. Spent output (value + spk): the fixture places the TxOut in field 0x01 (CTxOut format);
        //    the standard WITNESS_UTXO (0x02) is also CTxOut format, so decode_witness_utxo handles both
        let utxo_kv = psbt
            .input_map(0)
            .iter()
            .find(|kv| {
                kv.key[0] == input_type::NON_WITNESS_UTXO || kv.key[0] == input_type::WITNESS_UTXO
            })
            .unwrap();
        let (value, spent_spk) = decode_witness_utxo(utxo_kv.value).unwrap();
        // own it before the later &mut psbt (the Cow would hold the borrow)
        let spent_spk = spent_spk.into_owned();
        assert_eq!(value, 0x19bc);
        assert_eq!(&spent_spk[..2], &[0x51, 0x20]);

        // 3. Build the sighash input and compute — must equal the oracle value
        let prevouts = [(
            psbt.unsigned_tx.inputs[0].prev_out.txid,
            psbt.unsigned_tx.inputs[0].prev_out.vout,
        )];
        let sequences = [psbt.unsigned_tx.inputs[0].sequence];
        let spent_outputs = [SpentOutput {
            value,
            script_pubkey: spent_spk.to_vec(),
        }];
        let tx_outputs: alloc::vec::Vec<SpentOutput> = psbt
            .unsigned_tx
            .outputs
            .iter()
            .map(|o| SpentOutput {
                value: o.value,
                script_pubkey: o.script_pubkey.to_vec(),
            })
            .collect();
        let sighash_input = TaprootSighashInput {
            tx_version: psbt.unsigned_tx.version as u32,
            locktime: psbt.unsigned_tx.lock_time,
            prevouts: &prevouts,
            sequences: &sequences,
            spent_outputs: &spent_outputs,
            tx_outputs: &tx_outputs,
            input_index: 0,
            hash_type: SIGHASH_DEFAULT,
            annex_present: false,
            tapleaf_hash: None,
        };
        let sighash = bip341_keypath_sighash(&sighash_input).unwrap();
        assert_eq!(
            &hex_encode(&sighash),
            "90ecc5ee16cde022e26535908bbfdada42bd19b2f7dd1d6db8699946523d4ec3",
            "sighash from parsed PSBT must equal oracle"
        );

        // 4. Sign (internal sk from m/86\'/1\'/0\'/0/2, same seed as the fixture)
        let internal_sk =
            hex_decode_32arr("1fb777f1a6fb9b76724551f8bc8ad91b77f33b8c456d65d746035391d724922a");
        let aux_rand = [0u8; 32];
        let witness_sig = sign_p2tr_keypath(
            &P2TRKeypathSignInput {
                internal_sk,
                merkle_root,
            },
            &sighash,
            &aux_rand,
            SIGHASH_DEFAULT,
        )
        .unwrap();
        let mut sig64 = [0u8; 64];
        sig64.copy_from_slice(&witness_sig);

        // 5. Inject PSBT_IN_TAP_KEY_SIG and serialize
        sign_psbt_p2tr_keypath(
            &mut psbt,
            &PsbtP2TRSignInput {
                input_index: 0,
                internal_key_x,
                tweaked_schnorr_sig: sig64,
            },
        )
        .unwrap();
        let serialized = serialize_psbt(&psbt);
        assert_eq!(&serialized[..5], &PSBT_MAGIC);

        // 6. Parse again → fields exist, signature verifiable
        let reparsed = parse_psbt(&serialized).unwrap();
        let injected = reparsed
            .input_map(0)
            .iter()
            .find(|kv| kv.key == vec![input_type::TAP_KEY_SIG])
            .expect("TAP_KEY_SIG must be present after injection");
        assert_eq!(injected.value.len(), 64);

        // The signature verifies against the output key + sighash (k256 schnorr)
        let output_key_x = decode_p2tr_script_pubkey(&spent_spk).unwrap();
        let vk = k256::schnorr::VerifyingKey::from_bytes((&output_key_x).into()).unwrap();
        let k_sig = k256::schnorr::Signature::try_from(injected.value).unwrap();
        use k256::schnorr::signature::hazmat::PrehashVerifier;
        assert!(
            vk.verify_prehash(&sighash, &k_sig).is_ok(),
            "injected PSBT signature must verify against output key + sighash"
        );
    }

    fn hex_decode_32arr(s: &str) -> [u8; 32] {
        let v = hex_decode(s.strip_prefix("0x").unwrap_or(s));
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }
    /// Audit #7 P2-01: unit-test the helper directly (moved in from integration tests — invisible to the integration side once pub(crate))
    /// Boundaries: 44/45 (41B), 12/13 (9B), zero-element lower-bound defense, saturation, legitimate magnitudes
    #[test]
    fn helper_count_physically_feasible_boundaries() {
        // 60000 inputs need 2,460,000B wire; the remaining 1000B is rejected
        assert!(!count_physically_feasible(60_000, 1000, 41));
        // locktime margin boundary: 41*1+4=45 fits 1; 44 does not
        assert!(!count_physically_feasible(1, 44, 41));
        assert!(count_physically_feasible(1, 45, 41));
        // 9B/output also reserves locktime (re-review P2-02: outputs previously missed it)
        assert!(!count_physically_feasible(1, 12, 9));
        assert!(count_physically_feasible(1, 13, 9));
        // when remaining < 4, saturate to 0; any count > 0 is rejected
        assert!(!count_physically_feasible(1, 3, 41));
        // legitimate transaction magnitudes are not falsely rejected
        assert!(count_physically_feasible(100, 100 * 41 + 100, 41));
        // Audit #7 P2-01: the zero-element lower bound no longer panics (public API totality lesson)
        assert!(!count_physically_feasible(1, 100, 0));
        assert!(count_physically_feasible(0, 100, 0));
    }
}
