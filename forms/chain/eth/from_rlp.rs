//! RLP decoding + ETH raw transaction parse (Phase 5 v9.22)
//!
//! Benchmarked against keystone `eip1559_transaction::decode_raw`: from raw hex bytes,
//! decode the EIP-155 / EIP-1559 transaction structures for the confirmation-screen summary (`summary`).
//!
//! L1 pure functions. RLP decoding per the Yellow Paper:
//! - `0x00..0x7f`          a single byte, itself
//! - `0x80..0xb7`          string，len = b - 0x80
//! - `0xb8..0xbf`          string，len_of_len = b - 0xb7
//! - `0xc0..0xf7`          list，payload len = b - 0xc0
//! - `0xf8..0xff`          list，len_of_len = b - 0xf7

#[cfg(any(feature = "alloc-fallback", test))]
extern crate alloc;
// Alloc surface: consumers behind alloc-fallback / cfg(test).

use crate::chain::eth::eip155::Eip155Transaction;
use crate::chain::eth::eip1559::Eip1559Transaction;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
#[cfg(test)]
use crate::types::SecretBytes;

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// RLP item: string or list
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rlp<'a> {
    Str(&'a [u8]),
    List(&'a [u8]),
}

impl<'a> Rlp<'a> {
    /// Read one RLP item; returns (item, remaining bytes)
    pub fn read(bytes: &'a [u8]) -> Result<(Rlp<'a>, &'a [u8])> {
        if bytes.is_empty() {
            return Err(err());
        }
        let b0 = bytes[0];
        let (payload, rest) = match b0 {
            0x00..=0x7f => (&bytes[..1], &bytes[1..]),
            0x80..=0xb7 => {
                let len = (b0 - 0x80) as usize;
                if bytes.len() < 1 + len {
                    return Err(err());
                }
                // A3c-F6 (2026-11-20): canonicality. A payload of exactly one byte below 0x80 has its
                // own encoding, so the short-string form is a second encoding of the same value —
                // accepting it is a parser differential against a node.
                if len == 1 && bytes[1] < 0x80 {
                    return Err(err());
                }
                (&bytes[1..1 + len], &bytes[1 + len..])
            }
            0xb8..=0xbf => {
                let lol = (b0 - 0xb7) as usize;
                // ETH-1 (external audit 2026-11-19): every offset below is built with
                // checked arithmetic. The old shape compared `bytes.len()` against
                // `1 + lol + len` where `len` came straight from the wire: with overflow
                // checks on the comparison itself panicked, and with them off the wrap
                // could pass the check and make the following slice panic.
                let start = match 1usize.checked_add(lol) {
                    Some(v) => v,
                    None => return Err(err()),
                };
                if start > bytes.len() {
                    return Err(err());
                }
                let mut len = 0usize;
                for &b in &bytes[1..start] {
                    len = match len.checked_mul(256).and_then(|v| v.checked_add(b as usize)) {
                        Some(v) => v,
                        None => return Err(err()),
                    };
                }
                let end = match start.checked_add(len) {
                    Some(v) => v,
                    None => return Err(err()),
                };
                if end > bytes.len() {
                    return Err(err());
                }
                // A3c-F6 (2026-11-20): the long form is only canonical for payloads >= 56 bytes and
                // with a minimal length field (no leading zero byte).
                if len <= 55 || bytes[1] == 0 {
                    return Err(err());
                }
                (&bytes[start..end], &bytes[end..])
            }
            0xc0..=0xf7 => {
                let len = (b0 - 0xc0) as usize;
                if bytes.len() < 1 + len {
                    return Err(err());
                }
                (&bytes[1..1 + len], &bytes[1 + len..])
            }
            0xf8..=0xff => {
                let lol = (b0 - 0xf7) as usize;
                // ETH-1: see the long-string branch above (same overflow shape).
                let start = match 1usize.checked_add(lol) {
                    Some(v) => v,
                    None => return Err(err()),
                };
                if start > bytes.len() {
                    return Err(err());
                }
                let mut len = 0usize;
                for &b in &bytes[1..start] {
                    len = match len.checked_mul(256).and_then(|v| v.checked_add(b as usize)) {
                        Some(v) => v,
                        None => return Err(err()),
                    };
                }
                let end = match start.checked_add(len) {
                    Some(v) => v,
                    None => return Err(err()),
                };
                if end > bytes.len() {
                    return Err(err());
                }
                // A3c-F6 (2026-11-20): same canonicality rules for lists — long form only for
                // payloads >= 56 bytes, and the length field must not start with a zero byte.
                if len <= 55 || bytes[1] == 0 {
                    return Err(err());
                }
                (&bytes[start..end], &bytes[end..])
            }
        };
        // A3c-F5 (external audit 2026-11-19, surfaced while building the ERC-20 review
        // fixture): the LONG string range 0xb8..=0xbf was classified as a list. Every RLP
        // string of 56 bytes or more therefore came back as `Rlp::List`, `as_str()` failed,
        // and `parse_eip1559_raw` rejected the transaction — i.e. a plain ERC-20 transfer
        // (68-byte calldata) could not be reviewed or signed at all. The string/list split
        // is at 0xc0, not at 0xb8.
        let item = match b0 {
            0x00..=0xbf => Rlp::Str(payload),
            _ => Rlp::List(payload),
        };
        Ok((item, rest))
    }

    pub fn as_str(&self) -> Result<&'a [u8]> {
        match self {
            Rlp::Str(s) => Ok(s),
            _ => Err(err()),
        }
    }

    pub fn as_list_items(&self) -> Result<heapless::Vec<Rlp<'a>, 16>> {
        let payload = match self {
            Rlp::List(p) => *p,
            _ => return Err(err()),
        };
        let mut items = heapless::Vec::new();
        let mut rest = payload;
        while !rest.is_empty() {
            let (item, r) = Rlp::read(rest)?;
            items
                .push(item)
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
            rest = r;
        }
        Ok(items)
    }
}

/// big-endian bytes → u128 (overlong rejected)
fn be_to_u128(bytes: &[u8]) -> Result<u128> {
    if bytes.len() > 16 || bytes.first() == Some(&0) && bytes.len() > 1 {
        return Err(err());
    }
    let mut n: u128 = 0;
    for &b in bytes {
        n = (n << 8) | b as u128;
    }
    Ok(n)
}

/// Structural parser: `0x02 || rlp([9 or 12 fields])` → the unsigned transaction.
///
/// Two list lengths are legal on the wire, both with the `0x02` type byte, and real
/// wallets send one or the other:
/// - **9 fields** — the signing preimage itself (`chain_id … access_list`). This is
///   what MetaMask's own QR keyring sends: `@metamask/eth-qr-keyring`
///   `dist/device.cjs`, `RLP.encode(transaction.getMessageToSign())`.
/// - **12 fields** — the unsigned transaction serialization, whose last three items
///   are the signature slots. This is what
///   `@keystonehq/metamask-airgapped-keyring` (≤ 0.15.x) sends:
///   `Buffer.from(tx.serialize())`.
///
/// A payload that already carries a signature is still parsed here — this is the
/// parser, used by round-trip pins and by callers that read signed transactions.
/// Use [`parse_eip1559_signing_request`] for anything we are about to sign or review.
///
/// Returns Err when access_list is non-empty (out of v2 scope).
pub fn parse_eip1559_raw(raw: &[u8]) -> Result<Eip1559Transaction<'_>> {
    parse_impl(raw, false)
}

/// The same parse, for a payload we are about to **sign or review**.
///
/// Refuses a payload whose signature slots are non-empty: that is not a signing
/// request, and signing over it would launder someone else's `r`/`s` as this
/// device's output. The policy lives here rather than in the parser because the
/// parser also serves callers that read already-signed transactions.
pub fn parse_eip1559_signing_request(raw: &[u8]) -> Result<Eip1559Transaction<'_>> {
    parse_impl(raw, true)
}

fn parse_impl(raw: &[u8], require_unsigned: bool) -> Result<Eip1559Transaction<'_>> {
    if raw.first() != Some(&0x02) {
        return Err(err());
    }
    let (top, tail) = Rlp::read(&raw[1..])?;
    if !tail.is_empty() {
        return Err(err());
    }
    let fields = top.as_list_items()?;
    match fields.len() {
        9 => {}
        12 => {
            // Structural check for all callers; emptiness only when require_unsigned.
            for f in &fields[9..12] {
                let slot = f.as_str()?;
                if require_unsigned && !slot.is_empty() {
                    return Err(err());
                }
            }
        }
        _ => return Err(err()),
    }
    let chain_id = be_to_u128(fields[0].as_str()?)?;
    let nonce = be_to_u128(fields[1].as_str()?)?;
    let max_priority_fee_per_gas = be_to_u128(fields[2].as_str()?)?;
    let max_fee_per_gas = be_to_u128(fields[3].as_str()?)?;
    let gas_limit = be_to_u128(fields[4].as_str()?)?;
    let dest_bytes = fields[5].as_str()?;
    let destination = match dest_bytes.len() {
        0 => None,
        20 => {
            let mut a = [0u8; 20];
            a.copy_from_slice(dest_bytes);
            Some(a)
        }
        _ => return Err(err()),
    };
    let amount = be_to_u128(fields[6].as_str()?)?;
    let data = crate::types::wire_bytes::wire_from(fields[7].as_str()?);
    // fields[8] = access_list; non-empty is rejected (shlosilo doesn't sign txs carrying an access list)
    if !fields[8].as_list_items()?.is_empty() {
        return Err(err());
    }
    // The signature slots (present only in the 12-field shape) were validated above.
    Ok(Eip1559Transaction {
        // A3c-F7 (2026-11-20): `as u64` silently truncated a wider wire integer, which rewrote the
        // request (chain_id 2^64+1 became 1). Reject instead: a value the model cannot represent is
        // not a transaction this device may review or sign.
        chain_id: u64::try_from(chain_id).map_err(|_| err())?,
        nonce: u64::try_from(nonce).map_err(|_| err())?,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit: u64::try_from(gas_limit).map_err(|_| err())?,
        destination,
        amount,
        data,
    })
}

/// Parse a raw EIP-155 legacy signed tx (no type prefix, rlp([...9 fields]))
///
/// v must be in EIP-155 form (≥35); chain_id = (v - 35) / 2.
pub fn parse_eip155_raw(raw: &[u8]) -> Result<Eip155Transaction<'_>> {
    let (top, tail) = Rlp::read(raw)?;
    if !tail.is_empty() {
        return Err(err());
    }
    let fields = top.as_list_items()?;
    if fields.len() != 9 {
        return Err(err());
    }
    let nonce = be_to_u128(fields[0].as_str()?)?;
    let gas_price = be_to_u128(fields[1].as_str()?)?;
    let gas_limit = be_to_u128(fields[2].as_str()?)?;
    let dest_bytes = fields[3].as_str()?;
    let destination = match dest_bytes.len() {
        0 => None,
        20 => {
            let mut a = [0u8; 20];
            a.copy_from_slice(dest_bytes);
            Some(a)
        }
        _ => return Err(err()),
    };
    let amount = be_to_u128(fields[4].as_str()?)?;
    let data = crate::types::wire_bytes::wire_from(fields[5].as_str()?);
    // A3c-F7 (2026-11-20): the same rule as the 1559 entry — no silent truncation of wire integers.
    let v = u64::try_from(be_to_u128(fields[6].as_str()?)?).map_err(|_| err())?;
    if v < 35 {
        return Err(err()); // pre-EIP-155 unsupported
    }
    for f in &fields[7..9] {
        let _ = f.as_str()?;
    }
    Ok(Eip155Transaction {
        chain_id: ((v - 35) / 2) as u64,
        nonce: u64::try_from(nonce).map_err(|_| err())?,
        gas_price,
        gas_limit: u64::try_from(gas_limit).map_err(|_| err())?,
        destination,
        amount,
        data,
    })
}

/// Parse a **legacy signing request** (`eth-sign-request`, `data_type` 1).
///
/// Wire shape — the EIP-155 preimage, which is what wallets send (`@metamask/
/// eth-qr-keyring` encodes `transaction.getMessageToSign()`, and EIP-155 defines it
/// as exactly this list):
///
/// ```text
/// rlp([nonce, gas_price, gas_limit, destination, amount, data, chain_id, [], []])
/// ```
///
/// ## Why this is not [`parse_eip155_raw`]
///
/// Item 6 means different things in the two shapes, and the difference is not
/// cosmetic:
///
/// | payload | item 6 | items 7/8 |
/// |---|---|---|
/// | signed transaction | `v` (>= 35) | `r`, `s` |
/// | signing request | `chain_id` | empty signature slots |
///
/// keystone's reference implementation draws the line at the same place —
/// `LegacyTransaction::chain_id()` returns `signature.v()` when the `s` slot is
/// zero ("unsigned eip155 compatible") and `(v - 35) / 2` only for a signed one.
/// Reading a request through the signed-transaction entry would take Polygon's
/// `chain_id = 137` for `v = 137` and sign a preimage for chain 51: a signature
/// the sender cannot use, produced while the device reports success.
///
/// ## Refused on purpose
///
/// - **6 items** (`rlp([nonce, gas_price, gas_limit, destination, amount, data])`)
///   — pre-EIP-155: no replay protection, so a signature over it is valid on every
///   chain that ever forked. `FeatureNotImplemented`: this is a shape we know and
///   choose not to sign, not a malformed request (the code used to be invisible
///   behind a generic parse failure). keystone signs it as if `chain_id` were 1,
///   which is exactly the outcome we do not want.
/// - **non-empty `r`/`s` slots** — the payload already carries a signature;
///   signing over it would launder someone else's `r`/`s` as this device's output.
///   Same policy as [`parse_eip1559_signing_request`].
/// - **`chain_id == 0`** — no chain has id 0, and the `v` it implies (35/36) is
///   indistinguishable from a protected transaction on a chain nobody names.
pub fn parse_eip155_signing_request(raw: &[u8]) -> Result<Eip155Transaction<'_>> {
    let (top, tail) = Rlp::read(raw)?;
    if !tail.is_empty() {
        return Err(err());
    }
    let fields = top.as_list_items()?;
    match fields.len() {
        // pre-EIP-155: known shape, deliberately not signable here.
        6 => return Err(ShlosiloError::new(ShlosiloErrorKind::FeatureNotImplemented)),
        9 => {}
        _ => return Err(err()),
    }
    // Items 7/8 are the signature slots of the signed form. A request leaves both
    // empty — that empty `s` is also how the reference implementation recognises
    // "unsigned eip155 compatible" and reads item 6 as a chain id.
    for slot in &fields[7..9] {
        if !slot.as_str()?.is_empty() {
            return Err(err());
        }
    }
    let nonce = be_to_u128(fields[0].as_str()?)?;
    let gas_price = be_to_u128(fields[1].as_str()?)?;
    let gas_limit = be_to_u128(fields[2].as_str()?)?;
    let dest_bytes = fields[3].as_str()?;
    let destination = match dest_bytes.len() {
        0 => None,
        20 => {
            let mut a = [0u8; 20];
            a.copy_from_slice(dest_bytes);
            Some(a)
        }
        _ => return Err(err()),
    };
    let amount = be_to_u128(fields[4].as_str()?)?;
    let data = crate::types::wire_bytes::wire_from(fields[5].as_str()?);
    // A3c-F7 discipline (already fixed for the other entries, kept identical here): a
    // wire integer the model cannot hold is rejected, never truncated.
    let chain_id = u64::try_from(be_to_u128(fields[6].as_str()?)?).map_err(|_| err())?;
    if chain_id == 0 {
        return Err(err());
    }
    Ok(Eip155Transaction {
        chain_id,
        nonce: u64::try_from(nonce).map_err(|_| err())?,
        gas_price,
        gas_limit: u64::try_from(gas_limit).map_err(|_| err())?,
        destination,
        amount,
        data,
    })
}

#[cfg(test)]
mod tests {
    /// A3c-F5: a string of 56+ bytes uses the long-form head (0xb8..=0xbf) and must still
    /// come back as `Rlp::Str`. Before this pin the classification matched only
    /// `0x00..=0xb7`, so every long string decoded as a list — which silently made any
    /// transaction with ≥56 bytes of calldata (i.e. every ERC-20 call) unparseable.
    #[test]
    fn long_string_is_a_string_not_a_list() {
        // Built as a literal so the pin also runs on the no-alloc (device) face.
        // 0xb8 = long string with a 1-byte length, 0x44 = 68, then 68 bytes of calldata.
        let mut enc = [0u8; 70];
        enc[0] = 0xb8;
        enc[1] = 0x44;
        for b in &mut enc[2..] {
            *b = 0xa9;
        }
        let (item, rest) = crate::chain::eth::from_rlp::Rlp::read(&enc).expect("long string");
        assert_eq!(item.as_str().expect("must be a string").len(), 68);
        assert!(rest.is_empty());

        // and the list split is still at 0xc0
        let lst = [0xc1u8, 0x80];
        let (item, rest) = crate::chain::eth::from_rlp::Rlp::read(&lst).expect("list");
        assert!(matches!(item, crate::chain::eth::from_rlp::Rlp::List(_)));
        assert!(rest.is_empty());
    }

    /// ETH-1 (external audit 2026-11-19): the long-form branches computed the end offset
    /// with a plain `usize` addition BEFORE any bound check. With overflow checks on
    /// (debug) that panics in the comparison itself; with them off (release) the wrap can
    /// make the check pass and the following slice panics instead.
    #[test]
    fn long_form_overflow_is_a_clean_error() {
        // 0xb8 = long string, 1 length byte; a huge length must not reach the slice.
        let s_over = [0xb8u8, 0x40, 0x00, 0x00];
        assert!(crate::chain::eth::from_rlp::Rlp::read(&s_over).is_err());
        // length byte count at the top of the range (lol = 8) with a value that would
        // overflow `1 + lol + len` on a 32-bit target and is nonsensical anyway.
        let mut l8 = alloc::vec![0xb8u8 + 7];
        l8.extend_from_slice(&[0xff; 8]);
        assert!(crate::chain::eth::from_rlp::Rlp::read(&l8).is_err());
        // long list branch (0xf8..)
        let l_over = [0xf8u8, 0x40, 0x00, 0x00];
        assert!(crate::chain::eth::from_rlp::Rlp::read(&l_over).is_err());
        // and the legal case still parses
        let ok = [0x83u8, 0x61, 0x62, 0x63];
        let (item, rest) = crate::chain::eth::from_rlp::Rlp::read(&ok).expect("3-byte string");
        assert_eq!(item.as_str().expect("string"), &[0x61, 0x62, 0x63]);
        assert!(rest.is_empty());
    }

    use super::*;
    // Alloc surface: consumers behind alloc-fallback / cfg(test).
    #[cfg(any(feature = "alloc-fallback", test))]
    #[cfg(any(feature = "alloc-fallback", test))]
    use alloc::vec::Vec;

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// v9.22: official vector signed tx → parse → fields match (the expected output of the eip1559.rs sign test)
    #[test]
    fn eip1559_official_vector_round_trip() {
        let raw = hex_decode("02f8730180843b9aca008504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080c001a0b3d7e5d4775918a0ec38e4f9da6263f69c2072c0e177ff9aa274575bfba17d04a062182875ae92e4de08aaf8ea1a43d3ea0d836745788801cdc79ccc473a76dfd9");
        let tx = parse_eip1559_raw(&raw).unwrap();
        assert_eq!(tx.chain_id, 1);
        assert_eq!(tx.nonce, 0);
        assert_eq!(tx.max_priority_fee_per_gas, 1_000_000_000);
        assert_eq!(tx.max_fee_per_gas, 20_000_000_000);
        assert_eq!(tx.gas_limit, 21000);
        assert_eq!(tx.destination, Some([0x35u8; 20]));
        assert_eq!(tx.amount, 1_000_000_000_000_000_000);
        assert!(tx.data.is_empty());
        // Recomputing the signing preimage should match the official sighash
        let sighash = crate::chain::eth::eip1559::signing_hash(&tx).unwrap();
        assert_eq!(
            &sighash[..],
            &hex_decode("f63a609bfdfcc60853764d633f8de24fc6bf6f85e19ee6c0f2d089f7ee8d5d86")[..]
        );
    }

    /// EIP-155 legacy: sign output → parse back, chain_id recovered from v
    #[test]
    fn eip155_sign_output_round_trip() {
        use crate::chain::eth::eip155::{sign_eip155, Eip155SignInput, Eip155Transaction};
        let tx = Eip155Transaction {
            chain_id: 1,
            nonce: 9,
            gas_price: 20 * 1_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new().into(),
        };
        let key = SecretBytes::new([0x46u8; 32]);
        let signed = sign_eip155(&Eip155SignInput {
            tx,
            private_key: &key,
        })
        .unwrap();
        let parsed = parse_eip155_raw(&signed.tx_bytes).unwrap();
        assert_eq!(parsed.chain_id, 1);
        assert_eq!(parsed.nonce, 9);
        assert_eq!(parsed.gas_price, 20 * 1_000_000_000);
        assert_eq!(parsed.destination, Some([0x35u8; 20]));
    }

    /// Non-0x02 prefix rejected; shapes beyond an empty access list rejected
    #[test]
    fn rejects_wrong_type_and_trailing_bytes() {
        assert!(parse_eip1559_raw(&[0x01, 0xc0]).is_err());
        assert!(parse_eip1559_raw(&[]).is_err());
        let mut raw = hex_decode("02f8730180843b9aca008504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080c001a0b3d7e5d4775918a0ec38e4f9da6263f69c2072c0e177ff9aa274575bfba17d04a062182875ae92e4de08aaf8ea1a43d3ea0d836745788801cdc79ccc473a76dfd9");
        raw.push(0xff); // trailing garbage
        assert!(parse_eip1559_raw(&raw).is_err());
    }

    /// A3c-F7 (external audit 2026-11-19, verified 2026-11-20): wire integers wider than the
    /// transaction model must be REJECTED, not silently truncated. Truncation rewrites the request —
    /// `chain_id = 2^64 + 1` used to parse as 1, i.e. the device reviewed and signed for a different
    /// chain than the bytes named (same shape for nonce and gas_limit, and for legacy `v`).
    #[test]
    fn oversized_wire_integers_are_rejected_not_truncated() {
        // control: identical shape with in-range fields parses
        let ok = hex_decode("02ed0109843b9aca008504a817c8008252089435353535353535353535353535353535353535358203e880c0800101");
        assert!(parse_eip1559_raw(&ok).is_ok());

        // chain_id / nonce / gas_limit each carrying 2^64 + small
        for raw_hex in [
            "02f68901000000000000000109843b9aca008504a817c8008252089435353535353535353535353535353535353535358203e880c0800101",
            "02f601890100000000000000c8843b9aca008504a817c8008252089435353535353535353535353535353535353535358203e880c0800101",
            "02f40109843b9aca008504a817c800890100000000000052089435353535353535353535353535353535353535358203e880c0800101",
        ] {
            assert!(
                parse_eip1559_raw(&hex_decode(raw_hex)).is_err(),
                "an oversized field must be rejected, not truncated: {raw_hex}"
            );
        }

        // legacy entry (L1 face, ported into the product with pool item 68): nonce and v
        assert!(parse_eip155_raw(&hex_decode(
            "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080250101"
        ))
        .is_ok());
        assert!(parse_eip155_raw(&hex_decode(
            "f5890100000000000000098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080250101"
        ))
        .is_err());
        assert!(parse_eip155_raw(&hex_decode(
            "f5098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080890100000000000000250101"
        ))
        .is_err());
    }

    /// A3c-F6 (2026-11-20): non-canonical RLP is rejected. Consensus-valid RLP has exactly one
    /// encoding per value, so accepting variants creates a parser differential between this device and
    /// a node (same decoded transaction, different bytes).
    #[test]
    fn non_canonical_rlp_is_rejected() {
        // a single byte < 0x80 must be encoded as itself, not as `0x81 xx`
        assert!(Rlp::read(&[0x81, 0x05]).is_err());
        assert!(Rlp::read(&[0x05]).is_ok()); // control

        // the long form is for payloads >= 56 bytes
        assert!(Rlp::read(&[0xb8, 0x03, b'd', b'o', b'g']).is_err());
        let mut ok_long = alloc::vec![0xb8u8, 0x38];
        ok_long.extend_from_slice(&[0xaa; 56]);
        assert!(Rlp::read(&ok_long).is_ok());

        // length bytes must not carry leading zeros (`0xb9 0x00 0x38 …`)
        let mut lead_zero = alloc::vec![0xb9u8, 0x00, 0x38];
        lead_zero.extend_from_slice(&[0xaa; 56]);
        assert!(Rlp::read(&lead_zero).is_err());

        // the same two rules for lists
        assert!(Rlp::read(&[0xf8, 0x01, 0x80]).is_err());
        let list_lead_zero = alloc::vec![0xf9u8, 0x00, 0x01, 0x80];
        assert!(Rlp::read(&list_lead_zero).is_err());
        let mut ok_list = alloc::vec![0xf8u8, 0x38];
        ok_list.extend_from_slice(&[0x80; 56]);
        assert!(Rlp::read(&ok_list).is_ok());

        // and through the transaction entry: nonce 5 written as `0x81 0x05`
        let non_canonical_tx = hex_decode(
            "02ee018105843b9aca008504a817c8008252089435353535353535353535353535353535353535358203e880c0800101",
        );
        assert!(
            parse_eip1559_raw(&non_canonical_tx).is_err(),
            "a transaction carrying a non-canonical field must be rejected"
        );
    }

    // ─── E-1 (2026-11-25): legacy signing requests (data_type 1) ────────────

    /// The live `eth-sign-request` fixture this repo already ships for legacy
    /// (`tests/ur_inject_matrix.rs` case `legacy`, UR-decoded 2026-11-25): a 9-item
    /// preimage whose item 6 is the CHAIN ID and whose signature slots are empty.
    ///
    /// `e4 07 85 06fc23ac00 82 5208 94 11…11 80 80 01 80 80`
    /// → nonce 7, 30 gwei, 21000 gas, to 0x1111…11, value 0, no data, chain 1.
    ///
    /// This is the shape the first wiring attempt broke on: reading it as a signed
    /// transaction makes item 6 a `v`, so chain 1 looks like "pre-EIP-155" and is
    /// refused — while chain 137 would have been read as chain 51 and signed.
    #[test]
    fn legacy_signing_request_reads_item_six_as_the_chain_id() {
        let raw = hex_decode(
            "e4078506fc23ac008252089411111111111111111111111111111111111111118080018080",
        );
        let tx = parse_eip155_signing_request(&raw).expect("the shipped legacy fixture parses");
        assert_eq!(tx.chain_id, 1, "item 6 is the chain id, not v");
        assert_eq!(tx.nonce, 7);
        assert_eq!(tx.gas_price, 30_000_000_000);
        assert_eq!(tx.gas_limit, 21_000);
        assert_eq!(tx.destination, Some([0x11u8; 20]));
        assert_eq!(tx.amount, 0);
        assert!(crate::types::wire_bytes::wire_slice(&tx.data).is_empty());

        // the same doc's chain ids: Polygon and Sepolia must not be re-derived
        // (as `v`-shaped parses they would read 137 → chain 51 and 11155111 → chain
        // 5577578), so item 6 is the chain id and nothing else.
        for (chain_id, raw_hex) in [
            (
                137u64,
                "e5078506fc23ac00825208941111111111111111111111111111111111111111808081898080",
            ),
            (
                11_155_111u64,
                "e7078506fc23ac00825208941111111111111111111111111111111111111111808083aa36a78080",
            ),
        ] {
            let raw = hex_decode(raw_hex);
            let tx = parse_eip155_signing_request(&raw).expect("chain id in range");
            assert_eq!(
                tx.chain_id, chain_id,
                "chain {chain_id} must survive the parse"
            );
        }
    }

    /// The gold EIP-155 preimage (spec example / pool #68) parses to the fields the
    /// core signs, so the request path and the `eip155` gold vector cannot drift.
    #[test]
    fn legacy_signing_request_parses_the_spec_example_preimage() {
        let raw = hex_decode(
            "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080",
        );
        let tx = parse_eip155_signing_request(&raw).expect("spec preimage parses");
        assert_eq!(tx.chain_id, 1);
        assert_eq!(tx.nonce, 9);
        assert_eq!(tx.gas_price, 20_000_000_000);
        assert_eq!(tx.gas_limit, 21_000);
        assert_eq!(tx.destination, Some([0x35u8; 20]));
        assert_eq!(tx.amount, 1_000_000_000_000_000_000);
    }

    /// A payload that already carries `r`/`s` is not a request: signing over it
    /// would hand back someone else's signature as ours. The signed form is still
    /// readable, but only through [`parse_eip155_raw`] — the two entries are not
    /// interchangeable, which is the whole point of having both.
    #[test]
    fn legacy_signing_request_refuses_a_presigned_payload() {
        use crate::chain::eth::eip155::{sign_eip155, Eip155SignInput, Eip155Transaction};
        let tx = Eip155Transaction {
            chain_id: 1,
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new().into(),
        };
        let key = SecretBytes::new([0x46u8; 32]);
        let signed = sign_eip155(&Eip155SignInput {
            tx,
            private_key: &key,
        })
        .unwrap();
        // the signed transaction is readable as a transaction ...
        assert!(parse_eip155_raw(&signed.tx_bytes).is_ok());
        // ... and refused as a signing request
        let e = parse_eip155_signing_request(&signed.tx_bytes)
            .expect_err("a signed payload is not a signing request");
        assert_eq!(e.kind, ShlosiloErrorKind::EncodingInvalidFormat);

        // r/s slots: empty = request, non-empty = pre-signed. Control on the same
        // shape with one slot filled (`... 01 01 80`).
        let with_r = hex_decode(
            "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080010180",
        );
        assert!(
            parse_eip155_signing_request(&with_r).is_err(),
            "a non-empty r slot means the payload is already signed"
        );
    }

    /// The unprotected legacy shape is refused with its own stable code: it is a
    /// known request we will not sign (no replay protection), not a malformed one.
    #[test]
    fn legacy_signing_request_refuses_unprotected_shape_with_a_stable_code() {
        // rlp([nonce=9, gas_price=20 gwei, gas_limit=21000, to, value=1 ETH, data=""])
        let raw = hex_decode(
            "e9098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080",
        );
        let e = parse_eip155_signing_request(&raw).expect_err("6 items = pre-EIP-155, refused");
        assert_eq!(
            e.kind,
            ShlosiloErrorKind::FeatureNotImplemented,
            "the unprotected shape must not read as a generic format error"
        );
    }

    /// Shape and range failures, each its own case: a wrong item count, an empty
    /// payload, `chain_id = 0`, and a chain id wider than u64 (A3c-F7 discipline:
    /// reject, never truncate).
    #[test]
    fn legacy_signing_request_rejects_bad_shapes() {
        let cases: [(&str, &str); 4] = [
            ("", "empty payload"),
            ("c0", "zero items"),
            // 8 items: one signature slot missing
            (
                "e3078506fc23ac0082520894111111111111111111111111111111111111111180800180",
                "8 items",
            ),
            // chain_id = 0
            (
                "e4078506fc23ac008252089411111111111111111111111111111111111111118080808080",
                "chain_id 0",
            ),
        ];
        for (hex, why) in cases {
            assert!(
                parse_eip155_signing_request(&hex_decode(hex)).is_err(),
                "{why} must be rejected"
            );
        }
        // chain id 2^64 + 1 must not truncate to 1
        let raw = hex_decode(
            "ed078506fc23ac008252089411111111111111111111111111111111111111118080890100000000000000018080",
        );
        assert!(
            parse_eip155_signing_request(&raw).is_err(),
            "an oversized chain id must be rejected, not truncated"
        );
    }
}
