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

#[cfg(feature = "alloc-fallback")]
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
                (&bytes[1..1 + len], &bytes[1 + len..])
            }
            0xb8..=0xbf => {
                let lol = (b0 - 0xb7) as usize;
                if bytes.len() < 1 + lol {
                    return Err(err());
                }
                let mut len = 0usize;
                for &b in &bytes[1..1 + lol] {
                    len = (len << 8) | b as usize;
                }
                if bytes.len() < 1 + lol + len {
                    return Err(err());
                }
                (&bytes[1 + lol..1 + lol + len], &bytes[1 + lol + len..])
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
                if bytes.len() < 1 + lol {
                    return Err(err());
                }
                let mut len = 0usize;
                for &b in &bytes[1..1 + lol] {
                    len = (len << 8) | b as usize;
                }
                if bytes.len() < 1 + lol + len {
                    return Err(err());
                }
                (&bytes[1 + lol..1 + lol + len], &bytes[1 + lol + len..])
            }
        };
        let item = match b0 {
            0x00..=0xb7 => Rlp::Str(payload),
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

/// Parse a raw EIP-1559 signed tx (`0x02 || rlp([...12 fields])`)
///
/// Returns the unsigned part (chain_id cannot be recovered from the signature — it's the list's item 0).
/// Returns Err when access_list is non-empty (out of v2 scope).
pub fn parse_eip1559_raw(raw: &[u8]) -> Result<Eip1559Transaction<'_>> {
    if raw.first() != Some(&0x02) {
        return Err(err());
    }
    let (top, tail) = Rlp::read(&raw[1..])?;
    if !tail.is_empty() {
        return Err(err());
    }
    let fields = top.as_list_items()?;
    if fields.len() != 12 {
        return Err(err());
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
    // fields[9..12] = y_parity, r, s — parse only cares that the structure is legal
    for f in &fields[9..12] {
        let _ = f.as_str()?;
    }
    Ok(Eip1559Transaction {
        chain_id: chain_id as u64,
        nonce: nonce as u64,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit: gas_limit as u64,
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
    let v = be_to_u128(fields[6].as_str()?)? as u64;
    if v < 35 {
        return Err(err()); // pre-EIP-155 unsupported
    }
    for f in &fields[7..9] {
        let _ = f.as_str()?;
    }
    Ok(Eip155Transaction {
        chain_id: ((v - 35) / 2) as u64,
        nonce: nonce as u64,
        gas_price,
        gas_limit: gas_limit as u64,
        destination,
        amount,
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    // Alloc surface: consumers behind alloc-fallback / cfg(test).
    #[cfg(feature = "alloc-fallback")]
    #[cfg(feature = "alloc-fallback")]
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
        let signed = sign_eip155(&Eip155SignInput {
            tx,
            private_key: SecretBytes::new([0x46u8; 32]),
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
}
