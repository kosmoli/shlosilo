//! base58 + base58check encoding (BTC legacy + XRP + SOL)
//!
//! **Phase 4 real implementation** (v2 §3.5 principle — L1 encodings implemented in-house, no alloc-crate dependency):
//! - the base58 algorithm core = treat the byte slice as a big integer, repeatedly divide by 58 and take remainders
//! - base58check = base58(data || sha256(sha256(data))[:4])
//!
//! **Why implement it in-house**: base58 is a character-set conversion + checksum algorithm, **involving no key inputs**;
//! the risk = a wrongly displayed string (no key leakage). Cryptographic primitives (sha256/sha512/k256/ed25519-dalek)
//! keep crate dependencies; encoding modules are implemented in-house to strictly honor v2 §3.5 zero heap allocation.

use crate::encoding::sha256;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// base58check string maximum length
pub const BASE58_MAX_LEN: usize = 128;

/// base58 character table (no 0/I/O/l)
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Reverse lookup table (255 = invalid)
fn base58_inverse() -> [u8; 256] {
    let mut inv = [255u8; 256];
    for (i, &c) in BASE58_ALPHABET.iter().enumerate() {
        inv[c as usize] = i as u8;
    }
    inv
}

#[derive(Clone, PartialEq, Eq)]
pub struct Base58String {
    bytes: heapless::String<BASE58_MAX_LEN>,
}

impl AsRef<str> for Base58String {
    fn as_ref(&self) -> &str {
        self.bytes.as_str()
    }
}

impl core::fmt::Display for Base58String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.bytes)
    }
}

impl core::fmt::Debug for Base58String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = self.bytes.as_str();
        if s.len() > 12 {
            write!(f, "Base58String({}…{})", &s[..4], &s[s.len() - 4..])
        } else {
            write!(f, "Base58String(<redacted>)")
        }
    }
}

/// base58 encode (no checksum)
///
/// Algorithm:
/// 1. Count the number of leading 0x00 bytes
/// 2. Treat the input bytes as a big integer, repeatedly divide by 58 → output characters in reverse
/// 3. Leading 0x00 bytes → leading '1' characters
///
/// **v0.4.0 implementation**: modeled on bitcoinjs-lib / bitcoin core
pub fn encode(data: &[u8]) -> Result<Base58String> {
    // 1. Count the number of leading 0x00 bytes
    let mut leading_zeros = 0;
    for &b in data.iter() {
        if b == 0 {
            leading_zeros += 1;
        } else {
            break;
        }
    }

    // 2. Big integer division by 58 (heapless::Vec<u8, 256> as workspace)
    let mut working = heapless::Vec::<u8, 256>::new();
    working
        .extend_from_slice(data)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;

    let mut result_bytes: heapless::Vec<u8, BASE58_MAX_LEN> = heapless::Vec::new();

    // Compute the number of characters to output = leading_zeros + log58(data) ≈ leading_zeros + log58(max_value)
    // Simple approach: divide by 58 while working is not all zero
    loop {
        // check whether all zero
        let mut all_zero = true;
        for &b in working.iter() {
            if b != 0 {
                all_zero = false;
                break;
            }
        }
        if all_zero {
            // output leading_zeros '1's (BASE58_ALPHABET[0])
            for _ in 0..leading_zeros {
                result_bytes
                    .push(BASE58_ALPHABET[0])
                    .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
            }
            break;
        }

        // big integer division by 58
        let mut remainder: usize = 0;
        let mut new_working = heapless::Vec::<u8, 256>::new();
        for &b in working.iter() {
            let acc = remainder * 256 + b as usize;
            let q = acc / 58;
            remainder = acc % 58;
            if !(new_working.is_empty() && q == 0) {
                new_working
                    .push(q as u8)
                    .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
            }
            // carry unchanged (acc already spread into q and remainder)
            let _ = remainder;
        }
        result_bytes
            .push(BASE58_ALPHABET[remainder])
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
        working = new_working;
    }

    // 3. Reverse result_bytes → output
    let mut out = heapless::String::<BASE58_MAX_LEN>::new();
    for &b in result_bytes.iter().rev() {
        out.push(b as char)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }

    Ok(Base58String { bytes: out })
}

/// base58check encode (with sha256d checksum)
///
/// `base58(data || sha256(sha256(data))[:4])`
pub fn encode_check(data: &[u8]) -> Result<Base58String> {
    let double_hash = sha256::hash_twice(data)?;
    let checksum = &double_hash[..4];

    let mut with_checksum = heapless::Vec::<u8, 256>::new();
    with_checksum
        .extend_from_slice(data)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    with_checksum
        .extend_from_slice(checksum)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;

    encode(&with_checksum)
}

/// base58 decode
///
/// Algorithm: treat the string as a base58 number, working (low byte first) = working * 58 + n
/// Z3.4 (T-05 frozen shape): base58 decode into a caller buffer.
/// Over-cap output raises EncodingBufferOverflow (never truncation).
pub fn decode_into(s: &str, out: &mut [u8]) -> Result<usize> {
    let decoded = decode(s)?;
    if out.len() < decoded.len() {
        return Err(ShlosiloError::new(
            ShlosiloErrorKind::EncodingBufferOverflow,
        ));
    }
    out[..decoded.len()].copy_from_slice(&decoded);
    Ok(decoded.len())
}

/// T-05 shape pins (Z3.4): the public forms are `*_into`; these pins freeze
/// the signatures against drift.
#[cfg(test)]
mod t05_shape {
    use super::*;
    const _: fn(&str, &mut [u8]) -> Result<usize> = decode_into;
    const _: fn(&str, &mut [u8]) -> Result<usize> = decode_check_into;
}

/// Internal/test shape (heapless working buffer — allowed internally per the
/// T-05 disposition; the frozen PUBLIC shape is [`decode_into`]).
pub(crate) fn decode(s: &str) -> Result<heapless::Vec<u8, 192>> {
    let inv = base58_inverse();

    let mut leading_ones = 0;
    let mut working = heapless::Vec::<u8, 192>::new();
    let mut started = false;

    for c in s.bytes() {
        if c == b'1' && !started {
            leading_ones += 1;
            continue;
        }
        started = true;
        let n = inv[c as usize];
        if n == 255 {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }

        // working = working * 58 + n (single-pass algorithm)
        let mut carry: usize = n as usize;
        for i in 0..working.len() {
            let acc = carry + (working[i] as usize) * 58;
            working[i] = (acc % 256) as u8;
            carry = acc / 256;
        }
        while carry > 0 {
            working
                .push((carry % 256) as u8)
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
            carry /= 256;
        }
    }

    // Output: leading_ones 0x00 bytes + working reversed (little-endian → big-endian = original byte order)
    let mut result = heapless::Vec::<u8, 192>::new();
    for _ in 0..leading_ones {
        result
            .push(0)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }
    for &b in working.iter().rev() {
        result
            .push(b)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }

    Ok(result)
}

/// base58check decode (verifies the checksum)
/// Z3.4 (T-05 frozen shape): base58 decode+checksum into a caller buffer.
pub fn decode_check_into(s: &str, out: &mut [u8]) -> Result<usize> {
    let decoded = decode_check(s)?;
    if out.len() < decoded.len() {
        return Err(ShlosiloError::new(
            ShlosiloErrorKind::EncodingBufferOverflow,
        ));
    }
    out[..decoded.len()].copy_from_slice(&decoded);
    Ok(decoded.len())
}

/// Internal/test shape — the frozen PUBLIC shape is [`decode_check_into`].
pub(crate) fn decode_check(s: &str) -> Result<heapless::Vec<u8, 128>> {
    let decoded = decode(s)?;
    if decoded.len() < 4 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    let split = decoded.len() - 4;
    let (data, checksum) = decoded.split_at(split);

    let expected = sha256::hash_twice(data)?;
    if &expected[..4] != checksum {
        return Err(ShlosiloError::new(
            ShlosiloErrorKind::EncodingInvalidChecksum,
        ));
    }

    let mut result = heapless::Vec::<u8, 128>::new();
    result
        .extend_from_slice(data)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BTC P2PKH address base58check standard test vector
    /// Pubkey hash: 010966776006953D5567439E5E39F86A0D273BEE
    /// Version: 0x00 (mainnet P2PKH)
    /// Expected: 16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM
    #[test]
    fn encode_check_p2pkh() {
        let data = [
            0x00u8, 0x01, 0x09, 0x66, 0x77, 0x60, 0x06, 0x95, 0x3d, 0x55, 0x67, 0x43, 0x9e, 0x5e,
            0x39, 0xf8, 0x6a, 0x0d, 0x27, 0x3b, 0xee,
        ];
        let result = encode_check(&data).unwrap();
        assert_eq!(result.as_ref(), "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM");
    }

    /// decode_check round-trip
    #[test]
    fn decode_check_round_trip() {
        let original = [
            0x00u8, 0x01, 0x09, 0x66, 0x77, 0x60, 0x06, 0x95, 0x3d, 0x55, 0x67, 0x43, 0x9e, 0x5e,
            0x39, 0xf8, 0x6a, 0x0d, 0x27, 0x3b, 0xee,
        ];
        let encoded = encode_check(&original).unwrap();
        let decoded = decode_check(encoded.as_ref()).unwrap();
        assert_eq!(decoded.as_slice(), &original[..]);
    }

    /// checksum error → returns error
    #[test]
    fn decode_check_wrong_checksum_rejected() {
        let data = [
            0x00u8, 0x01, 0x09, 0x66, 0x77, 0x60, 0x06, 0x95, 0x3d, 0x55, 0x67, 0x43, 0x9e, 0x5e,
            0x39, 0xf8, 0x6a, 0x0d, 0x27, 0x3b, 0xee,
        ];
        let encoded = encode_check(&data).unwrap();
        let encoded_str = encoded.as_ref();
        let last_char = encoded_str.chars().last().unwrap();
        let bad_last = if last_char == 'A' { 'B' } else { 'A' };
        let mut bad_chars: heapless::String<BASE58_MAX_LEN> = heapless::String::new();
        for (i, c) in encoded_str.chars().enumerate() {
            if i == encoded_str.len() - 1 {
                bad_chars.push(bad_last).unwrap();
            } else {
                bad_chars.push(c).unwrap();
            }
        }
        let result = decode_check(bad_chars.as_str());
        assert!(result.is_err());
    }

    /// base58 encoding empty input → empty string
    #[test]
    fn encode_empty() {
        let result = encode(&[]).unwrap();
        assert_eq!(result.as_ref(), "");
    }

    /// base58 encoding a single 0x00 byte → "1"
    #[test]
    fn encode_single_zero() {
        let result = encode(&[0x00]).unwrap();
        assert_eq!(result.as_ref(), "1");
    }

    /// base58 encoding multiple leading 0x00s → multiple '1's
    #[test]
    fn encode_multiple_leading_zeros() {
        let result = encode(&[0x00, 0x00, 0x00]).unwrap();
        assert_eq!(result.as_ref(), "111");
    }

    /// base58 decode + encode round-trip
    #[test]
    fn decode_encode_round_trip() {
        let original = b"hello world";
        let encoded = encode(original).unwrap();
        let decoded = decode(encoded.as_ref()).unwrap();
        assert_eq!(decoded.as_slice(), original);
    }

    /// invalid character → returns error
    #[test]
    fn decode_invalid_char_rejected() {
        // '0' is not in the base58 character set
        let r = decode("0ab");
        assert!(r.is_err());
    }
}
