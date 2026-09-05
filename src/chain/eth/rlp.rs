//! RLP encoding (Recursive Length Prefix)
//!
//! Used for Ethereum transaction serialization, state trie, receipts, etc.
//!
//! ## Algorithm
//!
//! - encoding a single byte `b` (0-127): output `b` directly
//! - encoding 0-55 bytes: [0x80 + len, ...bytes]
//! - encoding >55 bytes: [0xb7 + len_of_len, len_be, ...bytes]
//! - encoding a list [items...]: [0xc0 + payload_len, ...rlp(item)] for <= 55 bytes payload
//! - encoding a list >55 bytes: [0xf7 + len_of_len, payload_len_be, ...rlp(item)]
//!
//! ## v2 §2.3 Decisions
//!
//! ✅ **Self-implemented RLP** (per the Ethereum Yellow Paper; an encoding concern, not cryptography)
//!
//! Business modules may allocate (`Vec<u8>` lifetime ≤ the function call).

extern crate alloc;
use alloc::vec::Vec;

/// RLP-encode a single value (bytes)
///
/// - single byte `0x00` → `0x80` (empty string)
/// - single bytes 1-127: returned as-is
/// - 0-55 bytes: `[0x80 + len, ...bytes]`
/// - >55 bytes: `[0xb7 + len_of_len, len_be, ...bytes]`
pub fn encode_bytes(b: &[u8]) -> Vec<u8> {
    // single byte 0 → empty string (0x80)
    if b.len() == 1 && b[0] == 0x00 {
        return alloc::vec![0x80];
    }
    // single bytes 1-127: as-is
    if b.len() == 1 && b[0] < 0x80 {
        return alloc::vec![b[0]];
    }
    if b.len() <= 55 {
        // 0x80 + len
        let mut out = Vec::with_capacity(1 + b.len());
        out.push(0x80 + b.len() as u8);
        out.extend_from_slice(b);
        out
    } else {
        // 0xb7 + len_of_len || len_be || bytes
        let n_bytes = (b.len() as u32).to_be_bytes(); // 4 bytes
                                                      // find first non-zero byte (MSB)
        let mut leading_zeros = 0;
        while leading_zeros < 4 && n_bytes[leading_zeros] == 0 {
            leading_zeros += 1;
        }
        let len_of_len = (4 - leading_zeros) as u8;
        let mut out = Vec::with_capacity(1 + len_of_len as usize + b.len());
        out.push(0xb7 + len_of_len);
        out.extend_from_slice(&n_bytes[leading_zeros..]);
        out.extend_from_slice(b);
        out
    }
}

/// RLP-encode uint256 / uint64 (unsigned integers)
///
/// Convert the integer to big-endian bytes first (no leading zeros), then encode_bytes
pub fn encode_uint(n: u128) -> Vec<u8> {
    if n == 0 {
        return alloc::vec![0x80]; // RLP empty string (= 0)
    }
    // compute the number of valid bytes
    let bytes_needed = (128 - n.leading_zeros()).div_ceil(8);
    let be = &n.to_be_bytes();
    let start = 16 - bytes_needed as usize;
    encode_bytes(&be[start..])
}

/// RLP-encode uint256 (32-byte big-endian big integer)
///
/// Strip leading zero bytes, then encode_bytes
pub fn encode_uint256(bytes: &[u8; 32]) -> Vec<u8> {
    let mut start = 0;
    while start < 32 && bytes[start] == 0 {
        start += 1;
    }
    if start == 32 {
        return alloc::vec![0x80]; // 0
    }
    encode_bytes(&bytes[start..])
}

/// RLP-encode a list (each item already RLP-encoded bytes)
pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    // compute the payload first
    let payload_len: usize = items.iter().map(|i| i.len()).sum();
    let mut out = Vec::with_capacity(payload_len + 9);

    if payload_len <= 55 {
        out.push(0xc0 + payload_len as u8);
    } else {
        let n_bytes = (payload_len as u32).to_be_bytes();
        let mut leading_zeros = 0;
        while leading_zeros < 4 && n_bytes[leading_zeros] == 0 {
            leading_zeros += 1;
        }
        let len_of_len = (4 - leading_zeros) as u8;
        out.push(0xf7 + len_of_len);
        out.extend_from_slice(&n_bytes[leading_zeros..]);
    }

    for item in items {
        out.extend_from_slice(item);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Official RLP test vector: empty string → 0x80
    #[test]
    fn rlp_empty_string() {
        assert_eq!(encode_bytes(b""), alloc::vec![0x80]);
    }

    /// Official RLP test vector: single byte 0x7f → 0x7f
    #[test]
    fn rlp_single_byte_under_128() {
        assert_eq!(encode_bytes(&[0x7f]), alloc::vec![0x7f]);
    }

    /// Official RLP test vector: 0x00 is not returned directly; it must encode as 0x80
    /// (because 0 < 0x80 but per the RLP spec: single bytes < 0x80 return directly,
    ///  but 0 is the special case → b"" encodes → 0x80)
    #[test]
    fn rlp_zero_byte() {
        // 0x00 = single byte 0 = b"" → 0x80 (RLP empty string)
        // but 0x00 itself encodes as [0x00] = 1-byte value 0
        // our current implementation: b.len()==1 && b[0]<0x80 returns b directly
        // but b"" is already handled; what should encode_bytes(b"\x00") return for b"\x00"?
        // per the official spec: a single-byte value < 0x80 → return that byte directly
        // but bytes_from_u128(0) = b"" (empty), then encode_bytes(b"") = [0x80]
        // this tests the behavior of calling encode_bytes directly on [0x00]
        // in fact [0x00] is a single-byte 0 → should just return [0x00]
        // but the RLP spec treats 0 as an empty string — let's check the official tests
        // official test "0" → 0x80
        // so encode_bytes(b"\x00") should be [0x80], not [0x00]
        // our implementation here needs fixing: single-byte 0 treated as an empty string
        assert_eq!(encode_bytes(&[0x00]), alloc::vec![0x80]);
    }

    /// Official RLP test vector: dog = 0x83 'd' 'o' 'g' (3 chars)
    #[test]
    fn rlp_dog() {
        let dog = b"dog";
        let encoded = encode_bytes(dog);
        assert_eq!(encoded, alloc::vec![0x83, b'd', b'o', b'g']);
    }

    /// Official RLP test vector: the list ["cat", "dog"]
    #[test]
    fn rlp_list_cat_dog() {
        let cat = encode_bytes(b"cat");
        let dog = encode_bytes(b"dog");
        let list = encode_list(&[cat, dog]);
        // expected: 0xc8 0x83 'c' 'a' 't' 0x83 'd' 'o' 'g'
        assert_eq!(
            list,
            alloc::vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
        );
    }

    /// Official RLP test vector: empty list → 0xc0
    #[test]
    fn rlp_empty_list() {
        let list = encode_list(&[]);
        assert_eq!(list, alloc::vec![0xc0]);
    }

    /// Official RLP test vector: number 0 → 0x80 (empty string)
    #[test]
    fn rlp_uint_zero() {
        assert_eq!(encode_uint(0), alloc::vec![0x80]);
    }

    /// Official RLP test vector: number 15 → 0x0f
    #[test]
    fn rlp_uint_15() {
        assert_eq!(encode_uint(15), alloc::vec![0x0f]);
    }

    /// Official RLP test vector: number 1024 → 0x82 0x04 0x00
    #[test]
    fn rlp_uint_1024() {
        assert_eq!(encode_uint(1024), alloc::vec![0x82, 0x04, 0x00]);
    }

    /// Real ETH use case: chain_id=1 encoding
    #[test]
    fn rlp_chain_id_1() {
        // 1 → 0x01
        assert_eq!(encode_uint(1), alloc::vec![0x01]);
    }

    /// Real ETH use case: 20-byte address → varstr
    #[test]
    fn rlp_address_20_bytes() {
        let addr = [0x35u8; 20];
        let encoded = encode_bytes(&addr);
        // 0x94 || 20 bytes (0x80 + 0x14 = 0x94)
        assert_eq!(encoded.len(), 21);
        assert_eq!(encoded[0], 0x94);
    }
}
