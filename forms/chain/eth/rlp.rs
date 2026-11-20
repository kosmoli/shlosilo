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
//! Production paths use the zero-alloc `RlpWriter` (the `encode_* -> Vec<u8>`
//! family below is test/legacy convenience API).

#[cfg(any(feature = "alloc-fallback", test))]
extern crate alloc;
#[cfg(any(feature = "alloc-fallback", test))]
use alloc::vec::Vec;

/// RLP-encode a single value (bytes)
///
/// - single bytes 0x00-0x7f: returned as-is (a one-byte payload is its own encoding;
///   only INTEGERS map zero to the empty string, and that happens in `encode_uint`)
/// - 0-55 bytes: `[0x80 + len, ...bytes]`
/// - >55 bytes: `[0xb7 + len_of_len, len_be, ...bytes]`
#[cfg(any(feature = "alloc-fallback", test))]
pub fn encode_bytes(b: &[u8]) -> Vec<u8> {
    // single bytes 0x00-0x7f: as-is
    // A3c-F3 (external audit 2026-11-19, verified 2026-11-20): this used to special-case the single
    // byte 0x00 into the empty string 0x80. That is the INTEGER rule, and it already lives in
    // `encode_uint`/`write_uint`; applying it to a byte string silently turned calldata `0x00` into
    // empty calldata — the signed transaction was not the one that had been reviewed.
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
#[cfg(any(feature = "alloc-fallback", test))]
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
#[cfg(any(feature = "alloc-fallback", test))]
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
#[cfg(any(feature = "alloc-fallback", test))]
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

// --- Zero-alloc streaming form (production) --------------------------
//
// Byte-for-byte equivalent to the `encode_*` conveniences above. A one-byte payload
// 0x00-0x7f is its own encoding; only integers map zero to the empty string (0x80),
// and that rule lives in `write_uint` / `write_uint256` (A3c-F3, 2026-11-20).
//
// The writers are generic over `Sink` (types/push.rs): the signing preimage
// can stream straight into `KeccakSink` with NO intermediate buffer, and
// output serialization goes through `SinkCursor` over the caller's buffer.

use crate::error::Result;
use crate::types::push::Sink;

/// Byte length of `encode_bytes(b)`'s output.
pub fn encoded_bytes_len(b: &[u8]) -> usize {
    if b.len() == 1 && b[0] < 0x80 {
        return 1;
    }
    if b.len() <= 55 {
        return 1 + b.len();
    }
    let n_bytes = (b.len() as u32).to_be_bytes();
    let mut leading_zeros = 0;
    while leading_zeros < 4 && n_bytes[leading_zeros] == 0 {
        leading_zeros += 1;
    }
    1 + (4 - leading_zeros) + b.len()
}

/// Byte length of `encode_uint(n)`'s output.
pub fn encoded_uint_len(n: u128) -> usize {
    if n == 0 {
        return 1;
    }
    let bytes_needed = (128 - n.leading_zeros()).div_ceil(8) as usize;
    let be = n.to_be_bytes();
    // A3c-F4 (external audit 2026-11-19, verified 2026-11-20): this used to add up the length from
    // the payload SIZE alone, which is wrong for a single payload byte >= 0x80 — that one encodes as
    // `0x81 xx` (two bytes). Delegating to the slice-aware helper keeps one rule in one place.
    encoded_bytes_len(&be[16 - bytes_needed..])
}

/// Byte length of `encode_uint256(bytes)`'s output.
pub fn encoded_uint256_len(bytes: &[u8; 32]) -> usize {
    let mut start = 0;
    while start < 32 && bytes[start] == 0 {
        start += 1;
    }
    // all-zero → empty payload → 1 byte (0x80); otherwise delegate (A3c-F4, same rule as above)
    encoded_bytes_len(&bytes[start..])
}

/// Byte length of an RLP list header over `payload_len` payload bytes.
pub fn list_head_len(payload_len: usize) -> usize {
    if payload_len <= 55 {
        1
    } else {
        let n_bytes = (payload_len as u32).to_be_bytes();
        let mut leading_zeros = 0;
        while leading_zeros < 4 && n_bytes[leading_zeros] == 0 {
            leading_zeros += 1;
        }
        1 + (4 - leading_zeros)
    }
}

/// RLP string into a sink — same bytes as `encode_bytes`.
pub fn write_bytes<S: Sink>(s: &mut S, b: &[u8]) -> Result<()> {
    // A3c-F3 (2026-11-20): the single-zero special case used to live here. It belongs to the
    // INTEGER writers (`write_uint(0)` → 0x80), not to byte strings: as a byte string, 0x00 is a
    // 1-byte payload and encodes as itself.
    if b.len() == 1 && b[0] < 0x80 {
        return s.put(b);
    }
    if b.len() <= 55 {
        s.put(&[0x80 + b.len() as u8])?;
        return s.put(b);
    }
    let n_bytes = (b.len() as u32).to_be_bytes();
    let mut leading_zeros = 0;
    while leading_zeros < 4 && n_bytes[leading_zeros] == 0 {
        leading_zeros += 1;
    }
    let len_of_len = (4 - leading_zeros) as u8;
    s.put(&[0xb7 + len_of_len])?;
    s.put(&n_bytes[leading_zeros..])?;
    s.put(b)
}

/// RLP uint into a sink — same bytes as `encode_uint`.
pub fn write_uint<S: Sink>(s: &mut S, n: u128) -> Result<()> {
    if n == 0 {
        return s.put(&[0x80]);
    }
    let bytes_needed = (128 - n.leading_zeros()).div_ceil(8);
    let be = n.to_be_bytes();
    let start = 16 - bytes_needed as usize;
    write_bytes(s, &be[start..])
}

/// RLP uint256 into a sink — same bytes as `encode_uint256`.
pub fn write_uint256<S: Sink>(s: &mut S, bytes: &[u8; 32]) -> Result<()> {
    let mut start = 0;
    while start < 32 && bytes[start] == 0 {
        start += 1;
    }
    if start == 32 {
        return s.put(&[0x80]);
    }
    write_bytes(s, &bytes[start..])
}

/// RLP list header over a pre-computed `payload_len` — same bytes as
/// `encode_list`'s header.
pub fn write_list_head<S: Sink>(s: &mut S, payload_len: usize) -> Result<()> {
    if payload_len <= 55 {
        return s.put(&[0xc0 + payload_len as u8]);
    }
    let n_bytes = (payload_len as u32).to_be_bytes();
    let mut leading_zeros = 0;
    while leading_zeros < 4 && n_bytes[leading_zeros] == 0 {
        leading_zeros += 1;
    }
    let len_of_len = (4 - leading_zeros) as u8;
    s.put(&[0xf7 + len_of_len])?;
    s.put(&n_bytes[leading_zeros..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::push::SinkCursor;

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

    /// A3c-F3 (2026-11-20): the byte string `0x00` and the integer 0 are different values and encode
    /// differently. The old version of this test pinned the wrong one (byte string → 0x80); the RLP
    /// rule is "a single byte < 0x80 is its own encoding", and only integers strip to the empty string.
    #[test]
    fn rlp_zero_byte() {
        // byte string of length 1, value 0 → itself
        assert_eq!(encode_bytes(&[0x00]), alloc::vec![0x00]);
        // integer 0 → empty string
        assert_eq!(encode_uint(0), alloc::vec![0x80]);
        // empty byte string → empty string
        assert_eq!(encode_bytes(b""), alloc::vec![0x80]);
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

    /// A3c-F4 (2026-11-20): the length helper must agree with the writer for EVERY value, including
    /// the single payload bytes >= 0x80 — those encode as `0x81 xx` (2 bytes), not as one byte.
    /// Expected bytes below come from the independent Python RLP oracle.
    #[test]
    fn encoded_uint_len_matches_the_oracle_table() {
        let cases: [(u128, &str); 14] = [
            (0, "80"),
            (1, "01"),
            (15, "0f"),
            (127, "7f"),
            (128, "8180"),
            (129, "8181"),
            (137, "8189"),
            (200, "81c8"),
            (255, "81ff"),
            (256, "820100"),
            (65535, "82ffff"),
            (65536, "83010000"),
            (u64::MAX as u128, "88ffffffffffffffff"),
            (u128::MAX, "90ffffffffffffffffffffffffffffffff"),
        ];
        for (n, expected_hex) in cases {
            let expected_len = expected_hex.len() / 2;
            assert_eq!(
                encoded_uint_len(n),
                expected_len,
                "encoded_uint_len({n}) disagrees with the oracle"
            );
            // and the writer must actually produce that many bytes (internal consistency)
            let mut buf = [0u8; 64];
            let mut w = SinkCursor::new(&mut buf);
            write_uint(&mut w, n).unwrap();
            assert_eq!(w.pos(), expected_len, "write_uint({n}) length");
        }
    }

    /// Same for the uint256 form (signature r/s go through it).
    #[test]
    fn encoded_uint256_len_matches_the_oracle() {
        // stripped payload 0x80 / 0xff -> 2 bytes; 0x0102 -> 3 bytes; value 1 -> 1; all-zero -> 1
        let mut b = [0u8; 32];
        b[31] = 0x80;
        assert_eq!(encoded_uint256_len(&b), 2);
        b[31] = 0xff;
        assert_eq!(encoded_uint256_len(&b), 2);
        b[30] = 0x01;
        b[31] = 0x02;
        assert_eq!(encoded_uint256_len(&b), 3);
        assert_eq!(encoded_uint256_len(&[0u8; 32]), 1);
        let mut one = [0u8; 32];
        one[31] = 0x01;
        assert_eq!(encoded_uint256_len(&one), 1);
        // full 32-byte payload (r/s normally): 0x81 prefix + 32 bytes for a leading byte >= 0x80?
        // No — a 32-byte payload always takes the `0x80 + len` form: 1 + 32.
        let mut full = [0xffu8; 32];
        assert_eq!(encoded_uint256_len(&full), 33);
        full[0] = 0x7f;
        assert_eq!(encoded_uint256_len(&full), 33);
        // internal consistency against the writer for a few shapes
        for lead in [0x01u8, 0x7f, 0x80, 0xff] {
            let mut b = [0u8; 32];
            b[0] = lead;
            b[31] = 0x33;
            let mut buf = [0u8; 64];
            let mut w = SinkCursor::new(&mut buf);
            write_uint256(&mut w, &b).unwrap();
            assert_eq!(
                encoded_uint256_len(&b),
                w.pos(),
                "uint256 len vs writer (lead {:02x})",
                lead
            );
        }
    }

    /// A3c-F3 (2026-11-20): a single 0x00 BYTE is a byte string of length 1 and must encode as itself.
    /// Only integers map zero to the empty string (that path is `write_uint(0)`), so `write_bytes`
    /// must not rewrite it.
    #[test]
    fn single_zero_byte_is_a_byte_string_not_an_empty_string() {
        let mut buf = [0u8; 8];
        let n = {
            let mut w = SinkCursor::new(&mut buf);
            write_bytes(&mut w, &[0x00]).unwrap();
            w.pos()
        };
        assert_eq!(&buf[..n], &[0x00], "byte string 0x00 must stay 0x00");

        // control: 0x01 and other sub-0x80 bytes were already correct
        let mut buf = [0u8; 8];
        let n = {
            let mut w = SinkCursor::new(&mut buf);
            write_bytes(&mut w, &[0x01]).unwrap();
            w.pos()
        };
        assert_eq!(&buf[..n], &[0x01]);

        // integer zero still maps to the empty string
        let mut buf = [0u8; 8];
        let n = {
            let mut w = SinkCursor::new(&mut buf);
            write_uint(&mut w, 0).unwrap();
            w.pos()
        };
        assert_eq!(&buf[..n], &[0x80]);
    }
}
