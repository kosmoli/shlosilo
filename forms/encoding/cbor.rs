//! CBOR codec (RFC 8949) — Phase 6 P6.0a
//!
//! v2 §2.3 decision: self-implemented encode/decode (a bug = a parse error, not a key leak).
//! Keystone\'s approach uses minicbor, but shlosilo only needs the subset used by the UR registry:
//! uint / bytes / text / array / map / tag (optional) / simple (false/true/null).
//!
//! ## RFC 8949 summary
//!
//! First byte = major(3 bit) << 5 | additional info(5 bit):
//! - major 0: unsigned int；1: negative int (-1-n)；2: byte string；3: text string
//! - 4: array (count)；5: map (pair count)；6: tag；7: float/simple
//! - additional info 24: 1-byte len；25: 2-byte；26: 4-byte；27: 8-byte
//! - major 7 info 20/21/22 = false/true/null

extern crate alloc;
use alloc::vec::Vec;

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

// ─── Encoding ──────────────────────────────────────────────────────────

fn push_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    match arg {
        0..=23 => out.push(m | arg as u8),
        24..=0xff => {
            out.push(m | 24);
            out.push(arg as u8);
        }
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

/// Encode an unsigned int
pub fn encode_uint(n: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    push_head(&mut out, 0, n);
    out
}

/// Encode a byte string
pub fn encode_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + b.len());
    push_head(&mut out, 2, b.len() as u64);
    out.extend_from_slice(b);
    out
}

/// Encode a text string
pub fn encode_text(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + s.len());
    push_head(&mut out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
    out
}

/// Encode an array (items are already-encoded items)
pub fn encode_array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    push_head(&mut out, 4, items.len() as u64);
    for it in items {
        out.extend_from_slice(it);
    }
    out
}

/// Encode an ordered key-value map (keys are already-encoded items)
pub fn encode_map(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    push_head(&mut out, 5, pairs.len() as u64);
    for (k, v) in pairs {
        out.extend_from_slice(k);
        out.extend_from_slice(v);
    }
    out
}

/// Encode a negative int (-1 - n)
pub fn encode_neg(n: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    push_head(&mut out, 1, n);
    out
}

/// Encode a bool
pub fn encode_bool(b: bool) -> Vec<u8> {
    alloc::vec![if b { 0xf5 } else { 0xf4 }]
}

/// Encode tag(n) + inner item (inner already encoded)
pub fn encode_tag(tag: u64, inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + inner.len());
    push_head(&mut out, 6, tag);
    out.extend_from_slice(inner);
    out
}

// ─── Decoding ──────────────────────────────────────────────────────────

/// A decoded CBOR item
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cbor<'a> {
    Uint(u64),
    NegInt(u64), // value = -1 - n
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<Cbor<'a>>),
    /// Map keeps the original pair order (UR registry keys are all uint; sequential lookup suffices)
    Map(Vec<(Cbor<'a>, Cbor<'a>)>),
    /// tag + inner (the UR registry uses 303/304 etc.)
    Tag(u64, alloc::boxed::Box<Cbor<'a>>),
    Bool(bool),
    Null,
}

impl<'a> Cbor<'a> {
    pub fn as_uint(&self) -> Result<u64> {
        match self {
            Cbor::Uint(n) => Ok(*n),
            _ => Err(err()),
        }
    }

    /// Signed int: Uint / NegInt (neg = -1 - n)
    pub fn as_int(&self) -> Result<i128> {
        match self {
            Cbor::Uint(n) => Ok(*n as i128),
            Cbor::NegInt(n) => Ok(-1 - (*n as i128)),
            _ => Err(err()),
        }
    }

    pub fn as_bytes(&self) -> Result<&'a [u8]> {
        match self {
            Cbor::Bytes(b) => Ok(b),
            _ => Err(err()),
        }
    }

    pub fn as_array(&self) -> Result<&[Cbor<'a>]> {
        match self {
            Cbor::Array(a) => Ok(a),
            _ => Err(err()),
        }
    }

    /// Look up a map value by integer key (UR registry map keys are all uint)
    pub fn map_get_uint(&self, key: u64) -> Result<Option<&Cbor<'a>>> {
        match self {
            Cbor::Map(pairs) => Ok(pairs
                .iter()
                .find(|(k, _)| matches!(k, Cbor::Uint(n) if *n == key))
                .map(|(_, v)| v)),
            _ => Err(err()),
        }
    }

    pub fn as_text(&self) -> Result<&'a str> {
        match self {
            Cbor::Text(s) => Ok(s),
            _ => Err(err()),
        }
    }

    /// Strip one layer of tag; return as-is when there is no tag
    pub fn unwrap_tag(&self) -> &Cbor<'a> {
        match self {
            Cbor::Tag(_, inner) => inner,
            other => other,
        }
    }
}

/// X1: recursion depth limit — deeply nested malicious input would blow the stack under panic=abort.
/// The actual UR registry shape is at most ~4 levels deep (tag→map→array→bytes); 64 gives ample margin.
const MAX_DEPTH: usize = 64;

/// Gate4 #4 (2026-09-01 re-review): total node count budget.
/// The node count is naturally bounded by input length (at least 1 byte per node); this limit is an explicit defense line:
/// it prevents depth × width combined constructions (e.g. 64 levels × large arrays per level) from amplifying stack/heap beyond caller expectations.
const MAX_NODES: usize = 16384;

/// P1-02 discipline (2026-09-24 T-01): wire u64 -> usize fallible conversion —
/// lengths that do not fit the target usize are rejected outright instead of being
/// silently truncated by `as usize` (which on 32-bit targets desyncs the parser
/// with a wrong-but-in-bounds take()).
fn wire_len(n: u64) -> Result<usize> {
    usize::try_from(n).map_err(|_| err())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
    nodes: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        // X1 (2026-08-31 re-review remediation): checked_add prevents pos+n overflow (n is a wire-controlled u64)
        let end = self.pos.checked_add(n).ok_or_else(err)?;
        if end > self.bytes.len() {
            return Err(err());
        }
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn read_arg(&mut self, info: u8) -> Result<u64> {
        Ok(match info {
            0..=23 => info as u64,
            24 => self.take(1)?[0] as u64,
            25 => u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
            26 => u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64,
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            // indefinite length (info 31) not supported — the UR registry is entirely definite
            _ => return Err(err()),
        })
    }

    fn read_item(&mut self) -> Result<Cbor<'a>> {
        // X1: depth budget — over limit rejected (error code path, not a panic)
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.depth -= 1;
            return Err(err());
        }
        // Gate4 #4: node budget — each item read counts as one node
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            self.depth -= 1;
            return Err(err());
        }
        let r = self.read_item_inner();
        self.depth -= 1;
        r
    }

    fn read_item_inner(&mut self) -> Result<Cbor<'a>> {
        let head = self.take(1)?[0];
        let major = head >> 5;
        let info = head & 0x1f;
        match major {
            0 => Ok(Cbor::Uint(self.read_arg(info)?)),
            1 => Ok(Cbor::NegInt(self.read_arg(info)?)),
            2 => {
                let len = wire_len(self.read_arg(info)?)?;
                Ok(Cbor::Bytes(self.take(len)?))
            }
            3 => {
                let len = wire_len(self.read_arg(info)?)?;
                let s = core::str::from_utf8(self.take(len)?).map_err(|_| err())?;
                Ok(Cbor::Text(s))
            }
            4 => {
                let count = wire_len(self.read_arg(info)?)?;
                let mut items = Vec::with_capacity(count.min(256));
                for _ in 0..count {
                    items.push(self.read_item()?);
                }
                Ok(Cbor::Array(items))
            }
            5 => {
                let count = wire_len(self.read_arg(info)?)?;
                let mut pairs = Vec::with_capacity(count.min(128));
                for _ in 0..count {
                    let k = self.read_item()?;
                    let v = self.read_item()?;
                    pairs.push((k, v));
                }
                Ok(Cbor::Map(pairs))
            }
            6 => {
                let tag = self.read_arg(info)?;
                let inner = self.read_item()?;
                Ok(Cbor::Tag(tag, alloc::boxed::Box::new(inner)))
            }
            7 => match info {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                22 => Ok(Cbor::Null),
                _ => Err(err()), // float not supported
            },
            _ => unreachable!(),
        }
    }
}

/// Decode a single CBOR item. Requires bytes to contain exactly one complete item (trailing garbage errors).
pub fn decode(bytes: &[u8]) -> Result<Cbor<'_>> {
    let mut d = Decoder {
        bytes,
        pos: 0,
        depth: 0,
        nodes: 0,
    };
    let item = d.read_item()?;
    if d.pos != bytes.len() {
        return Err(err());
    }
    Ok(item)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8949 Appendix A official vectors (uint)
    #[test]
    fn rfc8949_uint_vectors() {
        assert_eq!(encode_uint(0), hex("00"));
        assert_eq!(encode_uint(23), hex("17"));
        assert_eq!(encode_uint(24), hex("1818"));
        assert_eq!(encode_uint(100), hex("1864"));
        assert_eq!(encode_uint(1000), hex("1903e8"));
        assert_eq!(encode_uint(1_000_000), hex("1a000f4240"));
        assert_eq!(encode_uint(1_000_000_000_000), hex("1b000000e8d4a51000"));
        // round trip
        for n in [
            0u64,
            23,
            24,
            255,
            256,
            65535,
            65536,
            4294967295,
            u32::MAX as u64 + 1,
        ] {
            let enc = encode_uint(n);
            match decode(&enc).unwrap() {
                Cbor::Uint(got) => assert_eq!(got, n),
                other => panic!("{other:?}"),
            }
        }
    }

    /// RFC 8949 negative int
    #[test]
    fn rfc8949_negative() {
        assert_eq!(encode_neg(9), hex("29")); // -10
        assert_eq!(encode_neg(99), hex("3863")); // -100
        match decode(&hex("3863")).unwrap() {
            Cbor::NegInt(n) => assert_eq!(-1 - n as i64, -100),
            other => panic!("{other:?}"),
        }
    }

    /// RFC 8949 byte string / text string
    #[test]
    fn rfc8949_strings() {
        // "IETF" = 64 49 45 54 46
        assert_eq!(encode_text("IETF"), hex("6449455446"));
        // %x44 01 02 03 04 (bytes 01020304)
        assert_eq!(encode_bytes(&[1, 2, 3, 4]), hex("4401020304"));
        // >23-byte string uses info 25 (2-byte len)
        let long = [0xab_u8; 300];
        let enc = encode_bytes(&long);
        assert_eq!(enc[0], 0x59);
        assert_eq!(&enc[1..3], &300u16.to_be_bytes());
        match decode(&enc).unwrap() {
            Cbor::Bytes(b) => assert_eq!(b, &long[..]),
            other => panic!("{other:?}"),
        }
    }

    /// RFC 8949 array: [_ 1, [2, 3], [4, 5]] = 83 01 82 02 03 82 04 05
    #[test]
    fn rfc8949_nested_array() {
        let item = encode_array(&[
            encode_uint(1),
            encode_array(&[encode_uint(2), encode_uint(3)]),
            encode_array(&[encode_uint(4), encode_uint(5)]),
        ]);
        assert_eq!(item, hex("8301820203820405"));
        match decode(&item).unwrap() {
            Cbor::Array(a) => {
                assert_eq!(a.len(), 3);
                assert_eq!(a[0].as_uint().unwrap(), 1);
                assert_eq!(a[1].as_array().unwrap()[1].as_uint().unwrap(), 3);
            }
            other => panic!("{other:?}"),
        }
    }

    /// map: {1: 2, "c": bytes} — UR registry shape (uint key)
    #[test]
    fn map_with_uint_keys_round_trip() {
        let m = encode_map(&[
            (encode_uint(1), encode_uint(2)),
            (encode_uint(3), encode_bytes(b"x")),
        ]);
        let dec = decode(&m).unwrap();
        assert_eq!(dec.map_get_uint(1).unwrap().unwrap().as_uint().unwrap(), 2);
        assert_eq!(
            dec.map_get_uint(3).unwrap().unwrap().as_bytes().unwrap(),
            b"x"
        );
        assert!(dec.map_get_uint(9).unwrap().is_none());
    }

    /// simple values: true/false/null; trailing garbage rejected; truncation rejected
    #[test]
    fn simple_and_rejects() {
        assert_eq!(decode(&hex("f4")).unwrap(), Cbor::Bool(false));
        assert_eq!(decode(&hex("f5")).unwrap(), Cbor::Bool(true));
        assert_eq!(decode(&hex("f6")).unwrap(), Cbor::Null);
        // truncated uint
        assert!(decode(&hex("19")).is_err());
        assert!(decode(&hex("1903")).is_err());
        // trailing garbage
        assert!(decode(&hex("0000")).is_err());
        // indefinite length rejected (info 31)
        assert!(decode(&hex("9fff")).is_err());
        // float rejected
        assert!(decode(&hex("fb3ff199999999999a")).is_err());
    }

    /// X1: over-deep nesting rejected (error path, no stack blowup)
    #[test]
    fn deep_nesting_rejected() {
        // 200 levels of nested array > MAX_DEPTH(64)
        let mut deep = alloc::vec![0x81u8; 200]; // 200 x array(1)
        deep.push(0x00); // uint 0
        assert!(decode(&deep).is_err());
        // 63 levels (≤64) pass normally
        let mut ok = alloc::vec![0x81u8; 63];
        ok.push(0x00);
        assert!(decode(&ok).is_ok());
    }

    /// X1: take() length overflow rejected (u64 len as usize + pos overflow)
    #[test]
    fn overflow_len_rejected() {
        // bytes(8) declares an 8-byte length but only 1 byte is given
        assert!(decode(&hex("4b01")).is_err());
        // u64::MAX length declaration (8-byte len = 0xffffffffffffffff)
        let huge = hex("5bffffffffffffffff");
        assert!(decode(&huge).is_err());
    }

    /// tag 304 + bool true
    #[test]
    fn tag_round_trip() {
        let inner = encode_bool(true);
        let enc = encode_tag(304, &inner);
        match decode(&enc).unwrap() {
            Cbor::Tag(304, boxed) => assert_eq!(*boxed, Cbor::Bool(true)),
            other => panic!("{other:?}"),
        }
    }

    /// T-01 (2026-09-24): wire lengths go through fallible `wire_len` (u64 -> usize).
    /// A declaration that does not fit the target usize must be rejected outright on
    /// every width (32-bit: try_from fails; 64-bit: take()/item reads fail) — never
    /// silently truncated into a wrong-but-in-bounds read.
    #[test]
    fn oversized_len_rejected_all_widths() {
        // bytes(0x5b) declaring an 8-byte length 0x00000001_00000001 (would truncate to 1 on 32-bit)
        assert!(decode(&hex("5b0000000100000001")).is_err());
        // array(0x9b) declaring an 8-byte count 0x00000001_00000001
        assert!(decode(&hex("9b0000000100000001")).is_err());
    }
}
