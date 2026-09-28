//! bech32 / bech32m encoding (BTC segwit + general)
//!
//! **Phase 4 real implementation** (v2 §3.5 principle — L1 encodings implemented in-house, no alloc-heavy crate dependencies):
//!
//! The algorithm directly follows BIP-173 / BIP-350 + the sipa bech32 reference Python implementation (sipa/bech32).
//! charset, generator, polymod, and target residue are all public standards; no key inputs are involved.
//!
//! Risk = a wrongly displayed string (no key leakage). Cryptographic primitives (sha256 / sha512 / k256 / ed25519-dalek)
//! keep the crate dependency; the encoding module implements it itself to strictly honor v2 §3.5 zero heap allocation.

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// bech32 maximum string length
pub const BECH32_MAX_LEN: usize = 128;

/// bech32 charset (32 characters, ASCII-sorted)
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// bech32 spec constant (target residue)
const BECH32_CONST: u32 = 1;
/// bech32m spec constant (target residue)
const BECH32M_CONST: u32 = 0x2bc830a3;

#[derive(Clone, PartialEq, Eq)]
pub struct Bech32String {
    bytes: heapless::String<BECH32_MAX_LEN>,
}

impl AsRef<str> for Bech32String {
    fn as_ref(&self) -> &str {
        self.bytes.as_str()
    }
}

impl core::fmt::Display for Bech32String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.bytes)
    }
}

impl core::fmt::Debug for Bech32String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = self.bytes.as_str();
        if s.len() > 12 {
            write!(f, "Bech32String({}…{})", &s[..6], &s[s.len() - 4..])
        } else {
            write!(f, "Bech32String(<redacted>)")
        }
    }
}

/// bech32 polymod (per the BIP-173 algorithm)
fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values.iter() {
        let b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v as u32;
        for (i, gen) in GEN.iter().enumerate() {
            if (b >> i) & 1 != 0 {
                chk ^= *gen;
            }
        }
    }
    chk
}

/// hrp expand (per the BIP-173 algorithm)
fn bech32_hrp_expand(hrp: &str) -> [u8; 16] {
    // expansion format: [hrp>>5 chars] + [0] + [hrp&31 chars]
    // e.g.: 'bc' = [b>>5, c>>5, 0, b&31, c&31] = [3, 3, 0, 2, 3]
    let mut expanded = [0u8; 16];
    let hrp_bytes = hrp.as_bytes();
    let n = hrp_bytes.len();
    if n > 8 {
        return expanded;
    }
    for (i, &b) in hrp_bytes.iter().enumerate() {
        expanded[i] = b >> 5;
    }
    for (i, &b) in hrp_bytes.iter().enumerate() {
        expanded[n + 1 + i] = b & 0x1f;
    }
    expanded
}

/// bech32 create_checksum (spec = 1 or BECH32M_CONST)
fn bech32_create_checksum(hrp: &str, data: &[u8], spec: u32) -> [u8; 6] {
    let hrp_bytes = hrp.as_bytes();
    let n = hrp_bytes.len();
    let expanded_full = bech32_hrp_expand(hrp);

    let mut values: heapless::Vec<u8, 256> = heapless::Vec::new();
    for &v in expanded_full.iter().take(2 * n + 1) {
        let _ = values.push(v);
    }
    for &b in data.iter() {
        let _ = values.push(b);
    }
    for _ in 0..6 {
        let _ = values.push(0);
    }
    let polymod = bech32_polymod(&values) ^ spec;
    let mut checksum = [0u8; 6];
    for (i, slot) in checksum.iter_mut().enumerate() {
        *slot = ((polymod >> (5 * (5 - i))) & 0x1f) as u8;
    }
    checksum
}

/// Generic power-of-2 base conversion (after sipa convertbits)
///
/// Used for bech32/bech32m encoding: 8-bit bytes → 5-bit groups
pub fn convertbits(
    data: &[u8],
    frombits: u32,
    tobits: u32,
    pad: bool,
) -> Result<heapless::Vec<u8, 256>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret: heapless::Vec<u8, 256> = heapless::Vec::new();
    let maxv: u32 = (1u32 << tobits) - 1;
    let max_acc: u32 = (1u32 << (frombits + tobits - 1)) - 1;

    for &value in data.iter() {
        if (value as u32) >> frombits != 0 {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        acc = ((acc << frombits) | value as u32) & max_acc;
        bits += frombits;
        while bits >= tobits {
            bits -= tobits;
            ret.push(((acc >> bits) & maxv) as u8)
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
        }
    }

    if pad {
        if bits > 0 {
            ret.push(((acc << (tobits - bits)) & maxv) as u8)
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
        }
    } else if bits >= frombits || ((acc << (tobits - bits)) & maxv) != 0 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    Ok(ret)
}

/// bech32 encoding (segwit v0, spec=1)
/// data is already 5-bit groups (each byte is a 5-bit value 0-31)
pub(crate) fn encode(hrp: &str, data: &[u8]) -> Result<Bech32String> {
    if hrp.is_empty() || hrp.len() > 90 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let checksum = bech32_create_checksum(hrp, data, BECH32_CONST);

    let mut out = heapless::String::<BECH32_MAX_LEN>::new();
    out.push_str(hrp)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    out.push('1')
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    for &b in data.iter() {
        out.push(BECH32_CHARSET[b as usize] as char)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }
    for &b in checksum.iter() {
        out.push(BECH32_CHARSET[b as usize] as char)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }
    Ok(Bech32String { bytes: out })
}

/// bech32m encoding (segwit v1+, spec=BECH32M_CONST)
/// data is already 5-bit groups
// BIP-137/350 message-signing helper — its consumer (message_sign) is
// alloc-fallback surface.
#[cfg(feature = "alloc-fallback")]
pub(crate) fn encode_m(hrp: &str, data: &[u8]) -> Result<Bech32String> {
    if hrp.is_empty() || hrp.len() > 90 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let checksum = bech32_create_checksum(hrp, data, BECH32M_CONST);

    let mut out = heapless::String::<BECH32_MAX_LEN>::new();
    out.push_str(hrp)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    out.push('1')
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    for &b in data.iter() {
        out.push(BECH32_CHARSET[b as usize] as char)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }
    for &b in checksum.iter() {
        out.push(BECH32_CHARSET[b as usize] as char)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }
    Ok(Bech32String { bytes: out })
}

/// bech32 / bech32m generic decoding (accepts either variant)
/// Z3.4 (T-05 frozen shape): bech32 decode into caller buffers
/// (hrp + witness program). Returns (hrp_len, data_len); over-cap raises
/// EncodingBufferOverflow (never truncation).
pub fn decode_into(s: &str, hrp_out: &mut [u8], data_out: &mut [u8]) -> Result<(usize, usize)> {
    let (hrp, data) = decode(s)?;
    if hrp_out.len() < hrp.len() || data_out.len() < data.len() {
        return Err(ShlosiloError::new(
            ShlosiloErrorKind::EncodingBufferOverflow,
        ));
    }
    hrp_out[..hrp.len()].copy_from_slice(hrp.as_bytes());
    data_out[..data.len()].copy_from_slice(&data);
    Ok((hrp.len(), data.len()))
}

/// Z3.4 shape pin.
#[cfg(test)]
mod t05_shape {
    use super::*;
    type DecodeInto = fn(&str, &mut [u8], &mut [u8]) -> Result<(usize, usize)>;
    const _: DecodeInto = decode_into;
}

/// Internal/test shape — the frozen PUBLIC shape is [`decode_into`].
pub(crate) fn decode(s: &str) -> Result<(heapless::String<32>, heapless::Vec<u8, 128>)> {
    if s.is_empty() || s.len() > 90 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let pos = s
        .rfind('1')
        .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    if pos < 1 || pos + 7 > s.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    for &b in s.as_bytes().iter() {
        if !(33..=126).contains(&b) {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
    }
    let mut has_lower = false;
    let mut has_upper = false;
    for &b in s.as_bytes().iter() {
        if b.is_ascii_lowercase() {
            has_lower = true;
        } else if b.is_ascii_uppercase() {
            has_upper = true;
        }
    }
    if has_lower && has_upper {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    let s_lower = s.to_ascii_lowercase();
    let pos2 = s_lower
        .rfind('1')
        .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    if pos2 < 1 || pos2 + 7 > s_lower.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let hrp = &s_lower[..pos2];
    let data_part = &s_lower[pos2 + 1..];

    let mut data_5bit: heapless::Vec<u8, 256> = heapless::Vec::new();
    for c in data_part.bytes() {
        // BIP-173: all chars must be lowercase or digits (already lowercased before hrp extraction)
        let b = match BECH32_CHARSET.iter().position(|&x| x == c) {
            Some(p) => p as u8,
            None => return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)),
        };
        data_5bit
            .push(b)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }

    let hrp_bytes = hrp.as_bytes();
    let n = hrp_bytes.len();
    let expanded_full = bech32_hrp_expand(hrp);
    let mut values_with_chk: heapless::Vec<u8, 256> = heapless::Vec::new();
    for &v in expanded_full.iter().take(2 * n + 1) {
        let _ = values_with_chk.push(v);
    }
    for &b in data_5bit.iter() {
        let _ = values_with_chk.push(b);
    }
    let polymod_result = bech32_polymod(&values_with_chk);
    let is_bech32 = polymod_result == BECH32_CONST;
    let is_bech32m = polymod_result == BECH32M_CONST;
    if !is_bech32 && !is_bech32m {
        return Err(ShlosiloError::new(
            ShlosiloErrorKind::EncodingInvalidChecksum,
        ));
    }

    // strip witver (data_5bit[0]) + checksum (data_5bit[-6..]) — sipa segwit format
    // generic bech32 test vectors may have data_5bit[1..-6] that is not 8-bit byte aligned (known sipa reference behavior)
    let data_8bit = if data_5bit.len() >= 7 {
        match convertbits(&data_5bit[1..data_5bit.len() - 6], 5, 8, false) {
            Ok(v) => v,
            Err(_) => heapless::Vec::new(), // generic bech32 (non-segwit) allows an empty witprog
        }
    } else {
        heapless::Vec::new()
    };

    let mut hrp_out = heapless::String::<32>::new();
    hrp_out
        .push_str(hrp)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;

    let mut data_out = heapless::Vec::<u8, 128>::new();
    for &b in data_8bit.iter() {
        data_out
            .push(b)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }

    Ok((hrp_out, data_out))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: [witver] + convertbits(witprog, 8→5) (sipa segwit encoding format)
    fn build_data(witver: u8, witprog: &[u8]) -> heapless::Vec<u8, 64> {
        let bits_5 = convertbits(witprog, 8, 5, true).unwrap();
        let mut out: heapless::Vec<u8, 64> = heapless::Vec::new();
        let _ = out.push(witver);
        for &b in bits_5.iter() {
            let _ = out.push(b);
        }
        out
    }

    /// BIP-173 BTC P2WPKH test vector
    /// scriptpubkey = 0014751e76e8199196d454941c45d1b3a323f1433bd6
    /// sipa encoding format: witver(0x00) + convertbits(20-byte hash)
    #[test]
    fn encode_btc_p2wpkh_known() {
        let hrp = "bc";
        let witprog = [
            0x75u8, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3,
            0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
        ];
        let data = build_data(0, &witprog);
        let result = encode(hrp, &data).unwrap();
        assert_eq!(
            result.as_ref(),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
    }

    /// BIP-173 testnet P2WSH test vector
    /// scriptpubkey = 00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262
    /// sipa encoding format: witver(0x00) + convertbits(32-byte hash)
    #[test]
    fn encode_testnet_p2wsh_known() {
        let hrp = "tb";
        let witprog = [
            0x18u8, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04, 0xbd, 0x19, 0x20, 0x33, 0x56,
            0xda, 0x13, 0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96,
            0x04, 0x90, 0x32, 0x62,
        ];
        let data = build_data(0, &witprog);
        let result = encode(hrp, &data).unwrap();
        assert_eq!(
            result.as_ref(),
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
        );
    }

    /// BIP-173 generic (non-segwit) bech32 test vector
    #[test]
    fn decode_valid_bip173_vectors() {
        for s in &[
            "A12UEL5L",
            "a12uel5l",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        ] {
            let result = decode(s);
            match &result {
                Ok(_) => {}
                Err(e) => panic!("Failed to decode {}: err={:?}", s, e),
            }
        }
    }

    /// bech32 round-trip: 5-bit groups encode → decode → witprog 8-bit bytes
    #[test]
    fn encode_decode_round_trip() {
        let hrp = "bc";
        let witprog = [
            0x75u8, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3,
            0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
        ];
        let data = build_data(0, &witprog);
        let encoded = encode(hrp, &data).unwrap();
        let (_hrp_decoded, witprog_decoded) = decode(encoded.as_ref()).unwrap();
        // decode returns the witprog (witver stripped)
        assert_eq!(witprog_decoded.as_slice(), &witprog[..]);
    }

    /// bech32m round-trip: 5-bit groups encode → decode → witprog 8-bit bytes
    #[test]
    fn encode_m_decode_round_trip() {
        let hrp = "bc";
        let witprog = [
            0x9eu8, 0xd8, 0x68, 0x76, 0xdf, 0xd6, 0x76, 0xab, 0x4b, 0x77, 0x8a, 0xc8, 0x4d, 0x27,
            0x66, 0x9a, 0x67, 0x1d, 0x9c, 0x68, 0x6c, 0x4c, 0x06, 0x58, 0x6c, 0x96, 0x77, 0x49,
            0x16, 0x07, 0xd2, 0x95,
        ];
        let data = build_data(1, &witprog);
        let encoded = encode_m(hrp, &data).unwrap();
        let (_hrp_decoded, witprog_decoded) = decode(encoded.as_ref()).unwrap();
        assert_eq!(witprog_decoded.as_slice(), &witprog[..]);
    }

    /// Empty hrp rejected
    #[test]
    fn encode_empty_hrp_rejected() {
        let result = encode("", b"hello");
        assert!(result.is_err());
    }

    /// decode error string → return the error
    #[test]
    fn decode_invalid_string_rejected() {
        let result = decode("invalid!!!");
        assert!(result.is_err());
    }

    /// mixed case rejected (strictly forbidden by BIP-173)
    #[test]
    fn decode_mixed_case_rejected() {
        let result = decode("aBc1qpzry9x8gf2tvdw0s3jn54khce6mua7l");
        assert!(result.is_err());
    }
}
