//! crypto-hdkey UR codec（BCR-2020-006）
//!
//! Public key export: split key / chain_code / parent fingerprint from a BIP-32 xpub (78 bytes),
//! and encode them into a UR registry map. origin (tag 304 crypto-keypath) is written when a path is given.

extern crate alloc;

use crate::derivation::path::DerivationPath;
use crate::encoding::cbor;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::ur::ur_decode;
use crate::ur::ur_encode::{self, UrEncoded, UrTypeTag};

/// BIP-32 extended public key (xpub, 78 bytes)
pub type Bip32XPub = [u8; 78];

const KEY_DATA: u64 = 3;
const CHAIN_CODE: u64 = 4;
const ORIGIN: u64 = 6;
const PARENT_FINGERPRINT: u64 = 8;
const KEYPATH_COMPONENTS: u64 = 1;
const KEYPATH_DEPTH: u64 = 3;
const TAG_CRYPTO_KEYPATH: u64 = 304;

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// Public key HDKey encoding (never exports the private key)
pub fn encode(xpub: &Bip32XPub, path: Option<&DerivationPath>) -> Result<UrEncoded> {
    let key = &xpub[45..78];
    let chain = &xpub[13..45];
    let parent_fp = u32::from_be_bytes(xpub[5..9].try_into().unwrap());

    let mut pairs: alloc::vec::Vec<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>)> = alloc::vec![
        (cbor::encode_uint(KEY_DATA), cbor::encode_bytes(key)),
        (cbor::encode_uint(CHAIN_CODE), cbor::encode_bytes(chain)),
        (
            cbor::encode_uint(PARENT_FINGERPRINT),
            cbor::encode_uint(parent_fp as u64)
        ),
    ];

    if let Some(path) = path {
        pairs.push((
            cbor::encode_uint(ORIGIN),
            cbor::encode_tag(TAG_CRYPTO_KEYPATH, &encode_keypath(path)),
        ));
    }

    let cbor = cbor::encode_map(&pairs);
    ur_encode::encode(UrTypeTag::CryptoHdKey, &cbor)
}

fn encode_keypath(path: &DerivationPath) -> alloc::vec::Vec<u8> {
    let mut comps = alloc::vec::Vec::new();
    for idx in path.as_slice() {
        comps.push(cbor::encode_uint(idx.value() as u64));
        comps.push(cbor::encode_bool(idx.is_hardened()));
    }
    cbor::encode_map(&[
        (
            cbor::encode_uint(KEYPATH_COMPONENTS),
            cbor::encode_array(&comps),
        ),
        (
            cbor::encode_uint(KEYPATH_DEPTH),
            cbor::encode_uint(path.len() as u64),
        ),
    ])
}

/// Decode crypto-hdkey: returns (key 33B, chain_code 32B, parent_fp)
pub fn decode_key_material(uri: &str) -> Result<([u8; 33], [u8; 32], u32)> {
    let d = ur_decode::decode(uri)?;
    if d.type_tag() != UrTypeTag::CryptoHdKey {
        return Err(err());
    }
    let item = cbor::decode(d.as_ref())?;
    let key = item.map_get_uint(KEY_DATA)?.ok_or_else(err)?.as_bytes()?;
    let chain = item.map_get_uint(CHAIN_CODE)?.ok_or_else(err)?.as_bytes()?;
    let fp = item
        .map_get_uint(PARENT_FINGERPRINT)?
        .ok_or_else(err)?
        .as_uint()? as u32;
    if key.len() != 33 || chain.len() != 32 {
        return Err(err());
    }
    let mut k = [0u8; 33];
    let mut c = [0u8; 32];
    k.copy_from_slice(key);
    c.copy_from_slice(chain);
    Ok((k, c, fp))
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn(&Bip32XPub, Option<&DerivationPath>) -> Result<UrEncoded> = encode;

    #[test]
    fn xpub_len() {
        assert_eq!(core::mem::size_of::<Bip32XPub>(), 78);
    }

    /// Codec round of key / chain / parent_fp from a constructed xpub
    #[test]
    fn encode_decode_key_material() {
        let mut xpub = [0u8; 78];
        xpub[5..9].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        for (i, b) in xpub[13..45].iter_mut().enumerate() {
            *b = i as u8;
        }
        for (i, b) in xpub[45..78].iter_mut().enumerate() {
            *b = 0x80 + i as u8;
        }
        let path = DerivationPath::parse("m/84'/0'/0'").unwrap();
        let enc = encode(&xpub, Some(&path)).unwrap();
        assert!(enc.as_str().starts_with("ur:crypto-hdkey/"));
        let (key, chain, fp) = decode_key_material(enc.as_str()).unwrap();
        assert_eq!(&key[..], &xpub[45..78]);
        assert_eq!(&chain[..], &xpub[13..45]);
        assert_eq!(fp, 0x11223344);
    }
}
