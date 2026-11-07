//! crypto-hdkey UR codec（BCR-2020-006）
//!
//! Public key export: split key / chain_code / parent fingerprint from a BIP-32 xpub (78 bytes),
//! and encode them into a UR registry map. origin (tag 304 crypto-keypath) is written when a path is given.

#[cfg(any(feature = "alloc-fallback", test))]
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
const USE_INFO: u64 = 5;
const ORIGIN: u64 = 6;
const CHILDREN: u64 = 7;
const PARENT_FINGERPRINT: u64 = 8;
const NAME: u64 = 9;
const NOTE: u64 = 10;
const KEYPATH_COMPONENTS: u64 = 1;
const KEYPATH_SOURCE_FINGERPRINT: u64 = 2;
const KEYPATH_DEPTH: u64 = 3;
const TAG_CRYPTO_KEYPATH: u64 = 304;
const TAG_CRYPTO_COIN_INFO: u64 = 305;
/// crypto-coin-info field numbers (BCR-2020-006; ur-registry `crypto_coin_info.rs:11-12`)
const COIN_INFO_COIN: u64 = 1;
const COIN_INFO_NETWORK: u64 = 2;
/// Network enumeration of crypto-coin-info (0 = mainnet, 1 = testnet).
const NETWORK_MAINNET: u64 = 0;
const NETWORK_TESTNET: u64 = 1;

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// SLIP-44 coin type + network for the export (crypto-coin-info fields).
///
/// The coin type is read from the path's second component (BIP-44
/// `m/purpose'/coin'/account'`); coin type 1 is the registered testnet coin
/// type, so it is the one value that also flips the network field.
///
/// Returns `None` when the path has no coin layer (`m/44'`), or when the coin
/// type does not fit the registry's u8 field — the field is then simply
/// omitted (the registry allows that) rather than emitted as a wrong value.
fn coin_info(path: &DerivationPath) -> Option<(u64, u64)> {
    let comps = path.as_slice();
    let coin = u8::try_from(comps.get(1)?.value()).ok()?;
    let network = if coin == 1 {
        NETWORK_TESTNET
    } else {
        NETWORK_MAINNET
    };
    Some((u64::from(coin), network))
}

/// `children` (`0/*`) only describes an **account-level** key
/// (`m/purpose'/coin'/account'`, three hardened components). Emitting a
/// wildcard under a leaf key would tell the wallet the wrong derivation rule.
fn is_account_level(path: &DerivationPath) -> bool {
    let comps = path.as_slice();
    comps.len() == 3 && comps.iter().all(|c| c.is_hardened())
}

/// Public key HDKey encoding (never exports the private key)
///
/// Emits the **extended-key** branch of BCR-2020-006 (ur-registry
/// `crypto_hd_key.rs:15-24`): fields 3 key / 4 chain_code / 5 use_info /
/// 6 origin / 7 children / 8 parent_fingerprint, in that order — the same field
/// set and order keystone's firmware emits. Fields 1 (is_master) and 2
/// (is_private) are deliberately absent: a public export claims neither.
///
/// `master_fingerprint` is the **root** fingerprint, which is not derivable
/// from the xpub itself (an account-level xpub only carries its *parent*
/// fingerprint). It lands in the origin keypath as `source_fingerprint` —
/// keystone's SDK (`wallet/hdKey.ts`) rejects a keypath without it, so pairing
/// dies silently otherwise.
///
/// Z2.4b-2: structural write into a caller-sized stack buffer (was Vec fragment pairs) —
/// the UR registry map is head-first, entries stream in order.
pub fn encode(
    xpub: &Bip32XPub,
    master_fingerprint: &[u8; 4],
    path: Option<&DerivationPath>,
) -> Result<UrEncoded> {
    use crate::encoding::cbor::CborWriter;

    // bounded: map head + key/chain/fp (~85B) + use_info (~9B) + origin
    // tag+keypath (~28B) + children tag+keypath (~12B). Measured worst case
    // ≈ 122B for a 5-level path; 256 keeps a 2x margin.
    let mut buf = [0u8; 256];
    let n = {
        let mut w = CborWriter::new(&mut buf);
        match path {
            Some(path) => encode_hdkey_map(&mut w, xpub, master_fingerprint, path)?,
            None => {
                // Bare key material (no path context): key / chain / parent fp.
                w.map_head(3)?;
                w.uint(KEY_DATA)?;
                w.bytes(&xpub[45..78])?;
                w.uint(CHAIN_CODE)?;
                w.bytes(&xpub[13..45])?;
                w.uint(PARENT_FINGERPRINT)?;
                w.uint(u64::from(parent_fingerprint(xpub)))?;
            }
        }
        w.pos()
    };
    ur_encode::encode(UrTypeTag::CryptoHdKey, &buf[..n])
}

/// Extended-key encoding **with the human-readable metadata** the reference
/// firmware emits for ETH: `name` (field 9) and `note` (field 10).
///
/// keystone writes both (`apps/wallets/src/metamask.rs:69-84`):
/// `name="Keystone"`, `note="account.standard"`/`"account.ledger_legacy"`.
/// They are optional here because they are display metadata, not wire
/// requirements - but a wallet that groups accounts by `note` needs them.
pub fn encode_with_meta(
    xpub: &Bip32XPub,
    master_fingerprint: &[u8; 4],
    path: Option<&DerivationPath>,
    name: Option<&str>,
    note: Option<&str>,
) -> Result<UrEncoded> {
    use crate::encoding::cbor;

    let path = match path {
        Some(p) => p,
        None => return encode(xpub, master_fingerprint, None),
    };
    let mut buf = [0u8; 384];
    let n = {
        let mut w = cbor::CborWriter::new(&mut buf);
        let coin = coin_info(path);
        let children = is_account_level(path);
        let count = 4
            + usize::from(coin.is_some())
            + usize::from(children)
            + usize::from(name.is_some())
            + usize::from(note.is_some());
        w.map_head(count)?;
        w.uint(KEY_DATA)?;
        w.bytes(&xpub[45..78])?;
        w.uint(CHAIN_CODE)?;
        w.bytes(&xpub[13..45])?;
        if let Some((coin, network)) = coin {
            w.uint(USE_INFO)?;
            w.tag(TAG_CRYPTO_COIN_INFO)?;
            w.map_head(2)?;
            w.uint(COIN_INFO_COIN)?;
            w.uint(coin)?;
            w.uint(COIN_INFO_NETWORK)?;
            w.uint(network)?;
        }
        w.uint(ORIGIN)?;
        w.tag(TAG_CRYPTO_KEYPATH)?;
        encode_keypath(&mut w, path, master_fingerprint)?;
        if children {
            w.uint(CHILDREN)?;
            w.tag(TAG_CRYPTO_KEYPATH)?;
            encode_children(&mut w)?;
        }
        w.uint(PARENT_FINGERPRINT)?;
        w.uint(u64::from(parent_fingerprint(xpub)))?;
        if let Some(name) = name {
            w.uint(NAME)?;
            w.text(name)?;
        }
        if let Some(note) = note {
            w.uint(NOTE)?;
            w.text(note)?;
        }
        w.pos()
    };
    ur_encode::encode(UrTypeTag::CryptoHdKey, &buf[..n])
}

/// Parent fingerprint carried by the xpub bytes (field 5..9 of the BIP-32
/// serialization) — **not** the master fingerprint; see `encode`.
fn parent_fingerprint(xpub: &Bip32XPub) -> u32 {
    u32::from_be_bytes([xpub[5], xpub[6], xpub[7], xpub[8]])
}

/// Write the extended-key crypto-hdkey map (fields 3,4,5,6,7,8 in registry
/// order). Shared with `crypto_account`, which nests a hdkey inside each
/// crypto-output — same bytes, one implementation.
pub(crate) fn encode_hdkey_map(
    w: &mut cbor::CborWriter<'_>,
    xpub: &Bip32XPub,
    master_fingerprint: &[u8; 4],
    path: &DerivationPath,
) -> Result<()> {
    let coin = coin_info(path);
    let children = is_account_level(path);
    // key / chain_code / origin / parent_fingerprint are always present;
    // use_info and children are conditional (see the field docs above).
    w.map_head(4 + usize::from(coin.is_some()) + usize::from(children))?;
    w.uint(KEY_DATA)?;
    w.bytes(&xpub[45..78])?;
    w.uint(CHAIN_CODE)?;
    w.bytes(&xpub[13..45])?;

    if let Some((coin, network)) = coin {
        w.uint(USE_INFO)?;
        w.tag(TAG_CRYPTO_COIN_INFO)?;
        w.map_head(2)?;
        w.uint(COIN_INFO_COIN)?;
        w.uint(coin)?;
        w.uint(COIN_INFO_NETWORK)?;
        w.uint(network)?;
    }

    w.uint(ORIGIN)?;
    w.tag(TAG_CRYPTO_KEYPATH)?;
    encode_keypath(w, path, master_fingerprint)?;

    if children {
        w.uint(CHILDREN)?;
        w.tag(TAG_CRYPTO_KEYPATH)?;
        encode_children(w)?;
    }

    w.uint(PARENT_FINGERPRINT)?;
    w.uint(u64::from(parent_fingerprint(xpub)))?;
    Ok(())
}

/// crypto-keypath map: {1: [idx0, hard0, idx1, hard1, ...], 2: source_fingerprint, 3: depth}
///
/// The components array is **flat** `[index, hardened]` pairs and the wildcard
/// is encoded as an empty array — both facts come from the registry's own
/// golden vector (`crypto_key_path.rs:313`), not from our own round-trip.
fn encode_keypath(
    w: &mut cbor::CborWriter<'_>,
    path: &DerivationPath,
    master_fingerprint: &[u8; 4],
) -> Result<()> {
    w.map_head(3)?;
    w.uint(KEYPATH_COMPONENTS)?;
    w.array_head(2 * path.len())?;
    for idx in path.as_slice() {
        w.uint(u64::from(idx.value()))?;
        w.bool(idx.is_hardened())?;
    }
    // Field 2: source fingerprint. Required by keystone-sdk `parseHDKey`;
    // the field number is fixed by BCR-2020-006 — do not renumber it to `depth`.
    w.uint(KEYPATH_SOURCE_FINGERPRINT)?;
    w.uint(u64::from(u32::from_be_bytes(*master_fingerprint)))?;
    w.uint(KEYPATH_DEPTH)?;
    w.uint(path.len() as u64)
}

/// crypto-keypath for `children` = `0/*` (address index 0, then the wildcard).
fn encode_children(w: &mut cbor::CborWriter<'_>) -> Result<()> {
    w.map_head(1)?;
    w.uint(KEYPATH_COMPONENTS)?;
    w.array_head(4)?;
    w.uint(0)?;
    w.bool(false)?;
    // wildcard: ur-registry's PathComponent decoder maps an empty array to
    // "no index" (`crypto_key_path.rs:250-262`)
    w.array_head(0)?;
    w.bool(false)?;
    Ok(())
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

    const _: fn(&Bip32XPub, &[u8; 4], Option<&DerivationPath>) -> Result<UrEncoded> = encode;

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
        let enc = encode(&xpub, &[0xAA, 0xBB, 0xCC, 0xDD], Some(&path)).unwrap();
        assert!(enc.as_str().starts_with("ur:crypto-hdkey/"));
        let (key, chain, fp) = decode_key_material(enc.as_str()).unwrap();
        assert_eq!(&key[..], &xpub[45..78]);
        assert_eq!(&chain[..], &xpub[13..45]);
        assert_eq!(fp, 0x11223344);
    }

    /// testnet coin type/network branch (crypto-coin-info)
    #[test]
    fn coin_info_follows_path_coin_type() {
        let p = DerivationPath::parse("m/84'/0'/0'").unwrap();
        assert_eq!(coin_info(&p), Some((0, NETWORK_MAINNET)));
        let p = DerivationPath::parse("m/84'/1'/0'").unwrap();
        assert_eq!(coin_info(&p), Some((1, NETWORK_TESTNET)));
        // No coin level (e.g. m/44') -> the field is omitted, never guessed
        let p = DerivationPath::parse("m/44'").unwrap();
        assert_eq!(coin_info(&p), None);
    }

    /// children are emitted only for account-level paths (all three levels hardened)
    #[test]
    fn children_only_for_account_level_paths() {
        assert!(is_account_level(
            &DerivationPath::parse("m/84'/0'/0'").unwrap()
        ));
        // Leaf address path: the last level is not hardened -> no children
        assert!(!is_account_level(
            &DerivationPath::parse("m/44'/0'/0'/0/0").unwrap()
        ));
        // Two levels -> not account level
        assert!(!is_account_level(&DerivationPath::parse("m/0'").unwrap()));
    }
}
