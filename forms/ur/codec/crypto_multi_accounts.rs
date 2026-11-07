//! crypto-multi-accounts UR codec (tag 1103) - the aggregated-wallet export.
//!
//! Reference behaviour (`keystone3-firmware/rust/apps/wallets/src/keystone_connect.rs`):
//!
//! ```text
//! CryptoMultiAccounts::new(master_fingerprint, keys,
//!     Some(device_type), Some(device_id), Some(device_version))
//! ```
//! i.e. a CBOR map `{1: mfp, 2: keys[], 3: device, 4: device_id, 5: device_version}`
//! where every entry in `keys` is a `crypto-hdkey` (tag 303).
//!
//! Entry rules taken from the reference builders in the same file:
//!
//! - `generate_k1_normal_key`: origin keypath = the **full account path** plus
//!   source fingerprint and depth; `children` = `[0, *]` when the caller marks it
//!   standard, else `[*]`; chain code present; **no `use_info`/coin_info** - the
//!   script type is expressed by the origin path alone (unlike `crypto-account`,
//!   which carries it in `script_expressions`); `name` is set ("Keystone" in the
//!   reference), optional `note` ("account.standard" / "account.ledger_legacy").
//! - `generate_eth_ledger_live_key` / `..._legacy_pubkey`: those variants drop
//!   the chain code (the key is an address-level key, not an account key).
//!
//! `name` and the device strings are **caller inputs** rather than hardcoded
//! reference strings: what a wallet displays as the key name is an identity
//! decision, not a wire requirement.

use super::crypto_hd_key::Bip32XPub;
use crate::derivation::path::DerivationPath;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::ur::ur_encode::{self, UrEncoded, UrTypeTag};

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

// keypath (CryptoKeyPath, tag 304) field numbers
const KEYPATH_COMPONENTS: u64 = 1;
const KEYPATH_SOURCE_FINGERPRINT: u64 = 2;
const KEYPATH_DEPTH: u64 = 3;
const TAG_CRYPTO_KEYPATH: u64 = 304;
const TAG_CRYPTO_HDKEY: u64 = 303;

// crypto-hdkey field numbers (BCR-2020-007)
const KEY_DATA: u64 = 3;
const CHAIN_CODE: u64 = 4;
const ORIGIN: u64 = 6;
const CHILDREN: u64 = 7;
const PARENT_FINGERPRINT: u64 = 8;
const NAME: u64 = 9;
const NOTE: u64 = 10;

// crypto-multi-accounts field numbers (registry tag 1103)
const MASTER_FINGERPRINT: u64 = 1;
const KEYS: u64 = 2;
const DEVICE: u64 = 3;
const DEVICE_ID: u64 = 4;
const DEVICE_VERSION: u64 = 5;

/// One key entry in the bundle.
#[derive(Clone, Copy, Debug)]
pub struct MultiAccountEntry<'a> {
    /// Account-level extended public key (78-byte BIP-32 serialization).
    pub xpub: &'a Bip32XPub,
    /// The path that produced `xpub` (becomes the hdkey origin).
    pub path: &'a DerivationPath,
    /// `children` shape: `[0, *]` (account key, standard) or `[*]` (address key).
    pub standard_children: bool,
    /// Reference behaviour: address-level ETH variants (ledger live / legacy)
    /// carry no chain code; account keys always do.
    pub include_chain_code: bool,
    /// Optional `note` field ("account.standard" etc.).
    pub note: Option<&'a str>,
}

/// Multi-account export input.
#[derive(Clone, Copy, Debug)]
pub struct MultiAccountsInput<'a> {
    pub master_fingerprint: [u8; 4],
    pub entries: &'a [MultiAccountEntry<'a>],
    /// `name` written on every hdkey entry (the reference writes its own brand).
    pub key_name: Option<&'a str>,
    pub device: Option<&'a str>,
    pub device_id: Option<&'a str>,
    pub device_version: Option<&'a str>,
}

/// Encode a multi-account bundle. Zero heap: one caller-sized CBOR buffer.
pub fn encode(input: &MultiAccountsInput<'_>) -> Result<UrEncoded> {
    use crate::encoding::cbor;

    if input.entries.is_empty() {
        return Err(err());
    }
    // Bounded: header + per-entry ~160B (pubkey 33 + chain code 32 + two
    // keypaths + fingerprints + name/note). 16 entries keeps a wide margin.
    let mut buf = [0u8; 16 * 160 + 64];
    let n = {
        let mut w = cbor::CborWriter::new(&mut buf);
        let optional = usize::from(input.device.is_some())
            + usize::from(input.device_id.is_some())
            + usize::from(input.device_version.is_some());
        w.map_head(2 + optional)?;

        w.uint(MASTER_FINGERPRINT)?;
        w.bytes(&input.master_fingerprint)?;

        w.uint(KEYS)?;
        w.array_head(input.entries.len())?;
        for e in input.entries {
            write_hdkey(&mut w, e, &input.master_fingerprint, input.key_name)?;
        }

        if let Some(d) = input.device {
            w.uint(DEVICE)?;
            w.text(d)?;
        }
        if let Some(d) = input.device_id {
            w.uint(DEVICE_ID)?;
            w.text(d)?;
        }
        if let Some(d) = input.device_version {
            w.uint(DEVICE_VERSION)?;
            w.text(d)?;
        }
        w.pos()
    };
    ur_encode::encode(UrTypeTag::CryptoMultiAccounts, &buf[..n])
}

fn write_hdkey(
    w: &mut crate::encoding::cbor::CborWriter<'_>,
    e: &MultiAccountEntry<'_>,
    mfp: &[u8; 4],
    key_name: Option<&str>,
) -> Result<()> {
    let mut count = 4u64; // key_data, origin, children, parent_fingerprint
    count += u64::from(e.include_chain_code);
    count += u64::from(key_name.is_some());
    count += u64::from(e.note.is_some());

    w.tag(TAG_CRYPTO_HDKEY)?;
    w.map_head(count as usize)?;

    w.uint(KEY_DATA)?;
    w.bytes(&e.xpub[45..78])?;
    if e.include_chain_code {
        w.uint(CHAIN_CODE)?;
        w.bytes(&e.xpub[13..45])?;
    }

    // origin: full account path + source fingerprint + depth
    w.uint(ORIGIN)?;
    w.tag(TAG_CRYPTO_KEYPATH)?;
    w.map_head(3)?;
    w.uint(KEYPATH_COMPONENTS)?;
    w.array_head(2 * e.path.len())?;
    for idx in e.path.as_slice() {
        w.uint(u64::from(idx.value()))?;
        w.bool(idx.is_hardened())?;
    }
    w.uint(KEYPATH_SOURCE_FINGERPRINT)?;
    w.uint(u64::from(u32::from_be_bytes(*mfp)))?;
    w.uint(KEYPATH_DEPTH)?;
    w.uint(e.path.len() as u64)?;

    // children: [0, *] for account keys, [*] for address keys
    w.uint(CHILDREN)?;
    w.tag(TAG_CRYPTO_KEYPATH)?;
    w.map_head(1)?;
    w.uint(KEYPATH_COMPONENTS)?;
    if e.standard_children {
        w.array_head(4)?;
        w.uint(0)?;
        w.bool(false)?;
    } else {
        w.array_head(2)?;
    }
    // wildcard = empty component array (ur-registry maps it to "no index")
    w.array_head(0)?;
    w.bool(false)?;

    w.uint(PARENT_FINGERPRINT)?;
    w.uint(u64::from(parent_fingerprint(e.xpub)))?;

    if let Some(name) = key_name {
        w.uint(NAME)?;
        w.text(name)?;
    }
    if let Some(note) = e.note {
        w.uint(NOTE)?;
        w.text(note)?;
    }
    Ok(())
}

/// Parent fingerprint carried by the xpub bytes (field 5..9), not the master one.
fn parent_fingerprint(xpub: &Bip32XPub) -> u32 {
    u32::from_be_bytes([xpub[5], xpub[6], xpub[7], xpub[8]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation::bip32_secp256k1::{master_fingerprint_from_seed, xpub_from_seed};

    const SEED: [u8; 64] = [0x5Au8; 64];

    struct Fixture {
        mfp: [u8; 4],
        xpub: Bip32XPub,
        path: DerivationPath,
        eth_xpub: Bip32XPub,
        eth_path: DerivationPath,
    }

    fn fixture() -> Fixture {
        let mfp = master_fingerprint_from_seed(&SEED).unwrap();
        let path = DerivationPath::parse("m/84'/0'/0'").unwrap();
        let eth_path = DerivationPath::parse("m/44'/60'/0'").unwrap();
        let xpub = xpub_from_seed(&SEED, &path).unwrap();
        let eth_xpub = xpub_from_seed(&SEED, &eth_path).unwrap();
        Fixture {
            mfp,
            xpub,
            path,
            eth_xpub,
            eth_path,
        }
    }

    /// Minimal independent CBOR walk: enough to assert map/tag/field shape
    /// without going through our own writer's inverse.
    fn walk(
        b: &[u8],
    ) -> (
        heapless::Vec<u64, 512>,
        heapless::Vec<heapless::Vec<u8, 64>, 64>,
    ) {
        let mut i = 0usize;
        let mut uints: heapless::Vec<u64, 512> = heapless::Vec::new();
        let mut bytes: heapless::Vec<heapless::Vec<u8, 64>, 64> = heapless::Vec::new();
        while i < b.len() {
            let head = b[i];
            let major = head >> 5;
            let info = head & 0x1f;
            i += 1;
            let len: usize = if info <= 23 {
                info as usize
            } else if info == 24 {
                let v = b[i] as usize;
                i += 1;
                v
            } else if info == 25 {
                let v = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
                i += 2;
                v
            } else if info == 26 {
                let v = u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as usize;
                i += 4;
                v
            } else if info == 27 {
                let v = u64::from_be_bytes([
                    b[i],
                    b[i + 1],
                    b[i + 2],
                    b[i + 3],
                    b[i + 4],
                    b[i + 5],
                    b[i + 6],
                    b[i + 7],
                ]) as usize;
                i += 8;
                v
            } else {
                0
            };
            match major {
                0 => {
                    uints.push(len as u64).ok();
                }
                1 => {}
                2 => {
                    let mut v: heapless::Vec<u8, 64> = heapless::Vec::new();
                    v.extend_from_slice(&b[i..i + len]).ok();
                    bytes.push(v).ok();
                    i += len;
                }
                3 => i += len,
                4 | 5 => {}
                6 => {
                    uints.push(len as u64).ok();
                }
                _ => {}
            }
        }
        (uints, bytes)
    }

    #[test]
    fn bundle_carries_both_entries_and_device_fields() {
        let f = fixture();
        let entries = [
            MultiAccountEntry {
                xpub: &f.xpub,
                path: &f.path,
                standard_children: true,
                include_chain_code: true,
                note: None,
            },
            MultiAccountEntry {
                xpub: &f.eth_xpub,
                path: &f.eth_path,
                standard_children: true,
                include_chain_code: true,
                note: Some("account.standard"),
            },
        ];
        let enc = encode(&MultiAccountsInput {
            master_fingerprint: f.mfp,
            entries: &entries,
            key_name: Some("TestDevice"),
            device: Some("TestDevice"),
            device_id: Some("SN-0001"),
            device_version: Some("0.1.0"),
        })
        .expect("encode");
        assert!(enc.as_str().starts_with("ur:crypto-multi-accounts/"));

        let d = crate::ur::ur_decode::decode(enc.as_str()).expect("decode");
        let (uints, bytes) = walk(d.as_ref());

        // tags are recorded as uint heads by the walk; assert the field numbers
        for field in [
            MASTER_FINGERPRINT,
            KEYS,
            DEVICE,
            DEVICE_ID,
            DEVICE_VERSION,
            NAME,
            NOTE,
        ] {
            assert!(uints.contains(&field), "field {field} must be present");
        }
        for tag in [TAG_CRYPTO_HDKEY, TAG_CRYPTO_KEYPATH] {
            assert!(uints.contains(&tag), "tag {tag} must be present");
        }
        assert_eq!(
            bytes[0].as_slice(),
            &f.mfp[..],
            "field 1 = master fingerprint"
        );
        assert_eq!(
            bytes.iter().filter(|b| b.len() == 33).count(),
            2,
            "one public key per entry"
        );
        assert_eq!(
            bytes.iter().filter(|b| b.len() == 32).count(),
            2,
            "one chain code per entry"
        );
    }

    #[test]
    fn entry_without_chain_code_is_allowed() {
        let f = fixture();
        let entries = [MultiAccountEntry {
            xpub: &f.eth_xpub,
            path: &f.eth_path,
            standard_children: true,
            include_chain_code: false,
            note: Some("account.ledger_live"),
        }];
        let enc = encode(&MultiAccountsInput {
            master_fingerprint: f.mfp,
            entries: &entries,
            key_name: None,
            device: None,
            device_id: None,
            device_version: None,
        })
        .expect("encode");
        let d = crate::ur::ur_decode::decode(enc.as_str()).expect("decode");
        let (_u, bytes) = walk(d.as_ref());
        assert_eq!(
            bytes.iter().filter(|b| b.len() == 32).count(),
            0,
            "ledger-live style entries carry no chain code"
        );
    }

    #[test]
    fn empty_bundle_is_refused() {
        let f = fixture();
        assert!(encode(&MultiAccountsInput {
            master_fingerprint: f.mfp,
            entries: &[],
            key_name: None,
            device: None,
            device_id: None,
            device_version: None,
        })
        .is_err());
    }
}
