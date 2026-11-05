//! crypto-hdkey / crypto-account registry shape pins (BCR-2020-006)
//!
//! ## Why this file exists
//!
//! Wallets in the keystone ecosystem (MetaMask / Sparrow / BlueWallet / Nunchuk all go
//! through `@keystonehq/keystone-sdk`) **require** the keypath to carry
//! `source_fingerprint` when parsing `crypto-hdkey`:
//! `keystone-sdk-web/src/wallet/hdKey.ts` does `throw new Error("HDKey is invalid")`
//! when `getOrigin().getSourceFingerprint() === undefined`. A missing field kills the
//! whole pairing leg, and our own tests (round-trip through our decoder only) **cannot
//! see it** -- when encode and decode are wrong the same way, the test stays green.
//!
//! ## Oracle sources (external authority, not self-referential)
//!
//! `ur-registry` 1.0.9 (the same crate version pinned in the keystone firmware
//! `Cargo.toml`):
//! - `src/crypto_hd_key.rs:15-24`    map keys: 1 is_master / 2 is_private /
//!   3 key / 4 chain_code / 5 use_info(tag 305) / 6 origin(tag 304) /
//!   7 children(tag 304) / 8 parent_fingerprint
//! - `src/crypto_key_path.rs:13-15`  keypath keys: 1 components /
//!   **2 source_fingerprint** / 3 depth
//! - `src/crypto_key_path.rs:313`    golden vector:
//!   `a3018a182cf51876f500f500f480f4021a782308040305`
//!   -> `{1: [44',true,118',true,0',true,0,f,<empty-array>,f], 2: 0x78230804, 3: 5}`
//!   (components are **flat** `[idx, hardened, ...]`; the `*` wildcard encodes as an
//!   **empty array** 0x80)
//! - `src/crypto_account.rs`         map: 1 master_fingerprint / 2 [crypto-output]
//! - `src/crypto_output.rs`          crypto-output has **no map shell**: a number of
//!   script-expression tags (400 p2sh / 403 pkh / 404 wpkh / 409 tr), then tag(303) + hdkey
//!
//! The CBOR walker in this file **deliberately avoids** `forms::encoding::cbor`: a shape
//! pin must be judged by a parser independent of the implementation, otherwise a field
//! misread in the implementation makes the pin misread it the same way.

use shlosilo::derivation::bip32_secp256k1::{master_fingerprint_from_seed, xpub_from_seed};
use shlosilo::derivation::path::DerivationPath;
use shlosilo::ur::codec::crypto_hd_key;
use shlosilo::ur::ur_decode;

// ------------------------- standalone CBOR walker (test side) -------------------------

#[derive(Debug, Clone, PartialEq)]
enum Cbor {
    Uint(u64),
    Bytes(Vec<u8>),
    Bool(bool),
    Null,
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Tag(u64, Box<Cbor>),
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, i: 0 }
    }

    fn byte(&mut self) -> u8 {
        let v = self.b[self.i];
        self.i += 1;
        v
    }

    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        s
    }

    fn uint_of(&mut self, ai: u8) -> u64 {
        match ai {
            0..=23 => u64::from(ai),
            24 => u64::from(self.byte()),
            25 => {
                let s = self.take(2);
                u64::from(u16::from_be_bytes([s[0], s[1]]))
            }
            26 => {
                let s = self.take(4);
                u64::from(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
            }
            27 => {
                let s = self.take(8);
                let mut a = [0u8; 8];
                a.copy_from_slice(s);
                u64::from_be_bytes(a)
            }
            other => panic!("unsupported additional-info {other}"),
        }
    }

    fn item(&mut self) -> Cbor {
        let head = self.byte();
        let major = head >> 5;
        let ai = head & 0x1f;
        match major {
            0 => Cbor::Uint(self.uint_of(ai)),
            1 => panic!("negative ints unused in these registry shapes"),
            2 => {
                let n = self.uint_of(ai) as usize;
                Cbor::Bytes(self.take(n).to_vec())
            }
            3 => {
                let n = self.uint_of(ai) as usize;
                let _ = self.take(n);
                panic!("text unused in these registry shapes");
            }
            4 => {
                let n = self.uint_of(ai) as usize;
                Cbor::Array((0..n).map(|_| self.item()).collect())
            }
            5 => {
                let n = self.uint_of(ai) as usize;
                Cbor::Map((0..n).map(|_| (self.item(), self.item())).collect())
            }
            6 => {
                let t = self.uint_of(ai);
                Cbor::Tag(t, Box::new(self.item()))
            }
            7 => match ai {
                20 => Cbor::Bool(false),
                21 => Cbor::Bool(true),
                22 => Cbor::Null,
                other => panic!("unsupported simple value {other}"),
            },
            _ => unreachable!(),
        }
    }
}

fn parse(bytes: &[u8]) -> Cbor {
    let mut r = Reader::new(bytes);
    let v = r.item();
    assert_eq!(r.i, bytes.len(), "CBOR has trailing bytes (shape mismatch)");
    v
}

fn map_get(m: &Cbor, key: u64) -> Option<Cbor> {
    let Cbor::Map(pairs) = m else {
        panic!("expected a map, got {m:?}");
    };
    pairs.iter().find_map(|(k, v)| match k {
        Cbor::Uint(n) if *n == key => Some(v.clone()),
        _ => None,
    })
}

fn as_uint(v: &Cbor) -> u64 {
    match v {
        Cbor::Uint(n) => *n,
        other => panic!("expected uint, got {other:?}"),
    }
}

fn as_bytes(v: &Cbor) -> &[u8] {
    match v {
        Cbor::Bytes(b) => b,
        other => panic!("expected bytes, got {other:?}"),
    }
}

fn untag(v: &Cbor, tag: u64) -> Cbor {
    match v {
        Cbor::Tag(t, inner) => {
            assert_eq!(*t, tag, "registry tag mismatch");
            (**inner).clone()
        }
        other => panic!("expected tag {tag}, got {other:?}"),
    }
}

fn map_keys(m: &Cbor) -> Vec<u64> {
    let Cbor::Map(pairs) = m else {
        panic!("expected a map");
    };
    pairs
        .iter()
        .map(|(k, _)| match k {
            Cbor::Uint(n) => *n,
            other => panic!("non-uint map key {other:?}"),
        })
        .collect()
}

// ------------------------- fixtures -------------------------

fn from_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

/// Walker self-check: validate this file's CBOR parser against the official
/// `ur-registry` 1.0.9 test vector.
///
/// Without this pin, "our implementation + our walker" could be the same mistake
/// expressed twice.
/// Vector source: `test_encode` in `ur-registry-1.0.9/src/crypto_key_path.rs`,
/// semantics = `m/44'/118'/0'/0/*` + source_fingerprint 0x78230804 + depth 5.
#[test]
fn walker_agrees_with_registry_golden_vector() {
    let bytes = from_hex("a3018a182cf51876f500f500f480f4021a782308040305");
    let top = parse(&bytes);
    assert_eq!(map_keys(&top), vec![1, 2, 3]);
    assert_eq!(
        map_get(&top, 1).expect("components"),
        Cbor::Array(vec![
            Cbor::Uint(44),
            Cbor::Bool(true),
            Cbor::Uint(118),
            Cbor::Bool(true),
            Cbor::Uint(0),
            Cbor::Bool(true),
            Cbor::Uint(0),
            Cbor::Bool(false),
            Cbor::Array(vec![]),
            Cbor::Bool(false),
        ])
    );
    assert_eq!(
        as_uint(&map_get(&top, 2).expect("source_fingerprint")),
        0x7823_0804
    );
    assert_eq!(as_uint(&map_get(&top, 3).expect("depth")), 5);
}

const SEED: [u8; 64] = [0x42; 64];

fn fixture(purpose: u32) -> ([u8; 4], [u8; 78], DerivationPath) {
    let mfp = master_fingerprint_from_seed(&SEED).expect("mfp");
    let path = DerivationPath::parse(&format!("m/{purpose}'/0'/0'")).expect("path");
    let xpub = xpub_from_seed(&SEED, &path).expect("xpub");
    (mfp, xpub, path)
}

fn payload_of(uri: &str) -> Vec<u8> {
    let d = ur_decode::decode(uri).expect("ur decode");
    d.as_ref().to_vec()
}

// ------------------------- shape pins -------------------------

/// W0-2 defect pin: the origin keypath must carry source_fingerprint (field 2).
///
/// Writing only field 1 (components) and field 3 (depth) makes the keystone SDK
/// `parseHDKey` throw "HDKey is invalid", so pairing is unusable.
#[test]
fn crypto_hdkey_origin_carries_source_fingerprint() {
    let (mfp, xpub, path) = fixture(84);
    let enc = crypto_hd_key::encode(&xpub, &mfp, Some(&path)).expect("encode");
    let payload = payload_of(enc.as_str());
    let top = parse(&payload);

    let origin = untag(&map_get(&top, 6).expect("key 6 origin missing"), 304);
    let sfp = map_get(&origin, 2).expect(
        "PINNED: crypto-keypath is missing field 2 (source_fingerprint) -- \
         keystone SDK parseHDKey throws \"HDKey is invalid\"",
    );
    assert_eq!(
        as_uint(&sfp),
        u64::from(u32::from_be_bytes(mfp)),
        "source_fingerprint must be our master fingerprint"
    );

    // depth = number of path levels (field 3)
    assert_eq!(as_uint(&map_get(&origin, 3).expect("depth")), 3);
    // components are a flat array: 84'/0'/0' -> [84,true,0,true,0,true]
    let comps = map_get(&origin, 1).expect("components");
    assert_eq!(
        comps,
        Cbor::Array(vec![
            Cbor::Uint(84),
            Cbor::Bool(true),
            Cbor::Uint(0),
            Cbor::Bool(true),
            Cbor::Uint(0),
            Cbor::Bool(true),
        ])
    );
}

/// crypto-account (311): the entry shape for BTC pairing in the keystone ecosystem.
///
/// Shape taken from `ur-registry` 1.0.9: `crypto_account.rs` = map{1: mfp,
/// 2: [crypto-output]}; each crypto-output has **no map shell** -- first a number of
/// script-expression tags (400 p2sh / 403 pkh / 404 wpkh / 409 tr),
/// then tag(303) + crypto-hdkey.
#[test]
fn crypto_account_shape_matches_registry() {
    use shlosilo::ur::codec::crypto_account::{self, AccountOutput};

    let mfp = master_fingerprint_from_seed(&SEED).expect("mfp");
    let p44 = DerivationPath::parse("m/44'/0'/0'").expect("path");
    let p49 = DerivationPath::parse("m/49'/0'/0'").expect("path");
    let p84 = DerivationPath::parse("m/84'/0'/0'").expect("path");
    let p86 = DerivationPath::parse("m/86'/0'/0'").expect("path");
    let x44 = xpub_from_seed(&SEED, &p44).expect("xpub");
    let x49 = xpub_from_seed(&SEED, &p49).expect("xpub");
    let x84 = xpub_from_seed(&SEED, &p84).expect("xpub");
    let x86 = xpub_from_seed(&SEED, &p86).expect("xpub");

    let outputs = [
        AccountOutput {
            xpub: &x44,
            path: &p44,
            script_expressions: &[403],
        },
        AccountOutput {
            xpub: &x49,
            path: &p49,
            script_expressions: &[400, 404],
        },
        AccountOutput {
            xpub: &x84,
            path: &p84,
            script_expressions: &[404],
        },
        AccountOutput {
            xpub: &x86,
            path: &p86,
            script_expressions: &[409],
        },
    ];
    let enc = crypto_account::encode(&mfp, &outputs).expect("encode");
    assert!(
        enc.as_str().starts_with("ur:crypto-account/"),
        "got {}",
        enc.as_str()
    );
    let payload = payload_of(enc.as_str());
    let top = parse(&payload);
    assert_eq!(map_keys(&top), vec![1, 2]);
    assert_eq!(
        as_uint(&map_get(&top, 1).expect("master fingerprint")),
        u64::from(u32::from_be_bytes(mfp))
    );
    let Cbor::Array(items) = map_get(&top, 2).expect("outputs") else {
        panic!("field 2 must be an array");
    };
    assert_eq!(items.len(), 4);

    // Tag sequence of each output plus the origin path of the embedded hdkey.
    let expect: [(&[u64], &str); 4] = [
        (&[403], "m/44'/0'/0'"),
        (&[400, 404], "m/49'/0'/0'"),
        (&[404], "m/84'/0'/0'"),
        (&[409], "m/86'/0'/0'"),
    ];
    for (item, (tags, path)) in items.iter().zip(expect.iter()) {
        // Strip the script-expression tags; the last one is the tag(303) hdkey.
        let mut cur = item.clone();
        let mut seen = Vec::new();
        loop {
            match cur {
                Cbor::Tag(t, inner) => {
                    if t == 303 {
                        cur = *inner;
                        break;
                    }
                    seen.push(t);
                    cur = *inner;
                }
                other => panic!("unexpected crypto-output tail {other:?}"),
            }
        }
        assert_eq!(
            seen,
            tags.to_vec(),
            "script expression tag sequence mismatch"
        );
        // The hdkey must carry origin (source fingerprint + path) and children.
        let origin = untag(&map_get(&cur, 6).expect("origin"), 304);
        assert!(
            map_get(&origin, 2).is_some(),
            "the hdkey inside crypto-output must carry source_fingerprint too"
        );
        let comps = map_get(&origin, 1).expect("components");
        let want = DerivationPath::parse(path).expect("path");
        let mut flat = Vec::new();
        for c in want.as_slice() {
            flat.push(Cbor::Uint(u64::from(c.value())));
            flat.push(Cbor::Bool(c.is_hardened()));
        }
        assert_eq!(comps, Cbor::Array(flat), "components mismatch for {path}");
        assert!(map_get(&cur, 7).is_some(), "children missing");
    }
}

/// Full field set of an extended key (the shape the keystone ecosystem actually emits).
#[test]
fn crypto_hdkey_extended_shape_matches_registry() {
    let (mfp, xpub, path) = fixture(84);
    let enc = crypto_hd_key::encode(&xpub, &mfp, Some(&path)).expect("encode");
    let payload = payload_of(enc.as_str());
    let top = parse(&payload);

    // 1 is_master: not emitted for extended keys (only the master key emits true)
    assert!(
        map_get(&top, 1).is_none(),
        "extended keys must not write is_master -- keystone/registry writes field 1 only on the master-key branch"
    );
    // 2 is_private: must not be emitted for public-key export (wallets would treat it as a private key)
    assert!(
        map_get(&top, 2).is_none(),
        "public-key export must not carry is_private"
    );
    // 3 key / 4 chain_code / 8 parent_fingerprint
    assert_eq!(as_bytes(&map_get(&top, 3).expect("key")), &xpub[45..78]);
    assert_eq!(
        as_bytes(&map_get(&top, 4).expect("chain_code")),
        &xpub[13..45]
    );
    assert_eq!(
        as_uint(&map_get(&top, 8).expect("parent_fingerprint")),
        u64::from(u32::from_be_bytes([xpub[5], xpub[6], xpub[7], xpub[8]]))
    );
    // 5 use_info: tag 305 {1: coin_type 0 (BTC), 2: network 0 (mainnet)}
    let coin_info = untag(&map_get(&top, 5).expect("use_info missing"), 305);
    assert_eq!(as_uint(&map_get(&coin_info, 1).expect("coin_type")), 0);
    assert_eq!(as_uint(&map_get(&coin_info, 2).expect("network")), 0);
    // 7 children: 0/* -> [0,false] + [wildcard empty array,false]
    let children = untag(&map_get(&top, 7).expect("children missing"), 304);
    let ccomps = map_get(&children, 1).expect("children components");
    assert_eq!(
        ccomps,
        Cbor::Array(vec![
            Cbor::Uint(0),
            Cbor::Bool(false),
            Cbor::Array(vec![]),
            Cbor::Bool(false),
        ]),
        "children must encode as 0/* (wildcard = empty array)"
    );

    // Field-set convergence assertion: any extra or missing field fails.
    let mut keys = map_keys(&top);
    keys.sort_unstable();
    assert_eq!(keys, vec![3, 4, 5, 6, 7, 8]);
}
