//! crypto-hdkey / crypto-account registry 形状钉（BCR-2020-006）
//!
//! ## 为什么需要这个文件
//!
//! keystone 生态的钱包（MetaMask / Sparrow / BlueWallet / Nunchuk 都走
//! `@keystonehq/keystone-sdk`）解析 `crypto-hdkey` 时**强制要求** keypath 携带
//! `source_fingerprint`：`keystone-sdk-web/src/wallet/hdKey.ts` 在
//! `getOrigin().getSourceFingerprint() === undefined` 时直接
//! `throw new Error("HDKey is invalid")`。缺这个字段 = 配对整条腿死掉，
//! 且我方自测（只用自家 decoder 的 round-trip）**看不见**——两个方向一起错就恒绿。
//!
//! ## oracle 来源（外部权威，非自证）
//!
//! `ur-registry` 1.0.9（keystone 固件 `Cargo.toml` 钉的同一 crate 版本）：
//! - `src/crypto_hd_key.rs:15-24`    map keys：1 is_master / 2 is_private /
//!   3 key / 4 chain_code / 5 use_info(tag 305) / 6 origin(tag 304) /
//!   7 children(tag 304) / 8 parent_fingerprint
//! - `src/crypto_key_path.rs:13-15`  keypath keys：1 components /
//!   **2 source_fingerprint** / 3 depth
//! - `src/crypto_key_path.rs:313`    金标向量：
//!   `a3018a182cf51876f500f500f480f4021a782308040305`
//!   → `{1: [44',true,118',true,0',true,0,f,<empty-array>,f], 2: 0x78230804, 3: 5}`
//!   （components 是**扁平** `[idx, hardened, ...]`；通配符 `*` 编码成**空数组** 0x80）
//! - `src/crypto_account.rs`         map：1 master_fingerprint / 2 [crypto-output]
//! - `src/crypto_output.rs`          crypto-output **没有 map 外壳**：先若干
//!   script-expression tag（400 p2sh / 403 pkh / 404 wpkh / 409 tr），再 tag(303) + hdkey
//!
//! 本文件里的 CBOR 走查器**刻意不用** `forms::encoding::cbor`：形状钉必须由一个
//! 与实现无关的解析器判读，否则实现读错字段时钉跟着一起读错。

use shlosilo::derivation::bip32_secp256k1::{master_fingerprint_from_seed, xpub_from_seed};
use shlosilo::derivation::path::DerivationPath;
use shlosilo::ur::codec::crypto_hd_key;
use shlosilo::ur::ur_decode;

// ───────────────────────── 独立 CBOR 走查器（测试侧） ─────────────────────────

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
    assert_eq!(r.i, bytes.len(), "CBOR 有尾部残留字节（形状不符）");
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

// ───────────────────────── 夹具 ─────────────────────────

fn from_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

/// 走查器自检：用 `ur-registry` 1.0.9 官方测试向量校验本文件的 CBOR 解析器。
///
/// 没有这一钉时，「我方实现 + 我方走查器」有可能是同一个错误的两次表达。
/// 向量来源：`ur-registry-1.0.9/src/crypto_key_path.rs` 的 `test_encode`，
/// 语义 = `m/44'/118'/0'/0/*` + source_fingerprint 0x78230804 + depth 5。
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

// ───────────────────────── 形状钉 ─────────────────────────

/// W0-2 缺陷钉：origin keypath 必须携带 source_fingerprint（field 2）。
///
/// 现行实现只写 field 1(components) 与 field 3(depth) → keystone SDK
/// `parseHDKey` 抛 "HDKey is invalid" → 配对不可用。
#[test]
fn crypto_hdkey_origin_carries_source_fingerprint() {
    let (mfp, xpub, path) = fixture(84);
    let enc = crypto_hd_key::encode(&xpub, &mfp, Some(&path)).expect("encode");
    let payload = payload_of(enc.as_str());
    let top = parse(&payload);

    let origin = untag(&map_get(&top, 6).expect("key 6 origin missing"), 304);
    let sfp = map_get(&origin, 2).expect(
        "PINNED: crypto-keypath 缺 field 2 (source_fingerprint) —— \
         keystone SDK parseHDKey 会 throw \"HDKey is invalid\"",
    );
    assert_eq!(
        as_uint(&sfp),
        u64::from(u32::from_be_bytes(mfp)),
        "source_fingerprint 必须是本机 master fingerprint"
    );

    // depth = 路径层数（field 3）
    assert_eq!(as_uint(&map_get(&origin, 3).expect("depth")), 3);
    // components 扁平数组：84'/0'/0' → [84,true,0,true,0,true]
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

/// crypto-account (311)：keystone 生态 BTC 配对的入口形状。
///
/// 形状来自 `ur-registry` 1.0.9：`crypto_account.rs` = map{1: mfp,
/// 2: [crypto-output]}；每个 crypto-output **无 map 外壳**，先是若干
/// script-expression tag（400 p2sh / 403 pkh / 404 wpkh / 409 tr），
/// 再 tag(303) + crypto-hdkey。
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
        panic!("field 2 必须是数组");
    };
    assert_eq!(items.len(), 4);

    // 每个 output 的 tag 序列 + 内嵌 hdkey 的 origin 路径
    let expect: [(&[u64], &str); 4] = [
        (&[403], "m/44'/0'/0'"),
        (&[400, 404], "m/49'/0'/0'"),
        (&[404], "m/84'/0'/0'"),
        (&[409], "m/86'/0'/0'"),
    ];
    for (item, (tags, path)) in items.iter().zip(expect.iter()) {
        // 剥掉 script-expression tag，最后一个是 tag(303) hdkey
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
        assert_eq!(seen, tags.to_vec(), "script expression tag 序列不符");
        // hdkey 必须带 origin（源指纹 + 路径）与 children
        let origin = untag(&map_get(&cur, 6).expect("origin"), 304);
        assert!(
            map_get(&origin, 2).is_some(),
            "crypto-output 里的 hdkey 同样必须带 source_fingerprint"
        );
        let comps = map_get(&origin, 1).expect("components");
        let want = DerivationPath::parse(path).expect("path");
        let mut flat = Vec::new();
        for c in want.as_slice() {
            flat.push(Cbor::Uint(u64::from(c.value())));
            flat.push(Cbor::Bool(c.is_hardened()));
        }
        assert_eq!(comps, Cbor::Array(flat), "{path} 的 components 不符");
        assert!(map_get(&cur, 7).is_some(), "children 缺失");
    }
}

/// 扩展键的完整字段面（keystone 实际发出的形状）。
#[test]
fn crypto_hdkey_extended_shape_matches_registry() {
    let (mfp, xpub, path) = fixture(84);
    let enc = crypto_hd_key::encode(&xpub, &mfp, Some(&path)).expect("encode");
    let payload = payload_of(enc.as_str());
    let top = parse(&payload);

    // 1 is_master：扩展键不发（只有 master key 才发 true）
    assert!(
        map_get(&top, 1).is_none(),
        "扩展键不应写 is_master —— keystone/registry 只在 master key 分支写 field 1"
    );
    // 2 is_private：公钥导出必须不发（否则钱包当私钥处理）
    assert!(map_get(&top, 2).is_none(), "公钥导出不得携带 is_private");
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
    // 5 use_info：tag 305 {1: coin_type 0 (BTC), 2: network 0 (mainnet)}
    let coin_info = untag(&map_get(&top, 5).expect("use_info missing"), 305);
    assert_eq!(as_uint(&map_get(&coin_info, 1).expect("coin_type")), 0);
    assert_eq!(as_uint(&map_get(&coin_info, 2).expect("network")), 0);
    // 7 children：0/* → [0,false] + [wildcard 空数组,false]
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
        "children 必须编码成 0/*（通配符=空数组）"
    );

    // 字段集合收敛断言：多写少写都要红
    let mut keys = map_keys(&top);
    keys.sort_unstable();
    assert_eq!(keys, vec![3, 4, 5, 6, 7, 8]);
}
