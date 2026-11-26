//! E-3 P2 pins: the pool's hash layer against the alloc encoder, byte for byte.
//!
//! ## What is pinned here
//!
//! **Differential, not duplicated expectations.** Every case below computes the digest
//! TWICE — once from the owned values `eip712.rs` builds, once from the zero-heap pool
//! — and asserts the two are equal. Neither side is compared against a constant the
//! other side produced, so a change to either encoder turns this red immediately.
//!
//! Externally anchored digests appear on top of that, never instead of it:
//!
//! 1. **11 real-world samples** — the same documents `tests/eip712_budget_spike.rs`
//!    measured (included below as a module, so the two files cannot drift apart about
//!    what a "real payload" is), covering Permit2, Seaport, SafeTx and the EIP-712
//!    `Mail` example: flat, nested-struct, and array-of-struct shapes.
//! 2. **`encodeType` lengths** — the two numbers the spike measured (Seaport 450 B,
//!    official Mail 77 B), plus the full string compared against the alloc encoder for
//!    every sample: `typeHash` is `keccak256` of exactly these bytes.
//! 3. **keystone golden vectors** — the EIP-712 vectors of
//!    `tests/eth_keystone_cross_validation.rs` rebuilt as typed-data JSON, so the same
//!    external digest is checked through BOTH faces. Those vectors are constructed
//!    programmatically there (no JSON), hence the JSON below: it is their field values
//!    and type definitions spelled out, and the expected hash is the oracle's.
// Chain axis: this file drives the eth surface; without that switch the
// API it uses does not exist.
#![cfg(feature = "chain-eth")]
#![cfg(feature = "alloc-fallback")]

use shlosilo::chain::eth::eip712::{self, parse_typed_data_v4};
use shlosilo::chain::eth::eip712_pool::{self, Eip712Field, Eip712Node, Eip712Pool, Eip712Type};
use shlosilo::error::{ErrorContext, ShlosiloError, ShlosiloErrorKind};

/// The 11 real-world documents, taken from the budget spike rather than copied.
#[path = "eip712_budget_spike.rs"]
mod spike;

// ─── harness ────────────────────────────────────────────────────────────────

/// Parse `json` into a pool and run `f` while its storage is alive.
fn with_pool<R>(json: &str, f: impl FnOnce(&Eip712Pool<'_>) -> R) -> Result<R, ShlosiloError> {
    let mut arena = std::vec![0u8; 8 * 1024];
    let mut nodes = std::vec![Eip712Node::default(); 4096];
    let mut types = std::vec![Eip712Type::default(); 64];
    let mut fields = std::vec![Eip712Field::default(); 256];
    match eip712_pool::parse(
        json.as_bytes(),
        &mut arena,
        &mut nodes,
        &mut types,
        &mut fields,
    ) {
        Ok(pool) => Ok(f(&pool)),
        Err(e) => Err(e),
    }
}

/// The alloc digest for `json`.
fn alloc_digest(json: &str) -> Result<[u8; 32], ShlosiloError> {
    let typed = parse_typed_data_v4(json)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    typed.signing_hash()
}

/// The pool digest for `json`.
fn pool_digest(json: &str) -> Result<[u8; 32], ShlosiloError> {
    with_pool(json, eip712_pool::signing_hash_pool)?
}

fn hex_encode(bytes: &[u8]) -> std::string::String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = std::string::String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Both faces on one document: the digests must be equal, and returned for anchoring.
fn assert_both_faces(json: &str, what: &str) -> [u8; 32] {
    let alloc =
        alloc_digest(json).unwrap_or_else(|e| panic!("{what}: the alloc face failed: {e:?}"));
    let pool = pool_digest(json).unwrap_or_else(|e| panic!("{what}: the pool face failed: {e:?}"));
    assert_eq!(
        hex_encode(&alloc),
        hex_encode(&pool),
        "{what}: the two faces must sign the same digest"
    );
    alloc
}

/// The pool's `encodeType` string for `primary`, as text.
fn pool_encode_type(json: &str, primary: &str) -> Result<std::string::String, ShlosiloError> {
    let bytes = with_pool(json, |pool| {
        let mut out = std::vec![0u8; 1024];
        let n = eip712_pool::encode_type_pool(pool, primary, &mut out)?;
        Ok::<std::vec::Vec<u8>, ShlosiloError>(out[..n].to_vec())
    })??;
    std::string::String::from_utf8(bytes)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))
}

/// The pool's `encodeType` length for `primary`.
fn pool_encode_type_len(json: &str, primary: &str) -> Result<usize, ShlosiloError> {
    with_pool(json, |pool| {
        eip712_pool::encode_type_pool(pool, primary, &mut std::vec![0u8; 1024])
    })?
}

// ─── 1. real-world samples ──────────────────────────────────────────────────

/// Every payload the spike measured must hash identically on both faces.
#[test]
fn real_world_samples_hash_identically_on_both_faces() {
    let samples = spike::samples();
    assert_eq!(samples.len(), 11, "the spike's sample set is the input");
    for (name, json) in samples {
        let digest = assert_both_faces(&json, name);
        // The digest is reported so a failure names the sample, not just a byte offset.
        println!("{name:<28} 0x{}", hex_encode(&digest));
    }
}

// ─── 2. encodeType: the bytes typeHash hashes ───────────────────────────────

/// The pool's `encodeType` must be the alloc string byte for byte, on every sample.
#[test]
fn encode_type_matches_the_alloc_encoder_on_every_sample() {
    for (name, json) in spike::samples() {
        let typed = parse_typed_data_v4(&json).expect("the alloc parser accepts the sample");
        let expected = eip712::encode_type(&typed.primary_type, &typed.types).expect("encode_type");
        let got = pool_encode_type(&json, typed.primary_type.as_str()).expect("encodeType fits");
        assert_eq!(got, expected, "{name}: encodeType must be identical");
    }
}

/// The two measured lengths (the spike's table): Seaport 450 B, official Mail 77 B.
///
/// These are the numbers the D-E budget was chosen against, so they are pinned as
/// lengths AND as the reason the `typeHash` buffer is sized 512.
#[test]
fn encode_type_lengths_are_the_measured_ones() {
    let n = pool_encode_type_len(spike::SEAPORT_ORDER, "OrderComponents").expect("seaport parses");
    assert_eq!(n, 450, "Seaport OrderComponents encodeType is 450 bytes");

    let n = pool_encode_type_len(spike::MAIL_OFFICIAL, "Mail").expect("official Mail parses");
    assert_eq!(n, 77, "the EIP-712 Mail example encodeType is 77 bytes");
}

/// A buffer one byte short refuses with the length it needed — never a truncated type
/// string, which would hash to a different digest.
#[test]
fn encode_type_buffer_too_small_is_capacity_not_format() {
    let json = spike::MAIL_OFFICIAL;
    with_pool(json, |pool| {
        let mut out = [0u8; 76];
        let err = eip712_pool::encode_type_pool(pool, "Mail", &mut out)
            .expect_err("76 bytes cannot hold a 77-byte encodeType");
        assert_eq!(err.kind, ShlosiloErrorKind::BufferTooSmall);
        match err.context {
            ErrorContext::RequiredLength(need) => assert!(need > 76, "need = {need}"),
            other => panic!("expected RequiredLength, got {other:?}"),
        }
    })
    .expect("official Mail parses");
}

// ─── 3. keystone golden vectors, through both faces ─────────────────────────

/// keystone `test_hash_typed_message_with_data`: `Message(data:string)` over a
/// four-field domain. Expected `232cd3ec…`.
const KEYSTONE_MESSAGE: &str = r#"{
  "types": {
    "EIP712Domain": [
      {"name":"name","type":"string"},
      {"name":"version","type":"string"},
      {"name":"chainId","type":"uint256"},
      {"name":"verifyingContract","type":"address"}
    ],
    "Message": [{"name":"data","type":"string"}]
  },
  "primaryType": "Message",
  "domain": {"name":"example.metamask.io","version":"1","chainId":1,
             "verifyingContract":"0x0000000000000000000000000000000000000000"},
  "message": {"data":"Hello!"}
}"#;

/// keystone `test_minimal_message`: an EMPTY domain declaration and an empty message.
/// shlosilo follows standard EIP-712 here (keystone skips the struct hash for
/// `primaryType == "EIP712Domain"`), so the oracle for this shape is the independent
/// computation documented in `tests/eth_keystone_cross_validation.rs`, not keystone's
/// own value.
const KEYSTONE_MINIMAL: &str = r#"{
  "types": {"EIP712Domain": []},
  "primaryType": "EIP712Domain",
  "domain": {},
  "message": {}
}"#;

/// keystone `test_encode_custom_array_type`: `Person(address[] wallet)` nested inside
/// `Mail(to: Person[])`. Expected `80a3aeb5…`.
const KEYSTONE_ARRAY: &str = r#"{
  "types": {
    "EIP712Domain": [],
    "Person": [
      {"name":"name","type":"string"},
      {"name":"wallet","type":"address[]"}
    ],
    "Mail": [
      {"name":"from","type":"Person"},
      {"name":"to","type":"Person[]"},
      {"name":"contents","type":"string"}
    ]
  },
  "primaryType": "Mail",
  "domain": {},
  "message": {
    "from": {"name":"Cow","wallet":[
      "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
      "0xDD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"]},
    "to": [{"name":"Bob","wallet":[
      "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"]}],
    "contents": "Hello, Bob!"
  }
}"#;

/// The three EIP-712 vectors of the keystone cross-validation file, each anchored to
/// the oracle's digest and computed on both faces.
#[test]
fn keystone_golden_vectors_agree_on_both_faces() {
    let cases: [(&str, &str, &str); 3] = [
        (
            "keystone typed message",
            KEYSTONE_MESSAGE,
            "232cd3ec058eb935a709f093e3536ce26cc9e8e193584b0881992525f6236eef",
        ),
        (
            "keystone minimal (empty) domain",
            KEYSTONE_MINIMAL,
            "85935f898ffc4239bfbe27fd9f097ef4cc1f8441ef1d141541cdd20ea0ab933a",
        ),
        (
            "keystone array/nested type",
            KEYSTONE_ARRAY,
            "80a3aeb51161cfc47884ddf8eac0d2343d6ae640efe78b6a69be65e3045c1321",
        ),
    ];
    for (what, json, expected) in cases {
        let digest = assert_both_faces(json, what);
        assert_eq!(
            hex_encode(&digest),
            expected,
            "{what}: both faces must reproduce the external oracle"
        );
    }
}

// ─── 4. the pieces the pin above exercises indirectly ───────────────────────

/// `typeHash` is `keccak256(encodeType)`: checked through its own entry point, and
/// against the alloc `type_hash` for the same type name.
#[test]
fn type_hash_is_keccak_of_encode_type() {
    let json = spike::MAIL_OFFICIAL;
    let typed = parse_typed_data_v4(json).expect("the alloc parser accepts Mail");
    with_pool(json, |pool| {
        let pool_hash = eip712_pool::type_hash_pool(pool, "Mail").expect("pool typeHash");
        let alloc_hash = eip712::type_hash("Mail", &typed.types).expect("alloc typeHash");
        assert_eq!(hex_encode(&pool_hash), hex_encode(&alloc_hash));
        // And it is the keccak of the string itself, not of something else.
        let mut buf = [0u8; 512];
        let n = eip712_pool::encode_type_pool(pool, "Mail", &mut buf).expect("encodeType fits");
        let direct = shlosilo::encoding::keccak256::hash(&buf[..n]).expect("keccak");
        assert_eq!(hex_encode(&pool_hash), hex_encode(&direct));
    })
    .expect("official Mail parses");
}

/// `hashStruct` of the message root on its own (the entry `signing_hash_pool` uses),
/// against the alloc `hash_struct` over the parsed values.
#[test]
fn hash_struct_of_the_message_root_agrees() {
    for (name, json) in spike::samples() {
        let typed = parse_typed_data_v4(&json).expect("the alloc parser accepts the sample");
        let alloc_hash = eip712::hash_struct(&typed.primary_type, &typed.message, &typed.types)
            .expect("alloc hashStruct");
        let pool_hash = with_pool(&json, |pool| {
            eip712_pool::hash_struct_pool(pool, pool.message_root().expect("root"))
        })
        .expect("the pool parses the sample")
        .expect("the pool hashes the message");
        assert_eq!(
            hex_encode(&alloc_hash),
            hex_encode(&pool_hash),
            "{name}: hashStruct"
        );
    }
}

// ─── 5. atom content, and the domain's leniency ─────────────────────────────

/// Atom shapes the real-world samples do not all reach, hashed on both faces: dynamic
/// `bytes` that is NOT hex (the alloc parser falls back to the literal text), `bytes`
/// that is hex with upper-case digits, a negative `int256`, a negative `int8` (sign
/// extension), a `uint256` spelled as 32 hex bytes, a wide `uint128` in decimal, a
/// short `bytes4` (right-padded with zeros), an `address` WITHOUT the `0x` prefix (the
/// alloc parser accepts that) and a `bool`.
#[test]
fn atom_encodings_agree_on_corner_cases() {
    const CORNERS: &str = r#"{
      "types": {
        "EIP712Domain": [
          {"name":"name","type":"string"},
          {"name":"salt","type":"bytes32"}
        ],
        "Corner": [
          {"name":"raw","type":"bytes"},
          {"name":"hexed","type":"bytes"},
          {"name":"negative","type":"int256"},
          {"name":"signed8","type":"int8"},
          {"name":"wide","type":"uint256"},
          {"name":"decimal128","type":"uint128"},
          {"name":"short","type":"bytes4"},
          {"name":"bare","type":"address"},
          {"name":"flag","type":"bool"}
        ]
      },
      "primaryType": "Corner",
      "domain": {"name":"corners",
                 "salt":"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"},
      "message": {
        "raw": "not-hex-text",
        "hexed": "0xdeadBEEF",
        "negative": "-12345678901234",
        "signed8": -1,
        "wide": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "decimal128": "340282366920938463463374607431768211455",
        "short": "0xdeadbeef",
        "bare": "CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
        "flag": false
      }
    }"#;
    let digest = assert_both_faces(CORNERS, "atom corner cases");
    assert_ne!(digest, [0u8; 32], "a real digest, not a placeholder");
}

/// A domain `salt` spelled WITHOUT the `0x` prefix. The alloc parser's domain path
/// accepts it (`parse_bytes32_hex` → `parse_hex_bytes`, whose prefix is optional) even
/// though a message-level `bytesN` requires the prefix — so the pool has to be lenient
/// here and strict there, or it would refuse a request the alloc face signs.
#[test]
fn a_bare_domain_salt_agrees_on_both_faces() {
    const TEMPLATE: &str = r#"{
      "types": {
        "EIP712Domain": [{"name":"name","type":"string"},{"name":"salt","type":"bytes32"}],
        "T": [{"name":"a","type":"uint256"}]
      },
      "primaryType": "T",
      "domain": {"name":"salted","salt":"SALT"},
      "message": {"a":1}
    }"#;
    let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let prefixed = TEMPLATE.replace("SALT", &std::format!("0x{hex}"));
    let bare = TEMPLATE.replace("SALT", hex);
    let with_prefix = assert_both_faces(&prefixed, "prefixed domain salt");
    let without = assert_both_faces(&bare, "bare domain salt");
    assert_eq!(
        hex_encode(&with_prefix),
        hex_encode(&without),
        "the prefix must not move the salt: both spellings are the same 32 bytes"
    );
}

/// A digest is refused, not guessed. Two asymmetries of the alloc domain handling are
/// pinned through both faces: an extra domain key the declaration does not cover is
/// ignored (wallets add them), and a declared field the document never filled produces
/// no digest at all (audit A3c-F16).
#[test]
fn domain_leniency_and_refusal_agree_on_both_faces() {
    let plain = assert_both_faces(KEYSTONE_MESSAGE, "keystone typed message");

    // (a) `salt` rides in the domain object but the declaration does not cover it: both
    //     faces leave it out, so the digest is the plain one.
    let extra = KEYSTONE_MESSAGE.replace(
        r#""chainId":1,"#,
        r#""salt":"0x0000000000000000000000000000000000000000000000000000000000000000","chainId":1,"#,
    );
    assert_eq!(
        hex_encode(&assert_both_faces(&extra, "undeclared domain salt")),
        hex_encode(&plain),
        "an undeclared domain key must not move the digest"
    );

    // (b) `verifyingContract` stays declared while the domain object swaps it for a
    //     salt: the declared field has no value.
    let missing = KEYSTONE_MESSAGE.replace(
        r#""verifyingContract":"0x0000000000000000000000000000000000000000""#,
        r#""salt":"0x0000000000000000000000000000000000000000000000000000000000000000""#,
    );
    assert!(
        alloc_digest(&missing).is_err(),
        "the alloc face refuses a declared domain field with no value"
    );
    let err = pool_digest(&missing).expect_err("the pool refuses it too");
    assert_eq!(
        err.kind,
        ShlosiloErrorKind::EncodingInvalidFormat,
        "a missing declared domain field is a malformed request, not a capacity problem"
    );
}

/// A diamond dependency: `A` reaches `C` both directly and through `B`.
///
/// `encodeType` must list every reached type exactly once. The candidate set of a
/// type's sub-structs is collected before the emit loop, so a branch that a deeper
/// call already emitted has to be re-checked inside the loop — without that check
/// `C` is written twice, `typeHash` changes, and the signature verifies against a
/// digest no wallet computes.
#[test]
fn a_diamond_dependency_emits_each_type_once() {
    let json = r#"{
      "types": {
        "EIP712Domain": [{"name":"name","type":"string"},{"name":"chainId","type":"uint256"}],
        "A": [{"name":"b","type":"B"},{"name":"c","type":"C"}],
        "B": [{"name":"c","type":"C"}],
        "C": [{"name":"x","type":"uint256"}]
      },
      "primaryType": "A",
      "domain": {"name":"Diamond","chainId":1},
      "message": {"b":{"c":{"x":7}},"c":{"x":7}}
    }"#;
    let td = parse_typed_data_v4(json).expect("the alloc face parses a diamond");
    let alloc = eip712::encode_type("A", &td.types).expect("the alloc face encodes");
    let pool = pool_encode_type(json, "A").expect("the pool encodes");
    assert_eq!(
        alloc, "A(B b,C c)B(C c)C(uint256 x)",
        "declaration order, then subtypes alphabetically, each type once"
    );
    assert_eq!(alloc, pool, "both faces agree on the diamond");
    assert_eq!(
        alloc.matches("C(uint256 x)").count(),
        1,
        "C must be written once, not once per reference path"
    );
    // The digest has to agree too, not just the string.
    assert_both_faces(json, "diamond");
}
