//! ETH cross-validation (v9.14)
//!
//! Uses the keystone `rust/apps/ethereum` test fixtures as the oracle:
//! 1. EIP-712 typed data hash — `eip712.rs::test_hash_typed_message_with_data`
//!    plus the metamask/minimal/array vectors in the same file
//! 2. EIP-155 legacy tx RLP — `legacy_transaction.rs::test_transfer_erc20_legacy_transaction`
//!
//! Methodology: the expected hash/RLP bytes in keystone's tests are external anchors,
//! shlosilo's independent implementation must produce identical bytes.
// Chain axis: this file exercises the feature = "chain-eth" surface; without that switch
// compiled in, the API it drives does not exist.
#![cfg(feature = "chain-eth")]
#![cfg(feature = "alloc-fallback")]

use shlosilo::chain::eth::eip712;
use shlosilo::chain::eth::rlp;

// ─── helpers ─────────────────────────────────────────────────────────

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&hex_bytes(s));
    out
}

fn hex_to_20(s: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&hex_bytes(s));
    out
}

fn hex_bytes(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(alloc_format).collect()
}

fn alloc_format(x: &u8) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2);
    s.push(HEX[(x >> 4) as usize] as char);
    s.push(HEX[(x & 0xf) as usize] as char);
    s
}

use std::string::String;

/// Build typed data matching keystone `test_hash_typed_message_with_data`:
/// EIP712Domain(name,version,chainId,verifyingContract) + Message(data:string)
fn keystone_typed_data() -> (
    eip712::Eip712Domain,
    String,
    eip712::Eip712Value,
    eip712::Types,
) {
    use std::string::ToString;

    let mut types = eip712::Types::new();
    types.insert(
        "EIP712Domain".to_string(),
        vec![
            ("name".to_string(), "string".to_string()),
            ("version".to_string(), "string".to_string()),
            ("chainId".to_string(), "uint256".to_string()),
            ("verifyingContract".to_string(), "address".to_string()),
        ],
    );
    types.insert(
        "Message".to_string(),
        vec![("data".to_string(), "string".to_string())],
    );

    let domain = eip712::Eip712Domain {
        name: Some("example.metamask.io".to_string()),
        version: Some("1".to_string()),
        chain_id: Some({
            let mut c = [0u8; 32];
            c[31] = 1;
            c
        }),
        verifying_contract: Some([0u8; 20]),
        salt: None,
    };

    let message = eip712::Eip712Value::Struct(
        "Message".to_string(),
        vec![eip712::Eip712Value::String(b"Hello!".to_vec())],
    );

    (domain, "Message".to_string(), message, types)
}

// ─── EIP-712 cross-validation ──────────────────────────────────────────────────

/// keystone `test_hash_typed_message_with_data`: expected signing hash
/// `232cd3ec058eb935a709f093e3536ce26cc9e8e193584b0881992525f6236eef`
#[test]
fn eth_eip712_keystone_typed_message_hash() {
    let (domain, primary, msg, types) = keystone_typed_data();
    let sighash = eip712::signing_hash(&domain, &primary, &msg, &types).unwrap();
    assert_eq!(
        hex_encode(&sighash),
        "232cd3ec058eb935a709f093e3536ce26cc9e8e193584b0881992525f6236eef",
        "shlosilo EIP-712 sighash must match keystone oracle"
    );
}

/// the keystone `test_minimal_message` vector **cannot be used as an oracle**:
/// keystone's `encode_eip712` (eip712.rs:454) skips struct_hash when `primaryType == "EIP712Domain"`
/// deliberately skips struct_hash (a MetaMask eth-sig-util compatibility quirk), differing from the standard EIP-712 definition.
/// shlosilo implements the standard (0x1901 || sep || structHash); the two inevitably diverge in this edge case.
#[test]
fn eth_eip712_minimal_edge_case_documented() {
    use std::string::ToString;

    let mut types = eip712::Types::new();
    types.insert("EIP712Domain".to_string(), vec![]);

    let domain = eip712::Eip712Domain::default();
    let msg = eip712::Eip712Value::Struct("EIP712Domain".to_string(), vec![]);

    // standard EIP-712 behavior: shlosilo's output differs from keystone's quirk value; that dialect
    // difference is documented by the assert_ne below, but excluding one wrong answer is not a check
    // (T1-08, 2026-11-19 audit, closed 2026-11-20) - so the value is also pinned against an
    // independent computation: typeHash = keccak("EIP712Domain()"), hashStruct over zero fields =
    // keccak(typeHash), and the signing hash = keccak(0x1901 || sep || sep).
    let sighash = eip712::signing_hash(&domain, "EIP712Domain", &msg, &types).unwrap();
    assert_eq!(
        hex_encode(&sighash),
        "85935f898ffc4239bfbe27fd9f097ef4cc1f8441ef1d141541cdd20ea0ab933a",
        "empty-domain signing hash must match the independent computation"
    );
    assert_ne!(
        hex_encode(&sighash),
        "8d4a3f4082945b7879e2b55f181c31a77c8c0a464b70669458abbaaf99de4c38",
        "shlosilo follows standard EIP-712; keystone's 8d4a3f... is its own quirk"
    );
}

/// keystone `test_encode_custom_array_type`: Person/address[] nested arrays
/// `80a3aeb51161cfc47884ddf8eac0d2343d6ae640efe78b6a69be65e3045c1321`
#[test]
fn eth_eip712_keystone_array_type_hash() {
    use std::string::ToString;

    let mut types = eip712::Types::new();
    types.insert("EIP712Domain".to_string(), vec![]);
    types.insert(
        "Person".to_string(),
        vec![
            ("name".to_string(), "string".to_string()),
            ("wallet".to_string(), "address[]".to_string()),
        ],
    );
    types.insert(
        "Mail".to_string(),
        vec![
            ("from".to_string(), "Person".to_string()),
            ("to".to_string(), "Person[]".to_string()),
            ("contents".to_string(), "string".to_string()),
        ],
    );

    // empty domain ("domain":{} in the keystone json)
    let domain = eip712::Eip712Domain::default();

    let from = eip712::Eip712Value::Struct(
        "Person".to_string(),
        vec![
            eip712::Eip712Value::String(b"Cow".to_vec()),
            eip712::Eip712Value::Array(vec![
                eip712::Eip712Value::Address(hex_to_20("CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")),
                eip712::Eip712Value::Address(hex_to_20("DD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")),
            ]),
        ],
    );
    let to = eip712::Eip712Value::Array(vec![eip712::Eip712Value::Struct(
        "Person".to_string(),
        vec![
            eip712::Eip712Value::String(b"Bob".to_vec()),
            eip712::Eip712Value::Array(vec![eip712::Eip712Value::Address(hex_to_20(
                "bBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
            ))]),
        ],
    )]);
    let mail = eip712::Eip712Value::Struct(
        "Mail".to_string(),
        vec![
            from,
            to,
            eip712::Eip712Value::String(b"Hello, Bob!".to_vec()),
        ],
    );

    let sighash = eip712::signing_hash(&domain, "Mail", &mail, &types).unwrap();
    assert_eq!(
        hex_encode(&sighash),
        "80a3aeb51161cfc47884ddf8eac0d2343d6ae640efe78b6a69be65e3045c1321",
        "array/nested type hash must match keystone oracle"
    );
}

// ─── EIP-155 legacy tx RLP cross-validation ─────────────────────────────────────

/// keystone `test_transfer_erc20_legacy_transaction`:
/// the unsigned RLP preimage must match keystone `LegacyTransaction::encode_raw()`.
/// Note that keystone's unsigned encoding contains (nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0)
/// The trailing three fields are EIP-155 replay protection; compared here against its full unsigned_hex.
#[test]
fn eth_legacy_rlp_keystone_erc20_unsigned() {
    // keystone fixture fields
    let nonce: u128 = 33;
    let gas_price: u128 = 15_198_060_006;
    let gas_limit: u128 = 46_000;
    let to = hex_to_20("fe2c232adDF66539BFd5d1Bd4B2cc91D358022a2");
    let value: u128 = 200_000_000_000_000;
    let data = hex_bytes("a9059cbb00000000000000000000000049ab56b91fc982fd6ec1ec7bb87d74efa6da30ab00000000000000000000000000000000000000000000000001480ff69d129e2d");
    let chain_id: u128 = 1; // the keystone test implies v=38 → EIP-155 (v = chain_id*2 + 35)

    // EIP-155 unsigned: rlp([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])
    let fields = vec![
        rlp::encode_uint(nonce),
        rlp::encode_uint(gas_price),
        rlp::encode_uint(gas_limit),
        rlp::encode_bytes(&to),
        rlp::encode_uint(value),
        rlp::encode_bytes(&data),
        rlp::encode_uint(chain_id),
        rlp::encode_uint(0),
        rlp::encode_uint(0),
    ];
    let list = rlp::encode_list(&fields);
    assert_eq!(
        hex_encode(&list),
        "f86f21850389dffde682b3b094fe2c232addf66539bfd5d1bd4b2cc91d358022a286b5e620f48000b844a9059cbb00000000000000000000000049ab56b91fc982fd6ec1ec7bb87d74efa6da30ab00000000000000000000000000000000000000000000000001480ff69d129e2d018080",
        "unsigned EIP-155 RLP must match keystone encode_raw output"
    );

    // signed raw tx: keystone gave fixed r/s/v; after reassembly it must match byte for byte + same tx hash
    let r_bytes = hex_to_32("35df2b615912b8be79a13c9b0a1540ade55434ab68778a49943442a9e6d3141a");
    let s_bytes = hex_to_32("0a6e33134ba47c1f1cda59ec3ef62a59d4da6a9d111eb4e447828574c1c94f66");
    let v: u128 = 38;

    let signed_fields = vec![
        rlp::encode_uint(nonce),
        rlp::encode_uint(gas_price),
        rlp::encode_uint(gas_limit),
        rlp::encode_bytes(&to),
        rlp::encode_uint(value),
        rlp::encode_bytes(&data),
        rlp::encode_uint(v),
        rlp::encode_bytes(&r_bytes),
        rlp::encode_bytes(&s_bytes),
    ];
    let signed_list = rlp::encode_list(&signed_fields);
    assert_eq!(
        hex_encode(&signed_list),
        "f8af21850389dffde682b3b094fe2c232addf66539bfd5d1bd4b2cc91d358022a286b5e620f48000b844a9059cbb00000000000000000000000049ab56b91fc982fd6ec1ec7bb87d74efa6da30ab00000000000000000000000000000000000000000000000001480ff69d129e2d26a035df2b615912b8be79a13c9b0a1540ade55434ab68778a49943442a9e6d3141aa00a6e33134ba47c1f1cda59ec3ef62a59d4da6a9d111eb4e447828574c1c94f66",
        "signed tx RLP must match keystone byte-for-byte"
    );

    // tx hash = keccak256(signed bytes)
    let tx_hash = shlosilo::encoding::keccak256::hash(&signed_list).unwrap();
    assert_eq!(
        hex_encode(&tx_hash),
        "fec8bfea5ec13ad726de928654cd1733b1d81d2d2916ac638e6b9a245f034ace",
        "tx hash must match keystone oracle"
    );
}

// ─── EIP-1559 signing pipeline (self-consistency + structural checks) ─────────────────────────

/// EIP-1559 signing preimage structure: 0x02 || rlp([...]).
/// keystone has no ready-made EIP-1559 sighash fixture (only parse-layer tests),
/// Here a known Ethereum-spec structure provides sanity + a consistency check that legacy and this share the same RLP encoder.
#[test]
fn eth_eip1559_signing_preimage_structure() {
    use shlosilo::chain::eth::eip1559::{signing_preimage, Eip1559Transaction};

    let tx = Eip1559Transaction {
        chain_id: 1,
        nonce: 42,
        max_priority_fee_per_gas: 2_000_000_000,
        max_fee_per_gas: 100_000_000_000,
        gas_limit: 21_000,
        destination: Some(hex_to_20("49aB56B91fc982Fd6Ec1EC7Bb87d74EFA6dA30ab")),
        amount: 1_000_000_000_000_000_000,
        data: vec![].into(),
    };
    let preimage = signing_preimage(&tx).unwrap();

    // the type byte must be 0x02
    assert_eq!(preimage[0], 0x02);

    // the rest of the preimage should be a valid RLP list — parse the length prefix correctly (including the 0xf8 long form)
    let (payload, len) = match preimage[1] {
        n if n < 0xc0 => panic!("expected list prefix >= 0xc0"),
        0xf8 => (&preimage[3..], preimage[2] as usize),
        0xf9 => (
            &preimage[4..],
            u16::from_be_bytes([preimage[2], preimage[3]]) as usize,
        ),
        n => (&preimage[2..], (n & 0x3f) as usize),
    };
    assert_eq!(
        payload.len(),
        len,
        "RLP length prefix must match payload size"
    );

    // T1-01 (2026-11-19 audit, closed 2026-11-20): the old assertion compared the signer with itself
    // (h1 == h2), which stays green even if both computations are wrong. The expected preimage and
    // sighash below come from a from-scratch Python Keccak-256 + RLP encoder - the same script
    // reproduces the official EIP-1559 vector sighash and the BIP-143/BIP-341 style controls - so this
    // pins the bytes against an independent implementation.
    assert_eq!(
        hex_encode(&preimage),
        "02f0012a847735940085174876e8008252089449ab56b91fc982fd6ec1ec7bb87d74efa6da30ab880de0b6b3a764000080c0",
        "EIP-1559 preimage must match the independent oracle byte for byte"
    );
    let sighash = shlosilo::chain::eth::eip1559::signing_hash(&tx).unwrap();
    assert_eq!(
        hex_encode(&sighash),
        "ee38168cca16acaed8c71f733f38b3f80a460117237ead322f547691c245b900",
        "sighash must match the independent oracle"
    );
}

// ─── personal_sign (EIP-191): the reference implementation's own signature bytes ──

/// `rust/apps/ethereum/src/lib.rs::test_sign_personal_message` pins a **raw 65-byte
/// signature** over a fixed message with the fixture seed. Both sides use
/// deterministic ECDSA (RFC 6979) and normalize to low-s, so `r`/`s` are unique for a
/// digest/key pair and the bytes must match exactly; EIP-191 takes `v` = 27/28 on both
/// sides. This is the only external byte-anchor for personal_sign, and it also covers
/// our zero-alloc EIP-191 digest (`personal_signing_hash_bytes`), which the device
/// path uses.
#[test]
fn eth_personal_sign_matches_keystone_signature_vector() {
    use shlosilo::business::sign::{sign, SignInput};
    use shlosilo::chain::eth::personal_sign;
    use shlosilo::types::SecretBytes;
    use shlosilo::ur::codec::eth_signature::parse_eth_signature;
    use shlosilo::ur::ur_encode::UrTypeTag;

    /// The 64-byte BIP-39 seed behind `0x9858EfFD232B4033E47d90003D41EC34EcaEda94`
    /// at `m/44'/60'/0'/0/0` — the key every keystone ETH test uses.
    const SEED_HEX: &str =
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    /// "Example `personal_sign` message"
    const MSG_HEX: &str = "4578616d706c652060706572736f6e616c5f7369676e60206d657373616765";
    const EXPECTED_SIG_HEX: &str = "b836ae2bac525ae9d2799928cf6f52919cb2ed5e5e52ca26e3b3cdbeb136ca2f618da0e6413a6aa3aaa722fbc2bcc87f591b8b427ee6915916f257de8125810e1b";

    let seed_vec = hex_bytes(SEED_HEX);
    assert_eq!(seed_vec.len(), 64, "64-byte BIP-39 seed");
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&seed_vec);
    let msg = hex_bytes(MSG_HEX);

    // 1. the digest + signature path on its own
    let path = shlosilo::derivation::path::DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
    let sk = shlosilo::derivation::bip32_secp256k1::derive_from_seed(&seed, &path).unwrap();
    let key = SecretBytes::new(shlosilo::curve_primitive::secp256k1::scalar_to_bytes(&sk));
    let sig = personal_sign::personal_sign_bytes(&msg, &key).expect("personal_sign");
    let mut direct: Vec<u8> = Vec::new();
    direct.extend_from_slice(&sig.r);
    direct.extend_from_slice(&sig.s);
    direct.push(sig.v);
    assert_eq!(
        hex_encode(&direct),
        EXPECTED_SIG_HEX,
        "personal_sign must reproduce keystone's 65 bytes (r || s || v), v = 27/28"
    );

    // 2. through the real exit: data_type 3 → ur:eth-signature
    let payload = personal_sign_request(&msg);
    let mut out = [0u8; 512];
    let n = sign(
        SignInput::Seed { seed: &seed },
        UrTypeTag::EthSignRequest,
        &payload,
        &mut out,
    )
    .expect("sign via the eth exit");
    let container = parse_eth_signature(&out[..n]).expect("eth-signature container");
    assert_eq!(
        hex_encode(container.signature_bytes()),
        EXPECTED_SIG_HEX,
        "the exit must carry the same signature bytes (65 = r ‖ s ‖ 27/28)"
    );
    assert_eq!(
        container.signature_len, 65,
        "EIP-191 keeps the one-byte v, so the container stays 65 bytes"
    );
    assert_eq!(
        container.request_id,
        [
            0x9b, 0x1d, 0xeb, 0x4d, 0x3b, 0x7d, 0x4b, 0xad, 0x9b, 0xdd, 0x2b, 0x0d, 0x7b, 0x3d,
            0xcb, 0x6d
        ],
        "the reply echoes the request id"
    );
}

/// `eth-sign-request` CBOR map for a personal message, hand-encoded: the `encode_*`
/// convenience helpers in `encoding::cbor` are `cfg(test)`-gated inside the library,
/// so an integration test cannot reach them.
/// `{1: tag(37) uuid, 2: sign_data, 3: data_type = 3 (PersonalMessage)}`
fn personal_sign_request(message: &[u8]) -> Vec<u8> {
    const ID: [u8; 16] = [
        0x9b, 0x1d, 0xeb, 0x4d, 0x3b, 0x7d, 0x4b, 0xad, 0x9b, 0xdd, 0x2b, 0x0d, 0x7b, 0x3d, 0xcb,
        0x6d,
    ];
    let mut out: Vec<u8> = Vec::new();
    out.push(0xa3); // map(3)
    out.push(0x01); // key 1
    out.extend_from_slice(&[0xd8, 0x25, 0x50]); // tag(37), bytes(16)
    out.extend_from_slice(&ID);
    out.push(0x02); // key 2
                    // CBOR byte-string head: short form under 24 bytes, 1-byte length up to 255.
    if message.len() < 24 {
        out.push(0x40 | message.len() as u8);
    } else {
        assert!(message.len() <= u8::MAX as usize, "1-byte length head only");
        out.push(0x58);
        out.push(message.len() as u8);
    }
    out.extend_from_slice(message);
    out.extend_from_slice(&[0x03, 0x03]); // key 3 = data_type 3 (PersonalMessage)
    out
}
