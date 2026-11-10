//! ETH address rendering (EIP-55) and EVM chain naming — pins with external oracles.
//!
//! ## EIP-55
//!
//! The checksum is a hash over the lowercase hex, so a single wrong nibble produces
//! an address that still looks right. The vectors are the four published in the
//! EIP-55 specification, plus four edge cases (all-zero, all-f, repeated pattern,
//! alternating digits/letters); every expected string was re-computed with an
//! independent implementation (`@noble/hashes` keccak256) before being written here,
//! so our keccak and our case rule are both checked against something that is not us.
//!
//! ## Chain names
//!
//! `tests/fixtures/eip155_chains.tsv` is the machine-read snapshot of
//! `ethereum-lists/chains` (the registry behind chainid.network) for the ten chains
//! the firmware names. The test walks it in both directions: every registry entry
//! must be named by us with the same (lowercased) name, and we must not name a chain
//! the registry snapshot does not contain.

use shlosilo::address::eth;
use shlosilo::business::review;
use shlosilo::chain::eth::chain_names::{chain_name, KNOWN_CHAINS};
use shlosilo::ur::ur_encode::UrTypeTag;

/// (raw 20-byte address hex, expected EIP-55 rendering)
const EIP55_VECTORS: &[(&str, &str)] = &[
    // --- the four vectors from EIP-55 itself ---
    (
        "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    ),
    (
        "fb6916095ca1df60bb79ce92ce3ea74c37c5d359",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    ),
    (
        "dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    ),
    (
        "d1220a0cf47c7b9be7a2e6ba89f429762e7b9adb",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ),
    // --- edge cases: no letters / all letters / patterns, nibble boundaries ---
    (
        "0000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffff",
        "0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF",
    ),
    (
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF",
    ),
    (
        "0123456789abcdef0123456789abcdef01234567",
        "0x0123456789abcDEF0123456789abCDef01234567",
    ),
];

fn addr20(hex: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(core::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    out
}

#[test]
fn eip55_checksum_matches_the_specification_and_independent_recomputation() {
    for (raw, expected) in EIP55_VECTORS {
        let rendered = eth::encode_bytes(&addr20(raw)).expect("render");
        assert_eq!(
            <_ as AsRef<str>>::as_ref(&rendered),
            *expected,
            "EIP-55 mismatch for {raw}"
        );
        assert_eq!(rendered.as_ref().len(), 42, "0x + 40 hex chars");
    }
}

#[test]
fn chain_table_matches_the_registry_snapshot() {
    let snapshot = include_str!("fixtures/eip155_chains.tsv");
    let mut registry: Vec<(u64, String)> = Vec::new();
    for line in snapshot.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut cols = line.split('\t');
        let id: u64 = cols.next().expect("id").parse().expect("numeric id");
        let name = cols.next().expect("name");
        registry.push((id, name.to_lowercase()));
    }
    assert_eq!(registry.len(), KNOWN_CHAINS.len(), "table size");

    // every registry entry is named, with the registry's name lowercased
    for (id, name) in &registry {
        assert_eq!(
            chain_name(*id),
            Some(name.as_str()),
            "chain {id} must be named `{name}` as the registry spells it"
        );
    }
    // and we name nothing the snapshot does not contain
    for (id, name) in KNOWN_CHAINS.iter() {
        assert!(
            registry
                .iter()
                .any(|(rid, rname)| rid == id && rname == name),
            "chain {id} `{name}` is not in the registry snapshot"
        );
    }
}

#[test]
fn unknown_chain_is_printed_as_its_raw_id() {
    assert_eq!(chain_name(5), None);
    assert_eq!(chain_name(u64::MAX), None);
}

/// The review page has to say which network the transaction lives on: an id alone
/// does not tell the operator, and a wrong-network send cannot be undone.
#[test]
fn eth_review_names_the_chain() {
    // Real eth-sign-request (EIP-1559 transfer, chain id 1).
    const ETH_SIGN_REQUEST_URI: &str = "ur:eth-sign-request/otaohddmaowpadlalrfrnysgaelrktecmwaelfgmaymwcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcplfaxvdlartlalalaaxadaaadrpceaadt";
    let ur = shlosilo::ur::ur_decode::decode(ETH_SIGN_REQUEST_URI).expect("ur decode");
    let payload = ur.as_ref();
    let mut arena = [0u8; 16 * 1024];
    let mut recs = [shlosilo::chain::btc::psbt::KvRec::EMPTY; 128];
    let view = review::build(
        UrTypeTag::EthSignRequest,
        payload,
        shlosilo::network::Network::EthereumMainnet,
        None,
        &mut arena,
        &mut recs,
    )
    .expect("review builds");
    let lines: Vec<String> = view
        .lines()
        .iter()
        .map(|l| l.as_str().to_string())
        .collect();
    assert!(
        lines.iter().any(|s| s == "chain 1 ethereum mainnet"),
        "review must name the chain: {lines:?}"
    );
}
