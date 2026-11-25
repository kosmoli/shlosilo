//! E-3 P1 pins: the zero-heap EIP-712 pool against the two things it must not
//! drift from — the alloc parser's syntax and the spike's measured sizes.
//!
//! ## What is pinned here
//!
//! 1. **Syntax acceptance** — for a set of real documents and a set of malformed
//!    ones, `eip712::parse_typed_data_v4(x).is_ok()` and `eip712_pool::parse(x, …)
//!    .is_ok()` must return the SAME verdict. This is the anti-drift nail: the two
//!    parsers are separate code (one builds owned values, one fills a pool), so any
//!    change to either acceptance surface turns this red immediately.
//! 2. **Scale** — the pool's type / field / node / depth counts must equal the
//!    numbers `tests/eip712_budget_spike.rs` measured (that file is the empirical
//!    basis of the D-E fixed-capacity decision, run with `--ignored --nocapture`).
//!    The sampling there counts the message root as one node, each atom as one, and
//!    each struct/array as one plus its children — the pool is held to that same
//!    accounting.
//! 3. **Capacity refusals** — a pool that is too small answers `BufferTooSmall` with
//!    `RequiredLength`, never `EncodingInvalidFormat`: the request is well formed and
//!    the operator must read "request too large" (B-7), not "not recognized".
//!
//! The sample documents are copied verbatim from the spike (its `permit2_batch_20()`
//! and `seaport_bulk_n()` generators included) so the two files cannot disagree about
//! what a "real" payload looks like.
#![cfg(feature = "alloc-fallback")]

use shlosilo::chain::eth::eip712::parse_typed_data_v4;
use shlosilo::chain::eth::eip712_pool::{
    self, Eip712Field, Eip712Node, Eip712Pool, Eip712Type, KIND_ADDRESS, KIND_ARRAY, KIND_BYTES32,
    KIND_STRUCT, KIND_UINT256,
};
use shlosilo::error::{ErrorContext, ShlosiloError, ShlosiloErrorKind};

// ─── harness ────────────────────────────────────────────────────────────────

/// Pool capacities for one run.
#[derive(Clone, Copy)]
struct Caps {
    arena: usize,
    nodes: usize,
    types: usize,
    fields: usize,
}

impl Caps {
    /// Far above every sample: used to measure what a document actually needs.
    const GENEROUS: Caps = Caps {
        arena: 8 * 1024,
        nodes: 4096,
        types: 64,
        fields: 256,
    };
}

/// What one successful parse measured.
#[derive(Debug, PartialEq, Eq)]
struct Counts {
    types: usize,
    fields: usize,
    fields_max: usize,
    /// Nodes of the `message` tree, under the spike's accounting.
    message_nodes: usize,
    /// Depth of the `message` tree (root = 0).
    message_depth: usize,
    /// Every node in the pool (domain tree + message tree).
    nodes: usize,
    /// Arena bytes consumed.
    arena: usize,
}

/// Parse `json` with `caps` and measure the result.
fn run(json: &str, caps: Caps) -> Result<Counts, ShlosiloError> {
    let mut arena = std::vec![0u8; caps.arena];
    let mut nodes = std::vec![Eip712Node::default(); caps.nodes];
    let mut types = std::vec![Eip712Type::default(); caps.types];
    let mut fields = std::vec![Eip712Field::default(); caps.fields];
    let out = match eip712_pool::parse(
        json.as_bytes(),
        &mut arena,
        &mut nodes,
        &mut types,
        &mut fields,
    ) {
        Ok(pool) => Ok(measure(&pool)),
        Err(e) => Err(e),
    };
    out
}

fn measure(pool: &Eip712Pool<'_>) -> Counts {
    let root = pool.message_root().expect("message root index") as usize;
    let (message_nodes, message_depth) = walk(pool, root, 0);
    let fields_max = (0..pool.types_len())
        .map(|i| pool.type_at(i).expect("type in range").n_fields as usize)
        .max()
        .unwrap_or(0);
    Counts {
        types: pool.types_len(),
        fields: pool.fields_len(),
        fields_max,
        message_nodes,
        message_depth,
        nodes: pool.nodes_len(),
        arena: pool.arena_used(),
    }
}

/// The spike's `measure_value`, replayed over the pool's views: (nodes, max depth).
fn walk(pool: &Eip712Pool<'_>, idx: usize, depth: usize) -> (usize, usize) {
    let node = pool.node(idx).expect("node in range");
    assert_eq!(
        pool.depth_of(idx).expect("depth is total"),
        depth,
        "depth_of agrees with the walk that produced it"
    );
    if node.n_children == 0 {
        return (1, depth);
    }
    // `children_of` is a slice only because a node's direct children are contiguous:
    // the length check keeps that layout property honest.
    let kids = pool.children_of(idx).expect("children in range");
    assert_eq!(kids.len(), node.n_children as usize);
    let first = node.first_child as usize;
    let (mut count, mut max) = (1usize, depth);
    for k in 0..kids.len() {
        let (c, d) = walk(pool, first + k, depth + 1);
        count += c;
        max = max.max(d);
    }
    (count, max)
}

/// The verdict of both parsers on one document.
fn verdicts(json: &str) -> (bool, bool) {
    let alloc_ok = parse_typed_data_v4(json).is_ok();
    let pool_ok = run(json, Caps::GENEROUS).is_ok();
    (alloc_ok, pool_ok)
}

// ─── samples: the same payloads the spike measured ──────────────────────────

/// ERC-2612 permit (USDC-like: name + version domain, 5 fields).
const PERMIT_2612: &str = r#"{
  "types": {
    "EIP712Domain": [
      {"name":"name","type":"string"},
      {"name":"version","type":"string"},
      {"name":"chainId","type":"uint256"},
      {"name":"verifyingContract","type":"address"}
    ],
    "Permit": [
      {"name":"owner","type":"address"},
      {"name":"spender","type":"address"},
      {"name":"value","type":"uint256"},
      {"name":"nonce","type":"uint256"},
      {"name":"deadline","type":"uint256"}
    ]
  },
  "primaryType": "Permit",
  "domain": {"name":"USD Coin","version":"2","chainId":1,
             "verifyingContract":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
  "message": {"owner":"0xd00387de9f68C9642e25d4c194d6e1cE233633C0",
              "spender":"0x000000000022D473030F116dDEE9F6B43aC78BA3",
              "value":"115792089237316195423570985008687907853269984665640564039457584007913129639935",
              "nonce":0,"deadline":1735689600}
}"#;

/// Permit2 `PermitSingle`: one nested struct (details) inside the primary type.
const PERMIT2_SINGLE: &str = r#"{
  "types": {
    "EIP712Domain": [
      {"name":"name","type":"string"},
      {"name":"chainId","type":"uint256"},
      {"name":"verifyingContract","type":"address"}
    ],
    "PermitDetails": [
      {"name":"token","type":"address"},
      {"name":"amount","type":"uint160"},
      {"name":"expiration","type":"uint48"},
      {"name":"nonce","type":"uint48"}
    ],
    "PermitSingle": [
      {"name":"details","type":"PermitDetails"},
      {"name":"spender","type":"address"},
      {"name":"sigDeadline","type":"uint256"}
    ]
  },
  "primaryType": "PermitSingle",
  "domain": {"name":"Permit2","chainId":1,
             "verifyingContract":"0x000000000022D473030F116dDEE9F6B43aC78BA3"},
  "message": {
    "details":{"token":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
               "amount":"1461501637330902918203684832716283019655932542975",
               "expiration":1735689600,"nonce":0},
    "spender":"0xE592427A0AEce92De3Edee1F18E0157C05861564",
    "sigDeadline":1735689600
  }
}"#;

/// Permit2 `PermitBatch`: an array of the nested struct — the shape a real
/// multi-token approval produces (`PermitDetails[]`).
const PERMIT2_BATCH: &str = r#"{
  "types": {
    "EIP712Domain": [
      {"name":"name","type":"string"},
      {"name":"chainId","type":"uint256"},
      {"name":"verifyingContract","type":"address"}
    ],
    "PermitDetails": [
      {"name":"token","type":"address"},
      {"name":"amount","type":"uint160"},
      {"name":"expiration","type":"uint48"},
      {"name":"nonce","type":"uint48"}
    ],
    "PermitBatch": [
      {"name":"details","type":"PermitDetails[]"},
      {"name":"spender","type":"address"},
      {"name":"sigDeadline","type":"uint256"}
    ]
  },
  "primaryType": "PermitBatch",
  "domain": {"name":"Permit2","chainId":1,
             "verifyingContract":"0x000000000022D473030F116dDEE9F6B43aC78BA3"},
  "message": {
    "details":[
      {"token":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","amount":"1000000","expiration":1735689600,"nonce":0},
      {"token":"0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2","amount":"2000000","expiration":1735689600,"nonce":1},
      {"token":"0x6B175474E89094C44Da98b954EedeAC495271d0F","amount":"3000000","expiration":1735689600,"nonce":2},
      {"token":"0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599","amount":"4000000","expiration":1735689600,"nonce":3},
      {"token":"0xdAC17F958D2ee523a2206206994597C13D831ec7","amount":"5000000","expiration":1735689600,"nonce":4},
      {"token":"0x514910771AF9Ca656af840dff83E8264EcF986CA","amount":"6000000","expiration":1735689600,"nonce":5},
      {"token":"0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984","amount":"7000000","expiration":1735689600,"nonce":6},
      {"token":"0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9","amount":"8000000","expiration":1735689600,"nonce":7}
    ],
    "spender":"0xE592427A0AEce92De3Edee1F18E0157C05861564",
    "sigDeadline":1735689600
  }
}"#;

/// Seaport `OrderComponents`: the deepest shape a mainstream wallet signs —
/// two arrays of nested structs (`OfferItem[]`, `ConsiderationItem[]`).
const SEAPORT_ORDER: &str = r#"{
  "types": {
    "EIP712Domain": [
      {"name":"name","type":"string"},
      {"name":"version","type":"string"},
      {"name":"chainId","type":"uint256"},
      {"name":"verifyingContract","type":"address"}
    ],
    "OfferItem": [
      {"name":"itemType","type":"uint8"},
      {"name":"token","type":"address"},
      {"name":"identifierOrCriteria","type":"uint256"},
      {"name":"startAmount","type":"uint256"},
      {"name":"endAmount","type":"uint256"}
    ],
    "ConsiderationItem": [
      {"name":"itemType","type":"uint8"},
      {"name":"token","type":"address"},
      {"name":"identifierOrCriteria","type":"uint256"},
      {"name":"startAmount","type":"uint256"},
      {"name":"endAmount","type":"uint256"},
      {"name":"recipient","type":"address"}
    ],
    "OrderComponents": [
      {"name":"offerer","type":"address"},
      {"name":"zone","type":"address"},
      {"name":"offer","type":"OfferItem[]"},
      {"name":"consideration","type":"ConsiderationItem[]"},
      {"name":"orderType","type":"uint8"},
      {"name":"startTime","type":"uint256"},
      {"name":"endTime","type":"uint256"},
      {"name":"zoneHash","type":"bytes32"},
      {"name":"salt","type":"uint256"},
      {"name":"conduitKey","type":"bytes32"},
      {"name":"counter","type":"uint256"}
    ]
  },
  "primaryType": "OrderComponents",
  "domain": {"name":"Seaport","version":"1.6","chainId":1,
             "verifyingContract":"0x0000000000000068F116a894984e2DB1123eB395"},
  "message": {
    "offerer":"0xd00387de9f68C9642e25d4c194d6e1cE233633C0",
    "zone":"0x00000000E88FEA1AD63c4b7bdD9985F3bC2B4FdC",
    "offer":[{"itemType":2,"token":"0x0000000000000000000000000000000000000000",
              "identifierOrCriteria":0,"startAmount":"1000000000000000000","endAmount":"1000000000000000000"}],
    "consideration":[
      {"itemType":0,"token":"0x0000000000000000000000000000000000000000","identifierOrCriteria":0,
       "startAmount":"950000000000000000","endAmount":"950000000000000000",
       "recipient":"0x0000a26b00c1F0DF003000390027140000fAa719"},
      {"itemType":0,"token":"0x0000000000000000000000000000000000000000","identifierOrCriteria":0,
       "startAmount":"25000000000000000","endAmount":"25000000000000000",
       "recipient":"0xd00387de9f68C9642e25d4c194d6e1cE233633C0"}
    ],
    "orderType":0,"startTime":1735689600,"endTime":1735693200,
    "zoneHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
    "salt":"24446860360504860771326149869030192442",
    "conduitKey":"0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000",
    "counter":0
  }
}"#;

/// Safe `SafeTx`: ten flat fields, no nesting — the flattest real shape.
const SAFE_TX: &str = r#"{
  "types": {
    "EIP712Domain": [
      {"name":"chainId","type":"uint256"},
      {"name":"verifyingContract","type":"address"}
    ],
    "SafeTx": [
      {"name":"to","type":"address"},
      {"name":"value","type":"uint256"},
      {"name":"data","type":"bytes"},
      {"name":"operation","type":"uint8"},
      {"name":"safeTxGas","type":"uint256"},
      {"name":"baseGas","type":"uint256"},
      {"name":"gasPrice","type":"uint256"},
      {"name":"gasToken","type":"address"},
      {"name":"refundReceiver","type":"address"},
      {"name":"nonce","type":"uint256"}
    ]
  },
  "primaryType": "SafeTx",
  "domain": {"chainId":1,"verifyingContract":"0x111CEEee040739fD91D29C34C33E6B3E112F2177"},
  "message": {
    "to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","value":"0",
    "data":"0xa9059cbb000000000000000000000000d00387de9f68c9642e25d4c194d6e1ce233633c0000000000000000000000000000000000000000000000000000000000000f4240",
    "operation":0,"safeTxGas":"0","baseGas":"0","gasPrice":"0",
    "gasToken":"0x0000000000000000000000000000000000000000",
    "refundReceiver":"0x0000000000000000000000000000000000000000","nonce":42
  }
}"#;

/// EIP-712's own `Mail` example: a nested struct plus a fixed-length array.
const MAIL_OFFICIAL: &str = r#"{
  "types": {
    "EIP712Domain": [
      {"name":"name","type":"string"},
      {"name":"version","type":"string"},
      {"name":"chainId","type":"uint256"},
      {"name":"verifyingContract","type":"address"}
    ],
    "Person": [
      {"name":"name","type":"string"},
      {"name":"wallet","type":"address"}
    ],
    "Mail": [
      {"name":"from","type":"Person"},
      {"name":"to","type":"Person"},
      {"name":"contents","type":"string"}
    ]
  },
  "primaryType": "Mail",
  "domain": {"name":"Ether Mail","version":"1","chainId":1,
             "verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
  "message": {
    "from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
    "to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
    "contents":"Hello, Bob!"
  }
}"#;

/// The official example grown the way a real group message grows: a 6-element
/// `Person[]`, i.e. a struct array inside the primary type.
const MAIL_GROUP: &str = r#"{
  "types": {
    "EIP712Domain": [
      {"name":"name","type":"string"},
      {"name":"version","type":"string"},
      {"name":"chainId","type":"uint256"},
      {"name":"verifyingContract","type":"address"}
    ],
    "Person": [
      {"name":"name","type":"string"},
      {"name":"wallet","type":"address"}
    ],
    "Mail": [
      {"name":"from","type":"Person"},
      {"name":"to","type":"Person[]"},
      {"name":"contents","type":"string"}
    ]
  },
  "primaryType": "Mail",
  "domain": {"name":"Ether Mail","version":"1","chainId":1,
             "verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
  "message": {
    "from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
    "to":[
      {"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
      {"name":"Alice","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
      {"name":"Carol","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
      {"name":"Dave","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
      {"name":"Eve","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
      {"name":"Frank","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"}
    ],
    "contents":"Weekly sync notes: nothing sensitive, just scheduling."
  }
}"#;

/// Permit2 `PermitBatch` at 20 tokens: a real "approve everything a DEX can
/// reach" flow, and the shape that made the 4096-byte display budget in the
/// reference implementation get hit.
fn permit2_batch_20() -> String {
    let mut s = String::from(
        r#"{"types":{
  "EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"},
                  {"name":"verifyingContract","type":"address"}],
  "PermitDetails":[{"name":"token","type":"address"},{"name":"amount","type":"uint160"},
                   {"name":"expiration","type":"uint48"},{"name":"nonce","type":"uint48"}],
  "PermitBatch":[{"name":"details","type":"PermitDetails[]"},{"name":"spender","type":"address"},
                 {"name":"sigDeadline","type":"uint256"}]
 },
 "primaryType":"PermitBatch",
 "domain":{"name":"Permit2","chainId":1,
           "verifyingContract":"0x000000000022D473030F116dDEE9F6B43aC78BA3"},
 "message":{"details":["#,
    );
    for i in 0..20u64 {
        if i > 0 {
            s.push(',');
        }
        // 40-hex-char addresses (160-bit) with the last byte varied: u128 cannot
        // hold an address literal, so the prefix is fixed text and only the tail
        // is formatted.
        s.push_str(&format!(
            r#"{{"token":"0xa0b86991c6218b36c1d19d4a2e9eb0ce360601{:02x}","amount":"{}","expiration":1735689600,"nonce":{}}}"#,
            i as u8,
            1_000_000u64 * (i + 1),
            i
        ));
    }
    s.push_str(
        r#"],"spender":"0xE592427A0AEce92De3Edee1F18E0157C05861564","sigDeadline":1735689600}}"#,
    );
    s
}

/// Seaport bulk: `n` consideration items plus three offer items. Marketplace
/// listings with a fee split and multiple NFTs produce exactly this shape.
fn seaport_bulk_n(n: u64) -> String {
    let item = |i: u64, extra: &str| {
        format!(
            r#"{{"itemType":{},"token":"0x0000000000000000000000000000000000000000","identifierOrCriteria":{},"startAmount":"1000000000000000000","endAmount":"1000000000000000000"{}}}"#,
            i % 3,
            i,
            extra
        )
    };
    let mut offers = Vec::new();
    for i in 0..3 {
        offers.push(item(i, ""));
    }
    let mut consider = Vec::new();
    for i in 0..n {
        consider.push(item(
            i,
            r#","recipient":"0x0000a26b00c1F0DF003000390027140000fAa719""#,
        ));
    }
    format!(
        r#"{{"types":{{
  "EIP712Domain":[{{"name":"name","type":"string"}},{{"name":"version","type":"string"}},
                  {{"name":"chainId","type":"uint256"}},{{"name":"verifyingContract","type":"address"}}],
  "OfferItem":[{{"name":"itemType","type":"uint8"}},{{"name":"token","type":"address"}},
               {{"name":"identifierOrCriteria","type":"uint256"}},{{"name":"startAmount","type":"uint256"}},
               {{"name":"endAmount","type":"uint256"}}],
  "ConsiderationItem":[{{"name":"itemType","type":"uint8"}},{{"name":"token","type":"address"}},
               {{"name":"identifierOrCriteria","type":"uint256"}},{{"name":"startAmount","type":"uint256"}},
               {{"name":"endAmount","type":"uint256"}},{{"name":"recipient","type":"address"}}],
  "OrderComponents":[{{"name":"offerer","type":"address"}},{{"name":"zone","type":"address"}},
               {{"name":"offer","type":"OfferItem[]"}},{{"name":"consideration","type":"ConsiderationItem[]"}},
               {{"name":"orderType","type":"uint8"}},{{"name":"startTime","type":"uint256"}},
               {{"name":"endTime","type":"uint256"}},{{"name":"zoneHash","type":"bytes32"}},
               {{"name":"salt","type":"uint256"}},{{"name":"conduitKey","type":"bytes32"}},
               {{"name":"counter","type":"uint256"}}]
 }},
 "primaryType":"OrderComponents",
 "domain":{{"name":"Seaport","version":"1.6","chainId":1,
           "verifyingContract":"0x0000000000000068F116a894984e2DB1123eB395"}},
 "message":{{"offerer":"0xd00387de9f68C9642e25d4c194d6e1cE233633C0",
            "zone":"0x00000000E88FEA1AD63c4b7bdD9985F3bC2B4FdC",
            "offer":[{}],
            "consideration":[{}],
            "orderType":0,"startTime":1735689600,"endTime":1735693200,
            "zoneHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
            "salt":"24446860360504860771326149869030192442",
            "conduitKey":"0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000",
            "counter":0}}}}"#,
        offers.join(","),
        consider.join(",")
    )
}

fn samples() -> Vec<(&'static str, String)> {
    vec![
        ("erc2612 permit", PERMIT_2612.to_string()),
        ("permit2 PermitSingle", PERMIT2_SINGLE.to_string()),
        ("permit2 PermitBatch (8)", PERMIT2_BATCH.to_string()),
        ("permit2 PermitBatch (20)", permit2_batch_20()),
        ("seaport OrderComponents", SEAPORT_ORDER.to_string()),
        ("seaport bulk (3+8)", seaport_bulk_n(8)),
        ("seaport bulk (3+20)", seaport_bulk_n(20)),
        ("seaport bulk (3+40)", seaport_bulk_n(40)),
        ("safe SafeTx", SAFE_TX.to_string()),
        ("eip712 Mail (official)", MAIL_OFFICIAL.to_string()),
        ("eip712 Mail (6-person)", MAIL_GROUP.to_string()),
    ]
}

// ─── 1. differential pin: same syntax acceptance as the alloc parser ────────

/// A minimal, complete typed-data document: small enough that every malformed
/// variant below has exactly ONE defect.
const TINY: &str = r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"}],"T":[{"name":"a","type":"uint256"},{"name":"b","type":"address"}]},"primaryType":"T","domain":{"name":"x"},"message":{"a":1,"b":"0x0000000000000000000000000000000000000001"}}"#;

#[test]
fn syntax_acceptance_matches_alloc_parser() {
    // Every real payload: both must accept.
    for (name, json) in samples() {
        let (alloc_ok, pool_ok) = verdicts(&json);
        assert!(alloc_ok, "{name}: the alloc parser must accept this sample");
        assert_eq!(alloc_ok, pool_ok, "{name}: parsers disagree");
    }

    // Structurally valid but unusual shapes: the verdicts must still match.
    let deep_ok = format!(
        "{{\"types\":{{\"T\":[{{\"name\":\"a\",\"type\":\"uint256\"}}]}},\"primaryType\":\"T\",\
         \"domain\":{{}},\"message\":{{\"a\":1}},\"deep\":{}1{}}}",
        "[".repeat(20),
        "]".repeat(20)
    );
    let positives: [(&str, String); 6] = [
        ("minimal document", TINY.to_string()),
        // Escaped key: the alloc parser decodes keys before matching, so "typ\u0065s"
        // IS the `types` key. The scanner compares decoded bytes for the same reason.
        (
            "escaped top-level key",
            PERMIT_2612.replace("\"types\"", r#""typ\u0065s""#),
        ),
        // Escaped string value: decoded on both sides.
        (
            "escaped string value",
            PERMIT_2612.replace("USD Coin", r"USD\u0020Coin"),
        ),
        // An unknown top-level key is ignored by both parsers.
        (
            "unknown top-level key",
            PERMIT_2612.replace(
                r#""primaryType""#,
                "\"note\":{\"a\":[1,2,null]},\"primaryType\"",
            ),
        ),
        // A raw control byte INSIDE a string: neither parser rejects it. That is the
        // alloc parser's behaviour and parity is the contract — tightening it is a
        // deliberate change on both sides, not a scanner side effect.
        (
            "raw control byte in a string",
            PERMIT_2612.replace("USD Coin", "USD\u{1}Coin"),
        ),
        // 20 levels of nesting is inside the 32-level budget.
        ("nesting inside the budget", deep_ok),
    ];
    for (name, json) in positives {
        let (alloc_ok, pool_ok) = verdicts(&json);
        assert_eq!(alloc_ok, pool_ok, "{name}: parsers disagree");
        assert!(alloc_ok, "{name}: expected both to accept");
    }

    // Malformed documents: every one must be refused by BOTH parsers.
    let deep_bad = format!(
        "{{\"types\":{{\"T\":[{{\"name\":\"a\",\"type\":\"uint256\"}}]}},\"primaryType\":\"T\",\
         \"domain\":{{}},\"message\":{{\"deep\":{}1{}, \"a\":1}}}}",
        "[".repeat(40),
        "]".repeat(40)
    );
    let negatives: [(&str, String); 13] = [
        ("unclosed object", TINY[..TINY.len() - 1].to_string()),
        ("unclosed array", TINY.replace(']', "")),
        ("trailing comma in an object", TINY.replace("}}", ",}}")),
        ("trailing comma in an array", TINY.replace("}]", "},]")),
        (
            "control byte outside a string",
            TINY.replacen('{', "{\u{1}", 1),
        ),
        ("nesting over the depth budget", deep_bad),
        (
            "number with a fraction",
            TINY.replace(r#""a":1"#, r#""a":1.5"#),
        ),
        (
            "number out of i64 range",
            TINY.replace(r#""a":1"#, r#""a":99999999999999999999999999"#),
        ),
        (
            "single-quoted string",
            TINY.replace(r#""primaryType":"T""#, r#""primaryType":'T'"#),
        ),
        (
            "null where a value belongs",
            TINY.replace(r#""a":1"#, r#""a":null"#),
        ),
        (
            "null domain",
            TINY.replace(r#""domain":{"name":"x"}"#, r#""domain":null"#),
        ),
        (
            "null message",
            TINY.replace(r#""message":{"#, r#""message":null,"x":{"#),
        ),
        ("trailing data", format!("{TINY} {{\"x\":1}}")),
    ];
    for (name, json) in negatives {
        let (alloc_ok, pool_ok) = verdicts(&json);
        assert_eq!(
            alloc_ok, pool_ok,
            "{name}: parsers disagree (alloc={alloc_ok}, pool={pool_ok})"
        );
        assert!(!alloc_ok, "{name}: expected both to refuse");
    }

    // A duplicate declared field, which is a semantic (not syntactic) refusal: both
    // parsers reject it, and the alloc parser reports `DuplicateKey` specifically.
    let duplicate = TINY.replace(r#""a":1,"#, r#""a":1,"a":2,"#);
    let (alloc_ok, pool_ok) = verdicts(&duplicate);
    assert!(!alloc_ok && !pool_ok, "a duplicate field must be refused");
    assert_eq!(
        parse_typed_data_v4(&duplicate).unwrap_err(),
        shlosilo::chain::eth::eip712::JsonError::DuplicateKey
    );
}

// ─── 2. scale pin: the pool against the spike's measured table ──────────────

#[test]
fn scale_matches_the_spike_table() {
    // sample, types, fields, max fields per type, message nodes, message depth
    let table: [(&str, usize, usize, usize, usize, usize); 11] = [
        ("erc2612 permit", 2, 9, 5, 6, 1),
        ("permit2 PermitSingle", 3, 10, 4, 8, 2),
        ("permit2 PermitBatch (8)", 3, 10, 4, 44, 3),
        ("permit2 PermitBatch (20)", 3, 10, 4, 104, 3),
        ("seaport OrderComponents", 4, 26, 11, 32, 3),
        ("seaport bulk (3+8)", 4, 26, 11, 86, 3),
        ("seaport bulk (3+20)", 4, 26, 11, 170, 3),
        ("seaport bulk (3+40)", 4, 26, 11, 310, 3),
        ("safe SafeTx", 2, 12, 10, 11, 1),
        ("eip712 Mail (official)", 3, 9, 4, 8, 2),
        ("eip712 Mail (6-person)", 3, 9, 4, 24, 3),
    ];
    let all = samples();
    assert_eq!(all.len(), table.len(), "one row per spike sample");
    println!();
    println!(
        "{:<26} {:>5} {:>6} {:>5} {:>5} {:>5}",
        "sample", "types", "fields", "maxF", "nodes", "depth"
    );
    println!("{}", "-".repeat(58));
    for ((name, json), expected) in all.iter().zip(table) {
        let (row_name, types, fields, fields_max, nodes, depth) = expected;
        assert_eq!(*name, row_name, "sample order");
        let counts = run(json, Caps::GENEROUS)
            .unwrap_or_else(|e| panic!("{row_name}: must parse ({:?})", e.kind));
        assert_eq!(counts.types, types, "{row_name}: types");
        assert_eq!(counts.fields, fields, "{row_name}: fields");
        assert_eq!(
            counts.fields_max, fields_max,
            "{row_name}: max fields per type"
        );
        assert_eq!(counts.message_nodes, nodes, "{row_name}: message nodes");
        assert_eq!(counts.message_depth, depth, "{row_name}: message depth");
        // The message tree is the bulk of the pool; the domain tree adds a handful.
        assert!(
            counts.nodes >= counts.message_nodes,
            "{row_name}: pool covers message"
        );
        println!(
            "{:<26} {:>5} {:>6} {:>5} {:>5} {:>5}   (all nodes {})",
            row_name,
            counts.types,
            counts.fields,
            counts.fields_max,
            counts.message_nodes,
            counts.message_depth,
            counts.nodes
        );
    }
}

// ─── 3. capacity refusals are "request too large", not "not recognized" ─────

/// The sample every capacity pin uses: 8 nested `PermitDetails` structs.
const BATCH: &str = PERMIT2_BATCH;

fn counts_of_batch() -> Counts {
    run(BATCH, Caps::GENEROUS).expect("PermitBatch(8) parses with generous capacities")
}

fn expect_capacity(err: ShlosiloError, at_least: usize, what: &str) {
    assert_eq!(
        err.kind,
        ShlosiloErrorKind::BufferTooSmall,
        "{what}: capacity must answer BufferTooSmall, got {:?}",
        err.kind
    );
    match err.context {
        ErrorContext::RequiredLength(n) => assert!(
            n > at_least,
            "{what}: RequiredLength({n}) must exceed the capacity ({at_least})"
        ),
        other => panic!("{what}: expected RequiredLength, got {other:?}"),
    }
}

#[test]
fn node_pool_capacity_refuses_with_required_length() {
    let counts = counts_of_batch();
    assert_eq!(counts.message_nodes, 44, "the sample is the measured one");
    // One slot missing: the refusal happens during the message fill.
    let err = run(
        BATCH,
        Caps {
            nodes: counts.nodes - 1,
            ..Caps::GENEROUS
        },
    )
    .expect_err("a pool one node short must refuse");
    expect_capacity(err, counts.nodes - 1, "nodes (one short)");

    // The literal "one slot left" case from the task.
    let err = run(
        BATCH,
        Caps {
            nodes: 1,
            ..Caps::GENEROUS
        },
    )
    .expect_err("a pool with one node slot must refuse");
    expect_capacity(err, 1, "nodes (one slot)");

    // Zero slots must refuse too, not silently hand back an empty tree.
    let err = run(
        BATCH,
        Caps {
            nodes: 0,
            ..Caps::GENEROUS
        },
    )
    .expect_err("no node slot at all");
    expect_capacity(err, 0, "nodes (zero)");
}

#[test]
fn type_table_capacity_refuses_with_required_length() {
    let counts = counts_of_batch();
    assert_eq!(counts.types, 3, "PermitBatch declares three types");
    let err = run(
        BATCH,
        Caps {
            types: counts.types - 1,
            ..Caps::GENEROUS
        },
    )
    .expect_err("a type table one entry short must refuse");
    expect_capacity(err, counts.types - 1, "types");
}

#[test]
fn field_pool_capacity_refuses_with_required_length() {
    let counts = counts_of_batch();
    assert_eq!(
        counts.fields, 10,
        "PermitBatch declares ten fields in total"
    );
    let err = run(
        BATCH,
        Caps {
            fields: counts.fields - 1,
            ..Caps::GENEROUS
        },
    )
    .expect_err("a field pool one entry short must refuse");
    expect_capacity(err, counts.fields - 1, "fields");
}

#[test]
fn arena_capacity_refuses_with_required_length() {
    let counts = counts_of_batch();
    // BORROW DISCIPLINE PIN: every type/field name in this sample is an unescaped
    // JSON string, so it is borrowed from the wire and costs no arena byte. The only
    // arena use is the built-in `EIP712Domain` type name of the domain root (12 B).
    assert_eq!(
        counts.arena, 12,
        "only the built-in domain type name is copied into the arena"
    );
    let err = run(
        BATCH,
        Caps {
            arena: counts.arena - 1,
            ..Caps::GENEROUS
        },
    )
    .expect_err("an arena one byte short must refuse");
    expect_capacity(err, counts.arena - 1, "arena");
}

// ─── 4. the views themselves ────────────────────────────────────────────────

/// Parse and run `f` while the pool's storage is still alive.
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

#[test]
fn permit_views_expose_the_declared_structure() {
    with_pool(PERMIT_2612, |pool| {
        assert_eq!(pool.primary_type().expect("primaryType"), "Permit");
        assert_eq!(pool.types_len(), 2, "types keep document order");

        let domain_type = pool.type_at(0).expect("EIP712Domain is first");
        assert_eq!(pool.type_name(domain_type).expect("name"), "EIP712Domain");
        let domain_fields = pool.fields_of(domain_type).expect("fields");
        assert_eq!(domain_fields.len(), 4);
        let names: Vec<&str> = domain_fields
            .iter()
            .map(|f| pool.field_name(f).expect("field name"))
            .collect();
        assert_eq!(names, ["name", "version", "chainId", "verifyingContract"]);
        let tys: Vec<&str> = domain_fields
            .iter()
            .map(|f| pool.field_type(f).expect("field type"))
            .collect();
        assert_eq!(tys, ["string", "string", "uint256", "address"]);

        // Out-of-range access asks `None`, never panics (non-existent type).
        assert!(pool.type_at(2).is_none());
        assert!(pool.node(pool.nodes_len()).is_none());

        // message: struct root with five atoms, in declaration order
        let message = pool.message().expect("message root");
        assert_eq!(message.kind, KIND_STRUCT);
        assert_eq!(pool.payload(message).expect("payload"), b"Permit");
        assert_eq!(
            pool.depth_of(pool.message_root().expect("root") as usize),
            Ok(0)
        );
        let kids = pool
            .children_of(pool.message_root().expect("root") as usize)
            .expect("kids");
        assert_eq!(kids.len(), 5);
        let kinds: Vec<u8> = kids.iter().map(|k| k.kind).collect();
        assert_eq!(
            kinds,
            [
                KIND_ADDRESS,
                KIND_ADDRESS,
                KIND_UINT256,
                KIND_UINT256,
                KIND_UINT256
            ]
        );
        assert_eq!(
            pool.payload(&kids[0]).expect("owner"),
            b"0xd00387de9f68C9642e25d4c194d6e1cE233633C0"
        );
        assert_eq!(
            pool.payload(&kids[2]).expect("value"),
            b"115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
        // Child nodes sit one level below the root.
        let first_child = message.first_child as usize;
        assert_eq!(pool.depth_of(first_child), Ok(1));
        assert!(pool.depth_of(0).is_ok(), "the domain root has a depth too");

        // domain: built-in type, values in canonical order
        let domain = pool.domain().expect("domain root");
        assert_eq!(domain.kind, KIND_STRUCT);
        assert_eq!(pool.payload(domain).expect("payload"), b"EIP712Domain");
        let dkids = pool
            .children_of(pool.domain_root().expect("root") as usize)
            .expect("kids");
        assert_eq!(dkids.len(), 4);
        assert_eq!(pool.payload(&dkids[0]).expect("name"), b"USD Coin");
        assert_eq!(pool.payload(&dkids[1]).expect("version"), b"2");
        assert_eq!(pool.payload(&dkids[2]).expect("chainId"), b"1");
        assert_eq!(dkids[3].kind, KIND_ADDRESS);

        // A struct field's payload is its type name, and its children are the fields.
        let _ = with_pool(PERMIT2_SINGLE, |pool| {
            let root = pool.message().expect("message root");
            assert_eq!(pool.payload(root).expect("type name"), b"PermitSingle");
            let kids = pool
                .children_of(pool.message_root().expect("root") as usize)
                .expect("kids");
            assert_eq!(kids[0].kind, KIND_STRUCT, "details is a nested struct");
            assert_eq!(pool.payload(&kids[0]).expect("type name"), b"PermitDetails");
            let inner = pool
                .children_of(root.first_child as usize)
                .expect("details children");
            assert_eq!(inner.len(), 4);
            assert_eq!(pool.payload(&inner[3]).expect("nonce"), b"0");
        });
    })
    .expect("permit parses");
}

#[test]
fn array_element_kind_is_readable_from_the_first_child() {
    with_pool(PERMIT2_BATCH, |pool| {
        let root = pool.message_root().expect("message root") as usize;
        let kids = pool.children_of(root).expect("kids");
        assert_eq!(kids[0].kind, KIND_ARRAY, "details is PermitDetails[]");
        // P3's fold strategy reads the element kind off the first child.
        let items = pool.children_of(root + 1).expect("details elements");
        assert_eq!(items.len(), 8);
        assert!(items.iter().all(|n| n.kind == KIND_STRUCT));
        // Array of atoms: the seaport offer is OfferItem[], the mail `to` is Person[].
        let _ = with_pool(SEAPORT_ORDER, |pool| {
            let root = pool.message_root().expect("root") as usize;
            let kids = pool.children_of(root).expect("kids");
            let offer = kids[2];
            assert_eq!(offer.kind, KIND_ARRAY);
            assert_eq!(offer.n_children, 1);
            assert_eq!(
                pool.children_of(root + 3).expect("offer items")[0].kind,
                KIND_STRUCT
            );
            // `zoneHash` is bytes32, `orderType` uint8.
            let kinds: Vec<u8> = kids.iter().map(|k| k.kind).collect();
            assert_eq!(kinds[7], KIND_BYTES32);
            assert_eq!(kinds[4], KIND_UINT256);
        });
    })
    .expect("batch parses");
}

#[test]
fn escaped_strings_are_decoded_and_borrowed_ones_are_not_copied() {
    // Escaped: the decoded bytes land in the arena and are what a reviewer sees.
    let escaped = PERMIT_2612.replace("USD Coin", r#"USD\u0020C\u006f in"#);
    with_pool(&escaped, |pool| {
        let domain = pool.domain_root().expect("root") as usize;
        let kids = pool.children_of(domain).expect("kids");
        assert_eq!(pool.payload(&kids[0]).expect("name"), b"USD Co in");
        // The escaped name costs arena bytes; the unescaped sample needs none of it.
        assert!(pool.arena_used() > 12);
    })
    .expect("escaped sample parses");

    // Borrowed: payload bytes ARE wire bytes (no copy), so the pointers agree.
    // (`json` is bound once: a `const` str may be materialised at more than one
    // address, which would make a pointer comparison meaningless.)
    let borrowed = PERMIT_2612;
    with_pool(borrowed, |pool| {
        let root = pool.message_root().expect("root") as usize;
        let kids = pool.children_of(root).expect("kids");
        let owner = pool.payload(&kids[0]).expect("owner");
        const OWNER: &[u8] = b"0xd00387de9f68C9642e25d4c194d6e1cE233633C0";
        assert_eq!(owner, OWNER);
        // `memcmp` of addresses is not enough: prove no copy happened.
        let wire_start = borrowed.as_ptr() as usize;
        let wire_end = wire_start + borrowed.len();
        let payload_start = owner.as_ptr() as usize;
        assert!(
            payload_start >= wire_start && payload_start + owner.len() <= wire_end,
            "an unescaped payload must point into the wire, not into a copy"
        );
    })
    .expect("plain sample parses");

    // A string value that the alloc parser also accepts, only escaped:
    // `\u00e9` is a two-byte character once decoded.
    let unicode = PERMIT_2612.replace("USD Coin", r#"Caf\u00e9"#);
    with_pool(&unicode, |pool| {
        let domain = pool.domain_root().expect("root") as usize;
        let kids = pool.children_of(domain).expect("kids");
        assert_eq!(pool.payload(&kids[0]).expect("name"), "Café".as_bytes());
        assert_eq!(pool.payload(&kids[0]).expect("name").len(), 5);
    })
    .expect("unicode escape parses");
}

#[test]
fn missing_and_duplicate_members_are_refused() {
    // Missing declared field: the alloc parser answers ExpectedKey, so must we.
    let missing = PERMIT_2612.replace(r#""nonce":0,"#, "");
    let (alloc_ok, pool_ok) = verdicts(&missing);
    assert!(!alloc_ok && !pool_ok, "a missing field must be refused");

    // Duplicate declared field: refused on both sides (A3c-F14 parity).
    let duplicate = PERMIT_2612.replace(r#""nonce":0,"#, r#""nonce":0,"nonce":1,"#);
    let (alloc_ok, pool_ok) = verdicts(&duplicate);
    assert!(!alloc_ok && !pool_ok, "a duplicate field must be refused");

    // An unknown field INSIDE the message is ignored by both (extras are not hashed).
    let extra = PERMIT_2612.replace(r#""nonce":0,"#, r#""nonce":0,"surprise":7,"#);
    let (alloc_ok, pool_ok) = verdicts(&extra);
    assert!(alloc_ok && pool_ok, "extra message fields are tolerated");

    // An undeclared primaryType has no fields to read.
    let unknown_type =
        PERMIT_2612.replace(r#""primaryType": "Permit""#, r#""primaryType": "Nope""#);
    let (alloc_ok, pool_ok) = verdicts(&unknown_type);
    assert!(
        !alloc_ok && !pool_ok,
        "an undeclared primaryType must be refused"
    );
}

#[test]
fn atom_content_validation_is_deferred_to_the_encoder() {
    // KNOWN GAP, pinned on purpose: the pool records the JSON SHAPE (a `uint8` field
    // must carry a number or a numeric string), while the alloc parser also checks the
    // declared width. `uint8 = 300` is therefore refused there and accepted here.
    //
    // P2/P3 (the encoder) is where the width belongs, because that is where the value
    // is turned into 32 bytes. If a later step moves the check into the pool, this
    // assertion is the one that must flip — the silence would otherwise look like
    // parity drift.
    let overflow = TINY
        .replace(r#""type":"uint256""#, r#""type":"uint8""#)
        .replace(r#""a":1"#, r#""a":300"#);
    assert!(
        parse_typed_data_v4(&overflow).is_err(),
        "the alloc parser checks the declared width"
    );
    assert!(
        run(&overflow, Caps::GENEROUS).is_ok(),
        "the pool defers width checks to the encoder"
    );
}
