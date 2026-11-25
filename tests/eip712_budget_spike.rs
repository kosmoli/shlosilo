//! E-3 spike: how big does a real-world EIP-712 payload actually get?
//!
//! Not part of the gate (`#[ignore]`). This exists to give the D-E fixed-capacity
//! decision an empirical basis instead of a guess: it parses a set of typed-data
//! documents shaped like what wallets really send, and reports the four dimensions
//! the container budget has to cover — type-table size, value-tree size/depth,
//! `encode_type` length (= what `typeHash` hashes), and the review text length.
//!
//! Run: `cargo test --offline --test eip712_budget_spike -- --ignored --nocapture`
//!
//! Re-run after E-3 lands to check the chosen budgets against the same sample set.
#![cfg(feature = "alloc-fallback")]

use shlosilo::chain::eth::eip712::{encode_type, parse_typed_data_v4, Eip712Value, TypedData};

/// Walk the value tree: (node count, max depth).
fn measure_value(v: &Eip712Value, depth: usize) -> (usize, usize) {
    match v {
        Eip712Value::Struct(_, fields) => {
            let mut nodes = 1usize;
            let mut max = depth;
            for f in fields {
                let (n, d) = measure_value(f, depth + 1);
                nodes += n;
                max = max.max(d);
            }
            (nodes, max)
        }
        Eip712Value::Array(items) => {
            let mut nodes = 1usize;
            let mut max = depth;
            for f in items {
                let (n, d) = measure_value(f, depth + 1);
                nodes += n;
                max = max.max(d);
            }
            (nodes, max)
        }
        _ => (1, depth),
    }
}

struct Row {
    name: &'static str,
    json_len: usize,
    type_count: usize,
    fields_total: usize,
    fields_max: usize,
    encode_type_len: usize,
    value_nodes: usize,
    value_depth: usize,
    summary_len: usize,
}

fn measure(name: &'static str, json: &str) -> Option<Row> {
    match parse_typed_data_v4(json) {
        Ok(td) => Some(row_of(name, json, &td)),
        Err(e) => {
            println!("{name:<34} PARSE FAILED: {e}");
            None
        }
    }
}

fn row_of(name: &'static str, json: &str, td: &TypedData) -> Row {
    let fields_total: usize = td.types.values().map(|f| f.len()).sum();
    let fields_max = td.types.values().map(|f| f.len()).max().unwrap_or(0);
    let encode_type_len = encode_type(&td.primary_type, &td.types)
        .map(|s| s.len())
        .unwrap_or(0);
    let (msg_nodes, msg_depth) = measure_value(&td.message, 0);
    Row {
        name,
        json_len: json.len(),
        type_count: td.types.len(),
        fields_total,
        fields_max,
        encode_type_len,
        value_nodes: msg_nodes,
        value_depth: msg_depth,
        summary_len: td.summary().len(),
    }
}

// ─── samples: shapes wallets actually put in front of a signer ───────────────

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
///
/// `pub(crate)`: `tests/eip712_pool_hash.rs` includes this file as a module so the P2
/// digest pin hashes the same documents this spike measured (no second copy).
pub(crate) const SEAPORT_ORDER: &str = r#"{
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
/// `pub(crate)`: see `SEAPORT_ORDER` — the P2 digest pin reads it too.
pub(crate) const MAIL_OFFICIAL: &str = r#"{
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

/// The measured sample set. `pub(crate)` because `tests/eip712_pool_hash.rs` includes
/// this file to hash the SAME documents — the digest pin and the size measurements must
/// never disagree about what a real payload is.
pub(crate) fn samples() -> Vec<(&'static str, String)> {
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

#[test]
#[ignore = "spike: run explicitly with --ignored --nocapture"]
fn measure_real_world_typed_data() {
    println!();
    println!(
        "{:<26} {:>6} {:>5} {:>7} {:>6} {:>9} {:>6} {:>5} {:>7}",
        "sample", "json", "types", "fields", "maxF", "encodeTp", "nodes", "depth", "summary"
    );
    println!("{}", "-".repeat(88));

    let mut rows: Vec<Row> = Vec::new();
    for (name, json) in samples() {
        if let Some(r) = measure(name, &json) {
            println!(
                "{:<26} {:>6} {:>5} {:>7} {:>6} {:>9} {:>6} {:>5} {:>7}",
                r.name,
                r.json_len,
                r.type_count,
                r.fields_total,
                r.fields_max,
                r.encode_type_len,
                r.value_nodes,
                r.value_depth,
                r.summary_len
            );
            rows.push(r);
        }
    }

    println!("{}", "-".repeat(88));
    let peak = |f: &dyn Fn(&Row) -> usize| rows.iter().map(f).max().unwrap_or(0);
    println!(
        "{:<26} {:>6} {:>5} {:>7} {:>6} {:>9} {:>6} {:>5} {:>7}",
        "PEAK",
        peak(&|r| r.json_len),
        peak(&|r| r.type_count),
        peak(&|r| r.fields_total),
        peak(&|r| r.fields_max),
        peak(&|r| r.encode_type_len),
        peak(&|r| r.value_nodes),
        peak(&|r| r.value_depth),
        peak(&|r| r.summary_len)
    );
    println!();
}
