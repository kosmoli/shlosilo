//! E-3 P3 pins: the EIP-712 review page, its fold policy, and the fact that the page and
//! the signer make ONE decision.
//!
//! Three groups, because three different things can silently drift:
//!
//! 1. **The fold policy** (`typed_data_fold_gate`): a struct-element array past three
//!    elements is refused, an atom array of the same length is folded and stays signable,
//!    and a struct past the expansion depth is named and counted but not refused. The
//!    `verifyingContract` pin is written to fail if the domain line ever disappears with a
//!    fold — that line is what tells the operator which contract will accept the signature.
//! 2. **`v`**: typed data carries 27/28 (the `rec_id + 27` convention the reference signer
//!    serializes), and the signature recovers to the device's own key over the digest the
//!    independent alloc parser computes. A yParity byte here would fail both halves.
//! 3. **Bidirectional alignment**: every document the signer refuses, the page refuses with
//!    the same code, and every document the page renders the signer signs. The one allowed
//!    asymmetry is the page's own fold policy (it refuses a structure it cannot itemize),
//!    which is named and asserted as such.
#![cfg(feature = "alloc-fallback")]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use shlosilo::business::review;
use shlosilo::business::sign::{
    carve_sign_ws, sign_with_entropy_ws, sign_with_network, SignInput, SignWsLayout,
};
use shlosilo::error::{ShlosiloError, ShlosiloErrorKind};
use shlosilo::network::Network;
use shlosilo::ur::codec::eth_signature::parse_eth_signature;
use shlosilo::ur::ur_encode::UrTypeTag;

const SEED: [u8; 64] = [7u8; 64];
/// USDC on mainnet — the verifying contract every document below is bound to.
const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

// ─── request plumbing ───────────────────────────────────────────────────────

/// An `eth-sign-request` payload carrying `json` as EIP-712 typed data (`data_type` 2).
fn typed_data_request(json: &str) -> Vec<u8> {
    typed_data_request_with_chain(json, None)
}

/// The same request with key 4 (`chain_id`) — the field the transaction schemes carry to state
/// the chain they believe they are signing for.
fn typed_data_request_with_chain(json: &str, chain_id: Option<u64>) -> Vec<u8> {
    use shlosilo::encoding::cbor;
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (
            cbor::encode_uint(1),
            cbor::encode_tag(37, &cbor::encode_bytes(&[0x9bu8; 16])),
        ),
        (cbor::encode_uint(2), cbor::encode_bytes(json.as_bytes())),
        (cbor::encode_uint(3), cbor::encode_uint(2)),
    ];
    if let Some(id) = chain_id {
        pairs.push((cbor::encode_uint(4), cbor::encode_uint(id)));
    }
    cbor::encode_map(&pairs)
}

/// Move the document's own `domain.chainId` to another chain (the rest of the document is
/// unchanged, so only the chain identity differs).
fn domain_chain(json: &str, id: u64) -> String {
    let needle = "\"chainId\":1,";
    assert_eq!(
        json.matches(needle).count(),
        1,
        "one domain chainId to move"
    );
    json.replace(needle, &format!("\"chainId\":{id},"))
}

/// The review workspace the C-ABI carves (`review_ws_len()` bytes; the page only uses the
/// typed-data tail of it).
fn review_ws() -> Vec<u8> {
    vec![0u8; shlosilo::ffi::c_abi::review_ws_len()]
}

/// Render the page and flatten it to the text the operator would read.
fn review_of(payload: &[u8]) -> Result<String, ShlosiloError> {
    let mut ws = review_ws();
    let view = review::build_eth(payload, &mut ws)?;
    let mut text = String::new();
    for line in view.lines() {
        text.push_str(line.as_str());
        text.push('\n');
    }
    Ok(text)
}

/// Sign through the workspace-provisioned entry (the face the C-ABI uses), so typed data has
/// the container it needs.
fn device_sign(payload: &[u8]) -> Result<Vec<u8>, ShlosiloError> {
    let need = SignWsLayout::compute().total;
    let mut ws_bytes = vec![0u8; need];
    let mut ws = carve_sign_ws(&mut ws_bytes).expect("workspace carve");
    let mut out = vec![0u8; 512];
    let n = sign_with_entropy_ws(
        SignInput::Seed { seed: &SEED },
        UrTypeTag::EthSignRequest,
        payload,
        &[],
        &[],
        Some(&mut ws),
        None,
        &mut out,
    )?;
    out.truncate(n);
    Ok(out)
}

// ─── documents ──────────────────────────────────────────────────────────────

/// A typed-data document with the standard four-field domain (bound to USDC on chain 1),
/// `extra` appended to the type table (leading comma), and the given root.
fn doc(extra: &str, primary: &str, message: &str) -> String {
    format!(
        r#"{{"types":{{"EIP712Domain":[{{"name":"name","type":"string"}},{{"name":"version","type":"string"}},{{"name":"chainId","type":"uint256"}},{{"name":"verifyingContract","type":"address"}}]{extra}}},"primaryType":"{primary}","domain":{{"name":"USD Coin","version":"2","chainId":1,"verifyingContract":"{USDC}"}},"message":{message}}}"#
    )
}

/// One real ERC-2612 permit.
fn permit() -> String {
    doc(
        r#","Permit":[{"name":"owner","type":"address"},{"name":"spender","type":"address"},{"name":"value","type":"uint256"},{"name":"nonce","type":"uint256"},{"name":"deadline","type":"uint256"}]"#,
        "Permit",
        r#"{"owner":"0x1111111111111111111111111111111111111111","spender":"0x2222222222222222222222222222222222222222","value":"1000000","nonce":0,"deadline":1700000000}"#,
    )
}

/// `uint256[] ids` with eight elements: an array the page can fold (every element is a
/// scalar whose type and count are printed).
fn atom_array(n: usize) -> String {
    let items: Vec<String> = (1..=n).map(|i| i.to_string()).collect();
    doc(
        r#","Ids":[{"name":"ids","type":"uint256[]"}]"#,
        "Ids",
        &format!(r#"{{"ids":[{}]}}"#, items.join(",")),
    )
}

/// `Item[] items`, each element a struct: an array whose every element is a value the
/// operator would have to accept on its own.
fn struct_array(n: usize) -> String {
    let items: Vec<String> = (1..=n)
        .map(|i| format!(r#"{{"to":"0x{i:040x}","amount":{i}}}"#))
        .collect();
    doc(
        r#","Batch":[{"name":"items","type":"Item[]"}],"Item":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}]"#,
        "Batch",
        &format!(r#"{{"items":[{}]}}"#, items.join(",")),
    )
}

/// `Outer { inner: Inner { deep: Deep { x } } }` — a struct three levels below the message
/// root, so the second level is past the page's expansion depth.
fn deep_struct() -> String {
    doc(
        r#","Outer":[{"name":"inner","type":"Inner"}],"Inner":[{"name":"deep","type":"Deep"}],"Deep":[{"name":"x","type":"uint256"}]"#,
        "Outer",
        r#"{"inner":{"deep":{"x":7}}}"#,
    )
}

/// `primaryType` is not in the document's own type table.
fn unknown_primary() -> String {
    doc("", "Nope", "{}")
}

/// The domain DECLARES `chainId` but never gives it a value: the digest layer refuses such a
/// domain, so both faces must.
fn missing_domain_value() -> String {
    r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"}],"T":[{"name":"x","type":"uint256"}]},"primaryType":"T","domain":{"name":"USD Coin"},"message":{"x":1}}"#.to_string()
}

// ─── 1. the fold policy ─────────────────────────────────────────────────────

/// A struct array past three elements is refused by BOTH faces.
///
/// Folding it would hide N separate authorizations behind one count; an atom array of the
/// same length is folded instead (next pin), and the difference is deliberate — see
/// `review::typed_data_fold_gate`.
#[test]
fn a_struct_array_over_three_is_refused_by_both_faces() {
    let payload = typed_data_request(&struct_array(8));
    let page = review_of(&payload).expect_err("the page cannot itemize eight struct elements");
    assert_eq!(
        page.kind,
        ShlosiloErrorKind::FeatureNotImplemented,
        "a folded struct array is a refusal, not a shorter page"
    );
    let signed = device_sign(&payload).expect_err("the signer refuses what the page refuses");
    assert_eq!(
        signed.kind,
        ShlosiloErrorKind::FeatureNotImplemented,
        "the sign face must apply the page's gate, or a direct call could blind-sign"
    );

    // Every length between four and seven is refused too: the bound is `> 3`, and an
    // off-by-one there would show up here rather than in a real request.
    for n in 4..=7 {
        let over = typed_data_request(&struct_array(n));
        assert_eq!(
            review_of(&over)
                .expect_err("the page refuses a folded struct array")
                .kind,
            ShlosiloErrorKind::FeatureNotImplemented,
            "{n} struct elements must be refused"
        );
        assert_eq!(
            device_sign(&over)
                .expect_err("the signer refuses it too")
                .kind,
            ShlosiloErrorKind::FeatureNotImplemented,
            "{n} struct elements must be refused by the sign face"
        );
    }

    // Three is still signable and fully itemized: the bound is the fold, not struct arrays.
    let three = typed_data_request(&struct_array(3));
    let text = review_of(&three).expect("three struct elements render");
    assert!(text.contains("items 3 items"), "{text}");
    assert!(text.contains("items[2] struct Item"), "{text}");
    assert!(device_sign(&three).is_ok(), "three struct elements sign");
}

/// An atom array folded to three stays signable, and the page says how much it folded.
#[test]
fn an_atom_array_over_three_folds_and_stays_signable() {
    let payload = typed_data_request(&atom_array(8));
    let text = review_of(&payload).expect("atom arrays are foldable");
    assert!(
        text.contains("ids 8 items"),
        "the length is always shown: {text}"
    );
    assert!(
        text.contains("and 5 more (3 of 8)"),
        "the fold is counted: {text}"
    );
    assert!(text.contains("ids[0] 1"), "{text}");
    assert!(text.contains("ids[2] 3"), "{text}");
    assert!(
        !text.contains("ids[3]"),
        "the fold must stop at three itemized elements: {text}"
    );
    assert!(
        device_sign(&payload).is_ok(),
        "a folded atom array is a display decision, not a refusal"
    );
}

/// `verifyingContract` is on the page in every folded shape.
///
/// Mutation check: this pin fails if the domain line is made to disappear with the fold
/// (move the domain render inside the fold branch, or let a fold clear the view) — the
/// address is what tells the operator which contract will accept the signature, so it may
/// never be part of what a fold hides.
#[test]
fn the_verifying_contract_survives_every_fold() {
    for (name, json) in [
        ("folded atom array", atom_array(8)),
        ("struct array within the limit", struct_array(3)),
        ("struct past the expansion depth", deep_struct()),
        ("plain permit", permit()),
    ] {
        let text = review_of(&typed_data_request(&json))
            .unwrap_or_else(|e| panic!("{name}: must render, got {:?}", e.kind));
        assert!(
            text.contains("verifying contract"),
            "{name}: the domain block must name the contract: {text}"
        );
        assert!(
            text.contains(USDC),
            "{name}: the verifying contract address must be on the page: {text}"
        );
    }
}

/// A struct past the expansion depth is named and counted, NOT refused — and the request
/// stays signable.
#[test]
fn a_struct_past_the_expansion_depth_is_counted_not_refused() {
    let payload = typed_data_request(&deep_struct());
    let text = review_of(&payload).expect("depth truncation is not a refusal");
    assert!(text.contains("inner struct Inner"), "{text}");
    assert!(text.contains("inner.deep struct Deep"), "{text}");
    assert!(
        text.contains("inner.deep 1 fields not shown"),
        "a truncated struct prints its size: {text}"
    );
    assert!(
        device_sign(&payload).is_ok(),
        "depth truncation is a page limit, not a signing refusal"
    );
}

// ─── 2. `v` and the digest ──────────────────────────────────────────────────

/// The typed-data `v` is 27/28, and the signature verifies against the EIP-712 digest an
/// independent implementation computes.
///
/// The digest comes from `eip712::signing_hash` (the alloc parser), not from the pool the
/// signer used: a signature that recovers against THAT digest proves the pool's
/// `signing_hash_pool` agrees with the reference face on a real permit. The `v` half is
/// separate: with a bare yParity byte the recovery below would recover nothing.
#[test]
fn typed_data_v_is_27_or_28_and_recovers_to_the_device_key() {
    use shlosilo::chain::eth::{eip712, sign as eth_sign};
    use shlosilo::curve_primitive::secp256k1;
    use shlosilo::derivation::bip32_secp256k1::derive_from_seed;
    use shlosilo::derivation::path::DerivationPath;

    let json = permit();
    let payload = typed_data_request(&json);
    let container = device_sign(&payload).expect("the permit signs");
    let sig = parse_eth_signature(&container).expect("the exit is an eth-signature container");

    assert_eq!(
        sig.signature_bytes().len(),
        65,
        "a typed-data signature is r ‖ s ‖ v with a one-byte v"
    );
    let v = sig.signature[64];
    assert!(
        v == 27 || v == 28,
        "EIP-712 carries v = 27/28 (the reference signer serializes rec_id + 27), got {v}"
    );

    let typed = eip712::parse_typed_data_v4(&json).expect("the alloc parser accepts the permit");
    let digest = typed.signing_hash().expect("the alloc digest");

    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(sig.signature_bytes());
    let recovered = eth_sign::ecdsa_recover(&digest, &sig65).expect("recover");

    let path = DerivationPath::parse("m/44'/60'/0'/0/0").expect("standard path");
    let sk = derive_from_seed(&SEED, &path).expect("derive");
    let device_pub = secp256k1::point_to_uncompressed(&secp256k1::base_mul(&sk));
    assert_eq!(
        recovered,
        device_pub[1..],
        "the signature must verify against the EIP-712 digest, with the device's own key"
    );

    // The offset is not cosmetic: the same r/s with the other parity recovers elsewhere.
    let mut wrong = sig65;
    wrong[64] = 27 + (1 - (v - 27));
    let mis_recovered = eth_sign::ecdsa_recover(&digest, &wrong).expect("recover (wrong parity)");
    assert_ne!(
        mis_recovered,
        device_pub[1..],
        "flipping the parity must not recover to the device key"
    );
}

// ─── 3. the network gate ────────────────────────────────────────────────────

/// `check_network` reads `domain.chainId` for typed data, in the three shapes it can take:
/// readable and matching (the gate passes), readable and wrong (`NetworkUnrecognized`), and
/// unreadable (the gate is skipped).
///
/// The matching and unreadable cases land on `BufferTooSmall` — the alloc shell has no
/// EIP-712 container (the C-ABI face always provisions one), which is exactly what the
/// brief requires of a no-workspace sign. What this pin asserts is that the NETWORK gate let
/// them through: a `NetworkUnrecognized` there would mean the pre-check misread the domain.
#[test]
fn the_network_gate_reads_the_domain_chain_id() {
    let sign_on = |json: &str, network: Network| -> ShlosiloErrorKind {
        let payload = typed_data_request(json);
        let mut out = vec![0u8; 512];
        match sign_with_network(
            SignInput::Seed { seed: &SEED },
            UrTypeTag::EthSignRequest,
            &payload,
            network,
            &mut out,
        ) {
            Ok(_) => panic!("the alloc shell has no typed-data container, it cannot sign"),
            Err(e) => e.kind,
        }
    };

    // readable + matching: the gate passes (the container refusal is the next wall)
    assert_eq!(
        sign_on(&permit(), Network::EthereumMainnet),
        ShlosiloErrorKind::BufferTooSmall,
        "chain 1 on mainnet must pass the network gate"
    );
    // readable + mismatched: the gate refuses
    assert_eq!(
        sign_on(&permit(), Network::EthereumSepolia),
        ShlosiloErrorKind::NetworkUnrecognized,
        "a mainnet domain must not sign under a Sepolia selection"
    );
    // unreadable: the gate is skipped, not failed
    let no_chain =
        r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"}],"T":[{"name":"x","type":"uint256"}]},"primaryType":"T","domain":{"name":"USD Coin"},"message":{"x":1}}"#
            .to_string();
    assert_eq!(
        sign_on(&no_chain, Network::EthereumMainnet),
        ShlosiloErrorKind::BufferTooSmall,
        "a domain without a chain id has nothing to compare: the gate must skip it"
    );
}

/// Key 4 (the request's own `chain_id`) cannot vouch for a chain the signed digest does not
/// name: `check_network` compares BOTH with the selected network, so a request cannot state one
/// chain in key 4 and sign another in `domain.chainId`.
///
/// Both directions are pinned because they fail at different places: a wrong key 4 is refused
/// before the `data_type` dispatch, a wrong `domain.chainId` after it. Each case keeps the other
/// field in agreement with the selection, so the refusal can only come from the field the case
/// is about.
#[test]
fn key_four_cannot_vouch_for_a_different_domain_chain() {
    let gate = |json: &str, key_four: Option<u64>, network: Network| -> ShlosiloErrorKind {
        let payload = typed_data_request_with_chain(json, key_four);
        let mut out = vec![0u8; 512];
        match sign_with_network(
            SignInput::Seed { seed: &SEED },
            UrTypeTag::EthSignRequest,
            &payload,
            network,
            &mut out,
        ) {
            Ok(_) => panic!("the alloc shell has no typed-data container, it cannot sign"),
            Err(e) => e.kind,
        }
    };

    // key 4 says mainnet, the domain says Sepolia: the domain comparison refuses.
    assert_eq!(
        gate(
            &domain_chain(&permit(), 11_155_111),
            Some(1),
            Network::EthereumMainnet
        ),
        ShlosiloErrorKind::NetworkUnrecognized,
        "a mainnet key 4 must not carry a Sepolia domain"
    );
    // key 4 says Sepolia, the domain says mainnet: the key-4 comparison refuses.
    assert_eq!(
        gate(&permit(), Some(11_155_111), Network::EthereumMainnet),
        ShlosiloErrorKind::NetworkUnrecognized,
        "a Sepolia key 4 must not sign a mainnet domain"
    );
    // Both on mainnet: the network gate passes (the container refusal is the next wall).
    assert_eq!(
        gate(&permit(), Some(1), Network::EthereumMainnet),
        ShlosiloErrorKind::BufferTooSmall,
        "key 4 and the domain agreeing must pass the network gate"
    );
}

// ─── 4. one decision, two faces ─────────────────────────────────────────────

/// Every document the signer refuses, the page refuses with the SAME code; every document the
/// page renders, the signer signs.
///
/// The single allowed asymmetry is the page's fold policy (`FeatureNotImplemented` from the
/// page only) — and the gate is shared, so even those two agree today. Any new divergence
/// fails here instead of reaching an operator as "the page showed it and the device would
/// not sign it" (or worse, the reverse).
#[test]
fn sign_and_review_refuse_the_same_documents() {
    let cases: [(&str, String); 7] = [
        ("permit", permit()),
        ("atom array 8", atom_array(8)),
        ("atom array 0", atom_array(0)),
        ("struct array 3", struct_array(3)),
        ("deep struct", deep_struct()),
        ("unknown primary type", unknown_primary()),
        (
            "declared domain field without a value",
            missing_domain_value(),
        ),
    ];
    for (name, json) in cases {
        let payload = typed_data_request(&json);
        let page = review_of(&payload);
        let signed = device_sign(&payload);
        match (&page, &signed) {
            (Ok(_), Ok(_)) => {}
            (Err(p), Err(s)) => assert_eq!(
                p.kind, s.kind,
                "{name}: both faces refuse, and they must refuse with one code"
            ),
            (Ok(_), Err(s)) => panic!(
                "{name}: the page rendered a request the signer refuses ({:?}) — the operator \
                 would confirm something the device will not sign",
                s.kind
            ),
            (Err(p), Ok(_)) => assert_eq!(
                p.kind,
                ShlosiloErrorKind::FeatureNotImplemented,
                "{name}: the page may only refuse alone on its own fold policy, got {:?}",
                p.kind
            ),
        }
    }
    // A payload that is not JSON at all: both faces call it a format error.
    let torndata = typed_data_request("{\"types\":");
    assert_eq!(
        review_of(&torndata).unwrap_err().kind,
        ShlosiloErrorKind::EncodingInvalidFormat
    );
    assert_eq!(
        device_sign(&torndata).unwrap_err().kind,
        ShlosiloErrorKind::EncodingInvalidFormat
    );
}
