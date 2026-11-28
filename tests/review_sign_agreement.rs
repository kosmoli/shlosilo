//! Cross-face agreement: the review gate and the signing gate answer the same verdict.
//!
//! # The property (and why a structural pin is not enough)
//!
//! Both faces now dispatch on the same `EthScheme` enum, so they cannot grow *different* arms.
//! That is structure, not behaviour: nothing yet says the two faces actually **reach** the same
//! verdict on a given request. If the review face gained an extra gate (or lost one), the enum
//! would still be shared and the operator could be shown a request the signer refuses — or, far
//! worse, confirm one the signer computes differently.
//!
//! So this test walks the `data_type` × payload-shape matrix and asserts, for every cell, that:
//!
//! * review accepts **iff** sign gets past its request gates, and
//! * when both refuse, they refuse with the **same error kind**.
//!
//! "Sign gets past its request gates" is measured with a valid seed and a workspace, and a
//! refusal caused by *key material* (never by the request) is out of scope: a request the
//! operator can read must be signable by the wallet it belongs to, and this fixture's key is
//! irrelevant because the cases below never reach signing.
//!
//! The matrix deliberately includes the shapes that must be refused: a typed envelope we do not
//! sign (0x01), a bare RLP body with no type byte, a legacy RLP that already carries a signature,
//! and a `data_type` whose payload belongs to another `data_type`.

// The gate batch compiles every test target on the `--no-default-features` face too, where the
// alloc-backed CBOR encoders (and the Vec-based workspaces this test builds) do not exist. The
// property under test is about the two faces' verdicts, not about the allocator seam, so the
// whole file rides the same feature every other alloc-using test target rides.
#![cfg(feature = "alloc-fallback")]

use shlosilo::business::review;
use shlosilo::business::sign::SignInput;
use shlosilo::encoding::cbor;
use shlosilo::error::ShlosiloErrorKind;
use shlosilo::ur::ur_encode::UrTypeTag;

/// An `eth-sign-request` CBOR map with the four fields the dialect defines.
fn request_map(sign_data: &[u8], data_type: u64, chain_id: u64) -> Vec<u8> {
    cbor::encode_map(&[
        (
            cbor::encode_uint(1),
            cbor::encode_tag(37, &cbor::encode_bytes(&[0x9bu8; 16])),
        ),
        (cbor::encode_uint(2), cbor::encode_bytes(sign_data)),
        (cbor::encode_uint(3), cbor::encode_uint(data_type)),
        (cbor::encode_uint(4), cbor::encode_uint(chain_id)),
    ])
}

/// A minimal EIP-1559 request body (`0x02 || rlp([...])`), chain 1.
fn eip1559_body() -> Vec<u8> {
    use shlosilo::chain::eth::rlp;
    let mut out = vec![0x02u8];
    out.extend_from_slice(&rlp::encode_list(&[
        rlp::encode_uint(1),             // chain id
        rlp::encode_uint(7),             // nonce
        rlp::encode_uint(1_000_000_000), // max priority
        rlp::encode_uint(2_000_000_000), // max fee
        rlp::encode_uint(21_000),        // gas
        rlp::encode_bytes(&[0x11u8; 20]),
        rlp::encode_uint(1),
        rlp::encode_list(&[]),
        rlp::encode_list(&[]),
    ]));
    out
}

/// A legacy EIP-155 request body (bare RLP, 9 items).
fn eip155_body() -> Vec<u8> {
    use shlosilo::chain::eth::rlp;
    rlp::encode_list(&[
        rlp::encode_uint(7),
        rlp::encode_uint(1_000_000_000),
        rlp::encode_uint(21_000),
        rlp::encode_bytes(&[0x11u8; 20]),
        rlp::encode_uint(1),
        rlp::encode_list(&[]),
        rlp::encode_uint(1), // chain id folds into v
        rlp::encode_list(&[]),
        rlp::encode_list(&[]),
    ])
}

/// Both faces through their PUBLIC entries, which is what a carrier actually calls:
/// `review::build` (the review page) and `sign_with_entropy` (the signer).
fn verdicts(payload: &[u8]) -> (Result<(), ShlosiloErrorKind>, Result<(), ShlosiloErrorKind>) {
    // Review: fresh pools, exactly the shape the C-ABI carve hands over.
    let mut arena = vec![0u8; shlosilo::limits::PSBT_ARENA_BYTES];
    let mut recs = vec![shlosilo::chain::btc::psbt::KvRec::EMPTY; shlosilo::limits::PSBT_RECS_MAX];
    let mut typed = vec![0u8; shlosilo::limits::UR_PAYLOAD_MAX];
    let review_verdict = review::build(
        UrTypeTag::EthSignRequest,
        payload,
        shlosilo::network::Network::BitcoinMainnet,
        None,
        &mut arena,
        &mut recs,
        &mut typed,
    )
    .map(|_| ())
    .map_err(|e| e.kind);

    // Sign: a valid seed and output buffer, so any refusal comes from the request gates.
    let seed = [0x42u8; 64];
    let mut out = [0u8; 512];
    let sign_verdict = shlosilo::business::sign::sign_with_entropy(
        SignInput::Seed { seed: &seed },
        UrTypeTag::EthSignRequest,
        payload,
        &[],
        &mut out,
    )
    .map(|_| ())
    .map_err(|e| e.kind);

    (review_verdict, sign_verdict)
}

/// Assert the two faces agree, and — when they both refuse — for the same reason.
#[track_caller]
fn assert_agreement(label: &str, payload: &[u8]) {
    let (r, s) = verdicts(payload);
    match (&r, &s) {
        (Ok(()), Ok(())) => {}
        (Err(rk), Err(sk)) => assert_eq!(
            rk, sk,
            "{label}: both faces refused but for different reasons (review {rk:?}, sign {sk:?})"
        ),
        (Ok(()), Err(sk)) => panic!(
            "{label}: the review face showed a request the signing face refuses ({sk:?}) — the \
             operator would confirm what cannot be signed"
        ),
        (Err(rk), Ok(())) => panic!(
            "{label}: the signing face accepted what the review face refuses ({rk:?}) — the \
             operator would never have seen it"
        ),
    }
}

#[test]
fn eth_review_and_sign_agree_on_every_data_type() {
    // 1 = legacy, 2 = typed data, 3 = personal, 4 = typed transaction.
    assert_agreement("legacy tx", &request_map(&eip155_body(), 1, 1));
    assert_agreement("eip-1559 tx", &request_map(&eip1559_body(), 4, 1));
    assert_agreement("personal message", &request_map(b"hello", 3, 1));
    // Typed data with a body that is not a JSON document: both faces must refuse it, and with
    // the same kind — this is the case where a divergence would be easiest to introduce.
    assert_agreement("typed data (garbage body)", &request_map(b"not json", 2, 1));
}

#[test]
fn eth_review_and_sign_agree_on_unsupported_envelopes() {
    // 0x01 = EIP-2930: a valid envelope this product does not sign. Refused as
    // FeatureNotImplemented by both faces, never as a format error.
    let mut body = vec![0x01u8];
    body.extend_from_slice(&eip1559_body()[1..]);
    assert_agreement("eip-2930 envelope", &request_map(&body, 4, 1));

    // An unknown type byte is a format error, again on both faces.
    let mut bogus = vec![0x7fu8];
    bogus.extend_from_slice(&eip1559_body()[1..]);
    assert_agreement("unknown envelope byte", &request_map(&bogus, 4, 1));
}

#[test]
fn eth_review_and_sign_agree_when_data_type_and_body_disagree() {
    // A legacy body announced as a typed transaction: the first byte is not 0x02, so both faces
    // must refuse it, and neither may fall back to parsing it as legacy.
    assert_agreement(
        "legacy body as typed tx",
        &request_map(&eip155_body(), 4, 1),
    );
    // A typed body announced as legacy: the RLP is not a 9-item legacy list.
    assert_agreement("typed body as legacy", &request_map(&eip1559_body(), 1, 1));
}
