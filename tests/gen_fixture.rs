//! Generates the eth-sign-request UR fixture for the C simulator (P6.1d)
//!
//! Run: cargo test --offline --test gen_fixture -- --ignored --nocapture
//! Output: flux/host-sim/fixture_eth_sign_request.txt (one UR line)
//!
//! **After P1-01/P1-02 (fixed 2026-08-29)**: the UR payload must be a CBOR map
//! {1: request_id, 2: sign_data, 3: data_type, 4: chain_id} — the old version stuffed the RLP
//! in directly (wrong wire shape, previously masked by sign()'s fallback logic; exposed after the
//! P1-02 network validation).
//! The payload's leading [1] type-tag prefix is handled by ur_encode::encode, no longer assembled by hand.
//!
//! **After the data_type dispatch fix (2026-11-24)**: `data_type` selects the scheme before the
//! payload is read (reference dialect: `eth_sign_tx_dynamic`). An EIP-1559 transaction is
//! `TypedTransaction` = **4**, whose first payload byte (0x02) then selects 1559; `data_type` 1 is
//! legacy (bare RLP, no type byte) and is not signable. This fixture therefore carries 4.
//!
//! **After E-1 (2026-11-24)**: the sign exit returns the `ur:eth-signature` container and echoes
//! the request's `request_id`, so the fixture must carry key 1 — a request without it is refused.
//! Key 1 is a tag(37) UUID wrapper over the 16 raw bytes (ur-registry `requestId`); the id is the
//! registry test vector's, the same one the business-layer fixtures use (`TEST_ETH_REQUEST_ID`).
#![cfg(feature = "alloc-fallback")]

use shlosilo::chain::eth::{eip1559, rlp};
use shlosilo::encoding::cbor;
use shlosilo::ur::ur_encode::{encode, UrTypeTag};

/// Request id echoed into the `ur:eth-signature` container: the ur-registry test
/// vector's `requestId` (9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d), shared with
/// `TEST_ETH_REQUEST_ID` in `forms/business/sign.rs`.
const REQUEST_ID: [u8; 16] = [
    0x9b, 0x1d, 0xeb, 0x4d, 0x3b, 0x7d, 0x4b, 0xad, 0x9b, 0xdd, 0x2b, 0x0d, 0x7b, 0x3d, 0xcb, 0x6d,
];

#[test]
#[ignore]
fn gen_fixture() {
    let tx = eip1559::Eip1559Transaction {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 2_000_000_000,
        gas_limit: 21_000,
        destination: Some([0x22u8; 20]),
        amount: 999,
        data: Vec::new().into(),
    };
    let list = rlp::encode_list(&[
        rlp::encode_uint(tx.chain_id as u128),
        rlp::encode_uint(tx.nonce as u128),
        rlp::encode_uint(tx.max_priority_fee_per_gas),
        rlp::encode_uint(tx.max_fee_per_gas),
        rlp::encode_uint(tx.gas_limit as u128),
        rlp::encode_bytes(&tx.destination.unwrap()),
        rlp::encode_uint(tx.amount),
        rlp::encode_bytes(&tx.data),
        rlp::encode_list(&[]),
        rlp::encode_bytes(b""),
        rlp::encode_bytes(b""),
        rlp::encode_bytes(b""),
    ]);
    let mut raw = vec![0x02u8];
    raw.extend_from_slice(&list);

    // CBOR map (consistent with the business::sign test encoding), canonical key order:
    // 1=request_id (tag 37 UUID), 2=sign_data, 3=data_type, 4=chain_id
    let pairs = vec![
        (
            cbor::encode_uint(1),
            cbor::encode_tag(37, &cbor::encode_bytes(&REQUEST_ID)),
        ),
        (cbor::encode_uint(2), cbor::encode_bytes(&raw)),
        (cbor::encode_uint(3), cbor::encode_uint(4)), // data_type 4 = TypedTransaction (0x02-prefixed 1559)
        (cbor::encode_uint(4), cbor::encode_uint(1)), // chain_id = 1
    ];
    let payload = cbor::encode_map(&pairs);

    let enc = encode(UrTypeTag::EthSignRequest, &payload).unwrap();
    println!("URI: {}", enc.as_str());
    let out = "flux/host-sim/fixture_eth_sign_request.txt";
    std::fs::write(out, enc.as_str()).unwrap();
    println!("written to {out}");
}
