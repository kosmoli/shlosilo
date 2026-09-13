//! Generates the eth-sign-request UR fixture for the C simulator (P6.1d)
//!
//! Run: cargo test --offline --test gen_fixture -- --ignored --nocapture
//! Output: flux/host-sim/fixture_eth_sign_request.txt (one UR line)
//!
//! **After P1-01/P1-02 (fixed 2026-08-29)**: the UR payload must be a CBOR map
//! {2: sign_data, 3: data_type, 4: chain_id} — the old version stuffed the RLP in directly (wrong wire shape,
//! previously masked by sign()'s fallback logic; exposed after the P1-02 network validation).
//! The payload's leading [1] type-tag prefix is handled by ur_encode::encode, no longer assembled by hand.

use shlosilo::chain::eth::{eip1559, rlp};
use shlosilo::encoding::cbor;
use shlosilo::ur::ur_encode::{encode, UrTypeTag};

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
        data: Vec::new(),
        access_list: Vec::new(),
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

    // CBOR map (consistent with the business::sign test encoding): 2=sign_data, 3=data_type, 4=chain_id
    let pairs = vec![
        (cbor::encode_uint(2), cbor::encode_bytes(&raw)),
        (cbor::encode_uint(3), cbor::encode_uint(1)), // type 1 = TypedTransaction
        (cbor::encode_uint(4), cbor::encode_uint(1)), // chain_id = 1
    ];
    let payload = cbor::encode_map(&pairs);

    let enc = encode(UrTypeTag::EthSignRequest, &payload).unwrap();
    println!("URI: {}", enc.as_str());
    let out = "flux/host-sim/fixture_eth_sign_request.txt";
    std::fs::write(out, enc.as_str()).unwrap();
    println!("written to {out}");
}
