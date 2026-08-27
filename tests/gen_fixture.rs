//! 生成 C 模拟器用的 eth-sign-request UR fixture（P6.1d）
//!
//! 运行：cargo test --offline --test gen_fixture -- --ignored --nocapture
//! 输出：simulator-l3/fixture_eth_sign_request.txt（一行 UR）
//!
//! integration test 在 std 环境，直接用 std Vec。

use shlosilo::chain::eth::{eip1559, rlp};
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
    let mut payload = vec![1u8]; // EthSignRequest type tag
    payload.extend_from_slice(&raw);

    let enc = encode(UrTypeTag::EthSignRequest, &payload).unwrap();
    println!("URI: {}", enc.as_str());
    let out = "simulator-l3/fixture_eth_sign_request.txt";
    std::fs::write(out, enc.as_str()).unwrap();
    println!("written to {out}");
}
