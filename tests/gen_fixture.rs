//! 生成 C 模拟器用的 eth-sign-request UR fixture（P6.1d）
//!
//! 运行：cargo test --offline --test gen_fixture -- --ignored --nocapture
//! 输出：simulator-l3/fixture_eth_sign_request.txt（一行 UR）
//!
//! **P1-01/P1-02 之后（2026-08-29 修复）**：UR payload 必须是 CBOR map
//! {2: sign_data, 3: data_type, 4: chain_id}——旧版直接塞 RLP（wire 形状错误，
//! 曾被 sign() 的 fallback 逻辑掩盖；P1-02 network 校验后暴露）。
//! payload 首字节 [1] type-tag 前缀由 ur_encode::encode 处理，不再手工拼。

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

    // CBOR map（与 business::sign 测试编码一致）：2=sign_data, 3=data_type, 4=chain_id
    let pairs = vec![
        (cbor::encode_uint(2), cbor::encode_bytes(&raw)),
        (cbor::encode_uint(3), cbor::encode_uint(1)), // type 1 = TypedTransaction
        (cbor::encode_uint(4), cbor::encode_uint(1)), // chain_id = 1
    ];
    let payload = cbor::encode_map(&pairs);

    let enc = encode(UrTypeTag::EthSignRequest, &payload).unwrap();
    println!("URI: {}", enc.as_str());
    let out = "simulator-l3/fixture_eth_sign_request.txt";
    std::fs::write(out, enc.as_str()).unwrap();
    println!("written to {out}");
}
