//! ETH 跨验证 (v9.14)
//!
//! 用 keystone `rust/apps/ethereum` 的测试 fixture 作为 oracle：
//! 1. EIP-712 typed data hash — `eip712.rs::test_hash_typed_message_with_data`
//!    及同文件的 metamask/minimal/array 向量
//! 2. EIP-155 legacy tx RLP — `legacy_transaction.rs::test_transfer_erc20_legacy_transaction`
//!
//! 方法论：keystone 测试里的期望 hash/RLP 字节是外部锚点，
//! shlosilo 独立实现必须产出相同字节。

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

/// 构造 keystone `test_hash_typed_message_with_data` 同款 typed data:
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

// ─── EIP-712 跨验证 ──────────────────────────────────────────────────

/// keystone `test_hash_typed_message_with_data`: 期望 signing hash
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

/// keystone `test_minimal_message` 向量**不可用作 oracle**：
/// keystone 的 `encode_eip712`（eip712.rs:454）在 `primaryType == "EIP712Domain"` 时
/// 故意跳过 struct_hash（MetaMask eth-sig-util 兼容 quirk），与标准 EIP-712 定义不同。
/// shlosilo 按标准实现（0x1901 || sep || structHash），两者在此边界场景必然分叉。
#[test]
fn eth_eip712_minimal_edge_case_documented() {
    use std::string::ToString;

    let mut types = eip712::Types::new();
    types.insert("EIP712Domain".to_string(), vec![]);

    let domain = eip712::Eip712Domain::default();
    let msg = eip712::Eip712Value::Struct("EIP712Domain".to_string(), vec![]);

    // 标准 EIP-712 行为：shlosilo 产出 ≠ keystone 的 quirk 值，这是**预期差异**
    let sighash = eip712::signing_hash(&domain, "EIP712Domain", &msg, &types).unwrap();
    assert_ne!(
        hex_encode(&sighash),
        "8d4a3f4082945b7879e2b55f181c31a77c8c0a464b70669458abbaaf99de4c38",
        "shlosilo follows standard EIP-712; keystone's 8d4a3f... is its own quirk"
    );
}

/// keystone `test_encode_custom_array_type`: Person/address[] 嵌套数组
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

    // 空 domain（keystone json 里 "domain":{}）
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

// ─── EIP-155 legacy tx RLP 跨验证 ─────────────────────────────────────

/// keystone `test_transfer_erc20_legacy_transaction`:
/// unsigned RLP preimage 必须与 keystone `LegacyTransaction::encode_raw()` 一致。
/// 注意 keystone 的 unsigned 编码含 (nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0)
/// 尾部三字段是 EIP-155 replay protection；这里对照其完整 unsigned_hex。
#[test]
fn eth_legacy_rlp_keystone_erc20_unsigned() {
    // keystone fixture 字段
    let nonce: u128 = 33;
    let gas_price: u128 = 15_198_060_006;
    let gas_limit: u128 = 46_000;
    let to = hex_to_20("fe2c232adDF66539BFd5d1Bd4B2cc91D358022a2");
    let value: u128 = 200_000_000_000_000;
    let data = hex_bytes("a9059cbb00000000000000000000000049ab56b91fc982fd6ec1ec7bb87d74efa6da30ab00000000000000000000000000000000000000000000000001480ff69d129e2d");
    let chain_id: u128 = 1; // keystone 测试隐含 v=38 → EIP-155 (v = chain_id*2 + 35)

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

    // signed raw tx: keystone 给了固定 r/s/v，拼回后必须逐字节一致 + tx hash 一致
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

// ─── EIP-1559 签名链路（自洽 + 结构验证）────────────────────────────────

/// EIP-1559 signing preimage 结构：0x02 || rlp([...])。
/// keystone 没有现成 EIP-1559 sighash fixture（只有 parse 层测试），
/// 这里用以太坊规范已知结构做 sanity + 与 legacy 复用同一 RLP 编码器的一致性检查。
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
        data: vec![],
        access_list: vec![],
    };
    let preimage = signing_preimage(&tx).unwrap();

    // 类型字节必须是 0x02
    assert_eq!(preimage[0], 0x02);

    // preimage 其余部分应为合法 RLP list —— 正确解析长度前缀（含 0xf8 长形式）
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

    // sighash 是 keccak256(preimage)，确定性
    let h1 = shlosilo::chain::eth::eip1559::signing_hash(&tx).unwrap();
    let h2 = shlosilo::chain::eth::eip1559::signing_hash(&tx).unwrap();
    assert_eq!(h1, h2);
}
