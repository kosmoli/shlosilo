//! BTC scriptPubKey → address rendering（审阅页的显示基础）
//!
//! ## 为什么需要
//!
//! 审阅页必须把 PSBT 输出/输入的真实收款方显示成人能核对的地址串。现有
//! `address/btc_segwit.rs` 是「公钥 → 自己的地址」，与「任意 scriptPubKey →
//! 地址」是两个不同的函数（后者不需要任何密钥材料，纯结构转换）。
//!
//! ## oracle 来源（外部权威，非自证）
//!
//! 向量全部由脚本从 Bitcoin Core 的金标数据文件机读生成，**没有手抄**：
//! - `~/codebases/bitcoin/src/test/data/key_io_valid.json`
//!   （`[address, script_hex, {chain}]`，覆盖 P2PKH / P2SH / P2WPKH /
//!   P2WSH / P2TR × main/testnet）
//! - `~/codebases/bitcoin/src/test/data/base58_encode_decode.json`
//!   （纯 base58 编码 KAT）
//!
//! 生成脚本：把 key_io_valid 按脚本类型分组、每类取 main 与 testnet 各一条，
//! chain 映射 testnet4/signet → test、regtest 跳过（我方 Network 无 bcrt）。

use shlosilo::address::btc_script;
use shlosilo::address::btc_segwit::BtcAddress;
use shlosilo::network::Network;

/// (scriptPubKey hex, 网络, 期望地址)
const VECTORS: &[(&str, &str, &str)] = &[
    (
        "76a914a31c06bd463e3923bc1aadbde48b16976c08071788ac",
        "main",
        "1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo",
    ), // p2pkh
    (
        "76a914ce28b26c57472737f5c3561a1761185bd8589a4388ac",
        "test",
        "mzK2FFDEhxqHcmrJw1ysqFkVyhUULo45hZ",
    ), // p2pkh
    (
        "a914373b819a068f32b7a6b38b6b38729647cfde01c287",
        "main",
        "36j4NfKv6Akva9amjWrLG6MuSQym1GuEmm",
    ), // p2sh
    (
        "a914ce0bba75891ff9ec60148d4bd4a09ee2dc5c933187",
        "test",
        "2NC2hEhe28ULKAJkW5MjZ3jtTMJdvXmByvK",
    ), // p2sh
    (
        "00146100fc6343edc8c874496cb2f5bbfec88ea9b77c",
        "main",
        "bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv",
    ), // p2wpkh
    (
        "0014c0ef1202759fff90ff19128936814321ee59e111",
        "test",
        "tb1qcrh3yqn4nlleplcez2yndq2ry8h9ncg3qh7n54",
    ), // p2wpkh
    (
        "002027304b37f70e94bc8a0fbf500e0c957a80ebda87280ef58214d92f119811acdc",
        "main",
        "bc1qyucykdlhp62tezs0hagqury402qwhk589q80tqs5myh3rxq34nwqhkdhv7",
    ), // p2wsh
    (
        "0020e13e5e482870d58bb44d9cfbfccea78702aad18d4ceea91af0e022431de31bbe",
        "test",
        "tb1quyl9ujpgwr2chdzdnnalen48sup245vdfnh2jxhsuq3yx80rrwlq5hqfe4",
    ), // p2wsh
    (
        "51203c671ef1e3913f94980a9e146ba895908550ef4234abb7503d436521aba54c75",
        "main",
        "bc1p83n3au0rjylefxq2nc2xh2y4jzz4pm6zxj4mw5pagdjjr2a9f36s6jjnnu",
    ), // p2tr
    (
        "51208d2745489a35b75734afa2da43817d40e7e8d80d17a26cd4460b0055c521a3fa",
        "test",
        "tb1p35n52jy6xkm4wd905tdy8qtagrn73kqdz73xe4zxpvq9t3fp50aqk3s6gz",
    ), // p2tr
];

fn from_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn net(s: &str) -> Network {
    match s {
        "main" => Network::BitcoinMainnet,
        "test" => Network::BitcoinTestnet,
        other => panic!("unknown network {other}"),
    }
}

/// 四类脚本 × main/test 的地址渲染（金标来自 Bitcoin Core 数据文件）
#[test]
fn script_pubkey_renders_to_golden_address() {
    let mut checked = 0;
    for (script, network, expected) in VECTORS {
        let spk = from_hex(script);
        let got = btc_script::render(&spk, net(network))
            .unwrap_or_else(|e| panic!("render failed for {script}: {e:?}"));
        assert_eq!(
            <BtcAddress as AsRef<str>>::as_ref(&got),
            *expected,
            "script {script} on {network} rendered wrong"
        );
        checked += 1;
    }
    assert_eq!(checked, VECTORS.len());
}

/// 非标准 / 截断脚本必须稳定拒绝，不许产出假地址
#[test]
fn non_standard_scripts_are_rejected() {
    let cases: &[(&str, &str)] = &[
        ("", "empty"),
        ("6a0b68656c6c6f20776f726c64", "OP_RETURN"),
        ("51", "OP_TRUE"),
        (
            "76a914a31c06bd463e3923bc1aadbde48b16976c080717",
            "truncated p2pkh",
        ),
        ("0014", "witness with no program"),
        // witness v2（未知版本，不能在 v0/v1 规则下瞎编）
        (
            "5220a31c06bd463e3923bc1aadbde48b16976c08071788ac00",
            "witness v2",
        ),
        // 20 字节 program 配 v1 版本（非法组合）
        (
            "5114a31c06bd463e3923bc1aadbde48b16976c080717",
            "v1 with 20-byte program",
        ),
    ];
    for (script, what) in cases {
        let spk = from_hex(script);
        assert!(
            btc_script::render(&spk, Network::BitcoinMainnet).is_err(),
            "{what} must be rejected, not rendered"
        );
    }
}

/// 纯 base58 编码 KAT（Bitcoin Core base58_encode_decode.json，机读生成）
#[test]
fn base58_encode_matches_bitcoin_core_vectors() {
    use shlosilo::encoding::base58;
    // (payload hex, expected base58)
    const B58: &[(&str, &str)] = &[
        ("", ""),
        ("61", "2g"),
        ("626262", "a3gV"),
        ("636363", "aPEr"),
        (
            "73696d706c792061206c6f6e6720737472696e67",
            "2cFupjhnEsSn59qHXstmK2ffpLv2",
        ),
        (
            "00eb15231dfceb60925886b67d065299925915aeb172c06647",
            "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L",
        ),
    ];
    for (hex, expected) in B58 {
        let payload = from_hex(hex);
        let mut out = [0u8; 128];
        let n = base58::encode_into(&payload, &mut out).expect("encode");
        assert_eq!(
            core::str::from_utf8(&out[..n]).unwrap(),
            *expected,
            "payload {hex}"
        );
    }
}
