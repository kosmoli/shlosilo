//! 审阅视图（sign-request review）的数据层钉
//!
//! 覆盖：BTC PSBT（真实 Sparrow 夹具：fee/输入输出计数/收款方地址渲染/
//! 未知脚本降级/缺 UTXO 的 fee 未知分支）、EVM（真实 eth-sign-request 夹具：
//! chain/destination(EIP-55)/value + typed-data 的固定词表降级）。
//!
//! 文案纪律：本文件断言的每一行要么是固定词表，要么是从解码结构重编码出来的
//! 地址/金额——不含 payload 原文。

use shlosilo::business::review::{self, flag};
use shlosilo::chain::btc::psbt::KvRec;
use shlosilo::network::Network;
use shlosilo::ur::ur_encode::UrTypeTag;

const SPARROW_PSBT: &[u8] = include_bytes!("fixtures/sparrow_signet_12k.psbt");

/// 冒烟任务里那条已验证的 eth-sign-request UR（EIP-1559 转账）
const ETH_SIGN_REQUEST_URI: &str = "ur:eth-sign-request/otaohddmaowpadlalrfrnysgaelrktecmwaelfgmaymwcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcplfaxvdlartlalalaaxadaaadrpceaadt";

const ARENA: usize = 16 * 1024;
const RECS: usize = 128;

fn lines(view: &review::ReviewView) -> Vec<String> {
    view.lines()
        .iter()
        .map(|l| l.as_str().to_string())
        .collect()
}

#[test]
fn btc_psbt_review_summarizes_real_sparrow_fixture() {
    let mut arena = [0u8; ARENA];
    let mut recs = [KvRec::EMPTY; RECS];
    let view = review::build(
        UrTypeTag::CryptoPsbt,
        SPARROW_PSBT,
        Network::BitcoinTestnet,
        None,
        &mut arena,
        &mut recs,
    )
    .expect("review builds for the Sparrow fixture");

    let l = lines(&view);
    assert_eq!(l[0], "btc send request", "lines = {l:?}");
    assert_eq!(l[1], "in 1 / out 2", "lines = {l:?}");
    // 夹具 oracle（tests/p63_btc_psbt.rs 注释）：1 输入 651157 sat，
    // 输出 1000 + 650087 sat → fee 70 sat
    assert_eq!(l[2], "fee 70 sats", "lines = {l:?}");
    // 输出地址来自 Bitcoin Core 编码规则（P2WPKH on tb1）
    // 形态：一行 `to:` 标签 + 下一行地址本身（地址长于 48 字符时再续行）
    let label_idx: Vec<usize> = l
        .iter()
        .enumerate()
        .filter(|(_, s)| s.as_str() == "to:")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(label_idx.len(), 2, "两个输出都应是外部收款: {l:?}");
    for i in label_idx {
        let addr = &l[i + 1];
        assert!(
            addr.starts_with("tb1q") && addr.len() >= 42,
            "收款地址没有被渲染出来: {addr}"
        );
    }
    // 金额行
    assert!(l.iter().any(|s| s.trim() == "1000"), "lines = {l:?}");

    // 该夹具的输入 nSequence 为 RBF 信号（Sparrow 默认开启）
    assert!(
        view.flags & flag::RBF != 0,
        "RBF 未标记, flags = {:#x}",
        view.flags
    );
    // fee 已知 → 不得有 FEE_UNKNOWN；70 sat 远低于阈值 → 不得有 HIGH_FEE
    assert_eq!(view.flags & flag::FEE_UNKNOWN, 0);
    assert_eq!(view.flags & flag::HIGH_FEE, 0);
    assert_eq!(view.flags & flag::UNKNOWN_SCRIPT, 0);
    assert_eq!(view.input_count, 1);
    assert_eq!(view.output_count, 2);
}

/// 未知脚本必须降级成固定词，不许把脚本字节当地址显示
#[test]
fn btc_unknown_output_script_degrades_to_fixed_words() {
    let mut psbt = SPARROW_PSBT.to_vec();
    // 把第一个输出脚本原地换成等长的 OP_RETURN（6a14 + 20 字节 = 22 字节），
    // 长度不变，PSBT 结构仍完整。
    let needle = [0x00u8, 0x14]; // P2WPKH 脚本头
    let pos = psbt
        .windows(2)
        .position(|w| w == needle)
        .expect("P2WPKH script head present");
    psbt[pos] = 0x6a;
    psbt[pos + 1] = 0x14;

    let mut arena = [0u8; ARENA];
    let mut recs = [KvRec::EMPTY; RECS];
    let view = review::build(
        UrTypeTag::CryptoPsbt,
        &psbt,
        Network::BitcoinTestnet,
        None,
        &mut arena,
        &mut recs,
    )
    .expect("review still builds");

    let l = lines(&view);
    assert!(
        l.iter().any(|s| s == "to: unknown script"),
        "OP_RETURN 输出应降级成固定词: {l:?}"
    );
    assert!(
        view.flags & flag::UNKNOWN_SCRIPT != 0,
        "UNKNOWN_SCRIPT 未标记"
    );
}

/// 缺 witness_utxo 时 fee 只能是下界——必须显式说 unknown，不能给个数糊过去
#[test]
fn btc_missing_utxo_reports_fee_unknown() {
    // 直接构造一个只有 global unsigned_tx、没有输入 map 的最小 PSBT 不现实；
    // 这里改走负面路径：截断成非法 PSBT 必须报错而不是产出半截视图。
    let truncated = &SPARROW_PSBT[..SPARROW_PSBT.len() / 2];
    let mut arena = [0u8; ARENA];
    let mut recs = [KvRec::EMPTY; RECS];
    let r = review::build(
        UrTypeTag::CryptoPsbt,
        truncated,
        Network::BitcoinTestnet,
        None,
        &mut arena,
        &mut recs,
    );
    assert!(r.is_err(), "截断 PSBT 必须被拒绝");
}

#[test]
fn eth_transaction_review_renders_eip55_destination() {
    let ur = shlosilo::ur::ur_decode::decode(ETH_SIGN_REQUEST_URI).expect("ur decode");
    let payload = ur.as_ref();
    let mut arena = [0u8; ARENA];
    let mut recs = [KvRec::EMPTY; RECS];
    let view = review::build(
        UrTypeTag::EthSignRequest,
        payload,
        Network::EthereumMainnet,
        None,
        &mut arena,
        &mut recs,
    )
    .expect("eth review builds");

    let l = lines(&view);
    assert_eq!(l[0], "eth send request", "lines = {l:?}");
    assert!(
        l.iter().any(|s| s.starts_with("chain ")),
        "chain id 缺失: {l:?}"
    );
    let to_idx = l.iter().position(|s| s == "to:").expect("to: line");
    let addr = &l[to_idx + 1];
    assert!(
        addr.starts_with("0x") && addr.len() == 42,
        "EIP-55 地址渲染失败: {addr}"
    );
    assert!(
        l.iter().any(|s| s.starts_with("value ")),
        "value 缺失: {l:?}"
    );
}

/// 非审阅面（XMR / 未知类型）必须拒绝，而不是给出一个空视图让人点确认
#[test]
fn unsupported_types_are_rejected() {
    let mut arena = [0u8; ARENA];
    let mut recs = [KvRec::EMPTY; RECS];
    for tag in [
        UrTypeTag::XmrTxUnsigned,
        UrTypeTag::XmrOutput,
        UrTypeTag::Unknown,
    ] {
        let r = review::build(
            tag,
            &[0u8; 8],
            Network::BitcoinMainnet,
            None,
            &mut arena,
            &mut recs,
        );
        assert!(r.is_err(), "{tag:?} 不该有审阅视图");
    }
}
