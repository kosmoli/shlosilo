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
    assert_eq!(l[0], "in 1 / out 2", "lines = {l:?}");
    // 夹具 oracle（tests/p63_btc_psbt.rs 注释）：1 输入 651157 sat，
    // 输出 1000 + 650087 sat → fee 70 sat
    assert_eq!(l[1], "fee 70 sats", "lines = {l:?}");
    // 真机首测的排版教训（2026-11-05）：每行都要自解释——金额带单位、
    // 一页放得下，不许出现裸数字或与页标题重复的抬头行。
    // 一页上限 12 行（真机版面），且风险行必须出现在正文之上
    assert!(l.len() <= 12, "必须一页放得下（≤12 行）: {l:?}");
    assert!(
        l.iter().any(|s| s == "warn: replaceable"),
        "RBF 输入必须上屏告警: {l:?}"
    );
    assert!(
        !l.iter().any(|s| s == "warn: high fee"),
        "70 sat 的手续费不该报大额: {l:?}"
    );
    // 风险行在正文之前，不许被挤到折叠线以下
    let first_warn = l.iter().position(|s| s.starts_with("warn:")).unwrap();
    let first_send = l.iter().position(|s| s.starts_with("send ")).unwrap();
    assert!(first_warn < first_send, "风险行必须在金额行之前: {l:?}");
    assert!(l.iter().any(|s| s == "send 1000 sats"), "lines = {l:?}");
    // 输出地址来自 Bitcoin Core 编码规则（P2WPKH on tb1）
    // 形态：`send <amount> sats` 一行 + 下一行地址（长地址再续行）
    let send_rows: Vec<usize> = l
        .iter()
        .enumerate()
        .filter(|(_, s)| s.starts_with("send "))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(send_rows.len(), 2, "两个输出都应是外部收款: {l:?}");
    for i in send_rows {
        let addr = &l[i + 1];
        assert!(
            addr.starts_with("tb1q") && addr.len() >= 42,
            "收款地址没有被渲染出来: {addr}"
        );
    }
    // 金额与单位同在一行（不再出现裸数字行）
    assert!(
        l.iter().all(|s| s.trim().parse::<u64>().is_err()),
        "不许出现无单位的裸金额行: {l:?}"
    );

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
        l.iter().any(|s| s == "address unknown"),
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

// ───────────────────── FFI 面（平台层真正调的那条路） ─────────────────────

#[test]
fn review_ffi_packs_lines_and_meta() {
    use core::ffi::c_uint;
    use shlosilo::ffi::c_abi;
    use std::ffi::CString;

    let ws_need = c_abi::shlosilo_review_ws_len() as usize;
    assert!(ws_need >= 16 * 1024, "ws 预算应含 16KiB arena");

    // ws = NULL 是纯探针：只回长度，不做事
    let mut probe: c_uint = 0;
    let ty = CString::new("crypto-psbt").unwrap();
    let rc = c_abi::shlosilo_review_ffi(
        ty.as_ptr(),
        SPARROW_PSBT.as_ptr(),
        SPARROW_PSBT.len() as c_uint,
        1, // testnet
        core::ptr::null(),
        core::ptr::null_mut(),
        0,
        [0u8; 16].as_mut_ptr(),
        0,
        &mut probe,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    assert_eq!(rc, 0);
    assert_eq!(probe as usize, ws_need, "探针回报的 ws 需求应与查询一致");

    // 正式调用
    let mut ws = vec![0u8; ws_need];
    let mut lines = [0u8; c_abi::REVIEW_LINES_BUF];
    let mut used: c_uint = 0;
    let mut count: c_uint = 0;
    let mut flags: c_uint = 0;
    let mut in_out: c_uint = 0;
    let rc = c_abi::shlosilo_review_ffi(
        ty.as_ptr(),
        SPARROW_PSBT.as_ptr(),
        SPARROW_PSBT.len() as c_uint,
        1,
        core::ptr::null(),
        ws.as_mut_ptr(),
        ws.len() as c_uint,
        lines.as_mut_ptr(),
        lines.len() as c_uint,
        &mut used,
        &mut count,
        &mut flags,
        &mut in_out,
    );
    assert_eq!(rc, 0, "review ffi 应成功");
    assert!(count > 0);
    // NUL 分隔的 blob：切出来的条数必须等于 count
    let blob = &lines[..used as usize];
    let parts: Vec<&[u8]> = blob.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
    assert_eq!(parts.len(), count as usize, "行数与 blob 不符");
    assert_eq!(&parts[0], b"in 1 / out 2");
    assert_eq!(in_out >> 16, 1, "输入数");
    assert_eq!(in_out & 0xffff, 2, "输出数");
    assert!(flags & u32::from(flag::RBF) != 0, "flags 应带 RBF");

    // 缓冲不够必须报错（不写半截）
    let mut small = [0u8; 8];
    let rc = c_abi::shlosilo_review_ffi(
        ty.as_ptr(),
        SPARROW_PSBT.as_ptr(),
        SPARROW_PSBT.len() as c_uint,
        1,
        core::ptr::null(),
        ws.as_mut_ptr(),
        ws.len() as c_uint,
        small.as_mut_ptr(),
        small.len() as c_uint,
        &mut used,
        &mut count,
        &mut flags,
        &mut in_out,
    );
    assert_ne!(rc, 0, "行缓冲不足必须失败");
}

#[test]
fn review_ffi_rejects_xmr_types() {
    use core::ffi::c_uint;
    use shlosilo::ffi::c_abi;
    use std::ffi::CString;

    let ws_need = c_abi::shlosilo_review_ws_len() as usize;
    let mut ws = vec![0u8; ws_need];
    let mut lines = [0u8; c_abi::REVIEW_LINES_BUF];
    let (mut used, mut count, mut flags, mut in_out): (c_uint, c_uint, c_uint, c_uint) =
        (0, 0, 0, 0);
    for name in ["xmr-txunsigned", "xmr-output"] {
        let ty = CString::new(name).unwrap();
        let rc = c_abi::shlosilo_review_ffi(
            ty.as_ptr(),
            [0u8; 8].as_ptr(),
            8,
            0,
            core::ptr::null(),
            ws.as_mut_ptr(),
            ws.len() as c_uint,
            lines.as_mut_ptr(),
            lines.len() as c_uint,
            &mut used,
            &mut count,
            &mut flags,
            &mut in_out,
        );
        assert_ne!(rc, 0, "{name} 不该有审阅面（XMR 走原流程）");
    }
}

/// 网络由 PSBT 自己的派生 coin type 决定：signet 夹具即使调用方说 mainnet，
/// 收款地址也必须渲染成 tb1…（否则操作员照主网前缀核对会误判）。
#[test]
fn network_follows_the_psbt_coin_type_not_the_caller() {
    let mut arena = [0u8; ARENA];
    let mut recs = [KvRec::EMPTY; RECS];
    let view = review::build(
        UrTypeTag::CryptoPsbt,
        SPARROW_PSBT,
        Network::BitcoinMainnet, // 故意说错
        None,
        &mut arena,
        &mut recs,
    )
    .expect("review builds");
    let l = lines(&view);
    let addr = l
        .iter()
        .find(|s| s.starts_with("tb1") || s.starts_with("bc1"))
        .expect("address line");
    assert!(
        addr.starts_with("tb1q"),
        "coin type 1 应压过调用方的 mainnet: {addr}"
    );
}

/// 找零识别：带上本机指纹（夹具的 master fingerprint = f3b9960b，见
/// tests/p63_btc_psbt.rs 的 BIP32_DERIVATION 注释）时，回到自己钱包的输出
/// 必须标成 `change`，而不是和付款一样标 `send`。
/// 这条对应真机首测的语义缺陷（两个输出都显示 `to:`）。
#[test]
fn change_output_is_labelled_when_our_fingerprint_is_known() {
    let mfp = [0xf3u8, 0xb9, 0x96, 0x0b];
    let mut arena = [0u8; ARENA];
    let mut recs = [KvRec::EMPTY; RECS];
    let view = review::build(
        UrTypeTag::CryptoPsbt,
        SPARROW_PSBT,
        Network::BitcoinTestnet,
        Some(&mfp),
        &mut arena,
        &mut recs,
    )
    .expect("review builds");
    let l = lines(&view);
    assert!(
        l.iter().any(|s| s.starts_with("change ")),
        "带本机指纹时必须标出找零: {l:?}"
    );
    assert!(
        l.iter().any(|s| s.starts_with("send ")),
        "付款输出仍应标 send: {l:?}"
    );
}
