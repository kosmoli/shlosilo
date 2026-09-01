//! P0-02 审计整改（2026-08-25）：未实现的导出协议必须返回错误，不得假成功
//!
//! 审计发现：CryptoAccount / CryptoMultiAccounts / JsonMoneroViewkey /
//! ArweaveCryptoAccount 返回 stub_len 但不写 output_buf——调用者缓冲区旧内容
//! 会被当"导出结果"输出（信息泄露）。

use shlosilo::business::export_readonly::{export_readonly, ExportProtocol};
use shlosilo::derivation::path::DerivationPath;
use shlosilo::error::ShlosiloErrorKind;
use shlosilo::network::Network;

fn path() -> heapless::Vec<DerivationPath, 8> {
    let mut v = heapless::Vec::new();
    v.push(DerivationPath::parse("m/44'/0'/0'/0/0").unwrap())
        .ok();
    v
}

/// 四个 stub 协议必须全部返回 ExportProtocolUnimplemented（审计 P0-02）
#[test]
fn p0_02_stub_protocols_rejected() {
    let seed = [7u8; 64];
    let paths = path();
    let cases = [
        ExportProtocol::CryptoAccount,
        ExportProtocol::CryptoMultiAccounts,
        ExportProtocol::JsonMoneroViewkey,
        ExportProtocol::ArweaveCryptoAccount,
    ];
    for proto in cases {
        // 预填充非零缓冲区——验证失败路径不写任何字节
        let mut buf = [0xA5u8; 1024];
        let result = export_readonly(proto, &seed, Network::BitcoinMainnet, &paths, &mut buf);
        let err = result.expect_err("stub protocol must not fake success");
        assert!(
            matches!(err.kind, ShlosiloErrorKind::ExportProtocolUnimplemented),
            "unexpected error for {:?}",
            proto
        );
        assert!(
            buf.iter().all(|&b| b == 0xA5),
            "output buffer must be untouched on failure"
        );
    }
}

/// 唯一真实实现的 CryptoHdKey 必须继续工作且写满 [0..n]
#[test]
fn p0_02_crypto_hdkey_still_works_and_fills_buffer() {
    let seed = [7u8; 64];
    let paths = path();
    let mut buf = [0u8; 1024];
    let n = export_readonly(
        ExportProtocol::CryptoHdKey,
        &seed,
        Network::BitcoinMainnet,
        &paths,
        &mut buf,
    )
    .expect("CryptoHdKey must work");
    assert!(n > 0);
    let uri = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(uri.starts_with("ur:crypto-hdkey/"));
}
