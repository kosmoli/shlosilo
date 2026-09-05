//! P0-02 audit remediation (2026-08-25): unimplemented export protocols must return errors, not fake success
//!
//! Audit finding: CryptoAccount / CryptoMultiAccounts / JsonMoneroViewkey /
//! ArweaveCryptoAccount returned stub_len without writing output_buf — the caller's buffer's old contents
//! would be output as the "export result" (information leak).

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

/// The four stub protocols must all return ExportProtocolUnimplemented (audit P0-02)
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
        // prefill the buffer with nonzero bytes — verify the failure path writes nothing
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

/// The only real implementation, CryptoHdKey, must keep working and fill [0..n]
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
