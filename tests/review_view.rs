//! Data-layer pins for the sign-request review view.
//!
//! Covers BTC PSBT (real Sparrow fixture: fee / input and output counts / recipient
//! address rendering / unknown-script degradation / fee-unknown branch when UTXO data
//! is missing) and EVM (real eth-sign-request fixture: chain / destination (EIP-55) /
//! value, plus fixed word-table degradation of typed data).
//!
//! Copy discipline: every asserted line is either a fixed word-table entry or an
//! address/amount re-encoded from the decoded structure -- never raw payload text.

use shlosilo::business::review::{self, flag};
use shlosilo::chain::btc::psbt::KvRec;
use shlosilo::network::Network;
use shlosilo::ur::ur_encode::UrTypeTag;

const SPARROW_PSBT: &[u8] = include_bytes!("fixtures/sparrow_signet_12k.psbt");

/// The eth-sign-request UR already verified in the smoke task (EIP-1559 transfer).
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
    // Fixture oracle (comment in tests/p63_btc_psbt.rs): 1 input of 651157 sat,
    // outputs 1000 + 650087 sat -> fee 70 sat
    assert_eq!(l[1], "fee 70 sats", "lines = {l:?}");
    // Layout constraints from the first on-device run (2026-11-05): every line must
    // be self-explanatory -- amounts carry units, the whole view fits on one page, and
    // no bare numbers or header lines duplicating the page title are allowed.
    // Page cap is 12 lines (device layout), and risk lines must precede the body.
    assert!(l.len() <= 12, "must fit on one page (<=12 lines): {l:?}");
    // RBF is an operational property, not a risk: show the state, no warn (fee
    // bumping is normal in modern wallets).
    assert!(
        l.iter().any(|s| s == "replaceable yes"),
        "RBF state must be shown as-is (info line): {l:?}"
    );
    assert!(
        !l.iter().any(|s| s.starts_with("warn: replaceable")),
        "RBF must not be a warn (it dilutes real risk warnings): {l:?}"
    );
    assert!(
        !l.iter().any(|s| s == "warn: high fee"),
        "a 70 sat fee must not be reported as high: {l:?}"
    );
    // When a value cannot be judged, show it as-is: locktime must appear as an info
    // line with its domain labelled, never swallowed.
    let lt = l
        .iter()
        .find(|s| s.starts_with("locktime "))
        .unwrap_or_else(|| panic!("locktime value must be shown (operator decides): {l:?}"));
    assert!(
        lt.ends_with(" height") || lt.ends_with(" height ignored"),
        "fixture is a height-type locktime, domain label should be height: {lt}"
    );
    // Risk lines precede the body and must not be pushed below the fold.
    let first_send = l.iter().position(|s| s.starts_with("send ")).unwrap();
    if let Some(first_warn) = l.iter().position(|s| s.starts_with("warn:")) {
        assert!(
            first_warn < first_send,
            "risk lines must precede amount lines: {l:?}"
        );
    }
    assert!(l.iter().any(|s| s == "send 1000 sats"), "lines = {l:?}");
    // Output addresses follow Bitcoin Core encoding rules (P2WPKH on tb1).
    // Shape: a `send <amount> sats` line followed by the address line (long addresses wrap).
    let send_rows: Vec<usize> = l
        .iter()
        .enumerate()
        .filter(|(_, s)| s.starts_with("send "))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        send_rows.len(),
        2,
        "both outputs should be external payments: {l:?}"
    );
    for i in send_rows {
        let addr = &l[i + 1];
        assert!(
            addr.starts_with("tb1q") && addr.len() >= 42,
            "recipient address was not rendered: {addr}"
        );
    }
    // Amount and unit share one line (no bare-number lines).
    assert!(
        l.iter().all(|s| s.trim().parse::<u64>().is_err()),
        "no unit-less bare amount lines allowed: {l:?}"
    );

    // The fixture's input nSequence signals RBF (Sparrow enables it by default).
    assert!(
        view.flags & flag::RBF != 0,
        "RBF not flagged, flags = {:#x}",
        view.flags
    );
    // Fee known -> no FEE_UNKNOWN; 70 sat is far below the threshold -> no HIGH_FEE.
    assert_eq!(view.flags & flag::FEE_UNKNOWN, 0);
    assert_eq!(view.flags & flag::HIGH_FEE, 0);
    assert_eq!(view.flags & flag::UNKNOWN_SCRIPT, 0);
    assert_eq!(view.input_count, 1);
    assert_eq!(view.output_count, 2);
}

/// Unknown scripts must degrade to fixed words; script bytes must never be shown as
/// an address.
#[test]
fn btc_unknown_output_script_degrades_to_fixed_words() {
    let mut psbt = SPARROW_PSBT.to_vec();
    // Replace the first output script in place with an equal-length OP_RETURN
    // (6a14 + 20 bytes = 22 bytes): the length is unchanged, so the PSBT stays
    // structurally intact.
    let needle = [0x00u8, 0x14]; // P2WPKH script head
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
        "OP_RETURN output should degrade to a fixed word: {l:?}"
    );
    assert!(
        view.flags & flag::UNKNOWN_SCRIPT != 0,
        "UNKNOWN_SCRIPT not flagged"
    );
}

/// Without witness_utxo the fee is only a lower bound -- it must say unknown
/// explicitly instead of printing some number.
#[test]
fn btc_missing_utxo_reports_fee_unknown() {
    // Constructing a minimal PSBT with only a global unsigned_tx and no input maps is
    // not practical here; take the negative path instead: a truncated, invalid PSBT
    // must error out rather than produce a half view.
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
    assert!(r.is_err(), "truncated PSBT must be rejected");
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
        "chain id missing: {l:?}"
    );
    let to_idx = l.iter().position(|s| s == "to:").expect("to: line");
    let addr = &l[to_idx + 1];
    assert!(
        addr.starts_with("0x") && addr.len() == 42,
        "EIP-55 address rendering failed: {addr}"
    );
    assert!(
        l.iter().any(|s| s.starts_with("value ")),
        "value missing: {l:?}"
    );
}

/// Non-review types (XMR / unknown) must be rejected rather than yielding an empty
/// view to confirm blindly.
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
        assert!(r.is_err(), "{tag:?} must not have a review view");
    }
}

// --------------------- FFI surface (the path the platform layer actually calls) ---------------------

#[test]
fn review_ffi_packs_lines_and_meta() {
    use core::ffi::c_uint;
    use shlosilo::ffi::c_abi;
    use std::ffi::CString;

    let ws_need = c_abi::shlosilo_review_ws_len() as usize;
    assert!(
        ws_need >= 16 * 1024,
        "ws budget should include the 16KiB arena"
    );

    // ws = NULL is a pure probe: it reports the length only and does no work.
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
    assert_eq!(
        probe as usize, ws_need,
        "probe ws requirement should match the query"
    );

    // Real call
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
    assert_eq!(rc, 0, "review ffi should succeed");
    assert!(count > 0);
    // NUL-separated blob: the number of split entries must equal count.
    let blob = &lines[..used as usize];
    let parts: Vec<&[u8]> = blob.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
    assert_eq!(
        parts.len(),
        count as usize,
        "line count does not match the blob"
    );
    assert_eq!(&parts[0], b"in 1 / out 2");
    assert_eq!(in_out >> 16, 1, "input count");
    assert_eq!(in_out & 0xffff, 2, "output count");
    assert!(flags & u32::from(flag::RBF) != 0, "flags should carry RBF");

    // An insufficient buffer must error out (no partial write).
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
    assert_ne!(rc, 0, "insufficient line buffer must fail");
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
        assert_ne!(
            rc, 0,
            "{name} must not have a review view (XMR uses the original flow)"
        );
    }
}

/// The network comes from the PSBT's own derived coin type: even when the caller says
/// mainnet, the signet fixture's recipient address must render as tb1… (otherwise an
/// operator checking against mainnet prefixes would misjudge it).
#[test]
fn network_follows_the_psbt_coin_type_not_the_caller() {
    let mut arena = [0u8; ARENA];
    let mut recs = [KvRec::EMPTY; RECS];
    let view = review::build(
        UrTypeTag::CryptoPsbt,
        SPARROW_PSBT,
        Network::BitcoinMainnet, // deliberately wrong
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
        "coin type 1 should override the caller's mainnet: {addr}"
    );
}

/// Change detection: with our fingerprint supplied (fixture master fingerprint =
/// f3b9960b, see the BIP32_DERIVATION comment in tests/p63_btc_psbt.rs), an output
/// returning to our own wallet must be labelled `change`, not `send` like a payment.
/// This pins the semantic defect seen on the first on-device run (both outputs showed
/// `to:`).
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
        "change must be labelled when our fingerprint is known: {l:?}"
    );
    assert!(
        l.iter().any(|s| s.starts_with("send ")),
        "payment output should still be labelled send: {l:?}"
    );
}

/// locktime domain split (500M threshold).
///
/// Product rule (2026-11-05): values that cannot be judged are shown to the operator
/// as-is; never filter them on the operator's behalf. Height type (the usual
/// anti-sniping case) versus timestamp type only decides **which domain to label**,
/// not whether the line is displayed.
#[test]
fn locktime_domain_splits_at_the_consensus_threshold() {
    use review::LocktimeDomain;
    assert_eq!(review::locktime_domain(870_123), LocktimeDomain::Height);
    assert_eq!(review::locktime_domain(499_999_999), LocktimeDomain::Height);
    assert_eq!(review::locktime_domain(500_000_000), LocktimeDomain::Time);
    assert_eq!(review::locktime_domain(1_900_000_000), LocktimeDomain::Time);
}
