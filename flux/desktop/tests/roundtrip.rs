//! Shell + desktop carrier round trip, host-only (design 2026-11-26 §6 acceptance).
//!
//! Fixture: `tests/fixtures/core_regtest_p2sh_p2wpkh_331b.psbt` — a Bitcoin Core
//! `walletcreatefundedpsbt` product for the project's test seed (1 P2SH-P2WPKH input,
//! 1 output, 331 bytes, see tests/fixtures/README.md). It is the same fixture
//! `tests/p2sh_p2wpkh_device_path.rs` signs through the direct Rust entry, so a round
//! trip here is comparable with an existing, independent oracle.
//!
//! Seed: the fixture wallet's fixed BIP-39 seed (entropy `f284fb6c…b22916`, empty
//! passphrase) — TEST-ONLY material, published in tests/fixtures/README.md and shared
//! with the pico2 smoke and the P2SH device-path tests. Never real key material.
//!
//! What is asserted, in the order the flow does it:
//! 1. the review page is non-empty and carries the lines forms derives for this request;
//! 2. `Confirm` reaches forms' sign entry and produces an artifact;
//! 3. that artifact decodes back through forms' UR decoder and parses as a PSBT whose
//!    input now carries a partial signature;
//! 4. `Cancel` signs nothing;
//! 5. a refusal shows only forms' fixed words (no payload text, no code).

use std::collections::VecDeque;
use std::process::{Command, Stdio};

use shlosilo::chain::btc::psbt;
use shlosilo::network::Network;
use shlosilo::ur::ur_decode;
use shlosilo::ur::ur_encode::{self, UrTypeTag};
use shlosilo_flux_shell::{
    run_once, Action, Carrier, OutPiece, Page, Request, ShellConfig, ShellError,
};

/// The unsigned fixture, exactly as Bitcoin Core produced it.
const UNSIGNED_PSBT: &[u8] =
    include_bytes!("../../../tests/fixtures/core_regtest_p2sh_p2wpkh_331b.psbt");

/// The fixture wallet's BIP-39 seed. TEST-ONLY (see the module docs).
const SEED_HEX: &str = "d25e113e8f7be9936d67de81eb4d4bb94788b48b39f815f48f79dc029feddc918d07f5ac8ffbfb86514c4a0824ad187c5f6fc8b7c43b29356380aaeabc0267dc";

/// Rows per "screen" these tests use — enough to put this fixture's review on one page,
/// so the single-page assertions below stay readable. The multi-page test lowers it.
const ROWS: usize = 16;

fn seed() -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, slot) in out.iter_mut().enumerate() {
        let pair = &SEED_HEX[i * 2..i * 2 + 2];
        *slot = u8::from_str_radix(pair, 16).expect("fixture seed is hex");
    }
    out
}

/// Fixture fact (tests/fixtures/README.md): the input's BIP32_DERIVATION key.
const RECORD_PUBKEY: &str = "026c59ed538e8f38787d7f80411423c87aa3ecf6207801bace9e8992ac465027e5";
/// Fixture fact: BIP49 redeem script = the P2WPKH program inside the P2SH wrapper.
const REDEEM_SCRIPT: &str = "001464e4dbff0202485fd4d8217cc34a8d666fece529";

/// PSBT_IN_FINAL_SCRIPT_SIG / PSBT_IN_FINAL_SCRIPTWITNESS (BIP-174). Raw key bytes
/// because forms keeps `psbt::input_type` crate-private.
const FINAL_SCRIPT_SIG: u8 = 0x07;
const FINAL_SCRIPTWITNESS: u8 = 0x08;

fn hex_bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex"))
        .collect()
}

/// The request as a carrier would hand it over: the fixture inside a `crypto-psbt` UR.
fn request_uri() -> String {
    ur_encode::encode(UrTypeTag::CryptoPsbt, UNSIGNED_PSBT)
        .expect("the 331-byte fixture fits a single-frame UR")
        .as_str()
        .to_owned()
}

/// A carrier that scripts its actions and records what the shell asked it to do.
///
/// It does the two things the desktop carrier does and nothing else: it decodes the UR
/// text it was given (protocol work belongs to the carrier, and it uses forms' decoder
/// for it), and it frames the artifact back into UR text.
struct ScriptedCarrier {
    staged: Option<(String, Vec<u8>)>,
    taken: bool,
    actions: VecDeque<Action>,
    pages: Vec<String>,
    emitted: Option<(String, String)>,
}

impl ScriptedCarrier {
    fn new(uri: &str, actions: impl IntoIterator<Item = Action>) -> Self {
        // The carrier parses the transport, not the shell: `ur:<type>/<body>` is split
        // here so the type name reaches the shell byte-for-byte as it arrived.
        let (type_name, body) = uri
            .strip_prefix("ur:")
            .and_then(|rest| rest.split_once('/'))
            .expect("ur:<type>/<body>");
        assert!(
            !body.contains('/'),
            "this carrier test uses single-frame UR"
        );
        let decoded = ur_decode::decode(uri).expect("request decodes");
        ScriptedCarrier {
            staged: Some((type_name.to_owned(), decoded.as_ref().to_vec())),
            taken: false,
            actions: actions.into_iter().collect(),
            pages: Vec::new(),
            emitted: None,
        }
    }

    fn page_text(page: &Page<'_>) -> String {
        let mut text = format!("[page {}/{}]\n", page.page, page.pages);
        for line in page.lines {
            text.push_str(line);
            text.push('\n');
        }
        if let Some(status) = page.status {
            text.push_str(&format!("status: {status}\n"));
        }
        text
    }
}

impl Carrier for ScriptedCarrier {
    fn next_request(&mut self) -> Option<Request<'_>> {
        if self.taken {
            return None;
        }
        self.taken = true;
        self.staged
            .as_ref()
            .map(|(type_name, payload)| Request { type_name, payload })
    }

    fn draw(&mut self, page: &Page<'_>) {
        self.pages.push(Self::page_text(page));
    }

    fn action(&mut self) -> Action {
        // An exhausted script is a cancel: the seam requires the action source to make
        // progress (a carrier that keeps saying "next" would loop forever).
        self.actions.pop_front().unwrap_or(Action::Cancel)
    }

    fn emit(&mut self, out: &OutPiece<'_>) {
        let uri = ur_encode::encode(UrTypeTag::from_name(out.type_name), out.bytes)
            .expect("artifact frames into a single-frame UR");
        self.emitted = Some((out.type_name.to_owned(), uri.as_str().to_owned()));
    }
}

fn config() -> ShellConfig<'static> {
    // Leaks the fixture seed into a `&'static` so the config can outlive nothing in
    // particular: the seed is a published test vector, and this keeps the helper simple.
    static SEED: std::sync::OnceLock<[u8; 64]> = std::sync::OnceLock::new();
    ShellConfig {
        seed: SEED.get_or_init(seed),
        network: Network::BitcoinTestnet,
        master_fingerprint: None,
        rows_per_page: ROWS,
    }
}

#[test]
fn confirm_signs_and_the_artifact_decodes_back() {
    let uri = request_uri();
    let mut carrier = ScriptedCarrier::new(&uri, [Action::Confirm]);

    run_once(&mut carrier, &config()).expect("the flow completes");

    // 1. the operator saw something, and it is the review forms derived.
    let first = carrier.pages.first().expect("a review page was drawn");
    println!("--- review page ---\n{first}");
    assert!(
        first.starts_with("[page 1/1]"),
        "a one-page review says so: {first:?}"
    );
    assert!(
        first.contains("in 1 / out 1"),
        "the review carries forms' in/out line: {first:?}"
    );
    assert!(
        first.contains("fee"),
        "the review carries forms' fee line: {first:?}"
    );

    // 2./3. the artifact came out and forms can read it back.
    let (out_type, out_uri) = carrier.emitted.expect("an artifact was emitted");
    assert_eq!(
        out_type, "crypto-psbt",
        "the reply carries the request's name"
    );
    assert!(out_uri.starts_with("ur:crypto-psbt/"), "{out_uri}");
    let decoded = ur_decode::decode(&out_uri).expect("the artifact decodes");
    assert_eq!(decoded.type_tag(), UrTypeTag::CryptoPsbt);

    // The decoded payload is a PSBT whose input 0 now carries the finalized spend:
    // the BIP49 scriptSig (push of the redeem script) and the BIP-143 witness
    // (`<sig||sighash> <pubkey>`). Both are fixture-independent facts of *this* wallet,
    // so the check does not go through forms' own signing code.
    let signed = decoded.as_ref();
    assert!(
        signed.len() > UNSIGNED_PSBT.len(),
        "a signed PSBT is strictly larger than the request ({} vs {})",
        signed.len(),
        UNSIGNED_PSBT.len()
    );
    let mut arena = [0u8; 8192];
    let mut recs = [psbt::KvRec::EMPTY; 64];
    let parsed = psbt::parse_psbt_any(signed, Some(&mut arena), Some(&mut recs))
        .expect("the signed artifact parses as a PSBT");
    let input_map = parsed.input_map_checked(0).expect("input 0 has a map");

    let script_sig = input_map
        .get(&[FINAL_SCRIPT_SIG])
        .expect("the signed request carries a scriptSig");
    let mut expected_script_sig = vec![0x16];
    expected_script_sig.extend_from_slice(&hex_bytes(REDEEM_SCRIPT));
    assert_eq!(
        script_sig,
        expected_script_sig.as_slice(),
        "scriptSig is a push of the fixture's redeem script"
    );

    let witness = input_map
        .get(&[FINAL_SCRIPTWITNESS])
        .expect("the signed request carries a witness");
    // BIP-141 witness serialization: item count 2, the DER signature + sighash byte,
    // then the 33-byte compressed public key.
    assert_eq!(witness.first(), Some(&0x02), "two witness items");
    let sig_len = witness[1] as usize;
    assert!(
        (71..=73).contains(&sig_len),
        "a DER signature plus its sighash byte is 71-73 bytes, got {sig_len} in {witness:?}"
    );
    assert_eq!(
        witness.len(),
        2 + sig_len + 1 + 33,
        "witness = count, sig, pubkey with no padding: {witness:?}"
    );
    let pubkey = &witness[witness.len() - 33..];
    assert_eq!(
        pubkey,
        hex_bytes(RECORD_PUBKEY).as_slice(),
        "the witness public key is the fixture's derivation pubkey"
    );
    assert_eq!(
        witness[1 + sig_len],
        0x01,
        "the signature carries SIGHASH_ALL, as forms' require_sighash_all promises"
    );
}

#[test]
fn the_review_pages_through_when_the_screen_is_small() {
    // One row per page: every page holds exactly one line, and Next/Prev move between
    // them (both halves of the geometry are forms'; this asserts the shell honours them).
    let uri = request_uri();
    let mut carrier = ScriptedCarrier::new(
        &uri,
        [
            Action::Next,
            Action::Next,
            Action::Prev,
            Action::Next,
            Action::Confirm,
        ],
    );
    let mut cfg = config();
    cfg.rows_per_page = 1;

    run_once(&mut carrier, &cfg).expect("the flow completes");

    let drawn = carrier.pages.len();
    assert!(
        drawn > 2,
        "a one-row screen needs several pages, drew {drawn}"
    );
    // Page 1, 2, 3, then back to 2, then 3 again: the last page drawn before Confirm is
    // page 3 of the same set.
    for (i, page) in carrier.pages.iter().enumerate() {
        println!("--- page {i} ---\n{page}");
    }
    assert!(
        carrier.pages[0].starts_with("[page 1/"),
        "{}",
        carrier.pages[0]
    );
    assert!(
        carrier.pages[1].starts_with("[page 2/"),
        "{}",
        carrier.pages[1]
    );
    assert!(
        carrier.pages[2].starts_with("[page 3/"),
        "{}",
        carrier.pages[2]
    );
    assert!(
        carrier.pages[3].starts_with("[page 2/"),
        "{}",
        carrier.pages[3]
    );
    assert!(
        carrier.pages[4].starts_with("[page 3/"),
        "{}",
        carrier.pages[4]
    );
    assert!(carrier.emitted.is_some(), "the flow still signs");
}

#[test]
fn cancel_signs_nothing() {
    let uri = request_uri();
    let mut carrier = ScriptedCarrier::new(&uri, [Action::Cancel]);

    let outcome = run_once(&mut carrier, &config());

    assert_eq!(outcome, Err(ShellError::Cancelled));
    assert!(carrier.emitted.is_none(), "no artifact on the cancel path");
    assert_eq!(
        carrier.pages.len(),
        1,
        "the review was drawn once, then abandoned"
    );
}

#[test]
fn a_refusal_shows_only_forms_fixed_words() {
    // A request the signer must refuse: `bytes` is not a signable type. The payload is a
    // recognisable marker so the test can prove it never reaches the screen.
    const MARKER: &str = "PAYLOAD-MUST-NOT-BE-SHOWN";
    let uri = ur_encode::encode(UrTypeTag::Bytes, MARKER.as_bytes())
        .expect("an opaque bytes message encodes");
    let mut carrier = ScriptedCarrier::new(uri.as_str(), [Action::Confirm]);

    let outcome = run_once(&mut carrier, &config());

    assert_eq!(outcome, Err(ShellError::Refused));
    assert!(carrier.emitted.is_none(), "a refusal never emits");
    let page = carrier.pages.first().expect("the failure page was drawn");
    println!("--- refusal page ---\n{page}");
    // The page is forms' fixed template for this class, byte for byte:
    assert_eq!(
        page, "[page 1/1]\nsign failed\nrequest type not supported\nuse a single-key account\n",
        "a refusal uses the fixed word table, nothing else"
    );
    assert!(
        !page.contains(MARKER) && !page.contains("-14") && !page.contains("-10"),
        "no payload text and no internal code on screen: {page:?}"
    );
}

#[test]
fn the_desktop_binary_round_trips_through_files_and_stdin() {
    let dir = std::env::temp_dir().join(format!("shlosilo-flux-desktop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let request_path = dir.join("request.ur");
    let reply_path = dir.join("reply.ur");
    // A copy-paste dump, not a bare URI: the carrier takes the first `ur:` line.
    std::fs::write(
        &request_path,
        format!(
            "# fixture: core_regtest_p2sh_p2wpkh_331b\n{}\n",
            request_uri()
        ),
    )
    .expect("write the request");

    let output = Command::new(env!("CARGO_BIN_EXE_shlosilo-flux-desktop"))
        .args(["--in"])
        .arg(&request_path)
        .args(["--out"])
        .arg(&reply_path)
        .args([
            "--seed-hex",
            SEED_HEX,
            "--rows",
            "16",
            "--network",
            "testnet",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // `y\n` = confirm.
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.as_mut().expect("stdin").write_all(b"y\n")?;
            child.wait_with_output()
        })
        .expect("the desktop binary runs");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    println!("--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}");
    assert!(
        output.status.success(),
        "the binary exits 0 on a signed round trip; status {:?}",
        output.status
    );
    assert!(
        stdout.contains("[page 1/1]") && stdout.contains("in 1 / out 1"),
        "the review page reached stdout: {stdout:?}"
    );

    let reply = std::fs::read_to_string(&reply_path).expect("the reply file exists");
    let decoded = ur_decode::decode(reply.trim()).expect("the reply decodes");
    assert_eq!(decoded.type_tag(), UrTypeTag::CryptoPsbt);
    assert!(
        decoded.as_ref().len() > UNSIGNED_PSBT.len(),
        "the file carries a signed PSBT"
    );

    std::fs::remove_dir_all(&dir).ok();
}
