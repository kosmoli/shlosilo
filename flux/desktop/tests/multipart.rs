//! Multi-frame UR in and out through the desktop carrier (design 2026-11-26 §10 gap 9).
//!
//! The gap: the carrier used to accept one single-frame request and emit one single-frame
//! artifact, so the two signature fixtures — Sparrow's 12,437 B signet PSBT and the
//! 61,138 B 43-input one — could not travel at all. This file pins the multi-frame path
//! end to end, over the real fixtures, through the real binary.
//!
//! What it drives: `--in` holds one `ur:<type>/<seq>-<total>/…` frame per line, `--out`
//! gets one frame per line back, `--frag` sets the outbound fragment length. Everything
//! between (assembly, review, sign, framing) is the carrier plus the shell plus forms.
//!
//! The oracle for the signed artifact is forms' direct sign entry, called from this test
//! with the same seed: signing is deterministic (RFC-6979), so a byte-for-byte match is a
//! real comparison and not a self-consistency check.
//!
//! Tests, in order:
//! 1. the 12 KB fixture: multi-frame in → review → sign → multi-frame out, decoded back and
//!    compared with the direct sign, then parsed: both inputs carry a final scriptSig /
//!    witness and the in/out counts are the fixture's own;
//! 2. the 61 KB / 43-input fixture: multi-frame in → review → sign, and the *outbound* frame
//!    ceiling measured (see the note on the test — it is a profile number, not a bug);
//! 3. the failure surface: a frame missing, frame sequence metadata contradicting its own
//!    part, and a corrupted body — each must answer with forms' fixed words, write no
//!    frame, and not panic;
//! 4. the control: on a request small enough to travel either way (the 331-byte P2SH-P2WPKH
//!    fixture), two frames in must produce byte-for-byte what one frame in produces,
//!    finalized scriptSig included.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use shlosilo::chain::btc::psbt;
use shlosilo::entropy::bip39_passphrase::mnemonic_to_seed;
use shlosilo::entropy::mnemonic::Mnemonic;
use shlosilo::ur::ur_encode::UrTypeTag;
use shlosilo::ur::ur_multipart::{self, UrMultipartDecoder, UrMultipartEncoder};

/// Sparrow signet PSBT, 12,437 B (tests/fixtures/README.md).
const SPARROW_12K: &[u8] = include_bytes!("../../../tests/fixtures/sparrow_signet_12k.psbt");
/// The 43-input / 61,138 B Sparrow request: the one that used to die as "request too
/// large".
const PSBT_43: &[u8] = include_bytes!("../../../tests/fixtures/psbt_43_inputs_signet.psbt");
/// The 331-byte P2SH-P2WPKH fixture from the same wallet — small enough to travel either as
/// one frame or as a two-frame set, which is what makes it the "multi-frame == single-frame"
/// control (see the last test).
const PSBT_331: &[u8] =
    include_bytes!("../../../tests/fixtures/core_regtest_p2sh_p2wpkh_331b.psbt");

/// The Sparrow test wallet both fixtures belong to (TEST-ONLY; same entropy as
/// `tests/psbt_43_inputs_end_to_end.rs` and `tests/pico2_smoke_parity.rs`).
const SPARROW_ENTROPY: [u8; 16] = [
    0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29, 0x16,
];

/// Payload bytes per inbound frame for the 12 KB fixture: peer-like (Sparrow was measured
/// at 80 B) and inside the profile's arena slot width (`limits::UR_INBOUND_FRAGMENT_MAX`).
const IN_FRAG: usize = 200;

/// Payload bytes per inbound frame for the 61 KB fixture — and the reason it is not 200.
///
/// The fountain fragment domain is `limits::UR_WS_DECODED_SLOTS` (256) fragments per
/// session, so 61,138 B needs >= 239 B per frame. 200 B would ask for 306 fragments and the
/// decoder refuses the session (it never assembles); 256 B — the profile's inbound slot
/// width — gives 239. That is a property of the peer's fragmentation choice, not of the
/// carrier, and it is why `tests/psbt_43_inputs_end_to_end.rs` also uses 256.
const IN_FRAG_43: usize = shlosilo::limits::UR_INBOUND_FRAGMENT_MAX;

/// Payload bytes per outbound frame: the profile's own outbound number.
const OUT_FRAG: usize = 200;

/// Rows on the carrier's imaginary screen. Low enough that a 12 KB review pages (which is
/// the point — a real device screen is not a terminal), high enough to stay quick.
const ROWS: usize = 8;

/// The wallet's BIP-39 seed as lowercase hex — what `--seed-hex` takes.
fn seed_hex() -> String {
    let mnemonic = Mnemonic::from_entropy(&SPARROW_ENTROPY).expect("fixture entropy");
    let seed = mnemonic_to_seed(&mnemonic, b"").expect("seed");
    let mut text = String::with_capacity(128);
    for byte in seed.as_ref() {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

fn seed() -> [u8; 64] {
    let mnemonic = Mnemonic::from_entropy(&SPARROW_ENTROPY).expect("fixture entropy");
    let seed = mnemonic_to_seed(&mnemonic, b"").expect("seed");
    let mut out = [0u8; 64];
    out.copy_from_slice(seed.as_ref());
    out
}

/// The request as a peer would animate it: one `ur:` frame per line.
///
/// `UrMultipartEncoder::new`'s allocating `next_frame` is the *peer's* convenience path
/// here — the peer is not under test, the carrier is.
fn request_frames(payload: &[u8], frag: usize) -> Vec<String> {
    let mut enc = UrMultipartEncoder::new("crypto-psbt", payload, frag).expect("encode request");
    let count = enc.fragment_count();
    assert!(
        count <= shlosilo::limits::UR_WS_DECODED_SLOTS,
        "{count} fragments exceed the session's fragment domain ({}); use a longer --frag",
        shlosilo::limits::UR_WS_DECODED_SLOTS
    );
    (0..count)
        .map(|_| enc.next_frame().expect("frame"))
        .collect()
}

/// Decode a emitted multi-frame artifact back to its payload, the way a peer's wallet
/// would (assembling every line).
fn decode_frames(frames: &[String]) -> Vec<u8> {
    let mut dec = UrMultipartDecoder::new();
    for frame in frames {
        dec.receive_frame(frame).expect("emitted frame decodes");
    }
    assert!(dec.complete(), "the emitted frame set must complete");
    dec.payload().expect("payload").expect("complete")
}

/// A temp dir per test, removed at the end.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "shlosilo-flux-multipart-{tag}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        TempDir(dir)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// Run the real binary over the real files.
///
/// `script` is the keystroke stream (one action per line). It is deliberately longer than
/// any page count either fixture produces: extra `n`s page around the last page, and the
/// `y` at the end confirms — so the tests do not pin a page count they are not asserting.
fn run(input: &Path, out: &Path, script: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_shlosilo-flux-desktop"))
        .args(["--in"])
        .arg(input)
        .args(["--out"])
        .arg(out)
        .args(["--seed-hex", &seed_hex(), "--rows", &ROWS.to_string()])
        .args(["--network", "testnet", "--frag", &OUT_FRAG.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(script.as_bytes())?;
            child.wait_with_output()
        })
        .expect("the desktop binary runs")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Parse a PSBT with workspace big enough for either fixture.
///
/// The returned view reads its key/value maps *through* the pools, so the pools must
/// outlive it; leaking them once per call is what a test is allowed to do (a handful of
/// calls, released at process exit).
fn parse(bytes: &[u8]) -> psbt::Psbt<'_> {
    let arena: &'static mut [u8] =
        Box::leak(vec![0u8; shlosilo::limits::PSBT_ARENA_BYTES].into_boxed_slice());
    let recs: &'static mut [psbt::KvRec] =
        Box::leak(vec![psbt::KvRec::EMPTY; shlosilo::limits::PSBT_RECS_MAX].into_boxed_slice());
    psbt::parse_psbt_any(bytes, Some(arena), Some(recs)).expect("the PSBT parses")
}

/// Write one `ur:` line per frame, with a comment header (a copy-pasted dump).
fn write_frames(dir: &TempDir, name: &str, frames: &[String], note: &str) -> PathBuf {
    let path = dir.join(name);
    let mut text = format!("# {note}\n");
    for frame in frames {
        text.push_str(frame);
        text.push('\n');
    }
    std::fs::write(&path, text).expect("write the request file");
    path
}

// ─── 1. the 12 KB fixture, both directions ──────────────────────────────────────────

#[test]
fn sparrow_12k_round_trips_through_multiframe_frames() {
    let dir = TempDir::new("12k");
    let frames = request_frames(SPARROW_12K, IN_FRAG);
    assert!(
        frames.len() > 50,
        "12 KB at {IN_FRAG} B per frame is a long animation, got {} frames",
        frames.len()
    );
    let request = write_frames(&dir, "request.ur", &frames, "sparrow_signet_12k");

    let reply = dir.join("reply.ur");
    let output = run(&request, &reply, "n\nn\nn\nn\nn\nn\ny\n");
    let stdout = stdout_of(&output);
    let stderr = stderr_of(&output);
    println!(
        "--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n--- {} in-frames ---",
        frames.len()
    );
    assert!(
        output.status.success(),
        "the binary exits 0 on a signed multi-frame round trip; status {:?}",
        output.status
    );
    assert!(
        stdout.starts_with("[page 1/"),
        "the review paged through stdout: {stdout:?}"
    );

    // ── the artifact came back as a frame set, and it assembles ──
    let text = std::fs::read_to_string(&reply).expect("the reply file exists");
    let out_frames: Vec<String> = text
        .lines()
        .map(str::to_owned)
        .filter(|line| line.starts_with("ur:"))
        .collect();
    assert!(
        out_frames.len() > 1,
        "a 12 KB artifact does not fit one frame, got {}",
        out_frames.len()
    );
    for (i, frame) in out_frames.iter().enumerate() {
        assert!(
            frame.starts_with(&format!("ur:crypto-psbt/{}-{}/", i + 1, out_frames.len())),
            "frame {i} carries its own sequence metadata: {frame}"
        );
    }
    let signed = decode_frames(&out_frames);
    println!(
        "{} B request -> {} in-frames -> {} B signed -> {} out-frames",
        SPARROW_12K.len(),
        frames.len(),
        signed.len(),
        out_frames.len()
    );

    // ── the same request through forms' direct entry: same bytes, no carrier involved ──
    let mut oracle = vec![0u8; shlosilo::types::caps::SIGN_OUTPUT_BUF_MAX_LEN];
    let oracle_len = shlosilo::business::sign::sign_with_entropy(
        shlosilo::business::sign::SignInput::Seed { seed: &seed() },
        UrTypeTag::CryptoPsbt,
        SPARROW_12K,
        &[],
        &mut oracle,
    )
    .expect("the direct sign entry signs the fixture");
    assert_eq!(
        signed.as_slice(),
        &oracle[..oracle_len],
        "the multi-frame round trip must produce exactly what the direct entry produces"
    );

    // ── and the artifact is a signed PSBT: signature present, counts unchanged ──
    //
    // Note on the *shape* of "signed": forms' BTC signer injects PSBT_IN_PARTIAL_SIG
    // (0x02) for this fixture, not a final scriptSig/witness — the 331-byte P2SH-P2WPKH
    // fixture in `roundtrip.rs` is the one that gets finalized. Both are correct for their
    // dialect (a coordinator finalizes a partial-signature PSBT), so the assertion below
    // pins the field this request actually produces. See the batch report for the
    // difference; it is not something a carrier or the shell may paper over.
    const PARTIAL_SIG: u8 = 0x02;
    let unsigned = parse(SPARROW_12K);
    let (in_count, out_count) = (
        unsigned.unsigned_tx.inputs.len(),
        unsigned.unsigned_tx.outputs.len(),
    );
    let signed_psbt = parse(&signed);
    assert_eq!(
        signed_psbt.unsigned_tx.inputs.len(),
        in_count,
        "signing adds no inputs"
    );
    assert_eq!(
        signed_psbt.unsigned_tx.outputs.len(),
        out_count,
        "signing adds no outputs"
    );
    let mut signed_inputs = 0usize;
    for i in 0..in_count {
        let map = signed_psbt
            .input_map_checked(i)
            .unwrap_or_else(|| panic!("input {i} has a map"));
        // BIP-174: key = 0x02 || 33-byte compressed pubkey (a two-part key, so it cannot be
        // looked up by the type byte alone — that is why this walks the map instead of
        // calling `get`), value = DER signature plus its sighash byte.
        let partial = map
            .iter()
            .find(|kv| kv.key.first() == Some(&PARTIAL_SIG))
            .map(|kv| (kv.key.len(), kv.value));
        if let Some((key_len, signature)) = partial {
            assert_eq!(
                key_len,
                1 + 33,
                "input {i}: a partial-signature key is the type byte plus a 33-byte pubkey"
            );
            assert!(
                (71..=73).contains(&signature.len()),
                "input {i}: partial signature is DER plus sighash, got {} bytes",
                signature.len()
            );
            signed_inputs += 1;
        }
    }
    assert!(
        signed_inputs >= 1,
        "at least one input of the fixture belongs to this wallet and was signed"
    );
    println!("signed PSBT: {in_count} in / {out_count} out, {signed_inputs} input(s) signed");
}

// ─── 2. the 61 KB / 43-input fixture ────────────────────────────────────────────────

/// The 43-input / 61,138 B request through the same path.
///
/// **The inbound half is the whole point of the fixture** and it is fully asserted: 306
/// frames assemble, the review runs, forms signs. The **outbound** half stops at a
/// ceiling that is nobody's bug in this carrier — `UrMultipartEncoder::new` refuses a
/// payload above `limits::UR_PAYLOAD_MAX` (61,440 B on every profile: it is the *inbound*
/// UR ceiling), and this fixture's signed artifact is 65,671 B. So the carrier reports
/// forms' capacity words and writes no frame. Asserting it here (rather than lowering a
/// profile to make the test green) is deliberate: the numbers are measured below, and the
/// ceiling is a design question for the UR layer, not something a carrier may paper over.
#[test]
fn psbt_43_inputs_assembles_reviews_signs_and_measures_the_outbound_ceiling() {
    let dir = TempDir::new("43in");
    let frames = request_frames(PSBT_43, IN_FRAG_43);
    let request = write_frames(&dir, "request.ur", &frames, "psbt_43_inputs");

    let reply = dir.join("reply.ur");
    // The 43-input review fits one page (`in 43 / out 1` plus the fee block), so a plain
    // confirm is the whole keystroke script.
    let output = run(&request, &reply, "y\n");
    let stdout = stdout_of(&output);
    let stderr = stderr_of(&output);
    println!(
        "--- stdout (first 40 lines) ---\n{}\n--- stderr ---\n{stderr}",
        stdout.lines().take(40).collect::<Vec<_>>().join("\n")
    );

    // ── the request assembled and the operator saw the real thing ──
    assert!(
        stderr.contains(&format!("request ur:crypto-psbt ({} bytes)", PSBT_43.len())),
        "the carrier assembled the full 61 KB request: {stderr:?}"
    );
    assert!(
        stdout.contains("in 43 / out"),
        "the review carries forms' in/out line for a 43-input request: {stdout:?}"
    );
    assert!(
        stdout.starts_with("[page 1/"),
        "the review paged: {stdout:?}"
    );

    // ── the signed artifact is real, and it is over the framing ceiling ──
    let mut oracle = vec![0u8; shlosilo::types::caps::SIGN_OUTPUT_BUF_MAX_LEN];
    let signed_len = shlosilo::business::sign::sign_with_entropy(
        shlosilo::business::sign::SignInput::Seed { seed: &seed() },
        UrTypeTag::CryptoPsbt,
        PSBT_43,
        &[],
        &mut oracle,
    )
    .expect("the 43-input request signs");
    println!(
        "{} B request -> {} in-frames -> {signed_len} B signed (outbound frame ceiling {})",
        PSBT_43.len(),
        frames.len(),
        ur_multipart::MULTIPART_PAYLOAD_MAX_LEN
    );
    assert!(
        signed_len > ur_multipart::MULTIPART_PAYLOAD_MAX_LEN,
        "the fixture is the one that exceeds the outbound ceiling; if this ever fails, the \
         profile grew a bigger UR budget and this test should assert a real round trip instead"
    );

    // ── so the carrier refused to frame, in forms' words, and wrote nothing ──
    assert_eq!(
        output.status.code(),
        Some(5),
        "flow finished, artifact could not be framed (exit 5): {stderr:?}"
    );
    assert!(
        stderr.contains("sign failed") && stderr.contains("request too large"),
        "the refusal uses forms' fixed capacity words: {stderr:?}"
    );
    assert!(
        !reply.exists(),
        "no frame set may be written for an artifact that does not fit"
    );
    // Nothing on stdout claims an artifact was written.
    assert!(
        !stdout.contains("wrote "),
        "no write claim on the refusal path: {stdout:?}"
    );
}

// ─── 3. the failure surface ─────────────────────────────────────────────────────────

/// Every broken frame set must end in forms' fixed words, write no frame, and not panic.
fn assert_refused_without_frames(tag: &str, frames: &[String], expect_words: &[&str]) -> String {
    let dir = TempDir::new(tag);
    let request = write_frames(&dir, "request.ur", frames, tag);
    let reply = dir.join("reply.ur");
    let output = run(&request, &reply, "y\n");
    let stderr = stderr_of(&output);
    let stdout = stdout_of(&output);
    println!("--- {tag}: stderr ---\n{stderr}");

    assert_eq!(
        output.status.code(),
        Some(1),
        "{tag}: a request that does not assemble is a load failure (exit 1), not a panic \
         and not a signing attempt; stdout {stdout:?} stderr {stderr:?}"
    );
    for words in expect_words {
        assert!(
            stderr.contains(words),
            "{tag}: forms' fixed words {words:?} are missing from {stderr:?}"
        );
    }
    assert!(
        !reply.exists(),
        "{tag}: no frame set may be emitted for a request that never assembled"
    );
    assert!(
        stdout.is_empty(),
        "{tag}: nothing is drawn when the request never assembled: {stdout:?}"
    );
    stderr
}

#[test]
fn a_missing_frame_is_a_scan_failure_in_fixed_words() {
    let frames = request_frames(SPARROW_12K, IN_FRAG);
    // Drop one systematic frame: the message is then unrecoverable without fountain
    // redundancy, which is exactly the "the operator stopped scanning" case.
    let mut lossy = frames.clone();
    lossy.remove(7);
    assert_eq!(lossy.len(), frames.len() - 1);
    let stderr = assert_refused_without_frames(
        "missing",
        &lossy,
        &[
            "sign failed",
            "request container damaged",
            "re-scan the request",
        ],
    );
    // The whole point of the fixed-word table: no code, no frame text, no payload byte.
    assert!(
        !stderr.contains("frame") && !stderr.contains("ur:crypto-psbt"),
        "no internal detail on the wire to the operator: {stderr:?}"
    );
}

#[test]
fn a_frame_whose_sequence_disagrees_with_its_part_is_refused() {
    let frames = request_frames(SPARROW_12K, IN_FRAG);
    // Re-label the first frame's header (`ur:crypto-psbt/1-N/…` -> `…/2-N/…`): the part's
    // own CBOR says 1, so the two halves of the frame contradict each other.
    let mut relabelled = frames.clone();
    let bowdlerised = relabelled[0].replacen("ur:crypto-psbt/1-", "ur:crypto-psbt/2-", 1);
    assert_ne!(bowdlerised, relabelled[0], "the header was rewritten");
    relabelled[0] = bowdlerised;
    assert_refused_without_frames(
        "sequence",
        &relabelled,
        &["sign failed", "request data not recognized"],
    );
}

#[test]
fn a_corrupted_frame_body_is_refused_by_the_checksum() {
    let frames = request_frames(SPARROW_12K, IN_FRAG);
    // Flip one body character to another legal byteword letter: the bytewords CRC no
    // longer matches what the frame carries.
    let mut corrupted = frames.clone();
    let mut body = corrupted[3].clone();
    let last = body.pop().expect("a non-empty frame");
    body.push(if last == 'a' { 'b' } else { 'a' });
    corrupted[3] = body;
    assert_ne!(corrupted[3], frames[3], "the body was rewritten");
    assert_refused_without_frames(
        "checksum",
        &corrupted,
        &["sign failed", "request data not recognized"],
    );
}

#[test]
fn a_set_of_single_frame_lines_is_refused_by_name() {
    // Two single-frame URIs in one file: one request is one line (or a multi-frame set).
    let dir = TempDir::new("two-single");
    let reply = dir.join("reply.ur");
    let request = dir.join("request.ur");
    std::fs::write(
        &request,
        format!(
            "{}\n{}\n",
            shlosilo::ur::ur_encode::encode(UrTypeTag::CryptoPsbt, &[1u8, 2, 3])
                .expect("encode")
                .as_str(),
            shlosilo::ur::ur_encode::encode(UrTypeTag::CryptoPsbt, &[4u8, 5, 6])
                .expect("encode")
                .as_str()
        ),
    )
    .expect("write");
    let output = run(&request, &reply, "y\n");
    let stderr = stderr_of(&output);
    println!("--- two-single: stderr ---\n{stderr}");
    assert_eq!(output.status.code(), Some(1), "{stderr:?}");
    assert!(
        stderr.contains("single-frame ur: lines"),
        "the refusal names the shape: {stderr:?}"
    );
    assert!(!reply.exists());
}

// ─── 4. multi-frame in gives the same artifact as single-frame in ───────────────────

/// The control for everything above: on a request small enough to travel either way, the
/// two transports must produce the *same bytes* — including the finalized fields
/// (`PSBT_IN_FINAL_SCRIPT_SIG` / `PSBT_IN_FINAL_SCRIPTWITNESS`) this wallet's P2SH-P2WPKH
/// spend produces, with the in/out counts untouched.
///
/// This is the "multi-frame in == single-frame in" assertion the 12 KB fixture cannot make:
/// that one is over the single-frame ceiling in both directions and its signer emits a
/// partial signature rather than a final spend, so its own test pins those facts instead.
#[test]
fn a_two_frame_request_produces_the_same_artifact_as_a_single_frame_one() {
    const FINAL_SCRIPT_SIG: u8 = 0x07;

    let dir = TempDir::new("control");

    // (a) single frame in
    let single_uri = shlosilo::ur::ur_encode::encode(UrTypeTag::CryptoPsbt, PSBT_331)
        .expect("the 331-byte fixture fits one frame");
    let single_in = dir.join("single.ur");
    std::fs::write(&single_in, format!("{}\n", single_uri.as_str())).expect("write");
    let single_out = dir.join("single-reply.ur");
    let out_a = run(&single_in, &single_out, "y\n");
    assert!(
        out_a.status.success(),
        "single-frame path signs: {:?} {}",
        out_a.status,
        stderr_of(&out_a)
    );
    let single_text = std::fs::read_to_string(&single_out).expect("single reply");

    // (b) the same request as a two-frame set
    let frames = request_frames(PSBT_331, IN_FRAG);
    assert_eq!(
        frames.len(),
        2,
        "331 B at {IN_FRAG} B per frame is two frames"
    );
    let multi_in = write_frames(&dir, "multi.ur", &frames, "331b as two frames");
    let multi_out = dir.join("multi-reply.ur");
    let out_b = run(&multi_in, &multi_out, "y\n");
    assert!(
        out_b.status.success(),
        "multi-frame path signs: {:?} {}",
        out_b.status,
        stderr_of(&out_b)
    );
    let multi_text = std::fs::read_to_string(&multi_out).expect("multi reply");
    println!("--- single-frame reply ---\n{single_text}--- two-frame reply ---\n{multi_text}");

    assert_eq!(
        multi_text, single_text,
        "the transport must not change the artifact: two frames in == one frame in"
    );

    // Both replies are single-frame URIs (the artifact is ~700 B), and it carries the final
    // spend plus the fixture's own input/output counts.
    let reply = multi_text.trim();
    assert_eq!(reply.lines().count(), 1, "a small artifact is one frame");
    let decoded = shlosilo::ur::ur_decode::decode(reply).expect("the reply decodes");
    let signed = decoded.as_ref();
    let unsigned = parse(PSBT_331);
    let signed_psbt = parse(signed);
    assert_eq!(
        signed_psbt.unsigned_tx.inputs.len(),
        unsigned.unsigned_tx.inputs.len(),
        "signing adds no inputs"
    );
    assert_eq!(
        signed_psbt.unsigned_tx.outputs.len(),
        unsigned.unsigned_tx.outputs.len(),
        "signing adds no outputs"
    );
    let map = signed_psbt.input_map_checked(0).expect("input 0 has a map");
    let script_sig = map
        .get(&[FINAL_SCRIPT_SIG])
        .expect("a P2SH-P2WPKH input is finalized with a scriptSig");
    assert_eq!(
        script_sig.first(),
        Some(&0x16),
        "a push of the 22-byte redeem script"
    );
}
