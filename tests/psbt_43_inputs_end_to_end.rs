//! The real 43-input / 61 KB Sparrow request, end to end on the host.
//!
//! This began as a reproduction of the device's `request too large` and is now the
//! acceptance pin for it. It walks the same stages the carrier does - multipart decode,
//! then the typed sign entry - over the real fixture the device was given.
//!
//! What it caught on the way is worth keeping in view, because each was an invisible
//! ceiling rather than a protocol bug:
//!
//! - `tx_normalize::PAYLOAD_MAX` was a hard-coded 16,384, so any request above that died
//!   right after the UR layer had reassembled it perfectly (`request too large` on screen).
//! - `SIGN_WS_PSBT_RECS` was a flat 128 records while the byte arena was 64 KiB: the bytes
//!   fit, the record count did not.
//! - `SIGN_WS_PSBT_ARENA` had no room for the fields signing appends to each input map, and
//!   `SIGN_OUTPUT_BUF_MAX_LEN` was 377 B short of the signed artifact (61,138 -> 65,671 B).
//! - `PSBT_TEST_ARENA` / `PSBT_TEST_RECS` - the alloc convenience path used by tests and the
//!   host shell - still froze the old numbers, so a host reproduction measured those instead
//!   of the production caps. That is why the first three fixes looked ineffective.
//!
//! All of them are derived from the platform profile now.
#![cfg(feature = "alloc-fallback")]

const REAL_PSBT: &[u8] = include_bytes!("fixtures/psbt_43_inputs_signet.psbt");

/// The Sparrow test wallet that produced the fixture (same entropy as
/// `pico2_smoke_parity`), so ownership binding passes and a refusal can only be a
/// capacity one.
const ENTROPY: [u8; 16] = [
    0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29, 0x16,
];

#[test]
fn the_real_43_input_request_decodes_and_signs() {
    // Stage 1: decode the multipart stream at a peer-like fragment length.
    // Stay inside the device's inbound fragment ceiling; the exact value is a platform
    // profile number now, and the real peer (Sparrow) was measured at 80 B.
    let frag = core::cmp::min(400, shlosilo::limits::UR_INBOUND_FRAGMENT_MAX);
    let mut enc =
        shlosilo::ur::ur_multipart::UrMultipartEncoder::new("crypto-psbt", REAL_PSBT, frag)
            .expect("encode");
    let n = enc.fragment_count();
    assert!(
        n <= shlosilo::limits::UR_SOURCE_FRAGMENTS_MAX,
        "{n} fragments exceed the profile's source-fragment ceiling"
    );
    let frames: Vec<String> = (0..n).map(|_| enc.next_frame().expect("frame")).collect();

    let mut dec = shlosilo::ur::ur_multipart::UrMultipartDecoder::new();
    for (i, f) in frames.iter().enumerate() {
        dec.receive_frame(f)
            .unwrap_or_else(|e| panic!("decode refused at frame {i}/{n}: {:?}", e.kind));
    }
    assert!(dec.complete(), "decode must complete after {n} frames");
    let payload = dec.payload().expect("payload").expect("complete");
    assert_eq!(payload.len(), REAL_PSBT.len(), "reassembled payload size");
    assert_eq!(dec.ur_type(), Some("crypto-psbt"));

    // Stage 2: sign - the stage the device used to refuse.
    let mnemonic = shlosilo::entropy::mnemonic::Mnemonic::from_entropy(&ENTROPY)
        .expect("mnemonic from test entropy");
    let input = shlosilo::business::sign::SignInput::Mnemonic {
        mnemonic,
        passphrase: b"",
    };
    let mut out = std::vec![0u8; shlosilo::types::caps::SIGN_OUTPUT_BUF_MAX_LEN];
    let signed = shlosilo::business::sign::sign_with_entropy(
        input,
        shlosilo::ur::ur_encode::UrTypeTag::CryptoPsbt,
        &payload,
        &[],
        &mut out,
    )
    .unwrap_or_else(|e| panic!("sign refused: {:?} ctx={:?}", e.kind, e.context));

    assert!(
        signed > payload.len(),
        "the signed artifact carries the request plus signatures"
    );
    assert!(
        signed <= shlosilo::types::caps::SIGN_OUTPUT_BUF_MAX_LEN,
        "signed size {signed} exceeds the output cap"
    );
    println!(
        "OK: {} B request -> {n} fragments -> {signed} B signed (cap {})",
        REAL_PSBT.len(),
        shlosilo::types::caps::SIGN_OUTPUT_BUF_MAX_LEN
    );
}
