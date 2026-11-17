//! Reproduce the device's `request too large` on the real 43-input request, on the host.
//!
//! The device reports BufferTooSmall (-20) for this request before any QR is emitted, so the
//! failing call is somewhere in decode -> review -> sign. This walks the same three calls in
//! the same order the carrier makes them and prints which one refuses, so the fix targets a
//! measured stage instead of a guess.
#![cfg(feature = "alloc-fallback")]

const REAL_PSBT: &[u8] = include_bytes!("fixtures/psbt_43_inputs_signet.psbt");
/// Same 128-bit test entropy the Sparrow parity fixture uses (this wallet owns the
/// fixture's 43 UTXOs, so ownership binding passes and the only possible refusal is a
/// capacity one).
const ENTROPY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

#[test]
fn which_stage_refuses_the_real_request() {
    let passphrase: &[u8] = b"";

    // Stage 1: decode the multipart stream at a peer-like fragment length.
    let enc = shlosilo::ur::ur_multipart::UrMultipartEncoder::new("crypto-psbt", REAL_PSBT, 400)
        .expect("encode at 400 B");
    let n = enc.fragment_count();
    let frames: Vec<String> = {
        let mut e =
            shlosilo::ur::ur_multipart::UrMultipartEncoder::new("crypto-psbt", REAL_PSBT, 400)
                .expect("encoder");
        (0..n).map(|_| e.next_frame().expect("frame")).collect()
    };
    println!("payload {} B -> {n} fragments", REAL_PSBT.len());

    let mut dec = shlosilo::ur::ur_multipart::UrMultipartDecoder::new();
    let mut decode_err = None;
    for (i, f) in frames.iter().enumerate() {
        match dec.receive_frame(f) {
            Ok(_) => {}
            Err(e) => {
                decode_err = Some((i, e.kind));
                break;
            }
        }
    }
    match decode_err {
        Some((i, kind)) => panic!("DECODE refused at frame {i}/{n}: {kind:?}"),
        None => assert!(dec.complete(), "decode did not complete after {n} frames"),
    }
    let payload = dec.payload().expect("payload ok").expect("complete");
    println!("decode ok: {} B, type {:?}", payload.len(), dec.ur_type());

    println!(
        "caps: maps={} recs={} arena={} bt_in={} bt_out={}",
        shlosilo::limits::PSBT_MAPS_MAX,
        shlosilo::types::caps::SIGN_WS_PSBT_RECS,
        shlosilo::types::caps::SIGN_WS_PSBT_ARENA,
        shlosilo::limits::BT_TX_INPUTS_MAX,
        shlosilo::limits::BT_TX_OUTPUTS_MAX,
    );

    // Stage 2: sign (what the carrier calls after review).
    let mnemonic = shlosilo::entropy::mnemonic::Mnemonic::from_entropy(&ENTROPY)
        .expect("mnemonic from test entropy");
    let input = shlosilo::business::sign::SignInput::Mnemonic {
        mnemonic,
        passphrase,
    };
    let mut out = std::vec![0u8; 128 * 1024];
    let signed = shlosilo::business::sign::sign_with_entropy(
        input,
        shlosilo::ur::ur_encode::UrTypeTag::CryptoPsbt,
        &payload,
        &[],
        &mut out,
    );
    match signed {
        Ok(n) => panic!(
            "the remaining wall closed: signing now succeeds ({n} B out) - update this pin              and the 43-input acceptance record instead of leaving it green"
        ),
        Err(e) => {
            // State pin (2026-11-16): decode is clean, the sign stage still refuses. Two
            // caps were found and derived from the profile on the way here (the 16 KiB
            // `tx_normalize::PAYLOAD_MAX` and the flat 128 PSBT record ceiling); at least
            // one more sits inside the BTC sign path. When it is found, this assertion is
            // the signal to record the acceptance, not a nuisance to delete.
            println!("SIGN still refused: {:?}", e.kind);
            assert_eq!(
                e.kind,
                shlosilo::error::ShlosiloErrorKind::BufferTooSmall,
                "the refusal kind changed - re-diagnose before trusting the chain"
            );
        }
    }
}
