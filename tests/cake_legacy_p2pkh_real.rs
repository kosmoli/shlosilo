//! Real Cake `ur:psbt` legacy spend, captured 2026-11-14 as two screen frames.
//!
//! Two things about this request are non-standard and both used to be fatal:
//!
//! 1. **The derivation path is a label, not the key's path.** Cake's watch-only
//!    wallet holds our BIP-84 account key (`bitcoin:?xpub=` export) and builds a
//!    *legacy* address from `m/84'/0'/0'/0/0`, then labels the record
//!    `m/44'/0'/0'/0/0` with fingerprint `00000000`. Binding ownership by
//!    re-deriving the declared path therefore rejected our own key
//!    (`PsbtOwnershipRejected`, the -15 the device showed).
//! 2. **`NON_WITNESS_UTXO` is present but empty.** BIP-174 requires the whole
//!    previous transaction for a non-witness input; Cake ships zero bytes, so
//!    nothing tells us which script we are satisfying.
//!
//! The pins below fix the contract we settled on (2026-11-14): a request with no
//! prevout data is **refused** with a dedicated code, under either dialect. The
//! shape only appears when the wallet could not fetch the previous transaction,
//! which is not a normal flow, so the device does not guess a script template on
//! the wallet's behalf — it says "request input data missing" and stops.
#![cfg(feature = "alloc-fallback")]

use shlosilo::business::sign::{sign, SignInput};
use shlosilo::encoding::cbor;
use shlosilo::entropy::mnemonic::Mnemonic;
use shlosilo::ur::ur_encode::UrTypeTag;
use shlosilo::ur::ur_multipart::UrMultipartDecoder;

const FRAMES: &str = include_str!("fixtures/cake_legacy_frames.txt");

fn test_mnemonic() -> Mnemonic {
    const ENTROPY: [u8; 16] = [
        0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29,
        0x16,
    ];
    Mnemonic::from_entropy(&ENTROPY).expect("valid 16B entropy")
}

/// Reassemble the two photographed frames with the device's own decoder.
fn real_payload() -> Vec<u8> {
    let frames: Vec<&str> = FRAMES
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("ur:"))
        .collect();
    assert_eq!(frames.len(), 2, "capture = 2 fragments");
    let mut dec = UrMultipartDecoder::new();
    for f in &frames {
        dec.receive_frame(f).expect("frame feeds");
    }
    assert!(dec.complete(), "two fragments must complete");
    let mut out = vec![0u8; 16384];
    let n = dec.payload_into(&mut out).unwrap().expect("complete");
    out.truncate(n);
    assert_eq!(n, 163, "the real Cake payload is 163 bytes");
    assert_eq!(&out[..5], b"psbt\xff");
    out
}

fn sign_with(tag: UrTypeTag, payload: &[u8]) -> shlosilo::error::Result<usize> {
    let mut out = vec![0u8; payload.len() + 1024];
    sign(
        SignInput::Mnemonic {
            mnemonic: test_mnemonic(),
            passphrase: b"",
        },
        tag,
        &cbor::encode_bytes(payload),
        &mut out,
    )
}

#[test]
fn cake_legacy_psbt_is_refused_as_missing_input_data() {
    let payload = real_payload();
    for tag in [UrTypeTag::Psbt, UrTypeTag::CryptoPsbt] {
        let err = sign_with(tag, &payload).expect_err("must refuse");
        assert_eq!(
            err.kind,
            shlosilo::error::ShlosiloErrorKind::PrevoutMissing,
            "{tag:?} must refuse with the dedicated code, not a generic one"
        );
        // …and the operator-facing text is the fixed template for that code.
        let code = shlosilo::error::ShlosiloErrorCode::PrevoutMissing as i32;
        let text = shlosilo::failure_text::sign_failure_text(code)
            .to_str()
            .unwrap();
        assert_eq!(
            text,
            "sign failed\nrequest input data missing\nre-create the payment and retry"
        );
    }
}

/// The review refuses the request outright (it can never be signed), so the
/// platform never shows a confirm page for it — the operator gets the failure
/// text "request input data missing" and returns to welcome with `home`.
#[test]
fn cake_legacy_psbt_review_refuses_before_any_confirmation() {
    use shlosilo::chain::btc::psbt::KvRec;
    use shlosilo::network::Network;
    let payload = real_payload();
    let mut arena = vec![0u8; 16 * 1024];
    let mut recs = vec![KvRec::EMPTY; 256];
    let err = shlosilo::business::review::build(
        UrTypeTag::Psbt,
        &payload,
        Network::BitcoinTestnet,
        None,
        &mut arena,
        &mut recs,
    )
    .err()
    .expect("review must refuse");
    assert_eq!(err.kind, shlosilo::error::ShlosiloErrorKind::PrevoutMissing);
}
