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
//! The pins below keep both tolerances honest: the Cake dialect signs (with the
//! record pubkey proving the key is ours), and the strict `crypto-psbt` dialect
//! still refuses the same malformed request.
#![cfg(feature = "alloc-fallback")]

use shlosilo::business::sign::{sign, SignInput};
use shlosilo::chain::btc::psbt::parse_psbt;
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
fn cake_legacy_psbt_signs_as_legacy_p2pkh() {
    let payload = real_payload();
    let n = sign_with(UrTypeTag::Psbt, &payload).expect("Cake dialect signs the real request");
    assert_eq!(n, 265, "163 B request + one 0x07 record");

    let mut out = vec![0u8; payload.len() + 1024];
    let n2 = sign(
        SignInput::Mnemonic {
            mnemonic: test_mnemonic(),
            passphrase: b"",
        },
        UrTypeTag::Psbt,
        &cbor::encode_bytes(&payload),
        &mut out,
    )
    .expect("sign");
    assert_eq!(n, n2);

    let psbt = parse_psbt(&out[..n]).expect("signed output parses");
    let map = psbt.input_map(0);
    let script_sig = map
        .iter()
        .find(|kv| kv.key.first() == Some(&0x07u8))
        .map(|kv| kv.value.to_vec())
        .expect("FINAL_SCRIPT_SIG (0x07) must be present");
    assert!(
        map.iter().all(|kv| kv.key.first() != Some(&0x08u8)),
        "a legacy input must not carry FINAL_SCRIPTWITNESS"
    );
    // <push sig><push pubkey>: push length, DER+hash type, then the 33-byte key.
    let sig_len = script_sig[0] as usize;
    assert!((70..=72).contains(&sig_len), "DER+hashtype push length");
    assert_eq!(script_sig[sig_len + 1], 33);
    assert_eq!(script_sig[1], 0x30, "DER sequence tag");
    assert_eq!(script_sig[sig_len], 0x01, "SIGHASH_ALL trailer");
    // The pubkey must be the one Cake named — i.e. our BIP-84 first key.
    assert_eq!(
        &script_sig[sig_len + 2..],
        &[
            0x02, 0x94, 0xb2, 0x10, 0x02, 0x5b, 0x91, 0x94, 0x62, 0x44, 0x76, 0x2f, 0x23, 0x2d,
            0x2d, 0xa9, 0x23, 0xe1, 0x10, 0xc4, 0x90, 0x2e, 0xcb, 0x73, 0x4a, 0xb2, 0x81, 0xf4,
            0xe0, 0x1c, 0x9e, 0xf8, 0x9f
        ][..],
        "scriptSig must carry the pubkey the request names"
    );
}

/// The strict dialect keeps refusing a request that names no prevout: only the
/// wallet's own dialect may trade that check away.
#[test]
fn crypto_psbt_dialect_still_refuses_missing_prevout() {
    let payload = real_payload();
    let err = sign_with(UrTypeTag::CryptoPsbt, &payload).expect_err("must refuse");
    assert_eq!(
        err.kind,
        shlosilo::error::ShlosiloErrorKind::EncodingInvalidFormat
    );
}
