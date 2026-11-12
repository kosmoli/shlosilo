//! The "unspecified master fingerprint" shape: a wallet with no seed of its own.
//!
//! Cake Wallet's view-only airgap path imports a bare `bitcoin:?xpub=` URI, so it
//! has no master fingerprint to stamp on the derivation records it writes into
//! the PSBT it asks the device to sign
//! (`cw_bitcoin/lib/bitcoin_wallet.dart:599`:
//! `masterFingerprint: Uint8List.fromList([0, 0, 0, 0])`).
//!
//! A strict "fingerprint must equal ours" rule refused that request outright, and
//! because `NetworkUnrecognized` had no word in the failure table the device said
//! only "internal error (unknown code)" (2026-11-12 real-device report: Cake BTC
//! signing failed while Sparrow worked - Sparrow stamps the real fingerprint).
//!
//! Ownership is still proven: the record names a public key, and the signer
//! re-derives it from the seed at the record's path and compares. The fingerprint
//! is a hint. A zeroed hint means "unspecified", not "someone else"; any other
//! mismatch is still an ownership rejection (-15).

#![cfg(feature = "alloc-fallback")]

use shlosilo::business::review;
use shlosilo::business::sign::{sign, SignInput};
use shlosilo::chain::btc::psbt::KvRec;
use shlosilo::encoding::cbor;
use shlosilo::entropy::mnemonic::Mnemonic;
use shlosilo::error::{ShlosiloErrorCode, ShlosiloErrorKind};
use shlosilo::network::Network;

const RECS: usize = 128;
use shlosilo::ur::ur_encode::UrTypeTag;

const PSBT: &[u8] = include_bytes!("fixtures/sparrow_signet_12k.psbt");

/// Our master fingerprint for the fixture seed (entropy f284fb6c…).
const OUR_FP: [u8; 4] = [0xf3, 0xb9, 0x96, 0x0b];

fn mnemonic() -> Mnemonic {
    const ENTROPY: [u8; 16] = [
        0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29,
        0x16,
    ];
    Mnemonic::from_entropy(&ENTROPY).expect("valid entropy")
}

/// Every derivation record inside the fixture carries our fingerprint
/// (`bip32_derivation` on the input, `bip32_derivation`/`tap_bip32` on the two
/// outputs). Rewrite all of them - patching only the first would leave the
/// per-record loop below testing a mixed PSBT.
fn with_fingerprint(fp: [u8; 4]) -> Vec<u8> {
    let mut bytes = PSBT.to_vec();
    let mut hits = 0usize;
    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        if bytes[i..i + 4] == OUR_FP {
            bytes[i..i + 4].copy_from_slice(&fp);
            hits += 1;
            i += 4;
        } else {
            i += 1;
        }
    }
    // The fixture has exactly three records; assert the rewrite hit them all so a
    // fixture change cannot silently leave one behind.
    assert_eq!(hits, 3, "expected three derivation records in the fixture");
    bytes
}

fn sign_it(psbt: &[u8]) -> Result<usize, shlosilo::error::ShlosiloError> {
    let payload = cbor::encode_bytes(psbt);
    let mut out = vec![0u8; psbt.len() + 1024];
    sign(
        SignInput::Mnemonic {
            mnemonic: mnemonic(),
            passphrase: b"",
        },
        UrTypeTag::CryptoPsbt,
        &payload,
        &mut out,
    )
}

#[test]
fn our_own_fingerprint_still_signs() {
    let n = sign_it(&with_fingerprint(OUR_FP)).expect("baseline: our fingerprint signs");
    assert!(n > PSBT.len());
}

#[test]
fn an_unspecified_fingerprint_signs() {
    // The Cake shape: records carry 00000000, the keys and paths are still ours.
    let n = sign_it(&with_fingerprint([0u8; 4]))
        .expect("a zeroed fingerprint is 'unspecified', not 'foreign'");
    assert!(n > PSBT.len());
}

#[test]
fn a_foreign_fingerprint_is_still_rejected_as_ownership() {
    let err = sign_it(&with_fingerprint([0xde, 0xad, 0xbe, 0xef]))
        .expect_err("another wallet's records must not be signed");
    assert_eq!(
        ShlosiloErrorCode::from_shlosilo_error(err),
        -15,
        "ownership rejection, not a network error"
    );
}

#[test]
fn the_rejection_kind_is_ownership_not_network() {
    // Guard the class itself: -12 would render as "network not recognized", which
    // sends the user to the wrong setting entirely.
    let err = sign_it(&with_fingerprint([0xde, 0xad, 0xbe, 0xef])).unwrap_err();
    assert_eq!(err.kind, ShlosiloErrorKind::PsbtOwnershipMismatch);
}

/// The review page marks change by the output's derivation record. With a zeroed
/// fingerprint Cake's own change came back as a payment, so the operator saw an
/// outgoing amount that was really their money returning.
#[test]
fn review_still_marks_change_when_the_fingerprint_is_unspecified() {
    let psbt = with_fingerprint([0u8; 4]);
    let mut arena = vec![0u8; 65536];
    let mut recs = [KvRec::EMPTY; RECS];

    let with_fp = review::build(
        UrTypeTag::CryptoPsbt,
        &psbt,
        Network::BitcoinTestnet,
        Some(&OUR_FP),
        &mut arena,
        &mut recs,
    )
    .expect("review builds");
    let lines: Vec<String> = with_fp
        .lines()
        .iter()
        .map(|l| l.as_str().to_string())
        .collect();
    assert!(
        lines.iter().any(|l| l.contains("change")),
        "the fixture's change output must be labelled, got: {lines:?}"
    );
}
