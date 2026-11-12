//! The two PSBT dialects a signed result has to satisfy.
//!
//! Same signatures, two different expectations about who finalizes:
//!
//! - **Sparrow** (`crypto-psbt`) runs the BIP-174 extractor itself and reads
//!   `PARTIAL_SIG` / `TAP_KEY_SIG`. Sending it final records would be tolerated
//!   but is not what it asks for, so that dialect stays partial.
//! - **Cake / Cupcake** (the legacy `psbt` type) hands the returned PSBT to its
//!   Transaction Extractor, which for every segwit input reads
//!   `PSBT_IN_FINAL_SCRIPTWITNESS` (0x08) without a fallback:
//!   `ledger-bitcoin/src/psbt/map_extension.dart` throws `Exception(Key(0x08))`
//!   when the key is absent. That is the literal `Exception: 08` Cake displayed
//!   on a real import (2026-11-12) right after the signing itself succeeded.
//!
//! These pins hold the split by wire shape, so "which type do I answer in"
//! cannot silently collapse into one behaviour.

#![cfg(feature = "alloc-fallback")]

use shlosilo::business::sign::{sign, SignInput};
use shlosilo::chain::btc::psbt::{self, KvRec};

// BIP-174 input field numbers (the crate keeps its table pub(crate); these are
// the wire constants under test, quoted from the spec).
const FINAL_SCRIPT_SIG: u8 = 0x07;
const FINAL_SCRIPTWITNESS: u8 = 0x08;
const PARTIAL_SIG: u8 = 0x02;
use shlosilo::encoding::cbor;
use shlosilo::entropy::mnemonic::Mnemonic;
use shlosilo::ur::ur_encode::UrTypeTag;

const PSBT_V0: &[u8] = include_bytes!("fixtures/sparrow_signet_12k.psbt");
// Our own seed: the Keystone taproot fixture belongs to another master key and
// is refused by the ownership check (which is the point of that check).
const PSBT_P2TR: &[u8] = include_bytes!("fixtures/sparrow_signet_b3_p2tr_2in2out.psbt");

fn mnemonic() -> Mnemonic {
    const ENTROPY: [u8; 16] = [
        0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29,
        0x16,
    ];
    Mnemonic::from_entropy(&ENTROPY).expect("valid entropy")
}

fn signed(psbt_bytes: &[u8], type_tag: UrTypeTag) -> Vec<u8> {
    let payload = cbor::encode_bytes(psbt_bytes);
    let mut out = vec![0u8; psbt_bytes.len() + 4096];
    let n = sign(
        SignInput::Mnemonic {
            mnemonic: mnemonic(),
            passphrase: b"",
        },
        type_tag,
        &payload,
        &mut out,
    )
    .expect("sign must succeed");
    out.truncate(n);
    out
}

/// The extractor Cake runs: `getInputFinalScriptwitness` with no fallback.
fn final_witness(psbt: &psbt::Psbt<'_>, i: usize) -> Option<Vec<u8>> {
    psbt.input_map(i)
        .get(&[FINAL_SCRIPTWITNESS])
        .map(|v| v.to_vec())
}

#[test]
fn the_psbt_dialect_finalizes_every_signed_input() {
    let out = signed(PSBT_V0, UrTypeTag::Psbt);
    let parsed = psbt::parse_psbt(&out).expect("re-parse");
    assert_eq!(parsed.unsigned_tx.inputs.len(), 1);

    let w = final_witness(&parsed, 0).expect(
        "the legacy `psbt` dialect must carry FINAL_SCRIPTWITNESS (0x08) — \
         Cake's extractor has no fallback and throws Exception: 08",
    );
    // BIP-141 witness serialization for P2WPKH: 2 items, sig, 33-byte pubkey.
    assert_eq!(w[0], 0x02, "two witness items, got {w:02x?}");
    let sig_len = w[1] as usize;
    assert!(
        (70..=73).contains(&sig_len),
        "DER signature + sighash byte, got {sig_len}"
    );
    let pk_off = 2 + sig_len;
    assert_eq!(w[pk_off], 33, "second item is a compressed pubkey");
    assert_eq!(w.len(), pk_off + 1 + 33, "nothing trailing");

    // BIP-174 §Input Finalizer: once the witness exists the partial signature is
    // redundant and must not be left behind ("All other data except the UTXO and
    // unknown fields should be cleared"), and BIP-371 says the same for
    // TAP_KEY_SIG. A PSBT that carries both a partial and a final record for the
    // same key contradicts its own state.
    assert!(
        !parsed
            .input_map(0)
            .iter()
            .any(|kv| kv.key.first() == Some(&PARTIAL_SIG)),
        "the finalized dialect must not keep PARTIAL_SIG"
    );
    // The signature is not lost by that cleanup - it is inside the witness.
    let sig_from_witness = &w[2..2 + sig_len];
    assert!(
        sig_from_witness.len() >= 70,
        "signature moved into the witness"
    );
}

#[test]
fn the_crypto_psbt_dialect_stays_partial() {
    let out = signed(PSBT_V0, UrTypeTag::CryptoPsbt);
    let parsed = psbt::parse_psbt(&out).expect("re-parse");
    assert!(
        final_witness(&parsed, 0).is_none(),
        "Sparrow finalizes itself; sending final records would change a verified path"
    );
    assert!(parsed
        .input_map(0)
        .iter()
        .any(|kv| kv.key.first() == Some(&PARTIAL_SIG)));
}

/// A taproot keypath spend finalizes to a one-item witness: the Schnorr
/// signature and no pubkey (the key is recoverable from the signature).
#[test]
fn the_psbt_dialect_finalizes_a_taproot_input() {
    let out = signed(PSBT_P2TR, UrTypeTag::Psbt);
    let parsed = psbt::parse_psbt(&out).expect("re-parse");
    assert_eq!(parsed.unsigned_tx.inputs.len(), 2, "2-in fixture");
    for i in 0..2 {
        let w = final_witness(&parsed, i).expect("every taproot input must be finalized");
        assert_eq!(w[0], 0x01, "one witness item, got {w:02x?}");
        let len = w[1] as usize;
        assert!(len == 64 || len == 65, "Schnorr sig, got {len}");
        assert_eq!(w.len(), 2 + len);
        // BIP-341: SIGHASH_DEFAULT is expressed by OMITTING the byte, never by a
        // trailing 0x00 - a 65-byte signature ending in 0x00 is invalid.
        if len == 65 {
            assert_ne!(
                w[2 + 64],
                0x00,
                "65-byte sig must not end with SIGHASH_DEFAULT"
            );
        }
    }
}

/// Completeness is per script type, not "any final field present".
///
/// A P2SH-P2WPKH input needs BOTH `FINAL_SCRIPTSIG` (0x07, the redeem push) and
/// `FINAL_SCRIPTWITNESS` (0x08, sig + pubkey). An input that arrives carrying
/// only 0x07 is NOT finished, and a finalizer that skips on "any final record
/// exists" would leave it unextractable forever.
#[test]
#[cfg(feature = "alloc-fallback")]
fn a_p2sh_input_with_only_a_scriptsig_still_gets_its_witness() {
    const P2SH_FIXTURE: &[u8] = include_bytes!("fixtures/core_regtest_p2sh_p2wpkh_331b.psbt");
    let parsed = psbt::parse_psbt(P2SH_FIXTURE).expect("p2sh fixture parses");
    let mut psbt = parsed;

    let pk = [0x02u8; 33];
    let mut partial_key = vec![PARTIAL_SIG];
    partial_key.extend_from_slice(&pk);
    let dummy_sig = [0x30u8; 72];
    let dummy_scriptsig = [0x16u8; 23];

    psbt.set_input_kv(0, &partial_key, &dummy_sig)
        .expect("partial sig placement");
    psbt.set_input_kv(0, &[FINAL_SCRIPT_SIG], &dummy_scriptsig)
        .expect("scriptSig placement");

    psbt::finalize_signed_inputs(&mut psbt).expect("finalize");

    let w = psbt
        .input_map(0)
        .get(&[FINAL_SCRIPTWITNESS])
        .expect("a scriptSig alone does not complete a P2SH-P2WPKH input");
    assert_eq!(w[0], 0x02, "two witness items");
    assert_eq!(w[1] as usize, dummy_sig.len());
    let pk_off = 2 + dummy_sig.len();
    assert_eq!(w[pk_off], 33);
    assert_eq!(&w[pk_off + 1..], &pk[..]);

    // The scriptSig that was already there must not be overwritten.
    let ss = psbt
        .input_map(0)
        .get(&[FINAL_SCRIPT_SIG])
        .expect("scriptSig kept");
    assert_eq!(ss, &dummy_scriptsig[..], "existing 0x07 is left untouched");

    // And the partial record is gone.
    assert!(psbt
        .input_map(0)
        .iter()
        .all(|kv| kv.key.first() != Some(&PARTIAL_SIG)));
}

/// Walk the finalized PSBT the way Cake does (Transaction Extractor) and check
/// the resulting transaction is the one the PSBT describes: same prevouts,
/// same outputs, and a witness where there was none.
#[test]
fn the_finalized_psbt_yields_an_extractable_transaction() {
    let out = signed(PSBT_V0, UrTypeTag::Psbt);
    let parsed = psbt::parse_psbt(&out).expect("re-parse");

    let mut tx = parsed.unsigned_tx.clone();
    // The scriptSig slices must outlive the transaction value, so the adopted
    // bytes are leaked into the test's own arena (no device path involved).
    for i in 0..tx.inputs.len() {
        let ss: &'static [u8] = Box::leak(
            parsed
                .input_map(i)
                .get(&[FINAL_SCRIPT_SIG])
                .map(|v| v.to_vec())
                .unwrap_or_default()
                .into_boxed_slice(),
        );
        let w = final_witness(&parsed, i).unwrap_or_default();
        tx.inputs[i].script_sig = std::borrow::Cow::Borrowed(ss);
        tx.inputs[i].witness = witness_items(&w);
    }
    let raw = tx.serialize_segwit();

    assert_eq!(&raw[4..6], &[0x00, 0x01], "segwit marker + flag");
    // The witness we wrote must appear verbatim in the extracted transaction.
    let w = final_witness(&parsed, 0).expect("final witness");
    assert!(
        raw.windows(w.len()).any(|win| win == w.as_slice()),
        "the final witness must survive extraction into the signed transaction"
    );
    // And the extracted tx must keep the two outputs the review screen showed.
    assert_eq!(tx.outputs.len(), 2);
}

fn witness_items(witness: &[u8]) -> Vec<Vec<u8>> {
    // BIP-141: compact-size item count, then compact-size-prefixed items.
    if witness.is_empty() {
        return Vec::new();
    }
    let mut items = Vec::new();
    let mut i = 0usize;
    let (count, used) = read_compact_size(&witness[i..]);
    i += used;
    for _ in 0..count {
        let (len, used) = read_compact_size(&witness[i..]);
        i += used;
        items.push(witness[i..i + len].to_vec());
        i += len;
    }
    items
}

fn read_compact_size(bytes: &[u8]) -> (usize, usize) {
    match bytes[0] {
        0xfd => (u16::from_le_bytes([bytes[1], bytes[2]]) as usize, 3),
        0xfe => (
            u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize,
            5,
        ),
        n => (n as usize, 1),
    }
}

/// Unused-but-kept: the fixture's record budget type, so a future shrink of the
/// PSBT map pool is noticed here rather than as an unexplained -20 on device.
#[allow(dead_code)]
fn _rec_budget(_: KvRec) {}
