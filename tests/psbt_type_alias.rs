//! `psbt` vs `crypto-psbt`: the second name for a BTC PSBT (S2 / B-6 / gap G11).
//!
//! ## Why
//!
//! BC-UR has two names in the wild for a PSBT byte item: the registry name
//! `crypto-psbt` (what Sparrow speaks and BCR-2020-006 defines) and the short
//! name `psbt`, which is what the Cake family uses on the wire
//! (`~/codebases/cupcake/lib/coins/bitcoin/wallet.dart`: it matches
//! `case 'psbt' || ''` and emits `UR("psbt", cborEncoder.getBytes())`).
//! A device that only knows `crypto-psbt` cannot answer that family at all.
//!
//! ## Contract pinned here
//!
//! 1. The name is a **bijection**: `psbt` parses to its own tag and that tag
//!    prints back as `psbt`, so the reply carries the same name the request used
//!    (no silent re-typing of the response).
//! 2. Both names normalize to the BTC chain and sign through the same path.
//! 3. The signing result is **byte-identical** for the two names: an alias must
//!    not change what is signed.
//! 4. The firmware's type table knows the alias in all four places that decide
//!    what a scanned type means (output name, sign whitelist, review gate,
//!    operator-facing text). Those live in C, so the last pin is a source scan -
//!    a behavioural pin needs the device.

use sha2::{Digest, Sha256};
use shlosilo::business::sign::{carve_sign_ws, sign_with_entropy_ws, SignInput};
use shlosilo::tx::tx_normalize;
use shlosilo::types::chain_kind::ChainKind;
use shlosilo::ur::ur_encode::{self, UrTypeTag};

/// A real Sparrow signet PSBT (single P2WPKH input) keyed to the project seed.
/// 12 KB, so it only travels as a multi-frame UR - used for the signing pins.
const PSBT: &[u8] = include_bytes!("fixtures/sparrow_signet_12k.psbt");

/// A 288-byte keystone P2TR PSBT: small enough for a single-frame UR, which is
/// what lets the string-level decode pin below build a real `ur:psbt/...` URI.
const SMALL_PSBT: &[u8] = include_bytes!("fixtures/keystone_p2tr_keypath_288b.psbt");

const SEED_HEX: &str = "d25e113e8f7be9936d67de81eb4d4bb94788b48b39f815f48f79dc029feddc918d07f5ac8ffbfb86514c4a0824ad187c5f6fc8b7c43b29356380aaeabc0267dc";

const PRODUCT_TASK_C: &str = include_str!("../flux/forgebox/src/tasks/product_task.c");

fn hex_decode(s: &str) -> Vec<u8> {
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    clean
        .chunks(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16).unwrap();
            let lo = (p[1] as char).to_digit(16).unwrap();
            ((hi << 4) | lo) as u8
        })
        .collect()
}

fn seed() -> [u8; 64] {
    let v = hex_decode(SEED_HEX);
    let mut out = [0u8; 64];
    out.copy_from_slice(&v);
    out
}

/// Sign `payload` through the device entry with a real workspace carve.
fn device_sign(tag: UrTypeTag, payload: &[u8]) -> Vec<u8> {
    let ws_need = shlosilo::business::sign::SignWsLayout::compute().total;
    let mut ws_bytes = vec![0u8; ws_need];
    let mut ws = carve_sign_ws(&mut ws_bytes).expect("workspace carve");
    let s = seed();
    let mut out = vec![0u8; payload.len() + 1024];
    let n = sign_with_entropy_ws(
        SignInput::Seed { seed: &s },
        tag,
        payload,
        &[],
        &[],
        Some(&mut ws),
        &mut out,
    )
    .expect("signing must succeed under both names");
    out.truncate(n);
    out
}

/// Build the `psbt`-named URI for the same payload by re-typing an encoded one:
/// bytewords payload untouched, only the type token differs.
fn psbt_uri(payload: &[u8]) -> String {
    let encoded = ur_encode::encode(UrTypeTag::CryptoPsbt, payload).expect("encode");
    let uri = encoded.as_str().to_string();
    assert!(
        uri.starts_with("ur:crypto-psbt/"),
        "expected a crypto-psbt UR, got {}",
        &uri[..24.min(uri.len())]
    );
    uri.replacen("ur:crypto-psbt/", "ur:psbt/", 1)
}

// ---------------------------------------------------------------------------
// pins
// ---------------------------------------------------------------------------

/// 1. The name is a bijection and case-insensitive (QR alphanumeric has no
///    lowercase, so an encoder may upper-case the whole UR).
#[test]
fn psbt_name_round_trips_and_stays_distinct() {
    assert_eq!(UrTypeTag::from_name("psbt"), UrTypeTag::Psbt);
    assert_eq!(UrTypeTag::from_name("PSBT"), UrTypeTag::Psbt);
    assert_eq!(UrTypeTag::Psbt.type_name(), "psbt");
    // no regression: the registry name keeps its own tag
    assert_eq!(UrTypeTag::from_name("crypto-psbt"), UrTypeTag::CryptoPsbt);
    assert_eq!(UrTypeTag::CryptoPsbt.type_name(), "crypto-psbt");
    // an unknown name must not fall into either
    assert_eq!(UrTypeTag::from_name("psbtx"), UrTypeTag::Unknown);
}

/// 2a. The string decoder accepts `ur:psbt/...` and yields the raw PSBT bytes.
#[test]
fn psbt_named_ur_decodes() {
    let uri = psbt_uri(SMALL_PSBT);
    let decoded = shlosilo::ur::ur_decode::decode(&uri).expect("ur:psbt must decode");
    assert_eq!(decoded.type_tag(), UrTypeTag::Psbt);
    assert_eq!(
        decoded.as_ref(),
        SMALL_PSBT,
        "payload must be the PSBT itself"
    );
    // and the encoder prints the alias name back
    let re = ur_encode::encode(UrTypeTag::Psbt, SMALL_PSBT).expect("encode");
    assert!(re.as_str().starts_with("ur:psbt/"));
}

/// The multipart path is what the device actually uses for a 12 KB PSBT: the C
/// side hands the reassembled (type, payload) pair to the typed sign entry, so
/// the name has to survive that entry too. The entry rejects unknown type names
/// before anything else, so the discriminating fact is that `psbt` follows
/// exactly the same path as `crypto-psbt`.
#[test]
fn typed_sign_entry_treats_both_names_alike() {
    use core::ffi::c_uint;
    use std::ffi::CString;

    fn call(tag: &str) -> i32 {
        let tname = CString::new(tag).unwrap();
        let idx: Vec<u16> = vec![0u16; 12]; // deliberately an invalid mnemonic
        let passphrase: [u8; 0] = [];
        let mut out = vec![0u8; PSBT.len() + 1024];
        let mut actual: c_uint = 0;
        let mut ws = vec![0u8; shlosilo::ffi::c_abi::shlosilo_sign_ws_len() as usize];
        shlosilo::ffi::c_abi::r3::shlosilo_sign_typed_ffi(
            tname.as_ptr(),
            PSBT.as_ptr(),
            PSBT.len() as c_uint,
            idx.as_ptr(),
            12,
            passphrase.as_ptr(),
            0,
            0,
            core::ptr::null(),
            0,
            out.as_mut_ptr(),
            out.len() as c_uint,
            &mut actual,
            ws.as_mut_ptr(),
            ws.len() as c_uint,
        )
    }

    let rc_unknown = call("definitely-not-a-ur-type");
    let rc_crypto = call("crypto-psbt");
    let rc_psbt = call("psbt");

    assert_ne!(
        rc_unknown, rc_crypto,
        "an unknown type name must fail differently from a known one"
    );
    assert_eq!(
        rc_psbt, rc_crypto,
        "the short name must reach exactly the same code path as the registry name \
         (rc_unknown={rc_unknown} rc_crypto={rc_crypto} rc_psbt={rc_psbt})"
    );
}

/// 2b. Both names normalize to the BTC chain.
#[test]
fn both_names_normalize_to_btc() {
    for tag in [UrTypeTag::CryptoPsbt, UrTypeTag::Psbt] {
        let t = tx_normalize::to_template(tag, PSBT).expect("template");
        assert_eq!(t.chain_kind, ChainKind::Btc);
        assert_eq!(t.payload, PSBT);
    }
}

/// 3. The alias changes the DIALECT, not the signature.
///
/// Until 2026-11-12 this asserted byte equality. It was wrong: the two names
/// mark two different peers, and those peers disagree about who finalizes.
/// Sparrow (`crypto-psbt`) runs the BIP-174 extractor itself and wants the
/// partial records; Cake/Cupcake (`psbt`) hands the result straight to its own
/// extractor, which reads `PSBT_IN_FINAL_SCRIPTWITNESS` with no fallback and
/// throws `Exception: 08` when it is missing (real device, 2026-11-12). So the
/// short name now finalizes and the registry name does not.
///
/// What must still hold: the same request signed under either name produces the
/// same signature, the same unsigned transaction, and outputs that differ only
/// by the final records.
#[test]
fn both_names_sign_the_same_request_in_two_dialects() {
    let a = device_sign(UrTypeTag::CryptoPsbt, PSBT);
    let b = device_sign(UrTypeTag::Psbt, PSBT);
    assert!(a.len() > PSBT.len(), "signed PSBT must carry the signature");
    assert!(
        b.len() > a.len(),
        "the finalized dialect is strictly larger ({} vs {})",
        b.len(),
        a.len()
    );
    assert_ne!(
        Sha256::digest(&a),
        Sha256::digest(&b),
        "the dialects must differ on the wire"
    );

    // Structural comparison needs the alloc-face convenience parser; on the
    // device face the size delta is the pin (the finalized dialect strictly adds
    // one final-witness record per input).
    #[cfg(feature = "alloc-fallback")]
    {
        let pa = shlosilo::chain::btc::psbt::parse_psbt(&a).expect("crypto-psbt re-parse");
        let pb = shlosilo::chain::btc::psbt::parse_psbt(&b).expect("psbt re-parse");

        // Same unsigned transaction on both sides — the signature target is identical.
        // Both sides must describe the same transaction: same prevouts, same outputs.
        assert_eq!(pa.unsigned_tx.inputs.len(), pb.unsigned_tx.inputs.len());
        for (x, y) in pa
            .unsigned_tx
            .inputs
            .iter()
            .zip(pb.unsigned_tx.inputs.iter())
        {
            assert_eq!(x.prev_out.txid, y.prev_out.txid);
            assert_eq!(x.prev_out.vout, y.prev_out.vout);
            assert_eq!(x.sequence, y.sequence);
        }
        assert_eq!(pa.unsigned_tx.outputs.len(), pb.unsigned_tx.outputs.len());
        for (x, y) in pa
            .unsigned_tx
            .outputs
            .iter()
            .zip(pb.unsigned_tx.outputs.iter())
        {
            assert_eq!(x.value, y.value);
            assert_eq!(x.script_pubkey, y.script_pubkey);
        }
        // Same ECDSA signature. The partial dialect carries it in 0x02; the
        // finalized one moved it into the witness (and dropped the 0x02 record),
        // so both are read out and compared.
        let sig_of = |p: &shlosilo::chain::btc::psbt::Psbt<'_>| -> Vec<u8> {
            if let Some(kv) = p
                .input_map(0)
                .iter()
                .find(|kv| kv.key.first() == Some(&0x02u8))
            {
                kv.value.to_vec()
            } else {
                let w = p
                    .input_map(0)
                    .get(&[0x08u8])
                    .expect("finalized dialect carries the witness");
                let sig_len = w[1] as usize;
                w[2..2 + sig_len].to_vec()
            }
        };
        assert_eq!(
            sig_of(&pa),
            sig_of(&pb),
            "the ECDSA signature must not depend on the type name"
        );
        // Only the finished one carries the final witness (0x08).
        assert!(
            pa.input_map(0).get(&[0x08u8]).is_none(),
            "crypto-psbt stays partial for Sparrow"
        );
        assert!(
            pb.input_map(0).get(&[0x08u8]).is_some(),
            "psbt carries the final witness for Cake/Cupcake"
        );
    }
    #[cfg(not(feature = "alloc-fallback"))]
    {
        assert!(
            b.len() > a.len(),
            "the finalized dialect adds final records ({} vs {})",
            b.len(),
            a.len()
        );
        assert!(a.starts_with(b"psbt\xff") && b.starts_with(b"psbt\xff"));
    }
}

/// 4. Firmware type table: every place that decides what a scanned type means
///    must know `psbt`. Source scan because those functions live in C; the
///    behavioural check is the device acceptance run.
#[test]
fn firmware_type_table_knows_the_alias() {
    fn body<'a>(src: &'a str, signature: &str) -> &'a str {
        let at = src
            .find(signature)
            .unwrap_or_else(|| panic!("{signature} not found in product_task.c"));
        let mut depth = 0usize;
        let mut started = false;
        for (i, ch) in src[at..].char_indices() {
            match ch {
                '{' => {
                    depth += 1;
                    started = true;
                }
                '}' => {
                    depth -= 1;
                    if started && depth == 0 {
                        return &src[at..at + i];
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced braces after {signature}");
    }

    // (a) output name: a `psbt` request must come back as `psbt`
    let out = body(PRODUCT_TASK_C, "static void sign_out_type_for(");
    assert!(
        out.contains("\"psbt\""),
        "sign_out_type_for must echo the psbt name"
    );

    // (b) sign whitelist: otherwise the request never reaches the signer
    let is_sign = body(PRODUCT_TASK_C, "static int ur_type_is_sign(");
    assert!(
        is_sign.contains("\"psbt\""),
        "ur_type_is_sign must accept psbt"
    );

    // (c) review gate: a BTC PSBT must not skip the operator review
    let gate = body(PRODUCT_TASK_C, "static int review_type_gated(");
    assert!(
        gate.contains("\"psbt\""),
        "review_type_gated must cover psbt"
    );

    // (d) operator-facing text: fixed phrase, never the raw type string
    let display = body(PRODUCT_TASK_C, "static const char *ur_type_display(");
    assert!(
        display.contains("\"psbt\""),
        "ur_type_display must map psbt to a fixed phrase"
    );

    // (e) the signed-UR exit leg keys on the output type by name
    assert!(
        PRODUCT_TASK_C.contains("strcmp(g_sign_out_type, \"psbt\") == 0"),
        "the signed-UR carousel must include the psbt output type"
    );
}
