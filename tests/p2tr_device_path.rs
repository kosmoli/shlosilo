//! P2TR keypath spending on the DEVICE signing path (S2 / B-3 / gap G5).
//!
//! ## Why this file exists
//!
//! `chain/btc/taproot.rs` carried the full BIP-86/341 keypath algorithm but was
//! compiled out of the device face (`#[cfg(any(feature = "alloc-fallback",
//! test))]` in `chain/btc/mod.rs`) and the unified signing entry only dispatched
//! P2WPKH PSBTs. A Taproot wallet (the default in Sparrow and in most 2023+
//! wallets) therefore could not be signed at all. This test drives the very
//! entry the firmware uses (`business::sign::sign_with_entropy_ws`, with a real
//! caller workspace) and is deliberately NOT gated on `alloc-fallback`, so the
//! same file also runs on the `--no-default-features` face.
//!
//! ## Oracle (independent of the implementation under test)
//!
//! - **Fixture**: keystone3-firmware `apps/bitcoin/src/transactions/psbt/wrapped_psbt.rs`
//!   `test_taproot_sign` — a PSBT produced and signed by rust-bitcoin 0.32
//!   (BIP-371 shaped: WITNESS_UTXO + SIGHASH_TYPE + TAP_BIP32_DERIVATION +
//!   TAP_INTERNAL_KEY + TAP_MERKLE_ROOT). Two files are checked in:
//!   the unsigned PSBT and rust-bitcoin's *signed* result (only `0x13` added).
//! - **Sighash**: computed here by hand from the transaction facts (no call into
//!   `chain::btc::taproot`), the same way the existing
//!   `taproot_keystone_cross_validation` recomputes it.
//! - **Signature check**: `k256::schnorr::verify_prehash` against the x-only
//!   witness program taken straight from the fixture's WITNESS_UTXO — neither
//!   our taproot module nor our Schnorr verifier is in that path.
//!
//! ## Fixture facts (asserted to be present in the bytes, so they cannot drift)
//!
//! | field | value |
//! |---|---|
//! | unsigned tx | v2, 1 input, 1 output, nLockTime 0 |
//! | prevout | display `06980ca1…516b4dee3a`:0, nSequence `0xffffffff` |
//! | spent | 6588 sat, spk `5120 22f395…371bd1` (P2TR) |
//! | tx output | 6400 sat, spk `5120 2258f2…a99ce8` (P2TR) |
//! | path | m/86'/1'/0'/0/2, master fingerprint `73c5da0a` |
//! | sighash type | 0x00 (SIGHASH_DEFAULT) |
//! | taproot | internal key `b68df3…6cb296d`, merkle root `c913dc…b2bb0a` |

use sha2::{Digest, Sha256};
use shlosilo::business::sign::{carve_sign_ws, sign_with_entropy_ws, SignInput};
use shlosilo::ur::ur_encode::UrTypeTag;

/// BIP-39 seed of the keystone test suite (the fixture's own seed).
const SEED_HEX: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

/// rust-bitcoin's own signature for this PSBT (SIGHASH_DEFAULT, 64 bytes).
const KEYSTONE_SIG_HEX: &str = "92864dc9e56b6260ecbd54ec16b94bb597a2e6be7cca0de89d75e17921e0e1528cba32dd04217175c237e1835b5db1c8b384401718514f9443dce933c6ba9c87";

const UNSIGNED: &[u8] = include_bytes!("fixtures/keystone_p2tr_keypath_288b.psbt");
const REFERENCE_SIGNED: &[u8] = include_bytes!("fixtures/keystone_p2tr_keypath_signed_golden.psbt");

// ---------------------------------------------------------------------------
// fixture facts (see the table in the module docs)
// ---------------------------------------------------------------------------

/// Prevout txid in the byte order the transaction serializes it (internal order);
/// its display form is `06980ca1…516b4dee3a` reversed.
const PREV_TXID: &str = "3aee4d6b51da574900e56d173041115bd1e1d01d4697a845784cf716a10c9806";
const PREV_VOUT: u32 = 0;
const PREV_SEQUENCE: u32 = 0xffff_ffff;
const SPENT_VALUE: u64 = 6588;
const SPENT_SPK: &str = "512022f3956cc27a6a9b0e0003a0afc113b04f31b95d5cad222a65476e8440371bd1";
const TX_OUT_VALUE: u64 = 6400;
const TX_OUT_SPK: &str = "51202258f2d4637b2ca3fd27614868b33dee1a242b42582d5474f51730005fa99ce8";
const TX_VERSION: u32 = 2;
const TX_LOCKTIME: u32 = 0;

fn hex_decode(s: &str) -> Vec<u8> {
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert_eq!(clean.len() % 2, 0, "hex literal must be even-length");
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

/// The x-only witness program of the spent output (= the taproot output key).
fn spent_output_key() -> [u8; 32] {
    let spk = hex_decode(SPENT_SPK);
    let mut x = [0u8; 32];
    x.copy_from_slice(&spk[2..]);
    x
}

// ---------------------------------------------------------------------------
// independent BIP-341 sighash (no calls into chain::btc::taproot)
// ---------------------------------------------------------------------------

/// BIP-340/341 tagged hash.
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(msg);
    h.finalize().into()
}

/// BIP-341 keypath sighash for the single-input/single-output fixture shape.
fn reference_sighash(hash_type: u8, spent_value: u64, spent_spk: &[u8]) -> [u8; 32] {
    let mut prevouts = Vec::new();
    prevouts.extend_from_slice(&hex_decode(PREV_TXID));
    prevouts.extend_from_slice(&PREV_VOUT.to_le_bytes());
    let sha_prevouts = Sha256::digest(&prevouts);

    let sha_amounts = Sha256::digest(spent_value.to_le_bytes());

    let mut spks = Vec::new();
    spks.push(spent_spk.len() as u8);
    spks.extend_from_slice(spent_spk);
    let sha_scriptpubkeys = Sha256::digest(&spks);

    let sha_sequences = Sha256::digest(PREV_SEQUENCE.to_le_bytes());

    let mut outs = Vec::new();
    outs.extend_from_slice(&TX_OUT_VALUE.to_le_bytes());
    outs.push(hex_decode(TX_OUT_SPK).len() as u8);
    outs.extend_from_slice(&hex_decode(TX_OUT_SPK));
    let sha_outputs = Sha256::digest(&outs);

    let mut sigmsg = Vec::with_capacity(206);
    sigmsg.push(hash_type);
    sigmsg.extend_from_slice(&TX_VERSION.to_le_bytes());
    sigmsg.extend_from_slice(&TX_LOCKTIME.to_le_bytes());
    sigmsg.extend_from_slice(&sha_prevouts);
    sigmsg.extend_from_slice(&sha_amounts);
    sigmsg.extend_from_slice(&sha_scriptpubkeys);
    sigmsg.extend_from_slice(&sha_sequences);
    sigmsg.extend_from_slice(&sha_outputs);
    sigmsg.push(0u8); // spend_type: ext_flag 0, no annex
    sigmsg.extend_from_slice(&0u32.to_le_bytes()); // input_index

    let mut epoch = Vec::with_capacity(1 + sigmsg.len());
    epoch.push(0x00); // BIP-341: epoch byte
    epoch.extend_from_slice(&sigmsg);
    tagged_hash(b"TapSighash", &epoch)
}

/// Independent BIP-340 verification (k256), keyed by an x-only public key.
fn bip340_verify(pk_x: &[u8; 32], msg: &[u8; 32], sig: &[u8]) -> bool {
    let vk = match k256::schnorr::VerifyingKey::from_bytes(pk_x.into()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig_obj = match k256::schnorr::Signature::try_from(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    use k256::schnorr::signature::hazmat::PrehashVerifier;
    vk.verify_prehash(msg, &sig_obj).is_ok()
}

// ---------------------------------------------------------------------------
// the device signing path
// ---------------------------------------------------------------------------

/// Drive `sign_with_entropy_ws` with a real caller workspace — the same entry,
/// the same workspace carve, and the same `SignWs` the firmware uses.
fn device_sign(psbt: &[u8]) -> Result<Vec<u8>, shlosilo::error::ShlosiloError> {
    let ws_need = shlosilo::business::sign::SignWsLayout::compute().total;
    let mut ws_bytes = vec![0u8; ws_need];
    let mut ws = carve_sign_ws(&mut ws_bytes).expect("workspace carve");
    let s = seed();
    let mut out = vec![0u8; psbt.len() + 1024];
    match sign_with_entropy_ws(
        SignInput::Seed { seed: &s },
        UrTypeTag::CryptoPsbt,
        psbt,
        &[],
        &[],
        Some(&mut ws),
        &mut out,
    ) {
        Ok(n) => {
            out.truncate(n);
            Ok(out)
        }
        Err(e) => Err(e),
    }
}

/// Minimal PSBT walk good enough to pull one entry out of input map 0.
/// Deliberately independent of `chain::btc::psbt`.
fn input_map_entry(psbt: &[u8], wanted: u8) -> Option<Vec<u8>> {
    fn varint(b: &[u8], i: usize) -> (usize, usize) {
        let v = b[i] as usize;
        match v {
            0xfd => (u16::from_le_bytes([b[i + 1], b[i + 2]]) as usize, i + 3),
            0xfe => (
                u32::from_le_bytes([b[i + 1], b[i + 2], b[i + 3], b[i + 4]]) as usize,
                i + 5,
            ),
            _ => (v, i + 1),
        }
    }
    assert_eq!(&psbt[..5], b"psbt\xff", "fixture must be a PSBT");
    let mut i = 5;
    // global map
    loop {
        let (klen, ni) = varint(psbt, i);
        i = ni;
        if klen == 0 {
            break;
        }
        i += klen;
        let (vlen, ni) = varint(psbt, i);
        i = ni + vlen;
    }
    // input map 0
    loop {
        let (klen, ni) = varint(psbt, i);
        i = ni;
        if klen == 0 {
            return None;
        }
        let key = &psbt[i..i + klen];
        i += klen;
        let (vlen, ni) = varint(psbt, i);
        i = ni;
        let value = &psbt[i..i + vlen];
        i += vlen;
        // partial-sig style keys carry a payload after the type byte; match the
        // type byte and reject any extra key bytes for the singleton entries.
        if key[0] == wanted && (wanted == 0x16 || key.len() == 1) {
            if wanted == 0x16 && key.len() != 33 {
                continue;
            }
            return Some(value.to_vec());
        }
    }
}

/// Byte-level search used to tamper with exactly one field of the fixture.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("tamper target must exist in the fixture")
}

fn with_patched(psbt: &[u8], needle: &[u8], patch: &[u8]) -> Vec<u8> {
    assert_eq!(needle.len(), patch.len(), "in-place patch keeps the length");
    let at = find_subslice(psbt, needle);
    let mut out = psbt.to_vec();
    out[at..at + patch.len()].copy_from_slice(patch);
    out
}

// ---------------------------------------------------------------------------
// pins
// ---------------------------------------------------------------------------

/// The fixture facts in the module table must really be in the bytes, so the
/// reference sighash above cannot silently drift away from the fixture.
#[test]
fn fixture_carries_the_documented_facts() {
    assert!(find_subslice(UNSIGNED, &hex_decode(PREV_TXID)) > 0);
    assert!(find_subslice(UNSIGNED, &hex_decode(SPENT_SPK)) > 0);
    assert!(find_subslice(UNSIGNED, &hex_decode(TX_OUT_SPK)) > 0);
    assert!(find_subslice(UNSIGNED, &SPENT_VALUE.to_le_bytes()) > 0);
    assert!(find_subslice(UNSIGNED, &TX_OUT_VALUE.to_le_bytes()) > 0);
    // 0x16 TAP_BIP32_DERIVATION, 0x17 TAP_INTERNAL_KEY, 0x18 TAP_MERKLE_ROOT
    assert!(input_map_entry(UNSIGNED, 0x16).is_some());
    assert!(input_map_entry(UNSIGNED, 0x17).is_some());
    assert!(input_map_entry(UNSIGNED, 0x18).is_some());
    assert_eq!(
        input_map_entry(UNSIGNED, 0x13),
        None,
        "unsigned: no sig yet"
    );
}

/// The reference implementation (rust-bitcoin, via keystone) signs this PSBT
/// with TAP_KEY_SIG and nothing else. Our signature must verify against the
/// same hand-rolled sighash, and the reference's own signature must too — that
/// second check is what anchors the hand-rolled sighash to an external truth.
#[test]
fn reference_signature_verifies_against_the_hand_rolled_sighash() {
    let sighash = reference_sighash(0x00, SPENT_VALUE, &hex_decode(SPENT_SPK));
    let sig = hex_decode(KEYSTONE_SIG_HEX);
    assert_eq!(sig.len(), 64, "SIGHASH_DEFAULT carries no suffix byte");
    assert!(
        bip340_verify(&spent_output_key(), &sighash, &sig),
        "rust-bitcoin's signature must verify against the test's own sighash computation"
    );
}

/// B-3 acceptance: the device path signs a P2TR keypath input.
#[test]
fn device_path_signs_p2tr_keypath() {
    let signed = device_sign(UNSIGNED).expect("P2TR keypath input must be signable");
    assert!(signed.len() > UNSIGNED.len(), "signed PSBT must grow");

    let sig = input_map_entry(&signed, 0x13).expect("TAP_KEY_SIG (0x13) must be injected");
    assert_eq!(sig.len(), 64, "SIGHASH_DEFAULT signature is 64 bytes");

    let sighash = reference_sighash(0x00, SPENT_VALUE, &hex_decode(SPENT_SPK));
    assert!(
        bip340_verify(&spent_output_key(), &sighash, &sig),
        "the device's signature must verify against the spent output key"
    );
    // Deterministic case: with no entropy the BIP-340 aux is all zeros, and
    // rust-bitcoin signs the same way — so our signature must be BYTE-IDENTICAL
    // to the reference implementation's. (A stronger pin than "verifies": it
    // means sighash, tweak, parity and nonce derivation all agree.)
    assert_eq!(
        sig,
        hex_decode(KEYSTONE_SIG_HEX),
        "zero-aux Schnorr signing must reproduce rust-bitcoin's signature byte for byte"
    );
}

/// Shape parity with the reference implementation: the signed PSBT carries the
/// same maps as rust-bitcoin's output, with `0x13` added and every other entry
/// byte-identical.
#[test]
fn signed_psbt_shape_matches_the_reference_implementation() {
    let signed = device_sign(UNSIGNED).expect("sign");
    let mut ours = signed.clone();
    let mut theirs = REFERENCE_SIGNED.to_vec();
    // only the signature itself may differ
    let ours_sig = input_map_entry(&signed, 0x13).expect("0x13 present");
    let theirs_sig = input_map_entry(REFERENCE_SIGNED, 0x13).expect("0x13 present");
    assert_eq!(ours_sig.len(), theirs_sig.len());
    let at_ours = find_subslice(&ours, &ours_sig);
    let at_theirs = find_subslice(&theirs, &theirs_sig);
    if at_ours == at_theirs && ours.len() == theirs.len() {
        ours[at_ours..at_ours + ours_sig.len()].fill(0);
        theirs[at_theirs..at_theirs + theirs_sig.len()].fill(0);
        assert_eq!(
            ours, theirs,
            "outside TAP_KEY_SIG the signed PSBT must match rust-bitcoin's byte for byte"
        );
    } else {
        // Entry order inside a PSBT map is not normative; when our insertion
        // point differs, require the same length and every entry byte-equal.
        assert_eq!(ours.len(), theirs.len(), "same total size");
        for ty in [0x01u8, 0x03, 0x16, 0x17, 0x18] {
            assert_eq!(
                input_map_entry(&signed, ty),
                input_map_entry(REFERENCE_SIGNED, ty),
                "entry {ty:#04x} must be unchanged"
            );
        }
    }
}

/// With caller entropy supplying the BIP-340 aux randomness the signature must
/// differ from the deterministic one and still verify — that is the hardening
/// path a device with an entropy source takes.
#[test]
fn caller_entropy_becomes_the_schnorr_aux() {
    let ws_need = shlosilo::business::sign::SignWsLayout::compute().total;
    let mut ws_bytes = vec![0u8; ws_need];
    let mut ws = carve_sign_ws(&mut ws_bytes).unwrap();
    let s = seed();
    let mut out = vec![0u8; UNSIGNED.len() + 1024];
    let entropy = [0x5Au8; 32];
    let n = sign_with_entropy_ws(
        SignInput::Seed { seed: &s },
        UrTypeTag::CryptoPsbt,
        UNSIGNED,
        &[],
        &entropy,
        Some(&mut ws),
        &mut out,
    )
    .expect("sign with entropy");
    let sig = input_map_entry(&out[..n], 0x13).expect("0x13 present");
    assert_ne!(
        sig,
        hex_decode(KEYSTONE_SIG_HEX),
        "aux randomness must change the nonce"
    );
    let sighash = reference_sighash(0x00, SPENT_VALUE, &hex_decode(SPENT_SPK));
    assert!(bip340_verify(&spent_output_key(), &sighash, &sig));
}

/// The spent value is part of the sighash — a signature produced for a
/// different value must not verify. (Guards against a stub that "signs" a
/// payload the fee/amount never enters.)
#[test]
fn signature_binds_the_spent_value() {
    let signed = device_sign(UNSIGNED).expect("sign");
    let sig = input_map_entry(&signed, 0x13).expect("0x13 present");
    let honest = reference_sighash(0x00, SPENT_VALUE, &hex_decode(SPENT_SPK));
    let off_by_one = reference_sighash(0x00, SPENT_VALUE + 1, &hex_decode(SPENT_SPK));
    assert!(bip340_verify(&spent_output_key(), &honest, &sig));
    assert!(
        !bip340_verify(&spent_output_key(), &off_by_one, &sig),
        "signature must not verify against a different spent value"
    );
}

/// Ownership binding: a TAP_INTERNAL_KEY that is not ours must be refused.
/// (keystone's own firmware never compares the internal key with the prevout —
/// listed as quirk 4 in the capability plan; we do check it.)
#[test]
fn foreign_tap_internal_key_is_refused() {
    let mut bad_key =
        hex_decode("b68df382cad577d8304d5a8e640c3cb42d77c10016ab754caa4d6e68b6cb296d");
    bad_key[0] ^= 0xff;
    // appears twice: as the 0x16 key payload and as the 0x17 value; patch both
    let mut tampered = UNSIGNED.to_vec();
    let mut at = 0;
    while let Some(off) = tampered[at..].windows(32).position(|w| {
        w == &hex_decode("b68df382cad577d8304d5a8e640c3cb42d77c10016ab754caa4d6e68b6cb296d")[..]
    }) {
        let start = at + off;
        tampered[start] ^= 0xff;
        at = start + 32;
    }
    assert_eq!(input_map_entry(&tampered, 0x17).unwrap(), bad_key);
    assert!(
        device_sign(&tampered).is_err(),
        "foreign internal key must be refused"
    );
}

/// The prevout script must be the BIP-86 output key derived from OUR key.
#[test]
fn foreign_prevout_program_is_refused() {
    let mut spk = hex_decode(SPENT_SPK);
    spk[2] ^= 0xff;
    let tampered = with_patched(UNSIGNED, &hex_decode(SPENT_SPK), &spk);
    assert!(
        device_sign(&tampered).is_err(),
        "wrong prevout program must be refused"
    );
}

/// A PSBT that carries no taproot derivation record must not be signed
/// blindly (we would have no evidence the input is ours).
#[test]
fn missing_tap_derivation_is_refused() {
    // 0x16 -> 0x99: the map still parses but no longer declares a tap path.
    let mut tampered = UNSIGNED.to_vec();
    let at = find_subslice(&tampered, &hex_decode("b68df382cad577d8304d5a8e640c3c"));
    // the 0x16 entry's type byte sits right before the keylen-33 prefix
    let type_at = at - 2; // keylen(0x21) || type(0x16)
    assert_eq!(tampered[type_at], 0x21, "0x16 entry key length");
    assert_eq!(tampered[type_at + 1], 0x16, "0x16 entry type byte");
    tampered[type_at + 1] = 0x99;
    assert!(
        device_sign(&tampered).is_err(),
        "no tap derivation = refuse"
    );
}

/// A non-default sighash type must come back with the suffix byte BIP-371
/// requires (sig(64) || hash_type), and verify against the matching sighash.
#[test]
fn non_default_sighash_type_appends_the_type_byte() {
    // 0x03 SIGHASH_TYPE: 0x00 (DEFAULT) -> 0x01 (ALL)
    let site = hex_decode("01030400000000");
    let mut patched = site.clone();
    patched[3] = 0x01; // value u32 LE: 0x00000001 = SIGHASH_ALL
    let tampered = with_patched(UNSIGNED, &site, &patched);

    let signed = device_sign(&tampered).expect("SIGHASH_ALL keypath spend is legal");
    let sig = input_map_entry(&signed, 0x13).expect("0x13 present");
    assert_eq!(sig.len(), 65, "sig(64) || hash_type");
    assert_eq!(sig[64], 0x01, "hash_type byte must be ALL");
    let sighash = reference_sighash(0x01, SPENT_VALUE, &hex_decode(SPENT_SPK));
    assert!(bip340_verify(&spent_output_key(), &sighash, &sig[..64]));
}

/// Refusals must not write a partial PSBT into the caller's buffer.
#[test]
fn refusal_leaves_the_output_buffer_untouched() {
    let mut spk = hex_decode(SPENT_SPK);
    spk[2] ^= 0xff;
    let tampered = with_patched(UNSIGNED, &hex_decode(SPENT_SPK), &spk);

    let ws_need = shlosilo::business::sign::SignWsLayout::compute().total;
    let mut ws_bytes = vec![0u8; ws_need];
    let mut ws = carve_sign_ws(&mut ws_bytes).unwrap();
    let s = seed();
    let mut out = vec![0xA5u8; tampered.len() + 1024];
    let rc = sign_with_entropy_ws(
        SignInput::Seed { seed: &s },
        UrTypeTag::CryptoPsbt,
        &tampered,
        &[],
        &[],
        Some(&mut ws),
        &mut out,
    );
    assert!(rc.is_err(), "must be refused");
    assert!(
        out.iter().all(|b| *b == 0xA5),
        "no partial output on the failure path"
    );
}
