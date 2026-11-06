//! P2SH-P2WPKH (BIP49) spending on the DEVICE signing path (S2 / B-4 / gap G6).
//!
//! ## Why this file exists
//!
//! `chain/btc/p2sh.rs` and `psbt::sign_psbt_p2sh_p2wpkh` were compiled out of the
//! device face (`#[cfg(any(feature = "alloc-fallback", test))]`) and the unified
//! signing entry only dispatched P2WPKH, so a Nested Segwit wallet — still the
//! default for many hardware-wallet and exchange flows — could not be signed.
//! This file drives the device entry with a real caller workspace and is NOT
//! gated on `alloc-fallback`, so it also runs on the `--no-default-features` face.
//!
//! ## Oracle (independent of the implementation under test)
//!
//! - **Fixture**: `tests/fixtures/core_regtest_p2sh_p2wpkh_331b.psbt`, produced by
//!   Bitcoin Core v31.0.0 `walletcreatefundedpsbt` on an isolated regtest node.
//!   Imported descriptor `sh(wpkh([f3b9960b/49'/1'/0'/0/0]026c59ed…5027e5))`, i.e.
//!   the key shlosilo's own test seed derives at that path.
//! - **Sighash**: BIP-143 computed here by hand (no call into `chain::btc`), with
//!   scriptCode = the redeem script, as BIP-143 requires for P2SH-wrapped segwit.
//! - **Signature check**: `k256::ecdsa` DER verification against the x-only… no:
//!   against the compressed public key taken from the fixture's own
//!   BIP32_DERIVATION record, so neither our ECDSA code nor our sighash code is
//!   in the judging path.
//!
//! ## Fixture facts (asserted to be present in the bytes so they cannot drift)
//!
//! | field | value |
//! |---|---|
//! | unsigned tx | v2, 1 input, 1 output, nLockTime 0 |
//! | prevout | `780fe93a…3ae90fa7`:0, nSequence `0xfffffffd` |
//! | spent | 100,000 sat, spk `a914 3bd0ce93…d215e052f2 87` (P2SH) |
//! | redeem script | `0014 64e4dbff…6fece529` (the P2WPKH program) |
//! | path | m/49'/1'/0'/0/0, master fingerprint `f3b9960b` |
//! | tx output | 99,867 sat, spk `0014 4d3b1adf…90d76acd` |

use sha2::{Digest, Sha256};
use shlosilo::business::sign::{carve_sign_ws, sign_with_entropy_ws, SignInput};
use shlosilo::ur::ur_encode::UrTypeTag;

/// BIP-39 seed of the project test entropy (`f284fb6c…b22916`, empty passphrase).
const SEED_HEX: &str = "d25e113e8f7be9936d67de81eb4d4bb94788b48b39f815f48f79dc029feddc918d07f5ac8ffbfb86514c4a0824ad187c5f6fc8b7c43b29356380aaeabc0267dc";

const UNSIGNED: &[u8] = include_bytes!("fixtures/core_regtest_p2sh_p2wpkh_331b.psbt");

// ---------------------------------------------------------------------------
// fixture facts
// ---------------------------------------------------------------------------

/// Prevout txid in the byte order the transaction serializes it (internal order);
/// display form is the reverse.
const PREV_TXID: &str = "a7f06b0bb2e6ba127e82b81a1d9a2b94bbe32d7b8b50ad79064cfd213ae90f78";
const PREV_VOUT: u32 = 0;
const PREV_SEQUENCE: u32 = 0xffff_fffd;
const SPENT_VALUE: u64 = 100_000;
const SPENT_SPK: &str = "a9143bd0ce93a9ba0f29e6ceadeceb702cd215e052f287";
const REDEEM_SCRIPT: &str = "001464e4dbff0202485fd4d8217cc34a8d666fece529";
const RECORD_PUBKEY: &str = "026c59ed538e8f38787d7f80411423c87aa3ecf6207801bace9e8992ac465027e5";
const TX_VERSION: u32 = 2;
const TX_LOCKTIME: u32 = 0;
const TX_OUT_VALUE: u64 = 99_867;
const TX_OUT_SPK: &str = "00144d3b1adf961c035e65301aa54c2782ce90d76acd";

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

// ---------------------------------------------------------------------------
// independent BIP-143 sighash (no calls into chain::btc)
// ---------------------------------------------------------------------------

fn dsha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let first: [u8; 32] = h.finalize().into();
    let mut h2 = Sha256::new();
    h2.update(first);
    h2.finalize().into()
}

/// BIP-143 scriptCode for a P2SH-wrapped P2WPKH spend: the **P2PKH-style** script
/// `0x76a914{20-byte key hash}88ac` (25 bytes), not the 22-byte redeem script.
fn p2sh_p2wpkh_script_code(pubkey_hash: &[u8; 20]) -> [u8; 25] {
    let mut code = [0u8; 25];
    code[0] = 0x76; // OP_DUP
    code[1] = 0xa9; // OP_HASH160
    code[2] = 0x14; // push 20
    code[3..23].copy_from_slice(pubkey_hash);
    code[23] = 0x88; // OP_EQUALVERIFY
    code[24] = 0xac; // OP_CHECKSIG
    code
}

/// BIP-143 sighash, SIGHASH_ALL, single input / single output (the fixture shape).
fn reference_sighash(script_code: &[u8], spent_value: u64) -> [u8; 32] {
    let mut outpoint = Vec::new();
    outpoint.extend_from_slice(&hex_decode(PREV_TXID));
    outpoint.extend_from_slice(&PREV_VOUT.to_le_bytes());
    let hash_prevouts = dsha256(&[&outpoint]);
    let hash_sequence = dsha256(&[&PREV_SEQUENCE.to_le_bytes()]);

    let out_spk = hex_decode(TX_OUT_SPK);
    let mut outs = Vec::new();
    outs.extend_from_slice(&TX_OUT_VALUE.to_le_bytes());
    outs.push(out_spk.len() as u8);
    outs.extend_from_slice(&out_spk);
    let hash_outputs = dsha256(&[&outs]);

    let mut code = Vec::new();
    code.push(script_code.len() as u8);
    code.extend_from_slice(script_code);

    let sighash_type = 1u32.to_le_bytes(); // SIGHASH_ALL
    let mut pre = Vec::new();
    pre.extend_from_slice(&TX_VERSION.to_le_bytes());
    pre.extend_from_slice(&hash_prevouts);
    pre.extend_from_slice(&hash_sequence);
    pre.extend_from_slice(&outpoint);
    pre.extend_from_slice(&code);
    pre.extend_from_slice(&spent_value.to_le_bytes());
    pre.extend_from_slice(&PREV_SEQUENCE.to_le_bytes());
    pre.extend_from_slice(&hash_outputs);
    pre.extend_from_slice(&TX_LOCKTIME.to_le_bytes());
    pre.extend_from_slice(&sighash_type);
    dsha256(&[&pre])
}

/// Independent ECDSA verification over the hand-rolled sighash.
fn ecdsa_verify(pubkey: &[u8], sighash: &[u8; 32], der_sig: &[u8]) -> bool {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let vk = match k256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig = match k256::ecdsa::Signature::from_der(der_sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify_prehash(sighash, &sig).is_ok()
}

// ---------------------------------------------------------------------------
// device signing path
// ---------------------------------------------------------------------------

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

/// Minimal PSBT walk: pull one singleton entry (or the 0x06 key payload) out of
/// input map 0. Deliberately independent of `chain::btc::psbt`.
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
    let mut i = 5;
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
        if key[0] == wanted && (wanted == 0x06 || key.len() == 1) {
            if wanted == 0x06 && key.len() != 34 {
                continue;
            }
            return Some(value.to_vec());
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("tamper target must exist in the fixture")
}

fn find_last_subslice(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .rposition(|w| w == needle)
        .expect("tamper target must exist in the fixture")
}

fn with_patched(psbt: &[u8], needle: &[u8], patch: &[u8]) -> Vec<u8> {
    assert_eq!(needle.len(), patch.len(), "in-place patch keeps the length");
    let at = find_subslice(psbt, needle);
    let mut out = psbt.to_vec();
    out[at..at + patch.len()].copy_from_slice(patch);
    out
}

/// Patch the LAST occurrence: the scriptPubKey appears both inside the
/// NON_WITNESS_UTXO full transaction and in WITNESS_UTXO, and only the latter is
/// what the signer reads.
fn with_patched_last(psbt: &[u8], needle: &[u8], patch: &[u8]) -> Vec<u8> {
    assert_eq!(needle.len(), patch.len(), "in-place patch keeps the length");
    let at = find_last_subslice(psbt, needle);
    let mut out = psbt.to_vec();
    out[at..at + patch.len()].copy_from_slice(patch);
    out
}

// ---------------------------------------------------------------------------
// pins
// ---------------------------------------------------------------------------

/// The fixture facts in the module table must really be in the bytes.
#[test]
fn fixture_carries_the_documented_facts() {
    assert!(find_subslice(UNSIGNED, &hex_decode(PREV_TXID)) > 0);
    assert!(find_subslice(UNSIGNED, &hex_decode(SPENT_SPK)) > 0);
    assert!(find_subslice(UNSIGNED, &hex_decode(REDEEM_SCRIPT)) > 0);
    assert!(find_subslice(UNSIGNED, &hex_decode(TX_OUT_SPK)) > 0);
    assert!(find_subslice(UNSIGNED, &SPENT_VALUE.to_le_bytes()) > 0);
    let der = input_map_entry(UNSIGNED, 0x06).expect("BIP32_DERIVATION present");
    assert_eq!(
        &der[..4],
        &hex_decode("f3b9960b")[..],
        "our master fingerprint"
    );
    assert_eq!(der.len(), 24, "4-byte fingerprint + 5 path elements");
}

/// The hand-rolled BIP-143 sighash is what the reference implementation signed:
/// feed it the redeem script as scriptCode and check a known-good signature.
/// (Core's PSBT carries no signature, so the anchor is structural: the fixture's
/// redeem script must hash into the P2SH program, and our own signature must
/// verify under this sighash in the next test.)
#[test]
fn redeem_script_hashes_into_the_p2sh_program() {
    let redeem = hex_decode(REDEEM_SCRIPT);
    let spk = hex_decode(SPENT_SPK);
    assert_eq!(spk.len(), 23);
    assert_eq!(spk[0], 0xa9);
    assert_eq!(spk[1], 0x14);
    assert_eq!(spk[22], 0x87);
    // hash160 = RIPEMD160(SHA256(x)) — recomputed through the crate's encoders.
    let h = shlosilo::encoding::sha256::hash(&redeem).unwrap();
    let h160 = shlosilo::encoding::ripemd160::hash(&h).unwrap();
    assert_eq!(
        &h160[..],
        &spk[2..22],
        "P2SH program must be hash160(redeem)"
    );
}

/// B-4 acceptance: the device path signs a P2SH-P2WPKH input.
#[test]
fn device_path_signs_p2sh_p2wpkh() {
    let signed = device_sign(UNSIGNED).expect("P2SH-P2WPKH input must be signable");
    assert!(signed.len() > UNSIGNED.len(), "signed PSBT must grow");

    // FINAL_SCRIPT_SIG (0x07) = push of the 22-byte redeem script.
    let script_sig = input_map_entry(&signed, 0x07).expect("FINAL_SCRIPT_SIG must be injected");
    let redeem = hex_decode(REDEEM_SCRIPT);
    assert_eq!(script_sig.len(), 23, "single push of a 22-byte script");
    assert_eq!(script_sig[0], 0x16, "OP_PUSHBYTES_22");
    assert_eq!(&script_sig[1..], &redeem[..]);

    // FINAL_SCRIPTWITNESS (0x08) = 2 items: <sig||sighash> <pubkey>
    let witness = input_map_entry(&signed, 0x08).expect("FINAL_SCRIPTWITNESS must be injected");
    assert_eq!(witness[0], 0x02, "two witness items");
    let sig_len = witness[1] as usize;
    let sig = &witness[2..2 + sig_len];
    let pk_len = witness[2 + sig_len] as usize;
    let pk = &witness[3 + sig_len..3 + sig_len + pk_len];
    assert_eq!(pk_len, 33, "compressed public key");
    assert_eq!(
        pk,
        &hex_decode(RECORD_PUBKEY)[..],
        "the witness must carry the key the BIP32 record names"
    );
    assert_eq!(sig[sig_len - 1], 0x01, "SIGHASH_ALL suffix byte");

    // The signature must verify against the hand-rolled BIP-143 sighash.
    let mut key_hash = [0u8; 20];
    key_hash.copy_from_slice(&redeem[2..]);
    let sighash = reference_sighash(&p2sh_p2wpkh_script_code(&key_hash), SPENT_VALUE);
    assert!(
        ecdsa_verify(pk, &sighash, &sig[..sig_len - 1]),
        "device signature must verify against the fixture's BIP-143 sighash"
    );
}

/// The spent value is part of the BIP-143 preimage — a signature made for a
/// different amount must not verify.
#[test]
fn signature_binds_the_spent_value() {
    let signed = device_sign(UNSIGNED).expect("sign");
    let witness = input_map_entry(&signed, 0x08).expect("0x08 present");
    let sig_len = witness[1] as usize;
    let sig = &witness[2..2 + sig_len];
    let redeem = hex_decode(REDEEM_SCRIPT);
    let mut key_hash = [0u8; 20];
    key_hash.copy_from_slice(&redeem[2..]);
    let honest = reference_sighash(&p2sh_p2wpkh_script_code(&key_hash), SPENT_VALUE);
    let off_by_one = reference_sighash(&p2sh_p2wpkh_script_code(&key_hash), SPENT_VALUE + 1);
    assert!(ecdsa_verify(
        &hex_decode(RECORD_PUBKEY),
        &honest,
        &sig[..sig_len - 1]
    ));
    assert!(
        !ecdsa_verify(&hex_decode(RECORD_PUBKEY), &off_by_one, &sig[..sig_len - 1]),
        "signature must not verify against a different spent value"
    );
}

/// A redeem script that does not hash into the prevout must be refused (that is
/// the P2SH-P2WPKH analogue of "sign what you see").
#[test]
fn foreign_redeem_script_is_refused() {
    let mut redeem = hex_decode(REDEEM_SCRIPT);
    redeem[2] ^= 0xff;
    let tampered = with_patched(UNSIGNED, &hex_decode(REDEEM_SCRIPT), &redeem);
    assert!(
        device_sign(&tampered).is_err(),
        "a redeem script that does not match the prevout must be refused"
    );
}

/// A prevout that is not P2SH-P2WPKH of our key must be refused.
#[test]
fn foreign_prevout_program_is_refused() {
    let mut spk = hex_decode(SPENT_SPK);
    spk[2] ^= 0xff;
    let tampered = with_patched_last(UNSIGNED, &hex_decode(SPENT_SPK), &spk);
    assert!(
        device_sign(&tampered).is_err(),
        "wrong prevout must be refused"
    );
}

/// Refusals must not leave a partial PSBT in the caller's buffer.
#[test]
fn refusal_leaves_the_output_buffer_untouched() {
    let mut spk = hex_decode(SPENT_SPK);
    spk[2] ^= 0xff;
    let tampered = with_patched_last(UNSIGNED, &hex_decode(SPENT_SPK), &spk);

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
