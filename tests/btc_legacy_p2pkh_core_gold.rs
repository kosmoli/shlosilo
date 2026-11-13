//! B-9: legacy P2PKH input signing, pinned against Bitcoin Core's own output.
//!
//! The fixtures are real regtest spends built and signed by Bitcoin Core v31.0.0
//! (see `tests/fixtures/README.md`): the funding outputs pay the project test
//! seed's P2PKH keys, and the "gold" transactions below are Core's own signed
//! bytes. Core signs ECDSA with RFC 6979, exactly like our `ecdsa_secp256k1`
//! wrapper, so the strongest available assertion applies: our scriptSig must be
//! *byte-identical* to Core's. That single equality covers the sighash preimage,
//! the low-S/DER encoding, the push layout and the FINAL_SCRIPT_SIG placement.
//!
//! Three shapes:
//! - `1in1out`: one legacy input, NON_WITNESS_UTXO (0x00) as the witness-less
//!   wallet gives it.
//! - `2in1out`: two legacy inputs of the same key with WITNESS_UTXO (0x01) — the
//!   legacy preimage has no `hashPrevouts`, so a BIP-143-shaped implementation
//!   cannot pass both this and the single-input case.
//! - `abhash`: the spent pubkey hash contains `0xab`, which is the only case that
//!   separates the consensus (opcode-wise) `OP_CODESEPARATOR` deletion from the
//!   byte-wise one.
#![cfg(feature = "alloc-fallback")]

use shlosilo::business::sign::{sign, SignInput};
use shlosilo::chain::btc::psbt::{parse_psbt, Psbt};
use shlosilo::encoding::cbor;
use shlosilo::entropy::mnemonic::Mnemonic;
use shlosilo::ur::ur_encode::UrTypeTag;

const PSBT_1IN1OUT: &[u8] = include_bytes!("fixtures/core_regtest_p2pkh_1in1out.psbt");
const PSBT_2IN1OUT: &[u8] = include_bytes!("fixtures/core_regtest_p2pkh_2in1out.psbt");
const PSBT_ABHASH: &[u8] = include_bytes!("fixtures/core_regtest_p2pkh_abhash_1in1out.psbt");

/// Bitcoin Core v31.0.0 `signrawtransactionwithkey` output for the 1-in-1-out
/// spend (regtest, txid def876c27dc6668c493deac9732ae5bd05a1f7aa9617b4ce5709193865494f98).
const GOLD_1IN1OUT: &str = "0200000001d8aed20b9cb91141388fbe3d9cae6e064d09d038d165f64ff391876da8c076f7000000006a4730440220538a4057b6073f32ef8a6c075db91fc157480b30e04f670f9769b52b4aa26e4002200d0e0137b267ecd5e67bc687435c7e17971bfba7a54ba147d136d49d1acc4c56012102dd0f4486298974dda5cd73385b3b29306c5f13fa3c1609fb59010f651c88027efdffffff0170c9fa02000000001976a9149d96e4178f0b991bcec1b6b68ad165d8a9a6f6f888ac00000000";

/// Core's output for the 2-in-1-out spend (txid b3c5ecbaa49a057cfb769487e8302052739e8eececb434cbe6d9fe47d3fe27c5).
const GOLD_2IN1OUT: &str = "0200000002d8aed20b9cb91141388fbe3d9cae6e064d09d038d165f64ff391876da8c076f7000000006a47304402202cff3c9f163a4d957a3f726e814340811972caaf40fa9541445f12bda375e0fb02202332a5f57099fcf635de9809cf976231f070b750af19f037a2ae9cd58002c175012102dd0f4486298974dda5cd73385b3b29306c5f13fa3c1609fb59010f651c88027efdfffffff55dce984e1c4935e8f82d4b1ca8ef8e223387990643ac1cbaca9dc2ac7ac06e000000006a47304402205b36a8f60b77ff3ea24563e52c0581e66adc97fd57b679b25ddfb8eb9e8e67ba0220025f0a428f0a5ae13243d39962f75589431ea83b8fdb58ece345d5f6b3a5c7bd012102dd0f4486298974dda5cd73385b3b29306c5f13fa3c1609fb59010f651c88027efdffffff01e065c404000000001976a9149d96e4178f0b991bcec1b6b68ad165d8a9a6f6f888ac00000000";

/// Core's output for the spend whose pubkey hash contains 0xab
/// (m/84'/1'/0'/0/11, hash160 052babcd1f24c1d0aaf940396efcc40f333a80c4).
const GOLD_ABHASH: &str = "0200000001358284d0dcef515cbf042fdce65e41759c0c440291d52db0bf9c23fa9a06c053000000006a473044022016c87583e15cf4e5f235f97e43632e47b37fb3890c2ba9049c6270ba5d908fe6022057c2c2d9fc0b16c01fae546a716a7d0022810a7e35a0f448785ead65c1ef22f7012102a3673db5197d620cd354fa66285c8532054a680da03a7b8aabecb8107799d3c7fdffffff01f0053101000000001976a9149d96e4178f0b991bcec1b6b68ad165d8a9a6f6f888ac00000000";

fn test_mnemonic() -> Mnemonic {
    const ENTROPY: [u8; 16] = [
        0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29,
        0x16,
    ];
    Mnemonic::from_entropy(&ENTROPY).expect("valid 16B entropy")
}

fn hex_encode(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
    s
}

fn hex_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let nibble = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("bad hex"),
    };
    (0..bytes.len() / 2)
        .map(|i| (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]))
        .collect()
}

/// Sign the fixture through the unified entry (the device's own dispatch path)
/// and return the signed PSBT bytes.
fn sign_fixture(fixture: &[u8]) -> Vec<u8> {
    let mnemonic = test_mnemonic();
    let input = SignInput::Mnemonic {
        mnemonic,
        passphrase: b"",
    };
    let payload = cbor::encode_bytes(fixture);
    let mut out = vec![0u8; fixture.len() + 512];
    let n = sign(input, UrTypeTag::CryptoPsbt, &payload, &mut out)
        .expect("legacy P2PKH signing must succeed");
    out.truncate(n);
    out
}

/// Serialize the PSBT's every input with the final scriptSig it carries —
/// i.e. exactly what a wallet's extractor produces for a legacy transaction.
fn extract_legacy_tx(psbt: &Psbt<'_>) -> Vec<u8> {
    fn varint(out: &mut Vec<u8>, n: u64) {
        if n < 0xfd {
            out.push(n as u8);
        } else if n <= 0xffff {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        } else {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }

    let tx = &psbt.unsigned_tx;
    let mut out = Vec::new();
    out.extend_from_slice(&tx.version.to_le_bytes());
    varint(&mut out, tx.inputs.len() as u64);
    for (i, txin) in tx.inputs.iter().enumerate() {
        out.extend_from_slice(&txin.prev_out.txid);
        out.extend_from_slice(&txin.prev_out.vout.to_le_bytes());
        let script_sig = psbt
            .input_map(i)
            .iter()
            .find(|kv| kv.key.first() == Some(&0x07u8)) // PSBT_IN_FINAL_SCRIPTSIG
            .map(|kv| kv.value.to_vec())
            .expect("every input must carry FINAL_SCRIPT_SIG after signing");
        varint(&mut out, script_sig.len() as u64);
        out.extend_from_slice(&script_sig);
        out.extend_from_slice(&txin.sequence.to_le_bytes());
    }
    varint(&mut out, tx.outputs.len() as u64);
    for txout in tx.outputs.iter() {
        out.extend_from_slice(&txout.value.to_le_bytes());
        let spk = shlosilo::types::wire_bytes::wire_slice(&txout.script_pubkey);
        varint(&mut out, spk.len() as u64);
        out.extend_from_slice(spk);
    }
    out.extend_from_slice(&tx.lock_time.to_le_bytes());
    out
}

fn assert_matches_core(fixture: &[u8], gold_hex: &str) {
    let signed = sign_fixture(fixture);
    let psbt = parse_psbt(&signed).expect("signed output must parse as a PSBT");
    // A legacy input has no witness: FINAL_SCRIPTWITNESS must stay unset.
    for i in 0..psbt.unsigned_tx.inputs.len() {
        assert!(
            psbt.input_map(i)
                .iter()
                .all(|kv| kv.key.first() != Some(&0x08u8)),
            "input {i} must not carry FINAL_SCRIPTWITNESS"
        );
    }
    let ours = hex_encode(&extract_legacy_tx(&psbt));
    let gold = gold_hex.to_ascii_lowercase();
    if ours != gold {
        // Pinpoint the first differing byte so a failure is diagnosable without
        // a debugger: 6 push/DER layout problems and 1 sighash problems look
        // identical in a bare assert_eq.
        let (a, b) = (hex_decode(&ours), hex_decode(&gold));
        let first = a.iter().zip(b.iter()).position(|(x, y)| x != y);
        panic!(
            "our signed transaction differs from Bitcoin Core's\n  first diff at byte {:?}\n  ours: {}\n  gold: {}",
            first,
            ours,
            gold
        );
    }
}

#[test]
fn legacy_p2pkh_single_input_matches_core() {
    assert_matches_core(PSBT_1IN1OUT, GOLD_1IN1OUT);
}

#[test]
fn legacy_p2pkh_two_inputs_match_core() {
    assert_matches_core(PSBT_2IN1OUT, GOLD_2IN1OUT);
}

/// The spent pubkey hash contains 0xab. A byte-wise OP_CODESEPARATOR deletion
/// signs a different digest here (and only here), so this test is what keeps the
/// opcode-wise walker honest.
#[test]
fn legacy_p2pkh_ab_hash_matches_core() {
    assert_matches_core(PSBT_ABHASH, GOLD_ABHASH);
}
