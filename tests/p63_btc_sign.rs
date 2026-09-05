//! P6.3 BTC end-to-end signing cross-check: a real Sparrow signet PSBT + a real mnemonic → shlosilo sign()
//!
//! Oracle (independent Python SLIP-10 derivation verification):
//! - entropy f284fb6ca9f4d5835455be65e4b22916 → 12 words (empty passphrase)
//! - BIP39 seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048)
//! - m/84'/1'/0'/0/2 privkey 51f15ae12f89aebd635796b16d96ca8aa81e96687c918de96b2175c75604be1d
//!   pubkey 027b54f8c6f01ce468c291a2959532a925868762bf8330e67624b45292499be40f
//!   (exactly matching the test.psbt BIP32_DERIVATION key)

use shlosilo::business::sign::{sign, SignInput};
use shlosilo::chain::btc::psbt::parse_psbt;
use shlosilo::encoding::cbor;
use shlosilo::entropy::mnemonic::Mnemonic;

const PSBT_BYTES: &[u8] = include_bytes!("fixtures/sparrow_signet_12k.psbt");

/// entropy → Mnemonic (bidirectionally verified against the mnemonic "verb chief swamp ... collect")
fn test_mnemonic() -> Mnemonic {
    const ENTROPY: [u8; 16] = [
        0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29,
        0x16,
    ];
    Mnemonic::from_entropy(&ENTROPY).expect("valid 16B entropy")
}

/// UR payload: the crypto-psbt CBOR bytes item (P1-01: no leading tag byte; the type is passed explicitly)
fn ur_payload() -> Vec<u8> {
    cbor::encode_bytes(PSBT_BYTES)
}

/// P6.3-e1: the full signing flow — a 12KB real PSBT must pass without truncation and produce PARTIAL_SIG
#[test]
fn p63_sign_sparrow_psbt_end_to_end() {
    use shlosilo::ur::ur_encode::UrTypeTag;
    let mnemonic = test_mnemonic();
    let input = SignInput::Mnemonic {
        mnemonic,
        passphrase: b"",
    };
    let payload = ur_payload();
    // signed PSBT ≈ original PSBT + PARTIAL_SIG (~72+34B); leave ample margin
    let mut out_buf = vec![0u8; PSBT_BYTES.len() + 512];

    let n = sign(input, UrTypeTag::CryptoPsbt, &payload, &mut out_buf)
        .expect("sign must succeed on real fixture");
    assert!(
        n > PSBT_BYTES.len(),
        "signed psbt must be larger than unsigned"
    );

    // The output must parse with parse_psbt, and input 0 must show PARTIAL_SIG
    let signed = parse_psbt(&out_buf[..n]).expect("signed output must be a valid PSBT");
    let partial = signed.inputs[0]
        .iter()
        .find(|kv| kv.key.first() == Some(&0x02u8)); // BIP-174 PSBT_IN_PARTIAL_SIG
    let partial = partial.expect("PARTIAL_SIG must be injected");
    // key = 0x02 || compressed pubkey — the pubkey must be the fixture's own
    assert_eq!(partial.key.len(), 34);
    assert_eq!(
        &partial.key[1..7],
        &[0x02, 0x7b, 0x54, 0xf8, 0xc6, 0xf0],
        "partial sig keyed by the fixture's pubkey (prefix check)"
    );
    // value = DER sig + sighash byte (ALL=0x01)
    let v = &partial.value;
    assert_eq!(*v.last().unwrap(), 0x01, "sighash ALL suffix");
    assert!(
        v.len() >= 70 && v.len() <= 73,
        "DER length sane, got {}",
        v.len()
    );
}

/// R4: ownership binding negative test - tampered BIP32_DERIVATION pubkey must
/// be rejected. A malicious PSBT claiming someone else's pubkey must not yield
/// a "successful but unusable" signature.
#[test]
fn r4_tampered_bip32_derivation_rejected() {
    use shlosilo::ur::ur_encode::UrTypeTag;
    let mnemonic = test_mnemonic();
    let input = SignInput::Mnemonic {
        mnemonic,
        passphrase: b"",
    };
    // tamper fixture: flip 1 byte of the 33B pubkey inside BIP32_DERIVATION key
    let mut psbt = PSBT_BYTES.to_vec();
    let target = [0x02u8, 0x7b, 0x54, 0xf8, 0xc6, 0xf0]; // fixture pubkey prefix
    let mut patched = false;
    for i in 0..psbt.len() - 33 {
        if psbt[i..i + 6] == target {
            psbt[i + 32] ^= 0x01;
            patched = true;
            break;
        }
    }
    assert!(patched, "fixture pubkey must be found");
    let payload = cbor::encode_bytes(&psbt);
    let mut out_buf = vec![0u8; PSBT_BYTES.len() + 512];
    let r = sign(input, UrTypeTag::CryptoPsbt, &payload, &mut out_buf);
    let e = r.expect_err("tampered ownership must be rejected");
    assert_eq!(
        e.kind,
        shlosilo::error::ShlosiloErrorKind::PsbtOwnershipMismatch,
        "must fail on ownership binding, not parse"
    );
}

#[test]
fn p63_dump_signed_psbt() {
    use shlosilo::ur::ur_encode::UrTypeTag;
    let mnemonic = test_mnemonic();
    let input = SignInput::Mnemonic {
        mnemonic,
        passphrase: b"",
    };
    let payload = ur_payload();
    let mut out_buf = vec![0u8; PSBT_BYTES.len() + 512];
    let n = sign(input, UrTypeTag::CryptoPsbt, &payload, &mut out_buf).unwrap();
    std::fs::write(
        "/tmp/signed_psbt.b64",
        out_buf[..n]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>(),
    )
    .unwrap();
}
