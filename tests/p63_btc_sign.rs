//! P6.3 BTC 端到端签名互验：真实 Sparrow signet PSBT + 真实助记词 → shlosilo sign()
//!
//! Oracle（独立 python SLIP-10 派生验证）：
//! - entropy f284fb6ca9f4d5835455be65e4b22916 → 12 词（空 passphrase）
//! - BIP39 seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048)
//! - m/84'/1'/0'/0/2 privkey 51f15ae12f89aebd635796b16d96ca8aa81e96687c918de96b2175c75604be1d
//!   pubkey 027b54f8c6f01ce468c291a2959532a925868762bf8330e67624b45292499be40f
//!   （与 test.psbt BIP32_DERIVATION key 完全一致）

use shlosilo::business::sign::{sign, SignInput};
use shlosilo::chain::btc::psbt::{input_type, parse_psbt};
use shlosilo::encoding::cbor;
use shlosilo::entropy::mnemonic::Mnemonic;

const PSBT_BYTES: &[u8] = include_bytes!("/home/komo/testTX/test.psbt");

/// entropy → Mnemonic（与助记词 "verb chief swamp ... collect" 双向验证过）
fn test_mnemonic() -> Mnemonic {
    const ENTROPY: [u8; 16] = [
        0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2,
        0x29, 0x16,
    ];
    Mnemonic::from_entropy(&ENTROPY).expect("valid 16B entropy")
}

/// UR payload：crypto-psbt 的 CBOR bytes item（P1-01：无首字节 tag，type 显式传）
fn ur_payload() -> Vec<u8> {
    cbor::encode_bytes(PSBT_BYTES)
}

/// P6.3-e1：完整签名流程——12KB 真实 PSBT 必须无截断通过并产出 PARTIAL_SIG
#[test]
fn p63_sign_sparrow_psbt_end_to_end() {
    use shlosilo::ur::ur_encode::UrTypeTag;
    let mnemonic = test_mnemonic();
    let input = SignInput::Mnemonic {
        mnemonic: mnemonic,
        passphrase: b"",
    };
    let payload = ur_payload();
    // signed PSBT ≈ 原 PSBT + PARTIAL_SIG(~72+34B)，给足余量
    let mut out_buf = vec![0u8; PSBT_BYTES.len() + 512];

    let n = sign(input, UrTypeTag::CryptoPsbt, &payload, &mut out_buf)
        .expect("sign must succeed on real fixture");
    assert!(n > PSBT_BYTES.len(), "signed psbt must be larger than unsigned");

    // 输出可被 parse_psbt 解析，且 input 0 出现 PARTIAL_SIG
    let signed = parse_psbt(&out_buf[..n]).expect("signed output must be a valid PSBT");
    let partial = signed.inputs[0]
        .iter()
        .find(|kv| kv.key.first() == Some(&input_type::PARTIAL_SIG));
    let partial = partial.expect("PARTIAL_SIG must be injected");
    // key = 0x02 || compressed pubkey —— pubkey 必须是 fixture 里那把
    assert_eq!(partial.key.len(), 34);
    assert_eq!(
        &partial.key[1..7],
        &[0x02, 0x7b, 0x54, 0xf8, 0xc6, 0xf0],
        "partial sig keyed by the fixture's pubkey (prefix check)"
    );
    // value = DER sig + sighash byte (ALL=0x01)
    let v = &partial.value;
    assert_eq!(*v.last().unwrap(), 0x01, "sighash ALL suffix");
    assert!(v.len() >= 70 && v.len() <= 73, "DER length sane, got {}", v.len());
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
