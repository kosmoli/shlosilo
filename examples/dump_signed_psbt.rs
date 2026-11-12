//! Emit both signed-PSBT dialects for the Bitcoin Core oracle.
//!
//! `tools/psbt-oracle/finalize_cmp.sh` feeds these to `bitcoin-cli finalizepsbt`
//! and compares the transactions Core extracts with the one our own finalizer
//! produces. That is the invariant worth having (2026-11-13): not "does our PSBT
//! contain 0x08", but "does an independent implementation extract the same bytes".

use shlosilo::business::sign::{sign, SignInput};
use shlosilo::entropy::mnemonic::Mnemonic;
use shlosilo::ur::ur_encode::UrTypeTag;

const PSBT: &[u8] = include_bytes!("../tests/fixtures/sparrow_signet_12k.psbt");

fn b64(bytes: &[u8]) -> String {
    // minimal base64 encoder: this example must not pull a dependency in
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn main() {
    const ENTROPY: [u8; 16] = [
        0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29,
        0x16,
    ];
    let entropy = ENTROPY;

    // The UR exits strip the CBOR shell; the signer accepts the bare PSBT.
    for (name, tag) in [
        ("partial", UrTypeTag::CryptoPsbt),
        ("finalized", UrTypeTag::Psbt),
    ] {
        let mut out = vec![0u8; PSBT.len() + 4096];
        let n = sign(
            SignInput::Mnemonic {
                mnemonic: Mnemonic::from_entropy(&entropy).expect("mnemonic"),
                passphrase: b"",
            },
            tag,
            PSBT,
            &mut out,
        )
        .expect("sign");
        std::fs::write(format!("/tmp/psbt_oracle_{name}.b64"), b64(&out[..n])).expect("write");
        println!("{name}: {} bytes -> /tmp/psbt_oracle_{name}.b64", n);
    }
}
