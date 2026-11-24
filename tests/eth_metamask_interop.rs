//! Interop pins built from **MetaMask's own request bytes**.
//!
//! The payloads below are not hand-written: they were produced by running
//! MetaMask's shipping code paths locally (see the provenance block per vector).
//! A pin that only speaks our own dialect cannot catch a dialect mismatch, and
//! that is exactly the failure class a real wallet exposes first.
#![cfg(feature = "alloc-fallback")]

extern crate alloc;

use shlosilo::business::sign::{sign, SignInput};
use shlosilo::chain::eth::eip1559;
use shlosilo::types::SecretBytes;
use shlosilo::ur::codec::eth_signature::parse_eth_signature;
use shlosilo::ur::ur_encode::UrTypeTag;

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("fixture hex"))
        .collect()
}

/// `@metamask/eth-qr-keyring@3.0.2` — the QR hardware keyring MetaMask ships for
/// air-gapped devices. `dist/device.cjs::signTransaction` does:
///
/// ```js
/// const dataType = transaction.type === TransactionType.Legacy
///   ? DataType.transaction : DataType.typedTransaction;
/// const messageToSign = transaction.getMessageToSign();
/// const rawTransaction = Buffer.from(
///   Array.isArray(messageToSign) ? RLP.encode(messageToSign) : messageToSign);
/// EthSignRequest.constructETHRequest(rawTransaction, dataType, path, xfp, requestId, chainId)
/// ```
///
/// Reproduced with `@ethereumjs/tx` for a plain 0.01 ETH transfer on chain 1:
/// - `data_type` = 4 (typedTransaction) — so the device must dispatch on the first
///   payload byte, and the review must render a **send**, never typed data;
/// - `sign_data` = `0x02 || rlp([9 fields])`, i.e. the signing preimage **without**
///   the three signature slots. Until 2026-11-24 the parser demanded 12 fields, so
///   every request from this keyring was rejected as a format error.
#[test]
fn metamask_qr_keyring_1559_preimage_signs() {
    const CBOR_HEX: &str = concat!(
        // {1: tag(37) requestId, 2: sign_data, 3: data_type = 4,
        //  4: chain_id = 1, 5: tag(304) keypath m/44'/60'/0'/0/0}
        "a501d825508a20e8cb3e8243468c0e38b70744b942025831",
        "02ef01078459682f008506fc23ac00825208941111111111111111111111111111111111111111872386f2",
        "6fc1000080c00304040105d90130a2018a182cf5183cf500f500f400f4021a12345678",
    );
    // The transaction those bytes carry, spelled out for the independent oracle.
    let tx = eip1559::Eip1559Transaction {
        chain_id: 1,
        nonce: 7,
        max_priority_fee_per_gas: 1_500_000_000,
        max_fee_per_gas: 30_000_000_000,
        gas_limit: 21_000,
        destination: Some([0x11u8; 20]),
        amount: 10_000_000_000_000_000,
        data: alloc::vec::Vec::new().into(),
    };

    let seed = [7u8; 64];
    let path = shlosilo::derivation::path::DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
    let derived = shlosilo::derivation::bip32_secp256k1::derive_from_seed(&seed, &path).unwrap();
    let expected = eip1559::sign_eip1559(&eip1559::Eip1559SignInput {
        tx: tx.clone(),
        private_key: &SecretBytes::new(shlosilo::curve_primitive::secp256k1::scalar_to_bytes(
            &derived,
        )),
    })
    .expect("oracle");

    let payload = hex_decode(CBOR_HEX);
    let mut out = [0u8; 512];
    let n = sign(
        SignInput::Seed { seed: &seed },
        UrTypeTag::EthSignRequest,
        &payload,
        &mut out,
    )
    .expect("MetaMask's 9-field preimage must sign");

    let sig = parse_eth_signature(&out[..n]).expect("eth-signature container");
    assert_eq!(&sig.signature[..32], &expected.r[..], "r");
    assert_eq!(&sig.signature[32..64], &expected.s[..], "s");
    assert_eq!(sig.signature[64], expected.y_parity, "v = yParity");
    assert_eq!(
        sig.request_id,
        [
            0x8a, 0x20, 0xe8, 0xcb, 0x3e, 0x82, 0x43, 0x46, 0x8c, 0x0e, 0x38, 0xb7, 0x07, 0x44,
            0xb9, 0x42
        ],
        "the reply must echo MetaMask's requestId"
    );
}

/// The **other** shape real wallets send: `@keystonehq/metamask-airgapped-keyring`
/// (≤ 0.15.x) passes `Buffer.from(tx.serialize())` for a typed transaction, i.e.
/// `0x02 || rlp([12 fields])` with the three signature slots empty. Both shapes must
/// parse to the same transaction — a wallet's version must not decide whether the
/// user can sign.
#[test]
fn both_wire_shapes_parse_to_the_same_transaction() {
    use shlosilo::chain::eth::from_rlp;
    // 9-field preimage (MetaMask QR keyring), then the same tx as a 12-field
    // serialization with empty r/s/v (keystone keyring).
    let nine = hex_decode(
        "02ef01078459682f008506fc23ac00825208941111111111111111111111111111111111111111872386f26fc1000080c0",
    );
    let twelve = hex_decode(
        "02f201078459682f008506fc23ac00825208941111111111111111111111111111111111111111872386f26fc1000080c0808080",
    );
    let a = from_rlp::parse_eip1559_raw(&nine).expect("9-field preimage");
    let b = from_rlp::parse_eip1559_raw(&twelve).expect("12-field unsigned serialization");
    assert_eq!(a.chain_id, b.chain_id);
    assert_eq!(a.nonce, b.nonce);
    assert_eq!(a.max_priority_fee_per_gas, b.max_priority_fee_per_gas);
    assert_eq!(a.max_fee_per_gas, b.max_fee_per_gas);
    assert_eq!(a.gas_limit, b.gas_limit);
    assert_eq!(a.destination, b.destination);
    assert_eq!(a.amount, b.amount);
}

/// Poison pill for the 12-field branch: a payload that already carries a signature
/// is not a signing request. Accepting it would let a signed transaction be
/// re-signed, laundering someone else's `r/s` as this device's output.
#[test]
fn a_pre_signed_payload_is_refused() {
    use shlosilo::chain::eth::from_rlp;
    // Same 12-field shape, but y_parity/r/s are filled in.
    let signed = hex_decode(
        "02f87201078459682f008506fc23ac00825208941111111111111111111111111111111111111111872386f26fc1000080c001a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222",
    );
    assert!(
        from_rlp::parse_eip1559_signing_request(&signed).is_err(),
        "a payload carrying a signature must not be treated as a signing request"
    );
}
