//! BIP-86 output key and keypath signature for an internal key whose point has ODD y.
//!
//! ## Why this file exists
//!
//! BIP-341 keys the tweak off `lift_x(internal_x)` — the internal point is always the
//! EVEN-y one, so when the private key's public point has odd y the tweak must be added
//! to `-d`, not to `d`. Getting that backwards produces an output key (and a signature)
//! that is wrong for every odd-y key, i.e. for roughly half of all derivations, while
//! every test built on an even-y fixture stays green.
//!
//! The real-device Taproot acceptance run happened to land on an odd-y key
//! (`m/86'/0'/0'/0/0` of the test seed, master fingerprint `f3b9960b`), which is what
//! exposed the trap outside the code base: an address derived by hand with the naive
//! `P + t*G` rule did not match the address that wallet showed. The firmware was right;
//! the hand derivation was wrong. This file pins the firmware side so it stays right.
//!
//! ## Oracle (independent of the implementation under test)
//!
//! Both constants come from mainnet, not from our code:
//! - `OUTPUT_X` is the witness program of
//!   `bc1pza9xzt70a2td6el08t96pdee2p6hh8wnj8t6xa3gu2f2njuysczsdnsry8`
//!   (scriptPubKey `5120 174a612f…848605`, spent in `4eeb2afc…`, height 975336).
//! - `INTERNAL_SK` / `INTERNAL_X` are `m/86'/0'/0'/0/0` of the project test seed, whose
//!   master fingerprint (`f3b9960b`) matches the descriptor that wallet was created from.
//! - The signature is verified by `k256::schnorr::verify_prehash` against `OUTPUT_X`, so
//!   neither our taproot module nor our Schnorr verifier is in that path.

use k256::schnorr::signature::hazmat::PrehashVerifier;
use k256::schnorr::{Signature, VerifyingKey};
use shlosilo::chain::btc::taproot::{
    compute_output_key, sign_p2tr_keypath_into, P2TRKeypathSignInput,
};
use shlosilo::curve_primitive::secp256k1::point_to_compressed;

/// `m/86'/0'/0'/0/0` of the test seed (master fingerprint `f3b9960b`).
const INTERNAL_SK: [u8; 32] = [
    0xb0, 0xb6, 0x79, 0x6d, 0x6d, 0xaa, 0x2b, 0xe9, 0x16, 0xc1, 0x8d, 0xe3, 0x23, 0x63, 0x64, 0x39,
    0x13, 0xcb, 0x66, 0x52, 0x80, 0xbf, 0x84, 0x87, 0xdb, 0x70, 0x38, 0x4c, 0x47, 0x3d, 0x87, 0x07,
];

/// Same key, x-only internal key (this point has ODD y: the compressed form is `0x03…`).
const INTERNAL_X: [u8; 32] = [
    0x12, 0xf6, 0x8c, 0x9c, 0xd2, 0x16, 0x90, 0xfa, 0x2b, 0xbd, 0x91, 0x5e, 0xf5, 0x43, 0x1b, 0x43,
    0x2e, 0xfe, 0x40, 0xbb, 0xf0, 0x72, 0xf5, 0x4e, 0xd4, 0x00, 0x13, 0xf9, 0x56, 0x68, 0x45, 0x0a,
];

/// x-only output key = witness program of the mainnet address above.
const OUTPUT_X: [u8; 32] = [
    0x17, 0x4a, 0x61, 0x2f, 0xcf, 0xea, 0x96, 0xdd, 0x67, 0xef, 0x3a, 0xcb, 0xa0, 0xb7, 0x39, 0x50,
    0x75, 0x7b, 0x9d, 0xd3, 0x91, 0xd7, 0xa3, 0x76, 0x28, 0xe2, 0x92, 0xa9, 0xcb, 0x84, 0x86, 0x05,
];

#[test]
fn the_vector_really_is_an_odd_y_key() {
    // Guard the premise: if this ever stops holding, the file no longer tests parity.
    let p = shlosilo::curve_primitive::secp256k1::base_mul(
        &shlosilo::curve_primitive::secp256k1::scalar_from_bytes(&INTERNAL_SK)
            .expect("valid scalar"),
    );
    let compressed = point_to_compressed(&p);
    assert_eq!(
        compressed[0], 0x03,
        "internal key must have odd y for this pin to mean anything"
    );
    assert_eq!(
        &compressed[1..],
        &INTERNAL_X,
        "x-only form of the vector key"
    );
}

#[test]
fn odd_y_internal_key_produces_the_mainnet_output_key() {
    let output_key = compute_output_key(&INTERNAL_X).expect("lift_x + TapTweak must succeed");
    let compressed = point_to_compressed(&output_key);
    assert_eq!(
        &compressed[1..],
        &OUTPUT_X,
        "tweaked output key must equal the on-chain witness program"
    );
}

#[test]
fn odd_y_internal_key_signature_verifies_against_the_mainnet_output_key() {
    let input = P2TRKeypathSignInput {
        internal_sk: INTERNAL_SK,
        merkle_root: None,
    };
    let sighash = [0x5au8; 32]; // arbitrary prehash: this pins the key path, not a transaction
    let aux_rand = [0x07u8; 32];
    let mut out = [0u8; 65];

    let len = sign_p2tr_keypath_into(&input, &sighash, &aux_rand, 0x00, &mut out)
        .expect("keypath signing must succeed");
    assert_eq!(
        len, 64,
        "SIGHASH_DEFAULT carries no trailing hash_type byte"
    );

    let verifying_key = VerifyingKey::from_bytes((&OUTPUT_X).into()).expect("x-only output key");
    let signature = Signature::try_from(&out[..64]).expect("64-byte BIP-340 signature");
    verifying_key
        .verify_prehash(&sighash, &signature)
        .expect("signature must verify against the tweaked output key, not the internal one");
}
