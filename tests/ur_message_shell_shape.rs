//! UR message shapes: which types carry a CBOR byte-string shell and which are
//! the CBOR item itself (S2 / B-8).
//!
//! ## The defect this pins
//!
//! `ur_encode` used to wrap *every* outbound payload in a CBOR byte-string
//! shell. That is right for the container-carrying types (BCR-2020-006
//! `crypto-psbt` and the Monero types are decoded by peers with `decodeBytes`)
//! but wrong for the key/path registries: BCR-2020-007 defines the
//! `crypto-hdkey` / `crypto-account` message as the CBOR **map**, so the shell
//! put a byte string where the registry reads a map.
//!
//! It survived because our own decoder strips a complete byte-string shell: the
//! shape tests decoded the URI and saw the map, on both sides of the same
//! mistake. The keystone SDK's `parseHDKey` is what finally refused it
//! (`tools/sdk-gate`, "getData is not a function" - `map[5]` was a byte).
//!
//! These pins read the **raw message** (bytewords decoded, no shell stripping),
//! which is the only place the difference is visible.

use shlosilo::derivation::bip32_secp256k1::{master_fingerprint_from_seed, xpub_from_seed};
use shlosilo::derivation::path::DerivationPath;
use shlosilo::ur::codec::{crypto_account, crypto_hd_key};
use shlosilo::ur::ur_encode::{self, UrTypeTag};

const SEED_HEX: &str = "d25e113e8f7be9936d67de81eb4d4bb94788b48b39f815f48f79dc029feddc918d07f5ac8ffbfb86514c4a0824ad187c5f6fc8b7c43b29356380aaeabc0267dc";

fn seed64() -> [u8; 64] {
    let clean: Vec<u8> = SEED_HEX
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let mut out = [0u8; 64];
    for (i, c) in clean.chunks(2).enumerate() {
        let hi = (c[0] as char).to_digit(16).unwrap();
        let lo = (c[1] as char).to_digit(16).unwrap();
        out[i] = ((hi << 4) | lo) as u8;
    }
    out
}

/// The UR message exactly as it travels: bytewords decoded, nothing stripped.
fn raw_message(uri: &str) -> Vec<u8> {
    let rest = uri.strip_prefix("ur:").expect("ur: prefix");
    let (_type, body) = rest.split_once('/').expect("type/body split");
    let mut buf = vec![0u8; body.len() / 2];
    let n = shlosilo::encoding::bytewords::decode_minimal_into(body, &mut buf)
        .expect("bytewords decode");
    buf.truncate(n);
    buf
}

fn is_cbor_map(first: u8) -> bool {
    first & 0xe0 == 0xa0
}

fn is_bytes_shell(first: u8) -> bool {
    // 0x58/0x59 = definite-length byte string with a 1- or 2-byte length. The
    // shell the transport writes stays inside those two heads (payload <= 8 KiB).
    first == 0x58 || first == 0x59
}

/// `crypto-hdkey`: the message must be the map BCR-2020-007 describes.
#[test]
fn crypto_hdkey_message_is_the_map_not_a_shell() {
    let seed = seed64();
    let mfp = master_fingerprint_from_seed(&seed).expect("mfp");
    let path = DerivationPath::parse("m/84'/0'/0'").expect("path");
    let xpub = xpub_from_seed(&seed, &path).expect("xpub");
    let enc = crypto_hd_key::encode(&xpub, &mfp, Some(&path)).expect("encode");

    let msg = raw_message(enc.as_str());
    assert!(
        is_cbor_map(msg[0]),
        "crypto-hdkey message must be a CBOR map (BCR-2020-007), got head {:#04x} - \
         a byte-string shell here makes the keystone SDK's parseHDKey unreadable",
        msg[0]
    );
    // key 3 (`key_data`) is the first field our encoder writes
    assert_eq!(msg[1], 0x03, "first map key is key_data (3)");
}

/// `crypto-account`: same registry family, same rule.
#[test]
fn crypto_account_message_is_the_map_not_a_shell() {
    let seed = seed64();
    let mfp = master_fingerprint_from_seed(&seed).expect("mfp");
    let path = DerivationPath::parse("m/84'/0'/0'").expect("path");
    let xpub = xpub_from_seed(&seed, &path).expect("xpub");
    let sl = crypto_account::btc_script_expressions(84).expect("script");
    let out = [crypto_account::AccountOutput {
        xpub: &xpub,
        path: &path,
        script_expressions: sl,
    }];
    let enc = crypto_account::encode(&mfp, &out).expect("encode");

    let msg = raw_message(enc.as_str());
    assert!(
        is_cbor_map(msg[0]),
        "crypto-account message must be a CBOR map, got head {:#04x}",
        msg[0]
    );
}

/// The container-carrying types keep their shell - Cake and Sparrow decode with
/// `decodeBytes`, so removing it here would break the shipped flows.
#[test]
fn container_types_keep_their_byte_string_shell() {
    let payload = [0xAAu8; 32];
    for tag in [
        UrTypeTag::CryptoPsbt,
        UrTypeTag::Bytes,
        UrTypeTag::XmrTxUnsigned,
        UrTypeTag::XmrOutput,
    ] {
        let enc = ur_encode::encode(tag, &payload).expect("encode");
        let msg = raw_message(enc.as_str());
        assert!(
            is_bytes_shell(msg[0]),
            "{:?} must keep the byte-string shell (peers decodeBytes), got head {:#04x}",
            tag,
            msg[0]
        );
        // and our own decoder still hands back the payload either way
        let decoded = shlosilo::ur::ur_decode::decode(enc.as_str()).expect("decode");
        assert_eq!(decoded.type_tag(), tag);
        assert_eq!(decoded.as_ref(), &payload[..]);
    }
}

/// Both shapes must still decode to the same payload: the shell is a transport
/// detail, and a peer that (wrongly) shells a map-type message stays readable.
#[test]
fn decode_is_tolerant_of_the_shell_in_either_direction() {
    let seed = seed64();
    let mfp = master_fingerprint_from_seed(&seed).expect("mfp");
    let path = DerivationPath::parse("m/84'/0'/0'").expect("path");
    let xpub = xpub_from_seed(&seed, &path).expect("xpub");
    let enc = crypto_hd_key::encode(&xpub, &mfp, Some(&path)).expect("encode");
    let bare = raw_message(enc.as_str());

    // Re-shell by hand (what a non-conformant peer might send) and decode.
    let mut shelled = Vec::new();
    shelled.push(if bare.len() < 0x58 {
        0x40 + bare.len() as u8
    } else {
        0x58
    });
    if bare.len() >= 0x58 {
        shelled.push(bare.len() as u8);
    }
    shelled.extend_from_slice(&bare);
    let mut body = vec![0u8; (shelled.len() + 4) * 2];
    let mut n = 0usize;
    shlosilo::encoding::bytewords::encode_minimal_into(&shelled, &mut body, &mut n)
        .expect("bytewords");
    let uri_body = core::str::from_utf8(&body[..n]).expect("ascii");
    let uri = format!("ur:crypto-hdkey/{uri_body}");
    let decoded = shlosilo::ur::ur_decode::decode(&uri).expect("decode shelled hdkey");
    assert_eq!(
        decoded.as_ref(),
        &bare[..],
        "a shelled map-type message must still decode to the map"
    );
}
