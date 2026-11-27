//! Address-encoding primitives: what the D layer must produce, pinned from outside the crate.
//!
//! Why this file exists (chain-axis design §4, batch S8): the encoders were already shared — they
//! live in `forms/encoding/` — but nothing pinned them at the "payload in, string out" level from
//! outside. Existing coverage is end-to-end (a pubkey becomes an address) or sits inside the
//! module's own unit tests, so a change to a checksum rule could leave "a BTC address was
//! produced" green while the string changed. These cases feed a CONSTRUCTED PAYLOAD to an encoder
//! that is public API, and pin what actually matters: exact bytes against an independent source,
//! checksums being checked on decode, and a short buffer failing without partial output.
//!
//! Golden provenance — read from a machine-readable source, never hand-copied:
//!   ~/codebases/bitcoin/src/test/data/key_io_valid.json  (Bitcoin Core, `key_io_valid.json`)
//! Each vector names the `scriptPubKey` it came from, so it can be re-derived by hand: the payload
//! is `version_byte || HASH160` for base58, and the address for segwit comes from the scriptPubKey
//! through `address::btc_script::render` (the assembly layer that picks the encoder).
//!
//! What is deliberately NOT here: `bech32::encode` / `encode_m` are `pub(crate)`, so the
//! encode-side segwit pins live in that module's own tests. The one property worth guarding from
//! both sides — a v0 string must not be accepted as v1 and vice versa — is pinned there, where
//! both variants are reachable.

use shlosilo::address::btc_script;
use shlosilo::encoding::base58;
use shlosilo::error::ShlosiloErrorKind;
use shlosilo::network::Network;

/// `scriptPubKey` bytes from Core's key_io_valid.json (hex in, bytes out).
fn spk(hex: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hex.len() / 2);
    let b = hex.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        let hi = (b[i] as char).to_digit(16).expect("hex") as u8;
        let lo = (b[i + 1] as char).to_digit(16).expect("hex") as u8;
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

/// `76 a9 14 <20> 88 ac` → payload `version || hash160`.
fn p2pkh_payload(script_hex: &str, version: u8) -> [u8; 21] {
    let bytes = spk(script_hex);
    let hash: [u8; 20] = bytes[3..23].try_into().expect("20-byte hash160");
    let mut payload = [0u8; 21];
    payload[0] = version;
    payload[1..].copy_from_slice(&hash);
    payload
}

/// `a9 14 <20> 87` → payload `version || script_hash`.
fn p2sh_payload(script_hex: &str, version: u8) -> [u8; 21] {
    let bytes = spk(script_hex);
    let hash: [u8; 20] = bytes[2..22].try_into().expect("20-byte script hash");
    let mut payload = [0u8; 21];
    payload[0] = version;
    payload[1..].copy_from_slice(&hash);
    payload
}

fn encode_check_str(payload: &[u8]) -> String {
    let mut out = [0u8; base58::BASE58_MAX_LEN];
    let n = base58::encode_check_into(payload, &mut out).expect("base58check");
    core::str::from_utf8(&out[..n]).expect("utf8").to_string()
}

// ── base58check: payload in, Core's address out ───────────────────────────────────────────

#[test]
fn base58check_matches_core_key_io_vectors() {
    // (scriptPubKey, version byte, expected address) — all from Core's key_io_valid.json
    let vectors: &[(&str, u8, &str)] = &[
        (
            "76a914a31c06bd463e3923bc1aadbde48b16976c08071788ac",
            0x00,
            "1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo",
        ),
        (
            "a914373b819a068f32b7a6b38b6b38729647cfde01c287",
            0x05,
            "36j4NfKv6Akva9amjWrLG6MuSQym1GuEmm",
        ),
        (
            "76a914ce28b26c57472737f5c3561a1761185bd8589a4388ac",
            0x6f,
            "mzK2FFDEhxqHcmrJw1ysqFkVyhUULo45hZ",
        ),
        (
            "a914ce0bba75891ff9ec60148d4bd4a09ee2dc5c933187",
            0xc4,
            "2NC2hEhe28ULKAJkW5MjZ3jtTMJdvXmByvK",
        ),
    ];
    for (script, version, expected) in vectors {
        let payload = if *version == 0x05 || *version == 0xc4 {
            p2sh_payload(script, *version)
        } else {
            p2pkh_payload(script, *version)
        };
        assert_eq!(
            encode_check_str(&payload),
            *expected,
            "base58check(version {version:#04x} || hash) must render Core's address"
        );
    }
}

#[test]
fn base58check_decode_rejects_a_damaged_checksum() {
    let payload = p2pkh_payload("76a914a31c06bd463e3923bc1aadbde48b16976c08071788ac", 0x00);
    let good = encode_check_str(&payload);

    // Every single-character corruption of the checksum section must be refused. Sweeping the
    // whole alphabet (not one hand-picked swap) is what makes this a checksum pin rather than a
    // demonstration that one typo happens to be caught.
    let body_len = good.len() - 4;
    let alphabet: Vec<char> = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        .chars()
        .collect();
    let mut checked = 0usize;
    for pos in body_len..good.len() {
        for c in &alphabet {
            let mut damaged: Vec<char> = good.chars().collect();
            if damaged[pos] == *c {
                continue;
            }
            damaged[pos] = *c;
            let s: String = damaged.into_iter().collect();
            let mut out = [0u8; base58::BASE58_MAX_LEN];
            let got = base58::decode_check_into(&s, &mut out);
            assert!(
                got.is_err(),
                "a corrupted checksum character at {pos} was accepted: {s}"
            );
            checked += 1;
        }
    }
    assert!(
        checked > 200,
        "the sweep must actually exercise the alphabet"
    );
}

#[test]
fn base58check_short_buffer_fails_without_partial_output() {
    let payload = p2pkh_payload("76a914a31c06bd463e3923bc1aadbde48b16976c08071788ac", 0x00);
    let mut small = [0xAAu8; 8]; // the address needs 34
    let err = base58::encode_check_into(&payload, &mut small)
        .expect_err("a buffer shorter than the encoding must be refused");
    assert_eq!(err.kind, ShlosiloErrorKind::EncodingBufferOverflow);
    assert_eq!(small, [0xAAu8; 8], "no partial output on refusal");
}

// ── segwit through the assembly layer: scriptPubKey in, Core's address out ────────────────

#[test]
fn segwit_addresses_render_from_core_script_pubkeys() {
    // scriptPubKey → address, all four shapes, from Core's key_io_valid.json. This is the
    // payload-construction + encoder path a reviewer actually sees, so a wrong witness version,
    // a wrong HRP or the bech32/bech32m mix-up all land here as a string mismatch.
    let vectors: &[(&str, Network, &str)] = &[
        (
            // OP_0 PUSH20 <program>: witness v0 → bech32 (BIP-173)
            "00146100fc6343edc8c874496cb2f5bbfec88ea9b77c",
            Network::BitcoinMainnet,
            "bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv",
        ),
        (
            // OP_1 PUSH32 <program>: witness v1 → bech32m (BIP-350)
            "51203c671ef1e3913f94980a9e146ba895908550ef4234abb7503d436521aba54c75",
            Network::BitcoinMainnet,
            "bc1p83n3au0rjylefxq2nc2xh2y4jzz4pm6zxj4mw5pagdjjr2a9f36s6jjnnu",
        ),
        (
            // a test-chain v1 program (its own bytes, not the mainnet one re-encoded): the HRP
            // changes, the bech32m rule does not
            "51208d2745489a35b75734afa2da43817d40e7e8d80d17a26cd4460b0055c521a3fa",
            Network::BitcoinTestnet,
            "tb1p35n52jy6xkm4wd905tdy8qtagrn73kqdz73xe4zxpvq9t3fp50aqk3s6gz",
        ),
        (
            // OP_HASH160 <20>: P2SH is base58check, not bech32 — the branch that must not drift
            "a914373b819a068f32b7a6b38b6b38729647cfde01c287",
            Network::BitcoinMainnet,
            "36j4NfKv6Akva9amjWrLG6MuSQym1GuEmm",
        ),
    ];
    for (script, network, expected) in vectors {
        let rendered = btc_script::render(&spk(script), *network).expect("render");
        assert_eq!(
            rendered.as_ref(),
            *expected,
            "scriptPubKey {script} on {network:?}"
        );
    }
}
