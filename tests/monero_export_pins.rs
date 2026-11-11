//! Monero export pins: the address and the exported view key must satisfy Monero's
//! own `keyValid` check, which is `view_pub(address) == view_priv · G` with the
//! scalar used **as-is**.
//!
//! This is the check Feather and Cake run before importing a view-only wallet, and it
//! is where the export shipped broken: the address was built with the Ed25519 *keygen*
//! primitive (`clamp(SHA512(seed))·G`), so the embedded view key could never match the
//! private key we exported. Both wallets refused the QR; the fix is `base_mul_raw`
//! (raw scalar multiplication, the same primitive the XMR signing path uses).
//!
//! The test decodes the address block-wise (Monero base58 is 11 chars -> 8 bytes, the
//! tail 7 chars -> 5 bytes; a plain whole-string base58 decode gives the wrong bytes)
//! and checks both public keys plus the checksum.

use shlosilo::business::export_format::{build, ExportFormat, ExportLabels};
use shlosilo::curve_primitive::ed25519::{
    base_mul, base_mul_raw, point_to_compressed, scalar_to_bytes,
};
use shlosilo::derivation::monero_reduce_scalar::{self, MoneroPath};
use shlosilo::network::Network;

const SEED_HEX: &str = "f284fb6ca9f4d5835455be65e4b22916";
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn seed() -> [u8; 64] {
    let entropy = {
        let mut e = [0u8; 16];
        for (i, chunk) in SEED_HEX.as_bytes().chunks(2).enumerate() {
            e[i] = u8::from_str_radix(core::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        e
    };
    shlosilo::entropy::mnemonic::Mnemonic::from_entropy(&entropy)
        .expect("mnemonic")
        .to_seed(b"")
}

fn decode_block(block: &[u8], out_len: usize) -> Vec<u8> {
    let mut digits: Vec<u8> = vec![0];
    for &c in block {
        let v = ALPHABET
            .iter()
            .position(|&a| a == c)
            .expect("base58 alphabet") as u32;
        let mut carry = v;
        for d in digits.iter_mut() {
            let x = (*d as u32) * 58 + carry;
            *d = (x & 0xff) as u8;
            carry = x >> 8;
        }
        while carry > 0 {
            digits.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut be = vec![0u8; out_len];
    for (i, d) in digits.iter().enumerate() {
        if i < out_len {
            be[out_len - 1 - i] = *d;
        }
    }
    be
}

fn decode_address(addr: &str) -> Vec<u8> {
    let b = addr.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while b.len() - i >= 11 {
        out.extend_from_slice(&decode_block(&b[i..i + 11], 8));
        i += 11;
    }
    if b.len() - i == 7 {
        out.extend_from_slice(&decode_block(&b[i..], 5));
    }
    out
}

fn json_field(json: &str, field: &str) -> String {
    let pat = std::format!("\"{field}\":\"");
    let start = json
        .find(&pat)
        .unwrap_or_else(|| panic!("no {field} in {json}"))
        + pat.len();
    let end = json[start..].find('"').expect("closing quote") + start;
    json[start..end].to_string()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn exported_monero_pair_passes_moneros_own_keyvalid() {
    let labels = ExportLabels {
        label: Some("pin-test"),
        key_name: None,
        device: None,
        device_id: None,
        device_version: None,
        restore_height: 0,
    };
    let mut out = vec![0u8; 4096];
    let n = build(
        ExportFormat::MoneroJsonKeystone,
        &seed(),
        Network::BitcoinMainnet, // the Monero shapes ignore it
        &labels,
        &mut out,
    )
    .expect("export builds");
    let json = core::str::from_utf8(&out[..n]).expect("json");
    let addr = json_field(json, "primaryAddress");
    let view_hex = json_field(json, "privateViewKey");

    // --- decode what a wallet decodes ---
    let raw = decode_address(&addr);
    assert_eq!(raw.len(), 69, "standard address = 65 + 4");
    let payload = &raw[..65];
    let checksum_ok =
        shlosilo::encoding::keccak256::hash(payload).expect("keccak")[..4] == raw[65..69];
    assert!(checksum_ok, "keccak checksum must verify");
    assert_eq!(payload[0], 0x12, "Monero mainnet standard address byte");

    let spend_pub_in_addr = &payload[1..33];
    let view_pub_in_addr = &payload[33..65];

    // --- what we derived ---
    let kp = monero_reduce_scalar::derive(&seed(), &MoneroPath::mainnet(0)).expect("derive");
    let spend_bytes = scalar_to_bytes(kp.spend_priv());
    let view_bytes = scalar_to_bytes(kp.view_priv());
    assert_eq!(
        view_hex,
        hex(&view_bytes),
        "exported view key is the raw scalar"
    );

    let raw_spend = point_to_compressed(&base_mul_raw(&spend_bytes).expect("spend"));
    let raw_view = point_to_compressed(&base_mul_raw(&view_bytes).expect("view"));
    assert_eq!(
        spend_pub_in_addr,
        &raw_spend[..],
        "spend pub = s*G (Monero)"
    );
    assert_eq!(view_pub_in_addr, &raw_view[..], "view pub = v*G (Monero)");

    // --- and the keygen primitive would NOT match: keep the two apart ---
    let clamped_view = point_to_compressed(&base_mul(
        &shlosilo::curve_primitive::ed25519::scalar_from_bytes(&view_bytes).expect("scalar"),
    ));
    assert_ne!(
        view_pub_in_addr,
        &clamped_view[..],
        "the Ed25519 keygen form must not be what an address carries"
    );
}
