//! P63-XMR decisive diagnostics: call monero-clsag::verify with the wire blob's own data
//!
//! Logic: parse /tmp/signed_tx.hex → extract the ring (mixRing needed before pseudoOuts, from the fixture)
//! The key is reproducing monerod's verify inputs:
//!   - ring = fixture sources[0].outputs (dest, commitment=mask|amount)
//!   - I = wire vin key image
//!   - pseudo_out = wire pseudoOuts[0]
//!   - D, s, c1 = wire CLSAGs[0]
//!   - msg_hash = keccak(prefix_hash + H(base) + BP elements) - recomputed from the wire
//!
//! If local verify fails ⇒ msg_hash differs from the wire (a different value was used when signing); if it succeeds ⇒ the mixRing expansion differs from monerod's.

use std::fs;

#[test]
#[ignore]
fn diag_clsag_verify_from_wire() {
    let hex = fs::read_to_string("/tmp/signed_tx.hex").unwrap();
    let blob: Vec<u8> = hex
        .trim()
        .as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect();
    println!("blob len: {}", blob.len());

    // uses the same env as p63_xmr_sign to get the fixture (via TxConstructionData)
    let view_sk_hex = std::env::var("SHLOSILO_TEST_XMR_VIEW_SK").unwrap();
    let spend_sk_hex = std::env::var("SHLOSILO_TEST_XMR_SPEND_SK").unwrap();
    let _ = (view_sk_hex, spend_sk_hex);

    // recomputing msg_hash fully needs construction-side data — expose sign's intermediate value directly instead:
    // prints the s/c1/D/pseudo_out and key image of the wire's CLSAG section for manual comparison against the official verRctCLSAGSimple.
    let _ = &blob;

    // TODO-full: complete the end-to-end local verification once tx_signer exposes a diag interface.
}
