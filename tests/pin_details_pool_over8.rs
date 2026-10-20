//! MUST-RED pin — pool §37 ">8 outputs details pool cap" (shlosilo-待决与待验池.md).
//!
//! The pairing receive leg keeps its output-detail pool at
//! `PAIRING_DETAILS_MAX = 8` (forms/business/xmr_pairing.rs, carved into
//! `PairingWs`): a wallet export with more than 8 outputs hits the pool cap and
//! the leg hard-fails with `BufferTooSmall` (stable FFI code -20) instead of
//! answering the request (2026-10-19 inventory seg2).
//!
//! Pin: build a valid signed+encrypted 9-output `Monero output export\x04`
//! request (main-address outputs, keys derived exactly like a wallet would)
//! and drive it through the deployment receive leg
//! (`business::xmr_pairing::process_output_export`), asserting all nine
//! outputs are answered (parsed and given key images) — or at least that the
//! request is not rejected solely by the pool cap.
//!
//! This MUST fail today; the panic records the cap fact (9 > 8 -> -20) and the
//! fix direction (raise `PAIRING_DETAILS_MAX`/`PAIRING_RECORDS_MAX` to cover
//! real wallet output counts, or make the pool sizing dynamic).
//!
//! Run: cargo test --offline --test pin_details_pool_over8

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::rand_core::SeedableRng as _;
use shlosilo::business::xmr_pairing::{carve_pairing_ws, pairing_ws_len, process_output_export};
use shlosilo::chain::xmr::key_image_export::{encrypt_export_payload_into, OUTPUT_EXPORT_MAGIC};
use shlosilo::chain::xmr::subaddress::calc_output_key_offset;

/// The pinned export size: one output above the deployment details pool cap
/// (PAIRING_DETAILS_MAX = 8).
const NINE_OUTPUTS: usize = 9;

fn point(sk: &[u8; 32]) -> [u8; 32] {
    (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*sk))
        .compress()
        .to_bytes()
}

/// Independent LEB128 writer (fixture construction, same as
/// tests/epee_domain_probe.rs).
fn encode_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

/// Build an epee `export_outputs` plaintext with `count` main-address outputs
/// (major=0, minor=0), each with a wallet-faithful one-time output key:
/// out_pub = (spend_sk + Hs_a(tx_pub))·B, tx_pub = per-output throwaway.
fn build_plain(count: usize, view_sk: &[u8; 32], spend_sk: &[u8; 32]) -> Vec<u8> {
    let mut plain = Vec::new();
    encode_varint(1, &mut plain); // has_transfers
    encode_varint(0, &mut plain); // offset
    encode_varint(count as u64, &mut plain); // transfers total
    encode_varint(count as u64, &mut plain); // record count
    for i in 0..count {
        let tx_sk = [0x42u8.wrapping_add(i as u8 * 3); 32];
        let tx_pub = point(&tx_sk);
        let off = calc_output_key_offset(view_sk, &tx_pub, i as u64, 0, 0).unwrap();
        let input_sk = Scalar::from_bytes_mod_order(*spend_sk) + Scalar::from_bytes_mod_order(off);
        let out_pub = (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes();

        encode_varint(1, &mut plain); // record version
        plain.extend_from_slice(&out_pub); // output pubkey
        encode_varint(i as u64, &mut plain); // internal_output_index
        encode_varint(1000 + i as u64, &mut plain); // global_output_index
        plain.extend_from_slice(&tx_pub); // tx_pubkey
        plain.push(0b0000_0100); // flags (main address, no key-image request bit)
        encode_varint(1_000_000 + i as u64, &mut plain); // amount (piconero)
        encode_varint(0, &mut plain); // additional_tx_keys count
        encode_varint(0, &mut plain); // major
        encode_varint(0, &mut plain); // minor
    }
    plain
}

/// Pool §37: a 9-output export must not hard-fail on the details pool cap.
#[test]
fn pin_red_details_pool_handles_nine_outputs() {
    let view_sk = [6u8; 32];
    let spend_sk = [5u8; 32];
    let spend_pub = point(&spend_sk);
    let view_pub = point(&view_sk);

    let plain = build_plain(NINE_OUTPUTS, &view_sk, &spend_sk);

    // Wrap into the real signed+encrypted request container
    // (Monero output export\x04, envelope signature over keccak256(nonce||cipher)).
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(11);
    let mut req_buf = vec![0u8; 16384];
    let mut cn = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
    let req_n = encrypt_export_payload_into(
        OUTPUT_EXPORT_MAGIC,
        &view_sk,
        &spend_pub,
        &view_pub,
        0u32,
        &plain,
        &mut rng,
        &mut req_buf,
        &mut cn,
    )
    .expect("request container build");

    // Deployment receive leg — this is where the details pool is carved
    // (PAIRING_DETAILS_MAX = 8 inside PairingWs).
    let mut out = vec![0u8; 16384];
    let mut ws_raw = vec![0u8; pairing_ws_len()];
    let mut ws = carve_pairing_ws(&mut ws_raw).expect("carve pairing ws");

    let outcome = match process_output_export(
        &view_sk,
        &spend_sk,
        &req_buf[..req_n],
        &mut ws,
        &mut out,
        &mut rng,
    ) {
        Ok(o) => o,
        Err(e) => {
            let code = shlosilo::error::ShlosiloErrorCode::from_shlosilo_error(e);
            panic!(
                "PINNED RED: a 9-output export is rejected by the details pool cap — \
                 the pairing receive leg carves only PAIRING_DETAILS_MAX = 8 \
                 output-detail slots (forms/business/xmr_pairing.rs), so >8 outputs \
                 surface as BufferTooSmall = FFI {} (pool §37: >8 outputs -> -20 data \
                 error). Fix = raise PAIRING_DETAILS_MAX / PAIRING_RECORDS_MAX to \
                 cover real wallet output counts (or size the pool dynamically), so \
                 this request is answered instead of hard-failing",
                code
            );
        }
    };

    assert_eq!(
        outcome.output_count, NINE_OUTPUTS,
        "all nine outputs of the export must be parsed and answered with key images"
    );
}
