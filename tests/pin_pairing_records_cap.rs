//! Red pin — KI pairing record cap (2026-10-29, the KI-sync silent-fail case).
//!
//! A Cake `Outputs (all)` for the grown test wallet carried **38 records**
//! and the pairing leg refused (cap 32 = 4x the largest wallet observed at
//! design time). Product contract pinned here:
//! - real-wallet record counts (38 = the live 2026-10-29 case) MUST pair;
//! - counts beyond the cap MUST refuse with a non-zero rc (the device layer
//!   must surface that refusal visibly — display is pinned at the flux
//!   layer, the refusal itself is pinned here).
#![cfg(feature = "alloc-fallback")]

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::rand_core::SeedableRng as _;
use shlosilo::business::xmr_pairing::pairing_ws_len;
use shlosilo::chain::xmr::key_image_export::encrypt_export_payload_into;
use shlosilo::chain::xmr::key_image_export::OUTPUT_EXPORT_MAGIC;
use shlosilo::chain::xmr::subaddress::calc_output_key_offset;
use shlosilo::ffi::c_abi::r3::shlosilo_xmr_pairing_ffi;
use shlosilo::types::key_session::KeySession;

fn point(sk: &[u8; 32]) -> [u8; 32] {
    (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*sk))
        .compress()
        .to_bytes()
}

/// Build a Cake-shaped `xmr-output` request container with `n` records
/// (wire shape mirrors tests/xmr_pairing_zero_alloc.rs).
fn build_request(n: usize) -> (KeySession, Vec<u8>, [u8; 32]) {
    let session = KeySession::from_entropy(&[0x11u8; 16], b"").unwrap();
    let keys = session.monero();
    let view_sk = *keys.view_sk.expose();
    let spend_sk = *keys.spend_sk.expose();

    let mut plain = Vec::new();
    plain.extend_from_slice(&[0x01, 0x00, n as u8, n as u8]); // head, offset, total, record_count
    for i in 0..n {
        let tx_pub = point(&[0x42u8.wrapping_add(i as u8); 32]);
        // distinct tx_pub per record, same slot convention as the known-good
        // zero-alloc call (0, 0) — each record derives a distinct KI.
        let offset = calc_output_key_offset(&view_sk, &tx_pub, 0, 0, 0).unwrap();
        let input_sk =
            Scalar::from_bytes_mod_order(spend_sk) + Scalar::from_bytes_mod_order(offset);
        let out_pub = (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes();
        plain.extend_from_slice(&[0x01]); // version
        plain.extend_from_slice(&out_pub);
        plain.push(0x00); // internal_output_index
        plain.push(i as u8); // global_output_index (varint, <128)
        plain.extend_from_slice(&tx_pub);
        plain.push(0b0001_0100); // rct | key_image_request
        plain.extend_from_slice(&[0x80, 0x96, 0x98, 0x91, 0x04]); // amount varint
        plain.push(0x00); // add_keys count
        plain.push(0x00); // major
        plain.push(0x00); // minor (matches the derivation above)
    }

    let spend_pub = point(&spend_sk);
    let view_pub = point(&view_sk);
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
    let mut req_buf = vec![0u8; 65536];
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
    .expect("encrypt request");
    let mut req = req_buf;
    req.truncate(req_n);
    (session, req, [7u8; 32])
}

fn run_pairing(session: &KeySession, req: &[u8], entropy: &[u8; 32]) -> i32 {
    let ws_len = pairing_ws_len();
    let mut ws = vec![0u8; ws_len as usize];
    let mut out = vec![0u8; 16384];
    let mut actual: u32 = 0;
    shlosilo_xmr_pairing_ffi(
        session,
        req.as_ptr(),
        req.len() as core::ffi::c_uint,
        entropy.as_ptr(),
        entropy.len() as core::ffi::c_uint,
        out.as_mut_ptr(),
        out.len() as core::ffi::c_uint,
        &mut actual,
        ws.as_mut_ptr(),
        ws.len() as core::ffi::c_uint,
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
    )
}

/// The live 2026-10-29 case: 38 records must pair (RED until the cap moves).
#[test]
fn pairing_accepts_38_record_wallet() {
    let (session, req, entropy) = build_request(38);
    let rc = run_pairing(&session, &req, &entropy);
    assert_eq!(rc, 0, "a 38-record Outputs(all) must pair (the live case)");
}

/// Beyond the cap: refuse (non-zero) — the device layer must show it.
#[test]
fn pairing_refuses_beyond_cap() {
    let (session, req, entropy) = build_request(65);
    let rc = run_pairing(&session, &req, &entropy);
    assert_ne!(rc, 0, "beyond the record cap must refuse");
}
