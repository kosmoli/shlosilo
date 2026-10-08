//! Z6 runtime receipt: the Cake pairing receive leg
//! (`shlosilo_xmr_pairing_ffi`, the product face the forgebox staticlib
//! exports) performs ZERO heap allocations in steady state once the deploy
//! shape is provided: caller workspace (`PairingWs`, incl. the CryptoNight
//! key-derivation scratchpad) + caller entropy stream. Mirrors the
//! `xmr_sign_zero_alloc` instrument (counting `#[global_allocator]`, one
//! warm-up call first to absorb lazy init, only the FFI call inside the
//! measured window).
//!
//! This file carries exactly ONE test: a global counter would mix sibling
//! threads' allocations into the window (see the zero-heap instrument notes).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static MEASURING: AtomicBool = AtomicBool::new(false);
static EVENTS: AtomicU64 = AtomicU64::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if MEASURING.load(Ordering::Relaxed) {
            EVENTS.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if MEASURING.load(Ordering::Relaxed) {
            EVENTS.fetch_add(1, Ordering::Relaxed);
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn measured<T>(f: impl FnOnce() -> T) -> (T, u64) {
    EVENTS.store(0, Ordering::Relaxed);
    MEASURING.store(true, Ordering::Relaxed);
    let out = f();
    MEASURING.store(false, Ordering::Relaxed);
    (out, EVENTS.load(Ordering::Relaxed))
}

/// The pairing receive leg on the product FFI face is alloc-free: the CN key
/// derivation rides the workspace `cn_scratch`, every other buffer is caller
/// storage. A single allocation in the measured section fails the test.
#[test]
fn pairing_ffi_zero_alloc() {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    use rand_chacha::rand_core::SeedableRng as _;
    use shlosilo::business::xmr_pairing::pairing_ws_len;
    use shlosilo::chain::xmr::key_image_export::{
        encrypt_export_payload_into, KEY_IMAGE_EXPORT_MAGIC, OUTPUT_EXPORT_MAGIC,
    };
    use shlosilo::chain::xmr::output_export::KEY_IMAGE_RECORD_LEN;
    use shlosilo::chain::xmr::subaddress::calc_output_key_offset;
    use shlosilo::ffi::c_abi::r3::shlosilo_xmr_pairing_ffi;
    use shlosilo::types::key_session::KeySession;

    fn point(sk: &[u8; 32]) -> [u8; 32] {
        (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*sk))
            .compress()
            .to_bytes()
    }

    // ── fixture prep (OUTSIDE the measured window) ──────────────────────────
    let session = KeySession::from_entropy(&[0x11u8; 16], b"").unwrap();
    let keys = session.monero();
    let view_sk = *keys.view_sk.expose();
    let spend_sk = *keys.spend_sk.expose();
    let spend_pub = point(&spend_sk);
    let view_pub = point(&view_sk);

    // One main-address output with the key-image-request bit set (the same
    // plaintext shape the real wallet emits).
    let tx_pub = point(&[0x42u8; 32]);
    let offset = calc_output_key_offset(&view_sk, &tx_pub, 0, 0, 0).unwrap();
    let input_sk = Scalar::from_bytes_mod_order(spend_sk) + Scalar::from_bytes_mod_order(offset);
    let out_pub = (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes();
    let mut plain = Vec::new();
    plain.extend_from_slice(&[0x01, 0x00, 0x01, 0x00]); // has_transfers, offset, count, blob_size
    plain.extend_from_slice(&[0x01]); // version
    plain.extend_from_slice(&out_pub);
    plain.extend_from_slice(&[0x00]); // internal_output_index
    plain.extend_from_slice(&[0x64]); // global_output_index = 100
    plain.extend_from_slice(&tx_pub);
    plain.push(0b0001_0100); // rct | key_image_request
    plain.extend_from_slice(&[0x80, 0x96, 0x98, 0x91, 0x04]); // amount varint
    plain.extend_from_slice(&[0x00, 0x00, 0x00]); // no add keys, major=0, minor=0

    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
    let mut req_buf = vec![0u8; 2048];
    let mut cn = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
    let req_n = encrypt_export_payload_into(
        OUTPUT_EXPORT_MAGIC,
        &view_sk,
        &spend_pub,
        &view_pub,
        &plain,
        &mut rng,
        &mut req_buf,
        &mut cn,
    )
    .unwrap();
    let req = &req_buf[..req_n];

    let entropy = [7u8; 32];
    let mut out = vec![0u8; 8192];
    let mut ws = vec![0u8; pairing_ws_len()];

    // PURE PROBE: ws == NULL reports the workspace requirement.
    let mut actual: core::ffi::c_uint = 0;
    let rc = shlosilo_xmr_pairing_ffi(
        &session,
        req.as_ptr(),
        req.len() as core::ffi::c_uint,
        entropy.as_ptr(),
        entropy.len() as core::ffi::c_uint,
        out.as_mut_ptr(),
        out.len() as core::ffi::c_uint,
        &mut actual,
        core::ptr::null_mut(),
        0,
    );
    assert_eq!(rc, 0, "pure probe must succeed");
    assert_eq!(actual as usize, pairing_ws_len());

    // Instrument self-check: the counter must observe a known allocation —
    // a broken MEASURING flag would otherwise make every receipt vacuous.
    let (_v, probe_events) = measured(|| vec![0u8; 1]);
    assert!(
        probe_events > 0,
        "the counting allocator must observe allocations"
    );

    // Warm-up (lazy init outside the measured window).
    let rc = shlosilo_xmr_pairing_ffi(
        &session,
        req.as_ptr(),
        req.len() as core::ffi::c_uint,
        entropy.as_ptr(),
        entropy.len() as core::ffi::c_uint,
        out.as_mut_ptr(),
        out.len() as core::ffi::c_uint,
        &mut actual,
        ws.as_mut_ptr(),
        ws.len() as core::ffi::c_uint,
    );
    assert_eq!(rc, 0, "warm-up pairing call must succeed");

    // ── measured section: only the FFI call ─────────────────────────────────
    let (rc, events) = measured(|| {
        shlosilo_xmr_pairing_ffi(
            &session,
            req.as_ptr(),
            req.len() as core::ffi::c_uint,
            entropy.as_ptr(),
            entropy.len() as core::ffi::c_uint,
            out.as_mut_ptr(),
            out.len() as core::ffi::c_uint,
            &mut actual,
            ws.as_mut_ptr(),
            ws.len() as core::ffi::c_uint,
        )
    });
    assert_eq!(rc, 0, "measured pairing call must succeed");
    assert_eq!(
        events, 0,
        "Z6: the pairing receive leg allocated {events} time(s)"
    );

    // Response container shape: 1 key-image record (no CN — length math only).
    let n = actual as usize;
    assert_eq!(
        n,
        KEY_IMAGE_EXPORT_MAGIC.len() + 140 + KEY_IMAGE_RECORD_LEN,
        "response must carry exactly one 96B key-image record"
    );
}
