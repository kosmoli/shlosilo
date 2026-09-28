//! Z3.3b/3.3c UR decode workspace contract — v1 pin tests.
//!
//! The v1 decision (2026-09-28): C ABI UR decode runs on a caller-provided
//! workspace — handle / frame scratch / pool slots are carved once;
//! per-call allocation and leakage are out of the receive path. `free`
//! zeroes sensitive spans and drops in place (no deallocation).
//!
//! Each numbered invariant gets its own pin below.

use std::alloc::{GlobalAlloc, Layout, System};

struct Counting;
// Per-thread counting: cargo test runs tests on parallel threads — a global
// counter mixes threads and poisons the measurement windows (the
// capture-path lesson's cousin). Each test measures its own thread.
thread_local! {
    static THREAD_ALLOCS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        THREAD_ALLOCS.with(|c| c.set(c.get() + 1));
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        THREAD_ALLOCS.with(|c| c.set(c.get() + 1));
        unsafe { System.realloc(p, l, n) }
    }
}
#[global_allocator]
static A: Counting = Counting;

use shlosilo::ffi::c_abi::r3::{
    shlosilo_ur_decode_feed, shlosilo_ur_decode_free, shlosilo_ur_decode_new,
    shlosilo_ur_decode_payload, shlosilo_ur_encode_begin, shlosilo_ur_encode_free,
    shlosilo_ur_encode_next,
};
use shlosilo::ffi::c_abi::shlosilo_ur_decode_ws_len;
use shlosilo::ur::ur_multipart::UrDecodeWsLayout;

fn counter() -> usize {
    THREAD_ALLOCS.with(|c| c.get())
}

/// Fixture: drive the encoder to get a real multipart frame set.
fn encode_frames(payload: &[u8]) -> Vec<String> {
    use shlosilo::ur::ur_multipart::ur_encode_ws_len;
    let mut frames = Vec::new();
    let tname = std::ffi::CString::new("bytes").unwrap();
    let enc_ws_len = ur_encode_ws_len();
    let mut enc_ws = vec![0u8; enc_ws_len];
    let enc = shlosilo_ur_encode_begin(
        tname.as_ptr(),
        payload.as_ptr(),
        payload.len() as u32,
        200,
        enc_ws.as_mut_ptr(),
        enc_ws_len as u32,
    );
    assert!(!enc.is_null());
    for _ in 0..64 {
        let mut buf = vec![0u8; 4096];
        let mut n: u32 = 0;
        let rc = shlosilo_ur_encode_next(enc, buf.as_mut_ptr(), buf.len() as u32, &mut n);
        if rc != 0 || n == 0 {
            break;
        }
        buf.truncate(n as usize);
        frames.push(String::from_utf8(buf).unwrap());
    }
    shlosilo_ur_encode_free(enc);
    frames
}

/// Invariant 2: under-capacity ws returns NULL before anything is created;
/// exact capacity constructs.
#[test]
fn inv2_ws_capacity_contract() {
    let need = shlosilo_ur_decode_ws_len() as usize;
    let mut ws = vec![0u8; need];
    assert!(shlosilo_ur_decode_new(ws.as_mut_ptr(), (need - 1) as u32).is_null());
    let h = shlosilo_ur_decode_new(ws.as_mut_ptr(), need as u32);
    assert!(!h.is_null());
    shlosilo_ur_decode_free(h);
}

/// Invariants 3/4/6: the receive path (feed + payload) allocates zero times
/// per call, the BufferTooSmall retry learns the size without allocating,
/// and the roundtrip payload matches byte-for-byte.
#[test]
fn inv346_receive_path_zero_alloc() {
    let payload: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
    let frames = encode_frames(&payload);
    assert!(frames.len() >= 2);

    let need = shlosilo_ur_decode_ws_len() as usize;
    let mut ws = vec![0u8; need];
    let h = shlosilo_ur_decode_new(ws.as_mut_ptr(), need as u32);
    assert!(!h.is_null());

    // Measurement windows wrap ONLY the FFI calls (fixture allocations —
    // CStrings, out buffers — stay outside; the capture-path lesson).
    let cstrs: Vec<std::ffi::CString> = frames
        .iter()
        .map(|f| std::ffi::CString::new(f.as_str()).unwrap())
        .collect();
    let mut accepted: u32 = 0;

    let c0 = counter();
    for cstr in &cstrs {
        let rc = shlosilo_ur_decode_feed(h, cstr.as_ptr(), &mut accepted);
        assert_eq!(rc, 0, "feed must succeed");
    }
    let spent_feed = counter() - c0;
    assert_eq!(
        spent_feed, 0,
        "feed must allocate zero times (got {spent_feed})"
    );

    // invariant 4: undersized out buffer -> BufferTooSmall + required
    // capacity (message incl. fragment padding); delivery reports the true
    // length (padding excluded). No allocation on either leg.
    let mut actual: u32 = 0;
    let mut small = [0u8; 4];
    let c1 = counter();
    let rc = shlosilo_ur_decode_payload(h, small.as_mut_ptr(), 4, &mut actual);
    let spent_probe = counter() - c1;
    assert_ne!(rc, 0, "undersized payload buffer must fail");
    assert_eq!(spent_probe, 0, "the capacity probe must not allocate");
    let required = actual as usize;
    assert!(required >= payload.len(), "required must cover the payload");

    // and the sized call delivers the bytes
    let mut out = vec![0u8; required];
    let c2 = counter();
    let rc = shlosilo_ur_decode_payload(h, out.as_mut_ptr(), out.len() as u32, &mut actual);
    let spent_pull = counter() - c2;
    assert_eq!(rc, 0);
    assert_eq!(spent_pull, 0, "the payload pull must not allocate");
    let delivered = actual as usize;
    assert!(
        required >= delivered,
        "capacity covers delivery (contract 4)"
    );
    // byte equality: the UR message body IS the payload (the CBOR envelope
    // lives in the per-frame Part layer, not the message)
    assert_eq!(&out[..delivered], &payload[..], "payload byte-equal");

    shlosilo_ur_decode_free(h);
}

/// Invariant 5: free zeroes the sensitive spans before dropping in place.
#[test]
fn inv5_free_zeroizes_sensitive_spans() {
    let payload: Vec<u8> = (0..256u32).map(|i| (i % 251) as u8).collect();
    let frames = encode_frames(&payload);
    let need = shlosilo_ur_decode_ws_len() as usize;
    let mut ws = vec![0u8; need];
    let h = shlosilo_ur_decode_new(ws.as_mut_ptr(), need as u32);
    assert!(!h.is_null());
    for f in &frames {
        let cstr = std::ffi::CString::new(f.as_str()).unwrap();
        let mut accepted: u32 = 0;
        assert_eq!(shlosilo_ur_decode_feed(h, cstr.as_ptr(), &mut accepted), 0);
    }
    shlosilo_ur_decode_free(h);
    let l = UrDecodeWsLayout::compute();
    // every byte of the sensitive spans is zero after free
    for off in [l.decoded, l.buffer, l.queue, l.received, l.scratch] {
        assert_eq!(ws[off], 0, "span at {off} not zeroed");
    }
    // full-span check on the scratch (the frame CBOR copy)
    assert!(ws[l.scratch..l.scratch + 32].iter().all(|&b| b == 0));
}
