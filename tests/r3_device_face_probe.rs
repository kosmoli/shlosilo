//! R3 device-face probe: replicates the forgebox smoke battery's exact FFI
//! multipart composition (1024-byte payload, 200-byte max-part, ws-provisioned
//! handles) plus the mixed-redundancy recovery probe, so the device-only
//! faces can execute on host where iteration is fast.
//!
//! Run matrix (the second is the device face):
//!   cargo test --test r3_device_face_probe
//!   cargo test --no-default-features --features \
//!     "generator-cache-ffi,cn-timing-ffi,tx-phase-timing-ffi,device-timing,perf-bench-ffi" \
//!     --test r3_device_face_probe
//! Optionally add --target armv7-unknown-linux-musleabihf (qemu-arm runner)
//! for the 32-bit width face.

use std::ffi::{c_char, CString};

use shlosilo::ffi::c_abi::r3::{
    shlosilo_ur_decode_complete, shlosilo_ur_decode_feed, shlosilo_ur_decode_free,
    shlosilo_ur_decode_new, shlosilo_ur_decode_payload, shlosilo_ur_decode_progress,
    shlosilo_ur_encode_begin, shlosilo_ur_encode_free, shlosilo_ur_encode_next,
};
use shlosilo::ffi::c_abi::{shlosilo_ur_decode_ws_len, shlosilo_ur_encode_ws_len};
use shlosilo::ur::ur_multipart::{UrMultipartDecoder, UrMultipartEncoder};

const OK: i32 = 0;
const GUARD: u32 = 500;

/// IEEE 802.3 reflected CRC32 (same spec as the firmware's gc_crc32) — frame
/// digests are compared byte-level against the battery's hardcoded table.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// The smoke battery's synthetic payload: mp_payload[i] = i % 251.
fn smoke_payload() -> Vec<u8> {
    (0..1024u32).map(|i| (i % 251) as u8).collect()
}

struct Handles {
    _enc_ws: Vec<u8>,
    _dec_ws: Vec<u8>,
    enc: *mut UrMultipartEncoder<'static>,
    dec: *mut UrMultipartDecoder<'static>,
}

impl Handles {
    fn new(payload: &[u8]) -> Handles {
        let enc_ws_len = shlosilo_ur_encode_ws_len() as usize;
        let dec_ws_len = shlosilo_ur_decode_ws_len() as usize;
        let mut enc_ws = vec![0u8; enc_ws_len];
        let mut dec_ws = vec![0u8; dec_ws_len];
        let tname = CString::new("xmr-txunsigned").unwrap();
        let enc = shlosilo_ur_encode_begin(
            tname.as_ptr(),
            payload.as_ptr(),
            payload.len() as u32,
            200,
            enc_ws.as_mut_ptr(),
            enc_ws_len as u32,
        );
        let dec = shlosilo_ur_decode_new(dec_ws.as_mut_ptr(), dec_ws_len as u32);
        assert!(!enc.is_null(), "encode_begin returned null");
        assert!(!dec.is_null(), "decode_new returned null");
        Handles {
            _enc_ws: enc_ws,
            _dec_ws: dec_ws,
            enc,
            dec,
        }
    }

    /// Next encoder frame (the encoder NUL-terminates at out[n]; the C side
    /// feeds the buffer straight to decode_feed — smoke parity).
    fn next_frame(&mut self, frame: &mut [u8]) -> Result<usize, i32> {
        let mut actual: u32 = 0;
        let rc = shlosilo_ur_encode_next(
            self.enc,
            frame.as_mut_ptr(),
            frame.len() as u32,
            &mut actual,
        );
        if rc != OK {
            return Err(rc);
        }
        Ok(actual as usize)
    }

    fn feed(&mut self, frame: &[u8]) -> (i32, u32) {
        let mut accepted: u32 = 9;
        let rc = shlosilo_ur_decode_feed(self.dec, frame.as_ptr() as *const c_char, &mut accepted);
        (rc, accepted)
    }

    fn complete(&self) -> bool {
        shlosilo_ur_decode_complete(self.dec) != 0
    }

    fn progress(&self) -> i32 {
        shlosilo_ur_decode_progress(self.dec)
    }

    fn payload(&mut self, out: &mut [u8]) -> Result<usize, i32> {
        let mut actual: u32 = 0;
        let rc =
            shlosilo_ur_decode_payload(self.dec, out.as_mut_ptr(), out.len() as u32, &mut actual);
        if rc != OK {
            return Err(rc);
        }
        Ok(actual as usize)
    }
}

impl Drop for Handles {
    fn drop(&mut self) {
        shlosilo_ur_encode_free(self.enc);
        shlosilo_ur_decode_free(self.dec);
    }
}

/// The smoke battery's step-7 composition: feed encoder frames to a paired
/// decoder until complete (guard 500), payload must round-trip exactly.
#[test]
fn smoke_composition_roundtrip() {
    let payload = smoke_payload();
    let mut h = Handles::new(&payload);
    let mut frame = vec![0u8; 1024]; // FRAME_BUF_MAX_LEN parity
    let mut guard = 0u32;

    while !h.complete() {
        let flen = h
            .next_frame(&mut frame)
            .unwrap_or_else(|rc| panic!("encode_next rc={rc} seq={}", guard + 1));
        let (frc, acc) = h.feed(&frame[..=flen]);
        if guard < 12 {
            eprintln!(
                "f{}: len={} crc={:08x} feed={} acc={} p={}",
                guard + 1,
                flen,
                crc32(&frame[..flen]),
                frc,
                acc,
                h.progress()
            );
        }
        assert_eq!(frc, OK, "decode_feed rc={frc} seq={}", guard + 1);
        guard += 1;
        assert!(guard <= GUARD, "guard exceeded, progress={}", h.progress());
    }

    let mut out = vec![0u8; 2048];
    let n = h.payload(&mut out).expect("decode_payload");
    assert_eq!(n, payload.len(), "payload length mismatch");
    if let Some(i) = out[..n]
        .iter()
        .zip(payload.iter())
        .position(|(a, b)| a != b)
    {
        panic!(
            "payload bytes mismatch at {i}: {:02x} != {:02x}",
            out[i], payload[i]
        );
    }
    eprintln!("roundtrip PASS ({guard} frames)");
}

/// Mixed-redundancy recovery: give the decoder frames 1..5, withhold the
/// seq-6 frame (the 6th simple fragment = the message tail), then feed only
/// seq>count MIXED frames — the tail must arrive via fountain recovery.
#[test]
fn mixed_recovery_probe() {
    let payload = smoke_payload();
    let mut h = Handles::new(&payload);
    let mut frame = vec![0u8; 1024];
    let mut fed = 0u32;

    while fed < 5 {
        let flen = h.next_frame(&mut frame).expect("encode_next");
        let (frc, _) = h.feed(&frame[..=flen]);
        assert_eq!(frc, OK);
        fed += 1;
    }
    // Discard the seq-6 frame: from here on the decoder sees only mixed parts.
    h.next_frame(&mut frame).expect("encode_next seq6");

    let mut guard = 0u32;
    while !h.complete() {
        let flen = h
            .next_frame(&mut frame)
            .unwrap_or_else(|rc| panic!("encode_next rc={rc} mixed seq={}", guard + 7));
        let (frc, acc) = h.feed(&frame[..=flen]);
        if guard < 12 {
            eprintln!(
                "mx{}: len={} crc={:08x} feed={} acc={} p={}",
                guard + 7,
                flen,
                crc32(&frame[..flen]),
                frc,
                acc,
                h.progress()
            );
        }
        assert_eq!(frc, OK, "mixed feed rc={frc}");
        guard += 1;
        assert!(
            guard <= GUARD,
            "mixed guard exceeded, progress={}",
            h.progress()
        );
    }

    let mut out = vec![0u8; 2048];
    let n = h.payload(&mut out).expect("decode_payload");
    assert_eq!(n, payload.len());
    assert!(
        out[..n].iter().zip(payload.iter()).all(|(a, b)| a == b),
        "mixed recovery payload mismatch"
    );
    eprintln!("mixed recovery PASS ({} mixed frames)", guard);
}
