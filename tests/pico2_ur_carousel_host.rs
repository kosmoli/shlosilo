//! Host-side verification for the pico2 UR carousel (`ui ur`).
//!
//! The device renders fountain frames of a payload as a cycling QR
//! animation (`flux/pico2/src/ui.rs::qr_carousel_frame`, driven by
//! `console.rs::run_ui_ur`). This test proves, on the host and through
//! the SAME core API the device calls, that:
//!
//! 1. a real device-signed txset (3986 B - deliberately past the ~2953 B
//!    single-frame QR ceiling) encodes into a well-formed frame sequence;
//! 2. the core decoder reassembles the frames back to the exact payload;
//! 3. the frame set is dumped to /tmp/pico2_ur_frames.txt so an
//!    INDEPENDENT QR scanner (zxing, via the bench script
//!    `flux/pico2/bench/ur_frames_check.py`) can verify every frame
//!    renders and scans as a QR code.
//!
//! What this cannot check is the on-device rendering itself (pixels);
//! that is what the screen + phone scan acceptance covers.

use std::fs;

#[test]
fn ur_carousel_frames_roundtrip_real_signed_txset() {
    let payload =
        fs::read("tests/fixtures/signed_txset_1in_fresh.bin").expect("signed txset fixture");
    assert!(
        payload.len() > 2953,
        "fixture must exceed the single-frame v40/ECC-L byte ceiling for this test to mean anything"
    );

    let mut enc =
        shlosilo::ur::ur_multipart::UrMultipartEncoder::new("xmr-txunsigned", &payload, 200)
            .expect("encoder");
    let total = enc.fragment_count();
    assert!(total > 1, "a multi-frame payload is required");

    // The device cycles frames forever; emit two full cycles plus a few,
    // exactly the sequence `next_cyclic_frame` produces on-device.
    let mut frames = Vec::new();
    for _ in 0..(total * 2 + 3) {
        frames.push(enc.next_cyclic_frame().expect("frame"));
    }

    // Every frame is a well-formed multipart URI within the frame budget.
    for (i, f) in frames.iter().enumerate() {
        assert!(
            f.starts_with("ur:xmr-txunsigned/"),
            "frame {i} prefix: {f:.40}"
        );
        assert!(
            f.len() <= shlosilo::ur::ur_multipart::MULTIPART_FRAME_MAX_LEN,
            "frame {i} over budget: {}",
            f.len()
        );
    }

    // A single cycle must be enough for the decoder to reassemble the
    // payload, because that is the guarantee the carousel needs.
    let mut dec = shlosilo::ur::ur_multipart::UrMultipartDecoder::new();
    for f in frames.iter().take(total) {
        let _ = dec.receive_frame(f).expect("frame accepted");
    }
    assert!(
        dec.complete(),
        "decoder must complete after one full cycle of {total} frames"
    );
    let got = dec
        .payload()
        .expect("payload call")
        .expect("payload after completion");
    assert_eq!(got, payload, "reassembled payload must be byte-exact");

    println!(
        "payload {} B -> {total} frames; frame sizes {}..{} chars",
        payload.len(),
        frames.iter().map(|f| f.len()).min().unwrap(),
        frames.iter().map(|f| f.len()).max().unwrap(),
    );

    // Dump one cycle for the independent QR-scanner verification.
    let dump: String = frames
        .iter()
        .take(total)
        .map(|f| format!("{f}\n"))
        .collect();
    fs::write("/tmp/pico2_ur_frames.txt", dump).expect("dump frames");
    println!("one cycle dumped to /tmp/pico2_ur_frames.txt");
}
