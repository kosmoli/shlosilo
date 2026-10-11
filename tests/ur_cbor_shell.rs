//! CBOR byte-string shell bidirectional compatibility (2026-10-12).
//!
//! Inbound: strip a complete definite CBOR byte-string shell; bare messages
//! pass through (Cake's xmr-txunsigned leg is bare on the wire — the real
//! capture reassembles to `Monero unsigned tx set\x05...`).
//! Outbound: `ur_encode` wraps the container in the short shell forms
//! (`0x58`+1B / `0x59`+2B) before bytewords (keystone-ur Bytes /
//! monero_c `CborLite::encodeBytes` shape).
//!
//! Regression pin: `tests/fixtures/cake_real_frames.txt` — the two real-capture
//! Cake `xmr-output` animation frames (2026-10-11 photo decode). Reassembled
//! wire message = 242 B `58 f0 4d 6f 6e 65 72...` = shell(240) + wallet2
//! container; after the strip the payload must be the 240 B container whose
//! head is `4d6f6e6572` ("Moner").

use shlosilo::encoding::bytewords;
use shlosilo::ur::ur_decode;
use shlosilo::ur::ur_encode::{encode, UrTypeTag};
use shlosilo::ur::ur_multipart::{UrMultipartDecoder, UrMultipartEncoder};
use shlosilo::ur::ur_shell::{ur_message_content, ur_message_shell_len};

/// Decode the bytewords body of a single-frame URI back to the raw wire message.
fn wire_of(uri: &str) -> Vec<u8> {
    let body = uri.rsplit_once('/').expect("uri shape").1;
    let mut buf = vec![0u8; body.len()];
    let n = bytewords::decode_minimal_into(body, &mut buf).expect("bytewords");
    buf.truncate(n);
    buf
}

/// Single-frame URI built from a raw wire message WITHOUT the outbound wrap
/// (what a real peer's camera frame decodes to).
fn uri_of_wire(type_name: &str, wire: &[u8]) -> String {
    let mut buf = vec![0u8; wire.len() * 2 + 16];
    let mut n = 0usize;
    bytewords::encode_minimal_into(wire, &mut buf, &mut n).expect("bytewords");
    format!("ur:{type_name}/{}", std::str::from_utf8(&buf[..n]).unwrap())
}

fn container240() -> Vec<u8> {
    // wallet2 export_outputs container shape: `Monero output export\x04` + body
    let mut c = b"Monero output export\x04".to_vec();
    c.extend((0..219u8).map(|i| i ^ 0x5a));
    c.resize(240, 0xEE);
    c
}

// ─── (a) inbound: shell and bare forms yield the same container bytes ───────

#[test]
fn inbound_shell_and_bare_yield_same_container() {
    let container = container240();
    let mut shelled = vec![0x58u8, 0xf0];
    shelled.extend_from_slice(&container);
    assert_eq!(shelled.len(), 242);

    // pure function
    assert_eq!(ur_message_content(&shelled), &container[..]);
    assert_eq!(ur_message_content(&container), &container[..]);

    // single-frame exit: both wire forms decode to the same container
    let bare_uri = uri_of_wire("xmr-output", &container);
    let shelled_uri = uri_of_wire("xmr-output", &shelled);
    let bare = ur_decode::decode(&bare_uri).unwrap();
    let shell = ur_decode::decode(&shelled_uri).unwrap();
    assert_eq!(
        bare.as_ref(),
        &container[..],
        "bare leg (Cake txunsigned quirk)"
    );
    assert_eq!(
        shell.as_ref(),
        &container[..],
        "shell leg (Cake xmr-output)"
    );

    // multipart exit: the encoder owns the shell (2026-10-12), so the wire
    // message is the CBOR bytes item and the decode exit strips it back --
    // roundtrip delivers the container. Bare multipart WIRE tolerance (the
    // Cake xmr-txunsigned quirk) is pinned by the real-cake frames regression
    // (tests/ur_layer_probe.rs, artifacts/frames.txt) and the unit cases above.
    {
        let mut enc = UrMultipartEncoder::new("xmr-output", &container, 128).unwrap();
        let mut frames = Vec::new();
        for _ in 0..enc.fragment_count() {
            frames.push(enc.next_frame().unwrap());
        }
        let mut dec = UrMultipartDecoder::new();
        for f in &frames {
            dec.receive_frame(f).unwrap();
        }
        let mut out = vec![0u8; 16384];
        let n = dec.payload_into(&mut out).unwrap().expect("complete");
        assert_eq!(&out[..n], &container[..], "multipart shelled roundtrip");
    }
}

// ─── (b) exhaustion criterion: bare messages must never be mis-stripped ────

#[test]
fn exhaustion_criterion_blocks_bare_misfire() {
    // Real bare xmr-txunsigned message: 23 B, head 0x4d ('M') claims an inline
    // 13-byte byte-string — 1+13=14 ≠ 23, so the strip must refuse.
    let mut bare = b"Monero unsigned tx set\x05".to_vec();
    bare.extend_from_slice(&[0xAA; 7]); // container body
    assert_eq!(bare.len(), 30);
    assert_eq!(bare[0], 0x4d);
    assert_eq!(
        ur_message_content(&bare),
        &bare[..],
        "bare must pass through"
    );

    // positive control: the same head exactly consuming the message strips.
    let mut exact = vec![0x4du8];
    exact.extend_from_slice(&bare[1..14]); // 1 + 13 = 14
    assert_eq!(ur_message_content(&exact), &bare[1..14]);

    // trailing garbage after a valid shell → not a complete item → bare
    let mut odd = vec![0x58u8, 0x02, 0x01, 0x02, 0xff];
    assert_eq!(ur_message_content(&odd), &odd[..]);
    odd.truncate(3); // head claims 2 bytes, only 1 present → bare
    assert_eq!(ur_message_content(&odd), &odd[..]);

    // through the decode exits too
    let uri = uri_of_wire("xmr-txunsigned", &bare);
    let d = ur_decode::decode(&uri).unwrap();
    assert_eq!(d.as_ref(), &bare[..], "single-frame exit must not misfire");
    let mut enc = UrMultipartEncoder::new("xmr-txunsigned", &bare, 64).unwrap();
    let mut frames = Vec::new();
    for _ in 0..enc.fragment_count() {
        frames.push(enc.next_frame().unwrap());
    }
    let mut dec = UrMultipartDecoder::new();
    for f in &frames {
        dec.receive_frame(f).unwrap();
    }
    let mut out = vec![0u8; 4096];
    let n = dec.payload_into(&mut out).unwrap().unwrap();
    assert_eq!(&out[..n], &bare[..], "multipart exit must not misfire");
}

// ─── (c) outbound: the message carries the shell, its content is the container ──

#[test]
fn outbound_message_carries_shell_with_container_content() {
    let container = container240();

    // 240 B container → 0x58 0xf0 shell — byte-identical to the real Cake
    // capture's message head.
    let uri = encode(UrTypeTag::XmrKeyImage, &container).unwrap();
    let wire = wire_of(uri.as_str());
    assert_eq!(wire.len(), ur_message_shell_len(240).unwrap());
    assert_eq!(&wire[..2], &[0x58, 0xf0]);
    assert_eq!(ur_message_content(&wire), &container[..]);
    // and the round trip delivers the container
    let d = ur_decode::decode(uri.as_str()).unwrap();
    assert_eq!(d.as_ref(), &container[..]);

    // 300 B container → 0x59 + 2-byte length shell
    let big = vec![0x5Au8; 300];
    let uri = encode(UrTypeTag::XmrTxSigned, &big).unwrap();
    let wire = wire_of(uri.as_str());
    assert_eq!(&wire[..3], &[0x59, 0x01, 0x2c]);
    assert_eq!(ur_message_content(&wire), &big[..]);

    // small payload → 0x58 + 1-byte length shell
    let uri = encode(UrTypeTag::Bytes, b"data").unwrap();
    let wire = wire_of(uri.as_str());
    assert_eq!(&wire, &[0x58, 0x04, 0x64, 0x61, 0x74, 0x61][..]);
    assert_eq!(ur_message_content(&wire), &b"data"[..]);
}

// ─── (d) real-capture regression pin ───────────────────────────────────────

#[test]
fn real_cake_xmr_output_frames_strip_to_240b_container() {
    let path = format!(
        "{}/tests/fixtures/cake_real_frames.txt",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).expect("cake_real_frames.txt fixture");
    let frames: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("ur:"))
        .collect();
    assert_eq!(frames.len(), 2, "real capture = exactly 2 frames");
    assert!(frames[0].starts_with("ur:xmr-output/1-2/"));
    assert!(frames[1].starts_with("ur:xmr-output/2-2/"));

    let mut dec = UrMultipartDecoder::new();
    for f in &frames {
        dec.receive_frame(f).expect("frame feeds");
    }
    assert!(dec.complete());
    let mut out = vec![0u8; 16384];
    let n = dec.payload_into(&mut out).unwrap().expect("complete");
    // 242 B wire message `58 f0 ...` → stripped to the 240 B wallet2 container
    assert_eq!(n, 240, "stripped container length");
    assert_eq!(&out[..5], &[0x4d, 0x6f, 0x6e, 0x65, 0x72], "head = 'Moner'");
}
