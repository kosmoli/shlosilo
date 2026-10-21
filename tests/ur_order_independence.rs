//! Order-independence regression pin (the 2026-10-08 device wedge hunt).
//!
//! A combo-first feed order (mid-animation start, reverse play) used to make
//! `complete()` miss forever: the reduction cascade resolves several slots in
//! one feed, so decoded_count could JUMP OVER the exact-equality target.
//! Any of the rotation/reverse patterns below wedged before the fix
//! (progress pinned at the 99% cap, never complete).
#![cfg(feature = "alloc-fallback")]

use shlosilo::ur::ur_multipart::{UrMultipartDecoder, UrMultipartEncoder};

fn gen_frames() -> Vec<String> {
    let payload: Vec<u8> = (0..2052u32).map(|i| (i % 251) as u8).collect();
    let mut enc = UrMultipartEncoder::new("xmr-txunsigned", &payload, 130).expect("encoder");
    let n = enc.fragment_count();
    let mut out = Vec::with_capacity(2 * n + 2);
    for _ in 0..(2 * n + 2) {
        out.push(enc.next_frame().expect("frame"));
    }
    out
}

fn feed_all(order: Vec<&String>) -> (bool, u8) {
    let mut dec = UrMultipartDecoder::new();
    for f in order {
        dec.receive_frame(f).expect("feed");
        if dec.complete() {
            break;
        }
    }
    (dec.complete(), dec.progress())
}

#[test]
fn rotation_order_completes() {
    let frames = gen_frames();
    let n = frames.len();
    let rotated: Vec<&String> = (0..n).map(|i| &frames[(i + n / 2) % n]).collect();
    let (complete, progress) = feed_all(rotated);
    assert!(
        complete,
        "mid-animation start must complete (progress was {progress})"
    );
}

#[test]
fn reverse_order_completes() {
    let frames = gen_frames();
    let reversed: Vec<&String> = frames.iter().rev().collect();
    let (complete, progress) = feed_all(reversed);
    assert!(
        complete,
        "reverse play must complete (progress was {progress})"
    );
}

#[test]
fn combo_first_with_repeats_completes() {
    let frames = gen_frames();
    let n = frames.len();
    let mut order: Vec<&String> = Vec::new();
    for _cycle in 0..2 {
        for i in 0..n {
            let idx = (i + n / 2) % n;
            order.push(&frames[idx]);
            order.push(&frames[idx]); // camera oversampling repeats
        }
    }
    let (complete, progress) = feed_all(order);
    assert!(
        complete,
        "combo-first + repeats must complete (progress was {progress})"
    );
}
