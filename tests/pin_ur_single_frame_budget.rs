//! MUST-RED pin — pool §36 "UR exit budget shortfall" (shlosilo-待决与待验池.md).
//!
//! `UR_PAYLOAD_MAX_LEN` (forms/ur/ur_encode.rs, mirrored as the `shlosilo.h`
//! `#define`) is 2048, but a real Cake `xmr-output` message body is 2052 bytes
//! (2026-10-19 inventory seg2): the single-frame UR exit structurally
//! under-budgets real traffic by 4 bytes, so a genuine Cake request cannot
//! leave the device at all today.
//!
//! Pin: build a 2052-byte payload (real Cake message size; the body is
//! `OUTPUT_EXPORT_MAGIC` + deterministic filler — only the length is
//! load-bearing) and assert it exits completely through the single-frame UR
//! path (`ur_encode::encode` -> `ur_decode::decode` round trip, delivered
//! payload byte-identical).
//!
//! This MUST fail today; the panic records the 2048-vs-2052 under-budget fact
//! and the fix direction (raise `UR_PAYLOAD_MAX_LEN` to cover real messages,
//! keep `shlosilo.h` in sync, and let the decode-side payload cap and the wire
//! heapless caps scale with it).
//!
//! Run: cargo test --offline --test pin_ur_single_frame_budget

use shlosilo::chain::xmr::key_image_export::OUTPUT_EXPORT_MAGIC;
use shlosilo::ur::ur_decode::decode;
use shlosilo::ur::ur_encode::{encode, UrTypeTag, UR_PAYLOAD_MAX_LEN};

/// Real Cake `xmr-output` message body size (2026-10-19 inventory seg2,
/// pool §36): 2052 bytes.
const REAL_CAKE_MESSAGE_LEN: usize = 2052;

/// Pool §36: the single-frame UR exit must carry a real 2052-byte Cake message
/// whole. `UR_PAYLOAD_MAX_LEN` is 2048 — 4 bytes short of real traffic.
#[test]
fn pin_red_single_frame_carries_real_cake_message() {
    // Real-size Cake xmr-output message: container magic + deterministic filler.
    let mut payload: Vec<u8> = Vec::with_capacity(REAL_CAKE_MESSAGE_LEN);
    payload.extend_from_slice(OUTPUT_EXPORT_MAGIC);
    let mut i = 0u32;
    while payload.len() < REAL_CAKE_MESSAGE_LEN {
        payload.push((i % 251) as u8);
        i += 1;
    }
    assert_eq!(payload.len(), REAL_CAKE_MESSAGE_LEN);

    let enc = match encode(UrTypeTag::XmrOutput, &payload) {
        Ok(e) => e,
        Err(_) => panic!(
            "PINNED RED: single-frame UR exit cannot carry a real Cake message — \
             UR_PAYLOAD_MAX_LEN={} under-budgets the real Cake xmr-output message \
             of {} bytes (pool §36): encode() rejects the payload before it ever \
             reaches the wire. Fix = raise UR_PAYLOAD_MAX_LEN in forms/ur/ur_encode.rs \
             (keep the shlosilo.h #define in sync) to at least the real message size, \
             and let the decode-side payload cap plus the wire heapless caps scale \
             with it",
            UR_PAYLOAD_MAX_LEN,
            payload.len()
        ),
    };

    let dec = match decode(enc.as_str()) {
        Ok(d) => d,
        Err(_) => panic!(
            "PINNED RED: single-frame UR decode rejected the encoded real Cake \
             message — UR_PAYLOAD_MAX_LEN={} budgets the payload while the real \
             Cake xmr-output message is {} bytes (pool §36, 2048 vs 2052). Fix = \
             raise UR_PAYLOAD_MAX_LEN and the decode-side payload cap together \
             (forms/ur/ur_encode.rs + forms/ur/ur_decode.rs, shlosilo.h in sync)",
            UR_PAYLOAD_MAX_LEN,
            payload.len()
        ),
    };

    assert_eq!(dec.type_tag(), UrTypeTag::XmrOutput);
    assert_eq!(
        dec.as_ref(),
        &payload[..],
        "the full 2052 B real Cake message must exit intact through the single-frame UR"
    );
}
