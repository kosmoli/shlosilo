//! Decode-workspace budget pins (phase 5a).
//!
//! The UR decode workspace is 99.9% four pools, and the dedup pool alone was
//! 1,114,112 B of the 2,797,831 B workspace: 4,096 slots × a 264 B `IdxSet`, spent on
//! remembering which fragment combinations had already arrived. `IdxKey` stores the same
//! set fixed-width instead.
//!
//! These pins exist so the shrink cannot silently regress: a future field added to a
//! pool element (or a raised slot count) trips the ratchet instead of quietly costing
//! another megabyte of PSRAM.
#![cfg(feature = "alloc-fallback")]

use shlosilo::encoding::fountain::{IdxKey, Part};
use shlosilo::ur::ur_multipart::ur_decode_ws_len;

#[test]
fn the_dedup_key_is_fixed_width() {
    // 4 u64 words (32 B) + degree = 33 B, padded to 40 B, + 8 B for the Option
    // discriminant = 48 B. Against the 264 B `IdxSet` it replaces, 4,096 slots go from
    // 1,114,112 B to 196,608 B.
    // Width follows the source-fragment ceiling: MAX_SEQUENCE_COUNT/64 words + degree.
    // At 1,024 fragments that is 16 words = 128 B (+8 B degree, +8 B Option) = 144 B, and
    // 4,096 slots cost 589,824 B - which is why the ceiling cannot be raised much further
    // without reworking this pool.
    let cap = shlosilo::limits::UR_SOURCE_FRAGMENTS_MAX;
    let expected = cap.div_ceil(64) * 8 + 16;
    let key = core::mem::size_of::<Option<IdxKey>>();
    assert!(
        key <= expected,
        "dedup key grew to {key} B (expected <= {expected} for a {cap}-fragment ceiling)"
    );
    assert!(
        cap <= 1024,
        "a {cap}-fragment ceiling makes the dedup pool exceed the sign peak; rework this          pool before raising it"
    );
}

#[test]
fn the_decode_workspace_ratchet_only_moves_down() {
    // Phase 6 raised the source-fragment ceiling to 1,024 so a real 61 KB request at
    // 65 B/fragment (941 fragments) fits: 1,336,639 B. The meaningful bound is not an
    // absolute number, though - the carrier frees the decode workspace before signing, so
    // decode only has to stay under the sign peak to keep the lifecycle peak unchanged.
    let sign = shlosilo::business::sign::SignWsLayout::compute().total;
    let ws = ur_decode_ws_len();
    assert!(
        ws <= sign,
        "decode workspace {ws} B exceeds the sign peak {sign} B: the lifecycle peak grows"
    );
    // Absolute ratchet for the case where sign itself grows and quietly hides a decode
    // regression. Raise only with a measured reason.
    const CEILING: usize = 1_400_000;
    assert!(
        ws <= CEILING,
        "decode workspace {ws} B exceeds the {CEILING} B ratchet"
    );
}

#[test]
fn the_dominant_cost_is_now_the_equation_arena() {
    // After 5b the pools are metadata; the bytes are 256 equation slots x FRAGMENT_MAX
    // (2,048 B) plus the message arena. Phase 5c lowers FRAGMENT_MAX from the profile,
    // which is where the next megabyte-class saving lives - this pin keeps the accounting
    // pointing at the real component.
    let equations =
        shlosilo::types::caps::UR_WS_BUFFER_SLOTS * shlosilo::limits::UR_INBOUND_FRAGMENT_MAX;
    assert!(
        ur_decode_ws_len() >= equations,
        "equation arena ({equations} B) must be inside the workspace"
    );
    // `Part` is still the greedy wire type; it must not grow its inline fragment buffer.
    assert!(
        core::mem::size_of::<Part>() <= 2100,
        "Part grew: {size}",
        size = core::mem::size_of::<Part>()
    );
}

/// 5c: the arena slot width is a platform value, and it must cover our own outbound
/// fragment length (the same `Part` wire type carries both directions). build.rs enforces
/// the same inequality; this keeps the reason next to the number.
#[test]
fn the_arena_slot_covers_what_we_send_and_what_peers_send() {
    let inbound = shlosilo::limits::UR_INBOUND_FRAGMENT_MAX;
    assert!(
        inbound >= shlosilo::limits::UR_ENCODE_FRAGMENT_LEN,
        "inbound slot ({inbound}) is narrower than our outbound fragment"
    );
    // Interop evidence: Cake sends ~65 B fragments, Keystone's default
    // max_fragment_length is 200, and our Sparrow-shaped parity fixture
    // (`tests/pico2_smoke_parity.rs`) cuts 400 B fragments. A real Sparrow frame length
    // has never been measured on device - pool #71 - so the ceiling covers the fixture.
    assert!(
        inbound >= 400,
        "inbound slot ({inbound}) would reject our Sparrow-shaped fixture"
    );
    assert!(inbound <= 2048, "beyond the wire type's capacity");
}

#[test]
fn the_dedup_key_keeps_set_identity_not_sequence_identity() {
    // Same set, built from a different ordering of the same indices, must compare equal
    // (the decoder asks "have I seen this combination", not "which frame").
    let a = IdxKey::from_indexes(&[7, 3, 200]);
    let b = IdxKey::from_indexes(&[200, 7, 3]);
    assert_eq!(a, b);
    // A different set of the same degree must not collide.
    let c = IdxKey::from_indexes(&[7, 3, 201]);
    assert_ne!(a, c);
    // Degree is part of the key: a subset is not a duplicate.
    let d = IdxKey::from_indexes(&[7, 3]);
    assert_ne!(a, d);
}
