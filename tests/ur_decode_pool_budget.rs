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
    let key = core::mem::size_of::<Option<IdxKey>>();
    assert!(
        key <= 48,
        "dedup key grew to {key} B; the pool is 4096 slots, so every 8 B costs 32 KiB"
    );
}

#[test]
fn the_decode_workspace_ratchet_only_moves_down() {
    // 864,807 B after 5b (2,797,831 before 5a, 1,880,327 after 5a). Raise this only
    // with a measured reason.
    const CEILING: usize = 900_000;
    let ws = ur_decode_ws_len();
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
    let equations = shlosilo::types::caps::UR_WS_BUFFER_SLOTS * 2048;
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
