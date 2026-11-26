//! Platform limits profile: the zero-diff baseline and the schema guarantees.
//!
//! Phase 1 of the limits-knob plan is a *pure mechanism* change: `limits/<profile>.toml`
//! becomes the source of truth, `build.rs` emits the Rust ceilings, and every value must
//! equal the constant it replaced. This file pins that: if a profile silently drifts from
//! the documented numbers, the build goes red instead of a device discovering it.
//!
//! It also pins the two relations `build.rs` enforces, because they are the ones that
//! cost real debugging time (2026-11-15: a 61 KB inbound payload against a part domain
//! that could only ever assemble 16.6 KiB, and a PSBT map table one slot short of a real
//! 43-input request).

// Chain axis: this file drives the btc surface; without that switch the
// API it uses does not exist.
#![cfg(feature = "chain-btc")]

use shlosilo::chain::btc::p2wpkh::{BT_TX_INPUTS_MAX, BT_TX_OUTPUTS_MAX};
use shlosilo::limits;
use shlosilo::limits::PSBT_MAPS_MAX;
use shlosilo::types::caps::{
    UR_WS_BUFFER_SLOTS, UR_WS_DECODED_SLOTS, UR_WS_QUEUE_SLOTS, UR_WS_RECEIVED_SLOTS,
};
use shlosilo::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN;

/// The numbers the host profile must keep until a deliberate profile change moves them.
#[test]
fn host_profile_is_the_zero_diff_baseline() {
    assert_eq!(
        limits::PROFILE,
        "host",
        "cargo test builds default to the host profile"
    );
    assert_eq!(BT_TX_INPUTS_MAX, 64);
    assert_eq!(BT_TX_OUTPUTS_MAX, 64);
    assert_eq!(
        PSBT_MAPS_MAX,
        1 + limits::BT_TX_INPUTS_MAX + limits::BT_TX_OUTPUTS_MAX,
        "derived by build.rs from the two ceilings, not configured"
    );
    // The C side reads this from the header; the value must equal the derivation.
    assert_eq!(PSBT_MAPS_MAX, limits::PSBT_MAPS_MAX);
    assert_eq!(UR_WS_DECODED_SLOTS, 256);
    assert_eq!(UR_WS_BUFFER_SLOTS, 256);
    assert_eq!(UR_WS_QUEUE_SLOTS, 256);
    assert_eq!(UR_WS_RECEIVED_SLOTS, 4096);
    assert_eq!(MULTIPART_PAYLOAD_MAX_LEN, 61_440);
    assert_eq!(shlosilo::types::caps::SIGN_WS_BP_CHUNK_MAX, 36);
    // Phase 4a baseline: the signer's input tables are sized by this ceiling, and the
    // migration is only "zero behaviour change" while it stays at the pre-4a value.
    // Raising it (24) is a separate, separately verified change.
    assert_eq!(limits::XMR_INPUTS_MAX, 16);
    // E-3 container budgets, as shipped (measured peaks in parentheses).
    assert_eq!(limits::EIP712_TYPES_MAX, 8); // 4
    assert_eq!(limits::EIP712_TYPE_FIELDS_MAX, 16); // 11
    assert_eq!(limits::EIP712_NAME_BYTES, 32); // 20
    assert_eq!(limits::EIP712_DEPTH_MAX, 8); // 3
    assert_eq!(limits::EIP712_NODES_MAX, 256); // 104 typical, 310 for a 3+40 batch
    assert_eq!(limits::EIP712_ENCODE_TYPE_BYTES, 512); // 450
    assert_eq!(limits::EIP712_ARENA_BYTES, 4096);
    assert_eq!(limits::EIP712_DISPLAY_BYTES, 2048);
    // Derived, never configured: a document larger than the inbound transport can deliver
    // is not a limit anyone can reach, so the parser's budget follows the transport.
    assert_eq!(
        limits::EIP712_JSON_BYTES_MAX,
        limits::UR_PAYLOAD_MAX.min(16 * 1024),
        "build.rs derives the typed-data JSON budget as min(16 KiB, ur_payload_max)"
    );
}

/// The inbound buffer may never exceed what the part domain can assemble.
#[test]
fn payload_ceiling_stays_inside_the_part_domain() {
    assert_eq!(
        limits::ASSEMBLED_PAYLOAD_MAX,
        UR_WS_DECODED_SLOTS * 240,
        "240 B is the largest sender fragment this device accepts"
    );
    // Compile-time guarantee (clippy rejects constant `assert!` at runtime): the cap can
    // never exceed what the part domain assembles.
    const _: () = assert!(MULTIPART_PAYLOAD_MAX_LEN <= limits::ASSEMBLED_PAYLOAD_MAX);
}

/// A PSBT needs one map for the global data plus one per input and per output.
#[test]
fn psbt_map_table_covers_inputs_and_outputs() {
    assert_eq!(
        limits::PSBT_MAPS_MIN,
        1 + BT_TX_INPUTS_MAX + BT_TX_OUTPUTS_MAX
    );
    const _: () = assert!(PSBT_MAPS_MAX >= limits::PSBT_MAPS_MIN);
}

/// The firmware's C side must take its ceilings from the generated projection, not from
/// literals it maintains by hand (that mirror is what used to drift).
#[test]
fn the_firmware_reads_the_generated_projection() {
    let c = include_str!("../flux/forgebox/src/tasks/product_task.c");
    assert!(
        c.contains("#include \"shlosilo_limits.h\""),
        "the C carrier must include the profile projection"
    );
    assert!(
        c.contains("#define UR_PAYLOAD_MAX            SHLOSILO_LIMITS_UR_PAYLOAD_MAX"),
        "UR_PAYLOAD_MAX must mirror the profile, not a literal"
    );
    assert!(
        c.contains("#define PAIRING_KI_MAX SHLOSILO_LIMITS_PAIRING_RECORDS_MAX"),
        "PAIRING_KI_MAX must mirror the profile too"
    );
    assert!(
        c.contains("shlosilo_limits_fingerprint"),
        "the carrier must compare the library fingerprint at startup"
    );
    // And the numbers themselves still have to agree with the Rust profile.
    assert_eq!(MULTIPART_PAYLOAD_MAX_LEN, 256 * 240);
}

/// The test profiles exist to exercise the over-cap branches; they must be strictly
/// smaller than the production ceilings, otherwise they cannot do their job.
#[test]
fn test_profiles_are_smaller_than_production() {
    // The tiny profile is not compiled into this binary (it needs its own build), so its
    // numbers are pinned here by reading the profile file: a typo in a test profile is
    // still a silent-loss-of-coverage bug.
    let tiny = include_str!("../limits/tiny-test.toml");
    let stress = include_str!("../limits/stress-test.toml");
    let value = |text: &str, key: &str| -> u64 {
        text.lines()
            .find(|l| l.trim_start().starts_with(key))
            .and_then(|l| l.split('=').nth(1))
            .map(|v| v.split('#').next().unwrap_or("").trim().parse().unwrap())
            .unwrap_or_else(|| panic!("{key} missing from profile"))
    };
    assert!(value(tiny, "bt_tx_inputs_max") < BT_TX_INPUTS_MAX as u64);
    assert!(value(tiny, "ur_payload_max") < MULTIPART_PAYLOAD_MAX_LEN as u64);
    assert!(value(tiny, "ur_ws_decoded_slots") < UR_WS_DECODED_SLOTS as u64);
    assert_eq!(value(stress, "bt_tx_inputs_max"), BT_TX_INPUTS_MAX as u64);
}

/// Chain axis batch 2 (design note §9.3-ter / L1): a limits profile describes RESOURCE
/// CEILINGS only. The chain set is a build declaration (`builds/<name>.toml`), so no
/// profile may carry a `[chains]` table again — one profile per chain subset would
/// duplicate every number in it and re-couple two orthogonal axes.
///
/// `build.rs` refuses the section too; this pins the rule on the test face so a
/// reintroduction is red without needing a device or a specific build profile.
#[test]
fn limits_profiles_carry_no_chain_declaration() {
    let profiles = [
        ("host", include_str!("../limits/host.toml")),
        ("pico2", include_str!("../limits/pico2.toml")),
        ("forgebox", include_str!("../limits/forgebox.toml")),
        ("luckyfox", include_str!("../limits/luckyfox.toml")),
        ("tiny-test", include_str!("../limits/tiny-test.toml")),
        ("stress-test", include_str!("../limits/stress-test.toml")),
    ];
    for (name, text) in profiles {
        assert!(
            !text
                .lines()
                .any(|l| l.split('#').next().unwrap_or("").trim() == "[chains]"),
            "limits/{name}.toml declares a [chains] table: the chain set belongs in a \
             build manifest (builds/<name>.toml), a limits profile carries ceilings only"
        );
        // A stray `btc = true` would be a chain declaration without its section header;
        // build.rs rejects unknown keys, and this says so on the test face as well.
        for chain in ["btc", "eth", "xmr"] {
            assert!(
                !text.lines().any(|l| {
                    let l = l.split('#').next().unwrap_or("").trim();
                    l.starts_with(&format!("{chain} ="))
                }),
                "limits/{name}.toml carries a chain flag for {chain}"
            );
        }
    }
    // And the manifests that DO declare chains exist and are named after their request.
    // Read at RUNTIME, not through a compile-time include macro: scripts/check_fixtures.sh
    // requires every included target to be a git-tracked fixture, and a build manifest is
    // source, not a golden vector. Integration tests run with the package root as cwd.
    for name in ["builds/pico2-btc.toml", "builds/host-all.toml"] {
        let manifest =
            std::fs::read_to_string(name).unwrap_or_else(|e| panic!("cannot read {name}: {e}"));
        assert!(
            manifest.lines().any(|l| l.trim() == "[chains]"),
            "{name}: a build manifest declares its chain set"
        );
        assert!(
            manifest.contains("limits = \""),
            "{name}: a manifest references a limits profile by NAME (never copies it)"
        );
        assert!(
            manifest.contains("role = \""),
            "{name}: a manifest states its role (only delivery may produce a receipt)"
        );
    }
}
