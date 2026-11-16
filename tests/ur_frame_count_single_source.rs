//! The outbound UR fragment length is a platform knob, and it has exactly one owner.
//!
//! Two things are pinned here because both used to be replicated:
//!
//! 1. **The value.** `forms/ur/ur_multipart.rs::DEFAULT_FRAGMENT_LEN` carries a
//!    compile-time equality assertion against `limits::UR_ENCODE_FRAGMENT_LEN`, and the
//!    carrier reads `SHLOSILO_LIMITS_UR_ENCODE_FRAGMENT_LEN` from the generated header -
//!    so the Rust default, the C `begin` call and the profile cannot drift apart.
//! 2. **The frame count.** The carrier used to re-derive it as
//!    `ceil(payload_len / fragment)`, which ignores the CBOR byte-string shell and the
//!    fountain padding. `shlosilo_ur_encode_fragment_count` now reports the encoder's own
//!    number, and this test pins that the two formulas really do disagree - if a future
//!    "simplification" reintroduces the carrier-side formula, the label lies again.
#![cfg(feature = "alloc-fallback")]

use shlosilo::ur::ur_multipart::{UrMultipartEncoder, DEFAULT_FRAGMENT_LEN};

/// A payload whose shell and padding both matter: 1000 bytes is not a multiple of the
/// fragment length, and the CBOR head adds bytes the naive formula never sees.
fn sample_payload() -> Vec<u8> {
    (0..1000u32).map(|i| (i * 7 % 251) as u8).collect()
}

#[test]
fn the_rust_default_is_the_profile_value() {
    assert_eq!(
        DEFAULT_FRAGMENT_LEN,
        shlosilo::limits::UR_ENCODE_FRAGMENT_LEN
    );
    // The carrier renders a frame as `ur:<type>/<n>-<m>/<bytewords>` inside a
    // 1024-char buffer; bytewords cost 2 chars per byte. build.rs enforces the same
    // bound, this keeps the reason next to the number.
    const {
        assert!(DEFAULT_FRAGMENT_LEN > 0);
        assert!(DEFAULT_FRAGMENT_LEN <= 480);
    }
}

#[test]
fn the_encoder_count_is_not_the_carrier_formula() {
    let payload = sample_payload();
    let enc =
        UrMultipartEncoder::new("xmr-txsigned", &payload, DEFAULT_FRAGMENT_LEN).expect("encoder");
    let real = enc.fragment_count();
    // The formula the carrier used to compute: ceil(payload_len / fragment_len).
    let naive = payload.len().div_ceil(DEFAULT_FRAGMENT_LEN);
    assert_ne!(
        real, naive,
        "if these ever agree, this pin no longer proves the difference - check the shell \
         and padding assumptions before deleting it"
    );
    assert!(real >= naive, "the shell/padding can only add fragments");
    // The real count is what the on-screen `ur frame n/M` must show.
    assert!(real > 0);
}
