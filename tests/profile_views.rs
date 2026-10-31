//! WP1 interface-freeze pins: the dialect views (I3/I4), the explicit
//! session binding (I5) and the delete drill (I8).
//!
//! | pin | invariant |
//! |-----|-----------|
//! | `cake_view_materializes_wallet_owned_only` | I3/I12: Cake = wallet2 is_out_to_acc view |
//! | `keystone_export_is_empty_positional_plus_keyed_map` | I4: keystone = empty positional + two-fill keyed map (new outputs ∪ transfer KIs) |
//! | `profile_binding_is_explicit_and_sticky` | I5: one session byte, bound explicitly, unbound = None |
//! | `keystone_profile_unavailable_without_feature` | I8: the delete drill — dialect-off build refuses cleanly |
//!
//! The wire-level keystone bytes (I9 golden) land at WP3 against the
//! keystone3 3.2.0 material; these pins freeze the POLICY and CONTENT.

use shlosilo::canonical::SignKiEntry;
use shlosilo::chain::xmr::signed_txset::TxKeyImageEntry;
use shlosilo::profile::{
    key_images_positional_policy, materialize_tx_key_images, profile_bind, profile_current,
    tx_key_images_includes, KeyImagesPolicy, ProfileId,
};
use shlosilo::types::SliceVec;

fn entry(pubkey: u8, owned: bool) -> SignKiEntry {
    SignKiEntry {
        one_time_pub: [pubkey; 32],
        key_image: [pubkey.wrapping_add(1); 32],
        wallet_idx: if owned { Some(0) } else { None },
    }
}

/// Canonical new outputs of a D-shape: two wallet-owned (change + self-pay)
/// and one external recipient.
fn d_shape_outputs() -> [SignKiEntry; 3] {
    [entry(0xA1, true), entry(0xB2, false), entry(0xC3, true)]
}

fn materialize(
    profile: ProfileId,
    retained: &[SignKiEntry],
    outs: &[SignKiEntry],
) -> Vec<TxKeyImageEntry> {
    let mut slots = [TxKeyImageEntry::default(); 8];
    let mut sv = SliceVec::new(&mut slots);
    let n = materialize_tx_key_images(profile, retained, outs, &mut sv).expect("materialize");
    assert_eq!(n, sv.len(), "written count and slice length agree");
    sv.iter().copied().collect()
}

/// The retained transfer KIs (the wallet's known outputs — keystone reads its
/// `transfers.details` loop, we read the retention set).
fn retained_transfers() -> [SignKiEntry; 1] {
    [entry(0xD4, true)]
}

/// I3/I12: the Cake view is the wallet2 is_out_to_acc view — wallet-owned
/// outputs only (change + self-pay included, external excluded).
#[test]
fn cake_view_materializes_wallet_owned_only() {
    let outs = d_shape_outputs();
    let entries = materialize(ProfileId::CakeCupcake, &retained_transfers(), &outs);
    let pubs: Vec<[u8; 32]> = entries.iter().map(|e| e.output_pubkey).collect();
    assert_eq!(
        pubs,
        vec![[0xA1; 32], [0xC3; 32]],
        "owned new outputs only — wallet2's tx_key_images never carries transfer KIs"
    );
    assert_eq!(
        key_images_positional_policy(ProfileId::CakeCupcake).unwrap(),
        KeyImagesPolicy::WalletIndexedFull,
        "wallet2 demands the full wallet-indexed positional array (I3)"
    );
    assert!(tx_key_images_includes(ProfileId::CakeCupcake, true).unwrap());
    assert!(!tx_key_images_includes(ProfileId::CakeCupcake, false).unwrap());
}

/// I4: the keystone export is the D-case shape — the positional `key_images`
/// array stays EMPTY and `tx_key_images` is the keyed map over ALL new
/// outputs (external receive outputs included, keystone's outputs() quirk).
#[cfg(feature = "profile-keystone")]
#[test]
fn keystone_export_is_empty_positional_plus_keyed_map() {
    let outs = d_shape_outputs();
    let entries = materialize(ProfileId::Keystone, &retained_transfers(), &outs);
    let pubs: Vec<[u8; 32]> = entries.iter().map(|e| e.output_pubkey).collect();
    assert_eq!(
        pubs,
        vec![[0xA1; 32], [0xB2; 32], [0xC3; 32], [0xD4; 32]],
        "the two-fill union (transfer.rs:1250-1271): ALL new outputs first \
         (external included, the outputs() quirk), then the wallet's \
         transfer KIs (their transfers.details loop / our retention set)"
    );
    assert_eq!(
        key_images_positional_policy(ProfileId::Keystone).unwrap(),
        KeyImagesPolicy::Empty,
        "the keystone SignedTxSet shape is (pending_txs, vec![], tx_key_images)"
    );
    assert!(tx_key_images_includes(ProfileId::Keystone, true).unwrap());
    assert!(tx_key_images_includes(ProfileId::Keystone, false).unwrap());
}

/// I5: the profile is bound EXPLICITLY into one session byte; unbound is
/// `None` and there is deliberately NO inference surface.
#[test]
fn profile_binding_is_explicit_and_sticky() {
    use shlosilo::types::key_session::KeySession;

    let mut s = KeySession::from_entropy(&[0x22u8; 32], b"").expect("session");
    assert_eq!(profile_current(&s), None, "fresh sessions are unbound");
    assert_eq!(s.profile_id(), 0, "the unbound discriminant is byte 0");

    profile_bind(&mut s, ProfileId::CakeCupcake).expect("bind cake");
    assert_eq!(profile_current(&s), Some(ProfileId::CakeCupcake));
    assert_eq!(s.profile_id(), 1, "CakeCupcake discriminant = 1");
    // sticky: the byte changes only through profile_bind (no other setter is
    // public) — reading twice cannot change it.
    assert_eq!(profile_current(&s), Some(ProfileId::CakeCupcake));

    #[cfg(feature = "profile-keystone")]
    {
        profile_bind(&mut s, ProfileId::Keystone).expect("bind keystone");
        assert_eq!(profile_current(&s), Some(ProfileId::Keystone));
        assert_eq!(s.profile_id(), 2, "Keystone discriminant = 2");
    }
}

/// I8 delete drill (the "dialect off" variant): without the `profile-keystone`
/// feature the keystone dialect refuses cleanly (FeatureNotImplemented) —
/// never a half-bind, never a silent Cake fallback. The green default test
/// face IS the downstream zero-awareness proof (C5).
#[cfg(not(feature = "profile-keystone"))]
#[test]
fn keystone_profile_unavailable_without_feature() {
    use shlosilo::error::ShlosiloErrorKind;
    use shlosilo::types::key_session::KeySession;

    let mut s = KeySession::from_entropy(&[0x22u8; 32], b"").expect("session");
    let err = profile_bind(&mut s, ProfileId::Keystone)
        .expect_err("the disabled dialect must refuse, never half-bind");
    assert!(
        matches!(err.kind, ShlosiloErrorKind::FeatureNotImplemented),
        "expected FeatureNotImplemented, got {err:?}"
    );
    assert_eq!(
        profile_current(&s),
        None,
        "a refused bind leaves the byte untouched"
    );
    assert!(
        key_images_positional_policy(ProfileId::Keystone).is_err(),
        "the policy surface refuses too"
    );
}
