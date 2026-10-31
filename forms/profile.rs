//! Protocol profiles — the dialect adapters (WP1 interface freeze §1).
//!
//! Pure translation: `原始字节 ⇄ canonical` both ways, enum + match static
//! dispatch (C6: no trait object, no Box; deleting a dialect = deleting one
//! enum variant + its translation fns + one registry line). Dependency
//! direction (C1): `profile → canonical` — the core never imports here.
//!
//! **I11 (crypto boundary)**: this module NEVER takes key material or an rng.
//! Profiles decide WHAT is signed/serialized; how (keys, nonces, domain
//! separation) stays in the controlled crypto modules.
//!
//! **I5 (binding)**: the profile is bound EXPLICITLY at pairing time and
//! sticks to the session as a single byte (C3). An unbound session has no
//! profile (`None`) — callers must select or refuse; the API deliberately
//! offers NO inference from UR types (xmr-* type names are ambiguous across
//! dialects, design §5).
//!
//! **I8 (delete drill)**: `profile-keystone` is a NON-DEFAULT cargo feature.
//! Default builds are the "dialect off" variant (Cake only, tests green =
//! downstream zero-awareness proof); `--all-features` is the "on" variant.

use crate::canonical::SignKiEntry;
use crate::chain::xmr::signed_txset::TxKeyImageEntry;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::types::SliceVec;

/// The dialect discriminant (session byte: 0 = unbound, see
/// [`profile_current`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProfileId {
    CakeCupcake = 1,
    Keystone = 2,
}

/// The outer `key_images` positional-array policy per dialect (WP1 I3/I4):
/// wallet2 (Cake) demands the full wallet-transfer-indexed array; keystone's
/// `SignedTxSet::new(pending_txs, vec![], tx_key_images)` shape is EMPTY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyImagesPolicy {
    /// wallet2.cpp:8074 contract: one entry per wallet transfer position.
    WalletIndexedFull,
    /// keystone D-case: the positional array stays empty.
    Empty,
}

/// The positional `key_images` policy for the dialect (WP1 I3/I4).
pub fn key_images_positional_policy(profile: ProfileId) -> Result<KeyImagesPolicy> {
    match profile {
        ProfileId::CakeCupcake => Ok(KeyImagesPolicy::WalletIndexedFull),
        #[cfg(feature = "profile-keystone")]
        ProfileId::Keystone => Ok(KeyImagesPolicy::Empty),
        #[cfg(not(feature = "profile-keystone"))]
        ProfileId::Keystone => Err(ShlosiloError::new(ShlosiloErrorKind::FeatureNotImplemented)),
    }
}

/// The full wire-tail view for the dialect (the canonical enums are the
/// neutral handoff the core consumes — I1 keeps `profile::` out of core).
pub fn tail_view(profile: ProfileId) -> Result<crate::canonical::TailView> {
    Ok(crate::canonical::TailView {
        key_images: match key_images_positional_policy(profile)? {
            KeyImagesPolicy::WalletIndexedFull => {
                crate::canonical::KeyImagesPositionalView::WalletIndexedFull
            }
            KeyImagesPolicy::Empty => crate::canonical::KeyImagesPositionalView::Empty,
        },
        tx_key_images: match profile {
            ProfileId::CakeCupcake => crate::canonical::TxKeyImagesView::Wallet2Owned,
            #[cfg(feature = "profile-keystone")]
            ProfileId::Keystone => crate::canonical::TxKeyImagesView::AllPlusRetained,
            #[cfg(not(feature = "profile-keystone"))]
            ProfileId::Keystone => {
                return Err(ShlosiloError::new(ShlosiloErrorKind::FeatureNotImplemented));
            }
        },
    })
}

/// The `tx_key_images` inclusion rule per dialect (WP1 I12):
/// - Cake = the wallet2 `is_out_to_acc` view: wallet-owned outputs only
///   (change + self-pay INCLUDED, external EXCLUDED);
/// - keystone = every new output of the transaction (their `outputs()`
///   quirk — external receive outputs included too).
pub fn tx_key_images_includes(profile: ProfileId, wallet_owned: bool) -> Result<bool> {
    match profile {
        ProfileId::CakeCupcake => Ok(wallet_owned),
        #[cfg(feature = "profile-keystone")]
        ProfileId::Keystone => Ok(true),
        #[cfg(not(feature = "profile-keystone"))]
        ProfileId::Keystone => Err(ShlosiloError::new(ShlosiloErrorKind::FeatureNotImplemented)),
    }
}

/// Materialize the wire `tx_key_images` entries from canonical sets
/// (frozen semantics: I12 for Cake, I4 for keystone).
///
/// Content per dialect (keystone 3.2.0 source, transfer.rs:1250-1274):
/// - Cake = the wallet2 `is_out_to_acc` view over the NEW outputs
///   (wallet-owned only — change + self-pay in, external out);
/// - keystone = **new outputs first (ALL of them, external included — the
///   `outputs()` quirk), then the wallet's full transfer KIs** (their
///   `transfers.details` loop — our retention set is the same truth).
///
/// Returns the number of entries written.
pub fn materialize_tx_key_images(
    profile: ProfileId,
    retained: &[SignKiEntry],
    new_outputs: &[SignKiEntry],
    out: &mut SliceVec<'_, TxKeyImageEntry>,
) -> Result<usize> {
    let mut written = 0usize;
    let mut push = |e: &SignKiEntry| -> Result<()> {
        out.push(TxKeyImageEntry {
            output_pubkey: e.one_time_pub,
            key_image: e.key_image,
        })
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
        written += 1;
        Ok(())
    };
    match profile {
        ProfileId::CakeCupcake => {
            // The wallet2 view NEVER carries transfer KIs — `retained` is
            // deliberately unused on this arm.
            let _ = retained;
            for e in new_outputs {
                if tx_key_images_includes(profile, e.wallet_idx.is_some())? {
                    push(e)?;
                }
            }
        }
        #[cfg(feature = "profile-keystone")]
        ProfileId::Keystone => {
            // new outputs first (their per-tx loop), then the transfer KIs.
            for e in new_outputs {
                push(e)?;
            }
            for e in retained {
                push(e)?;
            }
        }
        #[cfg(not(feature = "profile-keystone"))]
        ProfileId::Keystone => {
            return Err(ShlosiloError::new(ShlosiloErrorKind::FeatureNotImplemented));
        }
    }
    Ok(written)
}

/// Bind the dialect to the session (I5): explicit, at pairing time. The
/// session byte changes ONLY here.
pub fn profile_bind(
    session: &mut crate::types::key_session::KeySession,
    id: ProfileId,
) -> Result<()> {
    // The availability check happens through the policy surface: binding a
    // feature-disabled dialect must fail, never half-bind.
    key_images_positional_policy(id)?;
    session.set_profile_id(id as u8);
    Ok(())
}

/// The session's bound dialect (`None` = unbound — select explicitly or
/// refuse; NEVER infer from the UR type).
pub fn profile_current(session: &crate::types::key_session::KeySession) -> Option<ProfileId> {
    match session.profile_id() {
        1 => Some(ProfileId::CakeCupcake),
        2 => Some(ProfileId::Keystone),
        _ => None,
    }
}
