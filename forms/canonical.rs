//! Canonical (dialect-neutral) forms — the WP1 interface freeze §1 shapes.
//!
//! The core produces these; dialect adapters (`crate::profile`) translate
//! them to wire views. Dependency direction (C1): `profile → canonical ←
//! core` — this module never imports a profile.
//!
//! Frozen 2026-10-31 (WP1 interface-freezing note, `规格/` doc). Changing a
//! shape below is a freeze break and needs a new sign-off.

/// Sign-leg entry (frozen): an output/input one-time address with its key
/// image. NO signature — the sync leg's 64B ring signature lives in
/// [`KiExportRecord`] only (two distinct signatures, GPT review 2026-10-30
/// §4), and the signed-set envelope signature is produced by the shared
/// crypto wrapper after dialect serialization (I11: profiles decide WHAT is
/// signed, never the key/rng/domain separation).
///
/// `wallet_idx`: `Some` = wallet-owned (and carries index material for
/// dialect-view materialization); `None` = foreign (external recipient).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignKiEntry {
    /// The output's one-time address (stealth address).
    pub one_time_pub: [u8; 32],
    pub key_image: [u8; 32],
    /// Wallet-owned marker + index material (see struct docs).
    pub wallet_idx: Option<u32>,
}

/// Sync-leg record (frozen): the KI export's accompanying 64B ring signature
/// proves the key image belongs to the output (the importer's cryptographic
/// brute match). It exists ONLY here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KiExportRecord {
    pub one_time_pub: [u8; 32],
    pub key_image: [u8; 32],
    /// The sync-leg ring signature (never in the sign-leg canonical).
    pub sig: [u8; 64],
    pub wallet_idx: Option<u32>,
}

/// Sync-leg canonical set (frozen): records at wallet indices
/// `offset..offset+records.len()`.
pub struct KiSyncSet<'a> {
    pub offset: u32,
    pub records: crate::types::SliceVec<'a, KiExportRecord>,
}
