//! Pairing key-image retention store policy (fix37), extracted from the
//! forgebox task glue (`product_task.c`) so the semantics are host-testable.
//!
//! Scope note: this module owns ONLY the pure store policy. The storage
//! arrays stay with the L3 host (caller-storage / zero-alloc discipline), and
//! the sign leg's read-side fingerprint filter lives in [`crate::business::sign`].
//!
//! The invariants below are a 1:1 characterization of the shipped fix37
//! behavior (verified end-to-end by the 2026-10-21 real-device acceptance,
//! vault `shlosilo-验收-fix37专项两场景-2026-10-21.md`):
//!
//! - **I1 换卡整库清**: incoming batch non-empty, store non-empty, and
//!   `store[0].wallet_fp != incoming[0].wallet_fp` → the whole store is voided
//!   before merging (a plate swap without a power cycle cannot leave stale
//!   records around).
//! - **I2 同 (fp, idx) 覆盖**: a record matching an existing slot by
//!   `(wallet_fp, transfer_idx)` overwrites that slot in place.
//! - **I3 追加与容量**: no match → append at `len`; store full → the record is
//!   dropped (the sign leg's conservative gap filler covers). Updates of
//!   existing slots still happen when the store is full.
//! - **I3b 入批截断**: at most `capacity` incoming records are considered
//!   (mirrors the C loop bound `i < PAIRING_KI_MAX`).
//! - **I4 齐性假定**: the wallet-change test looks at `store[0]` vs
//!   `incoming[0]` only — batches are assumed homogeneous per scan.

use crate::business::sign::WalletKiRecord;

/// Per-batch merge accounting (diagnostics / tests; callers may ignore).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MergeStats {
    /// I1 fired: the store was voided before merging.
    pub cleared: bool,
    /// Existing slots overwritten (I2).
    pub updated: usize,
    /// New slots appended (I3).
    pub appended: usize,
    /// Records dropped because the store was full (I3).
    pub dropped: usize,
}

/// Union-merge `incoming` into `store[..*len]`, updating `*len`.
///
/// `store` is caller storage (its `len()` is the capacity); `len` must
/// satisfy `len <= store.len()` on entry. Pure: no allocation, no I/O.
pub fn merge_pairing_records(
    store: &mut [WalletKiRecord],
    len: &mut usize,
    incoming: &[WalletKiRecord],
) -> MergeStats {
    let cap = store.len();
    debug_assert!(*len <= cap, "len must not exceed capacity on entry");
    let mut stats = MergeStats::default();

    // I1: wallet-change voids the whole store (first-element check, I4).
    if !incoming.is_empty() && *len > 0 && store[0].wallet_fp != incoming[0].wallet_fp {
        *len = 0;
        stats.cleared = true;
    }

    // I3b: at most `cap` incoming records are considered (mirrors the C
    // loop bound `i < PAIRING_KI_MAX`).
    for rec in incoming.iter().take(cap) {
        // I2: match by (wallet_fp, transfer_idx) — first match wins.
        let mut j = 0usize;
        while j < *len {
            if store[j].transfer_idx == rec.transfer_idx && store[j].wallet_fp == rec.wallet_fp {
                break;
            }
            j += 1;
        }
        // I3: full store drops appends (updates matched above survive).
        if j >= cap {
            stats.dropped += 1;
            continue;
        }
        store[j] = *rec;
        if j == *len {
            *len += 1;
            stats.appended += 1;
        } else {
            stats.updated += 1;
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    const FP_A: [u8; 8] = [0xA0; 8];
    const FP_B: [u8; 8] = [0xB0; 8];

    fn rec(fp: [u8; 8], idx: u32, ki: u8) -> WalletKiRecord {
        WalletKiRecord {
            transfer_idx: idx,
            wallet_fp: fp,
            key_image: [ki; 32],
        }
    }

    fn store3() -> [WalletKiRecord; 4] {
        [rec(FP_A, 0, 0xEE); 4] // 0xEE = poison; slots must never leak into results
    }

    fn key_images(store: &[WalletKiRecord], len: usize) -> Vec<[u8; 32]> {
        store[..len].iter().map(|r| r.key_image).collect()
    }

    #[test]
    fn empty_batch_is_noop_even_on_wallet_change() {
        let mut store = store3();
        let mut len = 1;
        store[0] = rec(FP_A, 0, 0x01);
        let stats = merge_pairing_records(&mut store, &mut len, &[]);
        assert!(!stats.cleared, "empty batch must not void the store");
        assert_eq!((stats.updated, stats.appended, stats.dropped), (0, 0, 0));
        assert_eq!(len, 1);
        assert_eq!(key_images(&store, len), vec![[0x01; 32]]);
    }

    #[test]
    fn empty_store_appends_without_clear() {
        let mut store = store3();
        let mut len = 0;
        let stats = merge_pairing_records(&mut store, &mut len, &[rec(FP_A, 0, 0x02)]);
        assert!(!stats.cleared);
        assert_eq!(stats.appended, 1);
        assert_eq!(len, 1);
    }

    #[test]
    fn same_fp_same_idx_overwrites_in_place() {
        // I2
        let mut store = store3();
        let mut len = 2;
        store[0] = rec(FP_A, 0, 0x01);
        store[1] = rec(FP_A, 1, 0x02);
        let stats = merge_pairing_records(&mut store, &mut len, &[rec(FP_A, 1, 0x22)]);
        assert!(!stats.cleared);
        assert_eq!((stats.updated, stats.appended, stats.dropped), (1, 0, 0));
        assert_eq!(len, 2);
        assert_eq!(key_images(&store, len), vec![[0x01; 32], [0x22; 32]]);
    }

    #[test]
    fn same_fp_new_idx_appends() {
        // I3
        let mut store = store3();
        let mut len = 1;
        store[0] = rec(FP_A, 0, 0x01);
        let stats = merge_pairing_records(&mut store, &mut len, &[rec(FP_A, 5, 0x55)]);
        assert_eq!((stats.updated, stats.appended), (0, 1));
        assert_eq!(len, 2);
        assert_eq!(key_images(&store, len), vec![[0x01; 32], [0x55; 32]]);
    }

    #[test]
    fn wallet_change_voids_whole_store_then_appends() {
        // I1 — the fix37 换卡语义: stale records are void, never mixed.
        let mut store = store3();
        let mut len = 2;
        store[0] = rec(FP_A, 0, 0x01);
        store[1] = rec(FP_A, 1, 0x02);
        let stats = merge_pairing_records(&mut store, &mut len, &[rec(FP_B, 0, 0xB1)]);
        assert!(stats.cleared);
        assert_eq!((stats.updated, stats.appended, stats.dropped), (0, 1, 0));
        assert_eq!(len, 1);
        assert_eq!(key_images(&store, len), vec![[0xB1; 32]]);
    }

    #[test]
    fn full_store_drops_appends_but_still_updates() {
        // I3: full → drop; I2 updates survive a full store.
        let mut store = [rec(FP_A, 0, 0x01), rec(FP_A, 1, 0x02)];
        let mut len = 2;
        let stats = merge_pairing_records(
            &mut store,
            &mut len,
            &[rec(FP_A, 1, 0x22), rec(FP_A, 7, 0x77)],
        );
        assert_eq!((stats.updated, stats.appended, stats.dropped), (1, 0, 1));
        assert_eq!(len, 2);
        assert_eq!(key_images(&store, len), vec![[0x01; 32], [0x22; 32]]);
    }

    #[test]
    fn incoming_batch_truncated_at_capacity() {
        // I3b: at most `capacity` incoming records are considered.
        let mut store = store3(); // capacity 4
        let mut len = 0;
        let batch: Vec<WalletKiRecord> = (0..6u8).map(|i| rec(FP_A, u32::from(i), i)).collect();
        let stats = merge_pairing_records(&mut store, &mut len, &batch);
        assert_eq!(stats.appended, 4, "only capacity records considered");
        assert_eq!(len, 4);
        assert_eq!(
            key_images(&store, len),
            vec![[0x00; 32], [0x01; 32], [0x02; 32], [0x03; 32]]
        );
    }

    #[test]
    fn wallet_change_uses_first_elements_only() {
        // I4 — characterization of the shipped [0]-vs-[0] check: a mixed
        // batch whose FIRST record matches the store fp is merged without
        // clearing (homogeneity is assumed, not enforced).
        let mut store = store3();
        let mut len = 1;
        store[0] = rec(FP_A, 0, 0x01);
        let stats = merge_pairing_records(
            &mut store,
            &mut len,
            &[rec(FP_A, 9, 0x99), rec(FP_B, 9, 0xBB)],
        );
        assert!(
            !stats.cleared,
            "first-element fp match suppresses the clear"
        );
        assert_eq!(len, 3);
        assert_eq!(
            key_images(&store, len),
            vec![[0x01; 32], [0x99; 32], [0xBB; 32]]
        );
    }

    #[test]
    fn update_survives_wallet_change_and_full_combo() {
        // I1 + I3 interaction: after a wallet-change clear the store is empty,
        // so a batch up to capacity appends cleanly even from a previously
        // full store.
        let mut store = [rec(FP_A, 0, 0x01), rec(FP_A, 1, 0x02)];
        let mut len = 2;
        let stats = merge_pairing_records(
            &mut store,
            &mut len,
            &[rec(FP_B, 0, 0xB0), rec(FP_B, 1, 0xB1)],
        );
        assert!(stats.cleared);
        assert_eq!((stats.updated, stats.appended, stats.dropped), (0, 2, 0));
        assert_eq!(len, 2);
        assert_eq!(key_images(&store, len), vec![[0xB0; 32], [0xB1; 32]]);
    }
}
