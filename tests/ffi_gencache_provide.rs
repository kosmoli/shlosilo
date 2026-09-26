//! Z5.2b: C-side generator table storage provisioning — the four ABI
//! invariants, each with its own regression test (contract text in
//! forms/ffi/c_abi.rs above `shlosilo_gencache_table_sizes`).
//!
//! Own integration binary: the generator registry is process-global.
//! A shared lock serializes the tests so slot-consumption ordering is
//! deterministic.

use std::sync::{Mutex, MutexGuard};

use shlosilo::ffi::c_abi::{shlosilo_gencache_provide_table, shlosilo_gencache_table_sizes};
use shlosilo::ffi::error_code::{ERR_BUFFER_TOO_SMALL, ERR_NULL_POINTER, ERR_SLOT_CONSUMED, OK};
use shlosilo::types::caps::{
    SHLOSILO_GENCACHE_BLOB_BYTES, SHLOSILO_GENCACHE_G_BYTES, SHLOSILO_GENCACHE_H_BYTES,
    SHLOSILO_GENPOINT_SIZE,
};

const SET_BP: i32 = 0;
const SET_BP_PLUS: i32 = 1;

static LOCK: Mutex<()> = Mutex::new(());

fn l() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// 8-aligned point-table scratch (0xAA-filled), plus a byte-size register.
fn pts_buf(bytes: u32) -> Vec<u64> {
    assert_eq!(SHLOSILO_GENPOINT_SIZE, 160);
    let words = (bytes as usize + 64) / 8;
    vec![0xAAAAAAAAAAAAAAAAu64; words]
}

fn probe(set: i32) -> (u32, u32, u32) {
    let (mut g, mut h, mut b) = (0u32, 0u32, 0u32);
    let rc = unsafe { shlosilo_gencache_table_sizes(set, &mut g, &mut h, &mut b) };
    assert_eq!(rc, OK);
    (g, h, b)
}

/// INV-1: pure probe — repeatable, side-effect free, and its values are the
/// same source of truth the provide/fill path uses (pinned against the deploy
/// caps AND by the provide acceptance of exactly these sizes).
#[test]
fn inv1_probe_pure_no_side_effects() {
    let _g = l();
    let (g1, h1, b1) = probe(SET_BP_PLUS);
    let (g2, h2, b2) = probe(SET_BP_PLUS);
    assert_eq!((g1, h1, b1), (g2, h2, b2), "probe must be repeatable");
    // caps == query (same source of truth, Z3.3b-style pin)
    assert_eq!(g1, SHLOSILO_GENCACHE_G_BYTES);
    assert_eq!(h1, SHLOSILO_GENCACHE_H_BYTES);
    assert_eq!(b1, SHLOSILO_GENCACHE_BLOB_BYTES);
    assert_eq!(g1 as usize % SHLOSILO_GENPOINT_SIZE, 0);

    // probe must not have consumed the slot: provide at exactly probe sizes
    // succeeds (over-capacity accepted too — give +64B headroom on the blob).
    let mut gb = pts_buf(g1);
    let mut hb = pts_buf(h1);
    let mut bb = vec![0xAAu8; b1 as usize + 64];
    let (mut gsz, mut hsz, mut bsz) = (g1, h1, b1 + 64);
    let rc = unsafe {
        shlosilo_gencache_provide_table(
            SET_BP_PLUS,
            gb.as_mut_ptr() as *mut u8,
            &mut gsz,
            hb.as_mut_ptr() as *mut u8,
            &mut hsz,
            bb.as_mut_ptr(),
            &mut bsz,
        )
    };
    assert_eq!(rc, OK, "probe must leave the slot free");
    // consumed by THIS provide (not by the probe): a repeat is rejected
    let rc2 = unsafe {
        shlosilo_gencache_provide_table(
            SET_BP_PLUS,
            gb.as_mut_ptr() as *mut u8,
            &mut gsz,
            hb.as_mut_ptr() as *mut u8,
            &mut hsz,
            bb.as_mut_ptr(),
            &mut bsz,
        )
    };
    assert_eq!(rc2, ERR_SLOT_CONSUMED);
}

/// INV-2: any capacity insufficiency fails BEFORE the first write/build and
/// reports the required lengths; no buffer byte is touched.
#[test]
fn inv2_capacity_prefail_reports_required() {
    let _g = l();
    let (req_g, req_h, req_b) = probe(SET_BP);
    let mut gb = pts_buf(req_g);
    let mut hb = pts_buf(req_h);
    let mut bb = vec![0xAAu8; req_b as usize];
    // undersize the blob by one byte
    let (mut gsz, mut hsz, mut bsz) = (req_g, req_h, req_b - 1);
    let rc = unsafe {
        shlosilo_gencache_provide_table(
            SET_BP,
            gb.as_mut_ptr() as *mut u8,
            &mut gsz,
            hb.as_mut_ptr() as *mut u8,
            &mut hsz,
            bb.as_mut_ptr(),
            &mut bsz,
        )
    };
    assert_eq!(rc, ERR_BUFFER_TOO_SMALL);
    // required lengths reported
    assert_eq!(gsz, req_g);
    assert_eq!(hsz, req_h);
    assert_eq!(bsz, req_b);
    // no write happened before the failure (INV-2): sentinels intact
    assert!(gb.iter().all(|w| *w == 0xAAAAAAAAAAAAAAAA));
    assert!(hb.iter().all(|w| *w == 0xAAAAAAAAAAAAAAAA));
    assert!(bb.iter().all(|b| *b == 0xAA));
}

/// INV-3: illegal buffer topology (partial-NULL, misaligned, overlapping) is
/// explicitly rejected; state untouched, buffers untouched.
#[test]
fn inv3_topology_rejects_illegal() {
    let _g = l();
    let (req_g, req_h, req_b) = probe(SET_BP);
    let mut gb = pts_buf(req_g);
    let mut hb = pts_buf(req_h);
    let mut bb = vec![0xAAu8; req_b as usize];
    let (mut gsz, mut hsz, mut bsz) = (req_g, req_h, req_b);
    let gp = gb.as_mut_ptr() as *mut u8;
    let hp = hb.as_mut_ptr() as *mut u8;
    let bp = bb.as_mut_ptr();

    // partial-NULL: g missing, others present
    let rc = unsafe {
        shlosilo_gencache_provide_table(
            SET_BP,
            core::ptr::null_mut(),
            &mut gsz,
            hp,
            &mut hsz,
            bp,
            &mut bsz,
        )
    };
    assert_eq!(rc, ERR_NULL_POINTER, "partial-NULL must be rejected");

    // misaligned g (point tables are 8-aligned)
    let rc = unsafe {
        shlosilo_gencache_provide_table(SET_BP, gp.add(1), &mut gsz, hp, &mut hsz, bp, &mut bsz)
    };
    assert_eq!(
        rc, ERR_NULL_POINTER,
        "misaligned point table must be rejected"
    );

    // overlapping g/h (same base address)
    let rc = unsafe {
        shlosilo_gencache_provide_table(SET_BP, gp, &mut gsz, gp, &mut hsz, bp, &mut bsz)
    };
    assert_eq!(rc, ERR_NULL_POINTER, "overlapping regions must be rejected");

    // overlapping g/blob (interior overlap)
    let rc = unsafe {
        shlosilo_gencache_provide_table(SET_BP, gp, &mut gsz, hp, &mut hsz, gp, &mut bsz)
    };
    assert_eq!(rc, ERR_NULL_POINTER, "g/blob overlap must be rejected");

    // state untouched: sentinels intact, slot still free for INV-4 to consume
    assert!(gb.iter().all(|w| *w == 0xAAAAAAAAAAAAAAAA));
    assert!(hb.iter().all(|w| *w == 0xAAAAAAAAAAAAAAAA));
    assert!(bb.iter().all(|b| *b == 0xAA));
}

/// INV-4: atomic state transition — success moves the slot to CONSUMED
/// (terminal); failure leaves state unchanged and a corrected retry succeeds.
#[test]
fn inv4_provide_atomic_consume_retry() {
    let _g = l();
    let (req_g, req_h, req_b) = probe(SET_BP);
    let mut gb = pts_buf(req_g);
    let mut hb = pts_buf(req_h);
    let mut bb = vec![0xAAu8; req_b as usize];
    let (mut gsz, mut hsz, mut bsz) = (req_g, req_h, req_b);
    let gp = gb.as_mut_ptr() as *mut u8;
    let hp = hb.as_mut_ptr() as *mut u8;
    let bp = bb.as_mut_ptr();

    // failure 1: topology (misaligned) — state must be unchanged
    let rc = unsafe {
        shlosilo_gencache_provide_table(SET_BP, gp.add(1), &mut gsz, hp, &mut hsz, bp, &mut bsz)
    };
    assert_eq!(rc, ERR_NULL_POINTER);
    // failure 2: capacity — state must be unchanged
    let mut bad_b = req_b - 1;
    let rc = unsafe {
        shlosilo_gencache_provide_table(SET_BP, gp, &mut gsz, hp, &mut hsz, bp, &mut bad_b)
    };
    assert_eq!(rc, ERR_BUFFER_TOO_SMALL);

    // corrected retry succeeds (state was never consumed by the failures)
    let rc = unsafe {
        shlosilo_gencache_provide_table(SET_BP, gp, &mut gsz, hp, &mut hsz, bp, &mut bsz)
    };
    assert_eq!(rc, OK, "retry after failures must succeed");

    // CONSUMED is terminal
    let rc = unsafe {
        shlosilo_gencache_provide_table(SET_BP, gp, &mut gsz, hp, &mut hsz, bp, &mut bsz)
    };
    assert_eq!(rc, ERR_SLOT_CONSUMED);
}
