//! Memory-contract pins: the caller-provided scratch region.
//!
//! Discipline: `v2-安全` §6 (scratch 与工作区的内存契约). Frozen invariants:
//! `shlosilo-接口冻结-内存契约-2026-11-23` (I1/I2/I3/I10).
//!
//! The region is optional: NULL keeps the old behaviour (the signer carves the
//! same capacity out of its own workspace — slower tier, identical output).
//! What is pinned here is the *contract* around it: the reported requirement,
//! and that a malformed region is rejected before any input work happens.

use shlosilo::error::ShlosiloErrorCode;
use shlosilo::ffi::c_abi::{
    shlosilo_sign_ffi, shlosilo_sign_scratch_len, shlosilo_sign_ws_len, SHLOSILO_SIGN_SCRATCH_ALIGN,
};
use shlosilo::types::caps;

/// I10: the requirement is a build-time fact derived from the profile chunk.
#[test]
fn scratch_len_matches_profile() {
    let reported = shlosilo_sign_scratch_len();
    assert_eq!(reported as usize, caps::SIGN_SCRATCH_BYTES);
    assert_eq!(
        reported as usize,
        curve25519_dalek::scratch::StrausScratch::storage_bytes(caps::SIGN_BP_CHUNK_TERMS)
    );
    // The CT path itself only touches the tables + digits for `chunk` terms;
    // the wider reservation is the vartime NAF5 worst case (documented in caps).
    let ct_only = caps::SIGN_BP_CHUNK_TERMS * (8 * 160) + caps::SIGN_BP_CHUNK_TERMS * 64;
    assert!(
        ct_only <= reported as usize,
        "the reported requirement must cover the CT working set ({ct_only} B)"
    );
}

/// A signing call that never gets past the prologue: enough workspace, junk
/// inputs. Every case below must be rejected by the scratch contract *before*
/// the junk inputs are looked at.
fn call_with_scratch(scratch: *mut u8, scratch_len: u32) -> i32 {
    let ws_need = shlosilo_sign_ws_len() as usize;
    let mut ws = std::vec![0u8; ws_need];
    let mut out = [0u8; 64];
    let mut actual: u32 = 0xDEAD_BEEF;
    let mnemonic = [0u16; 12];
    let payload = [0u8; 8];
    // SAFETY: every pointer below refers to a live local of the stated length.
    unsafe {
        shlosilo_sign_ffi(
            mnemonic.as_ptr(),
            12,
            core::ptr::null(),
            0,
            payload.as_ptr(),
            payload.len() as u32,
            0,
            out.as_mut_ptr(),
            out.len() as u32,
            &mut actual,
            ws.as_mut_ptr(),
            ws.len() as u32,
            scratch,
            scratch_len,
        )
    }
}

/// I2: a region smaller than the reported requirement is refused.
#[test]
fn scratch_too_small_rejected() {
    let need = shlosilo_sign_scratch_len() as usize;
    let mut buf = std::vec![0u8; need + SHLOSILO_SIGN_SCRATCH_ALIGN];
    let aligned = buf.as_mut_ptr();
    assert_eq!(aligned as usize % SHLOSILO_SIGN_SCRATCH_ALIGN, 0);
    let code = call_with_scratch(aligned, (need - 1) as u32);
    assert_eq!(
        code,
        ShlosiloErrorCode::BufferTooSmall as i32,
        "undersized scratch must be a capacity error, got {code}"
    );
}

/// I3: a misaligned region is refused (the alignment requirement is public).
#[test]
fn scratch_misaligned_rejected() {
    let need = shlosilo_sign_scratch_len() as usize;
    let mut buf = std::vec![0u8; need + 8];
    // SAFETY: one byte into a live buffer is still inside the allocation.
    let misaligned = unsafe { buf.as_mut_ptr().add(1) };
    assert_ne!(misaligned as usize % SHLOSILO_SIGN_SCRATCH_ALIGN, 0);
    let code = call_with_scratch(misaligned, need as u32);
    assert_eq!(
        code,
        ShlosiloErrorCode::InvalidArgument as i32,
        "misaligned scratch must be an argument error, got {code}"
    );
}

/// A NULL pointer with a non-zero length is a caller bug, not "no scratch".
#[test]
fn null_scratch_with_length_rejected() {
    let code = call_with_scratch(core::ptr::null_mut(), 64);
    assert_eq!(
        code,
        ShlosiloErrorCode::InvalidArgument as i32,
        "NULL with a length must be an argument error, got {code}"
    );
}

/// I1 (workspace half, unchanged): `ws == NULL` stays a pure probe — it reports
/// the workspace requirement and returns before any input work, regardless of
/// what the scratch arguments say.
#[test]
fn workspace_probe_still_pure() {
    let mut actual: u32 = 0;
    let out = [0u8; 8];
    let mnemonic = [0u16; 12];
    let payload = [0u8; 8];
    // SAFETY: the probe branch returns before dereferencing any of these.
    let code = unsafe {
        shlosilo_sign_ffi(
            mnemonic.as_ptr(),
            12,
            core::ptr::null(),
            0,
            payload.as_ptr(),
            payload.len() as u32,
            0,
            out.as_ptr() as *mut u8,
            out.len() as u32,
            &mut actual,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(code, ShlosiloErrorCode::Ok as i32);
    assert_eq!(actual, shlosilo_sign_ws_len());
}
