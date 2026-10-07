//! Shared keysource FFI workspace state: one live session slot per caller
//! workspace, common to EVERY keysource glue entry (QR scan flow and SE
//! password unlock).
//!
//! Task 8 extracts this from `ffi.rs` so the QR and SE C entries share ONE
//! teardown (`ws_close`) and ONE layout: a workspace opened by
//! `shlosilo_keysource_se_open_ffi` is closed by either close entry — both
//! are the same function — and the "one live session per workspace" capacity
//! gate is enforced on the shared state, so a QR session and an SE session
//! can never coexist in one workspace.
//!
//! # Workspace contract (Z3.3c caller-workspace, R3-style)
//!
//! - The caller hands over `ws_len()` bytes in a `static` or task workspace
//!   (BSS is zero-filled — REQUIRED initial state: the `live` marker's zero
//!   value means "no session", which is what makes `close` before the first
//!   `open` a defined no-op).
//! - The glue writes that workspace only through the entries above it. The
//!   caller must not inspect or rewrite it.
//! - The workspace must stay at a stable address from the first `open` until
//!   the matching `close` (the live handle borrows the slot inside it —
//!   self-referential placement, `ptr::write`, never `Box`; Z6 zero-heap).

use core::ffi::c_uint;
use core::mem::MaybeUninit;

use shlosilo::error::{ShlosiloError, ShlosiloErrorKind};
use shlosilo::ffi::error_code::{to_ffi_code, ERR_SLOT_OCCUPIED, OK};
use shlosilo::types::key_session::KeySession;

use super::{KeySessionHandle, KeySessionSlot};

/// The workspace-carried state (exactly one per caller workspace).
///
/// `#[repr(C)]` only so the shape is documented; no field offset is part of
/// any contract — the glue places the WHOLE struct at an aligned address
/// inside the workspace.
#[repr(C)]
pub(crate) struct KeyWs {
    /// `0` = no live session — the REQUIRED initial state of a fresh
    /// workspace (BSS-zeroed `static` / task workspace) and the state `close`
    /// restores. `1` = `handle` holds a live [`KeySessionHandle`]. Written
    /// only by this glue.
    live: u8,
    /// The one session slot (capacity 1), constructed in place at each open
    /// (`ptr::write`, caller storage — never `Box`, Z6).
    slot: KeySessionSlot,
    /// Single-owner handle of the live session. Self-referential: it borrows
    /// `slot` in this same workspace (fabricated `'static` under the
    /// caller-pinning contract, R3 `UrMultipartDecoder` style).
    handle: MaybeUninit<KeySessionHandle<'static>>,
}

/// Typed workspace base: align the raw `ws` up to [`KeyWs`].
///
/// # Safety
///
/// `ws` must be the caller workspace from the entry contract: at least
/// [`ws_len`] valid bytes, exclusive to this glue, pinned at a stable
/// address. The returned pointer is derived from `ws` — same validity.
#[inline(always)]
pub(crate) unsafe fn ws_state(ws: *mut u8) -> *mut KeyWs {
    let align = core::mem::align_of::<KeyWs>();
    let addr = (ws as usize).wrapping_add(align - 1) & !(align - 1);
    addr as *mut KeyWs
}

/// Workspace capacity for one keysource session (C-ABI workspace contract
/// v1: runtime query, never frozen into the ABI).
///
/// Pure: no state, no side effects. Covers the [`KeyWs`] state (slot + live
/// handle) plus the alignment slop any base address needs — the same
/// `size_of`/`align_of` computation the placement carve uses (contract 3:
/// one layout source of truth).
pub(crate) fn ws_len() -> c_uint {
    let align = core::mem::align_of::<KeyWs>();
    (core::mem::size_of::<KeyWs>() + align - 1) as c_uint
}

/// Install a fresh empty slot in the workspace and borrow it — the slot the
/// key source installs its session into (`slot.open()` stays the sole handle
/// source).
///
/// The `'static` borrow is fabricated under the caller-pinning contract (the
/// workspace outlives every use; R3 `UrMultipartDecoder` pattern) and is
/// consumed by [`ws_store_handle`] before any other workspace write.
///
/// # Safety
///
/// `state` must be inside the pinned caller workspace and `live == 0` (the
/// caller's occupancy gate ran first). `ptr::write` over the previous
/// (empty or never-initialized) slot skips its Drop, which is a no-op for an
/// empty slot — nothing is leaked.
pub(crate) unsafe fn ws_prepare(state: *mut KeyWs) -> &'static KeySessionSlot {
    core::ptr::write(&mut (*state).slot, KeySessionSlot::empty());
    &*core::ptr::addr_of!((*state).slot)
}

/// Commit a freshly opened handle (from [`ws_prepare`]'s slot) into the
/// workspace and hand the live session pointer out. `live` is set only after
/// the handle is in place: an interrupting close can never observe
/// `live == 1` without a valid handle.
pub(crate) unsafe fn ws_store_handle(
    state: *mut KeyWs,
    handle: KeySessionHandle<'static>,
    out_session: *mut *const KeySession,
) -> i32 {
    core::ptr::write(&mut (*state).handle, MaybeUninit::new(handle));
    (*state).live = 1;
    let live_session: *const KeySession = match (&*(*state).handle.as_ptr()).session() {
        Some(s) => s,
        None => {
            (*state).live = 0;
            return to_ffi_code(&ShlosiloError::new(ShlosiloErrorKind::InvariantViolation));
        }
    };
    *out_session = live_session;
    OK
}

/// Install a freshly derived session into the workspace and hand the live
/// session pointer out — the placement half the QR open shares (prepare +
/// `slot.open()` + store).
///
/// `state` must already be known `live == 0` (the caller's occupancy gate ran
/// first); the derivation is long done by the time this runs, so a failed
/// derivation never touches the workspace.
pub(crate) unsafe fn ws_open_into(
    state: *mut KeyWs,
    session: KeySession,
    out_session: *mut *const KeySession,
) -> i32 {
    let slot_ref = ws_prepare(state);
    // `open` is the sole handle source; a fresh slot is empty, so this
    // succeeds — mapped defensively to the invariant code if it ever does
    // not.
    let handle = match slot_ref.open(session) {
        Ok(h) => h,
        Err(_) => return to_ffi_code(&ShlosiloError::new(ShlosiloErrorKind::InvariantViolation)),
    };
    ws_store_handle(state, handle, out_session)
}

/// The shared teardown every keysource close entry runs: drop the live
/// handle in place (`ZeroizeOnDrop` wipes the key bytes) and restore the
/// reusable workspace state.
///
/// Total and idempotent by construction:
/// - fresh workspace (`live == 0` from BSS): defined no-op, `OK`;
/// - workspace whose `open` failed: defined no-op, `OK`;
/// - second `close` after a successful one: defined no-op, `OK` — the
///   zeroizing drop already ran exactly once.
pub(crate) unsafe fn ws_close(ws: *mut u8) -> i32 {
    // SAFETY: `ws` is the caller workspace from the contract (pinned,
    // exclusive); placement only needs the base.
    let state = ws_state(ws);
    // SAFETY: `live` is a plain byte (zero-initialized workspace contract).
    if (*state).live != 0 {
        // SAFETY: `live == 1` means the handle slot holds the live handle
        // (one-handle invariant + the open commit order). `assume_init_read`
        // MOVES the handle out — its Drop then runs the serial-guarded close
        // exactly once (drop_in_place on the slot session → key bytes wiped).
        // `live` is cleared BEFORE the drop, so a re-entrant close during the
        // drop sees `0` and no-ops: the drop can never run twice.
        let handle = (*state).handle.assume_init_read();
        (*state).live = 0;
        drop(handle);
    }
    // Total wipe of the WHOLE workspace window (Phase 4 acceptance ③: the
    // `se dump` forensic view must read ALL ZERO after close). The drop above
    // wipes the key bytes but leaves moved-out handle residue (serial /
    // slot pointer) and padding behind — volatile walk so no compiler can
    // dead-store-eliminate the final clear (same idiom as the C side's
    // WipeVolatile). Also covers the no-op paths (fresh / double close), so
    // any close leaves a defined, fully-zero workspace.
    let n = ws_len() as usize;
    for i in 0..n {
        core::ptr::write_volatile(ws.add(i), 0u8);
    }
    OK
}

/// The workspace-side occupancy gate: `ERR_SLOT_OCCUPIED` when a session is
/// already live, `OK` otherwise. Every open entry runs this BEFORE deriving
/// anything, so a busy workspace never disturbs the live session and never
/// burns a credential attempt.
pub(crate) unsafe fn ws_busy(ws: *mut u8) -> i32 {
    let state = ws_state(ws);
    if (*state).live != 0 {
        ERR_SLOT_OCCUPIED
    } else {
        OK
    }
}
