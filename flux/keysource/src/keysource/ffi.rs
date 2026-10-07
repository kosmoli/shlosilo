//! C-ABI glue for the seed-QR scan flow (Task 5a): **scan bytes in, session
//! pointer out**.
//!
//! Three entries, the whole scan flow on the Rust side:
//!
//! - [`shlosilo_keysource_qr_ws_len`] — workspace capacity query (same
//!   runtime-query contract as `shlosilo_sign_ws_len` / the R3 handle `ws_len`
//!   queries).
//! - [`shlosilo_keysource_qr_open_ffi`] — scan bytes → [`KeySession`], living
//!   in the caller's workspace; hands the live session pointer out for
//!   `shlosilo_sign_session_ffi`.
//! - [`shlosilo_keysource_qr_close_ffi`] — drop the live handle in place
//!   (`ZeroizeOnDrop` wipes the key bytes).
//!
//! # Invariants (pinned by `tests/qr_ffi.rs`)
//!
//! 1. **Seed never appears in any FFI signature** — in or out. Raw scan bytes
//!    go in, a session POINTER goes out (v2 §4.1). The word "seed" appears in
//!    no parameter and no return type; `tests/qr_ffi.rs` pins the signatures
//!    with a source-level grep.
//! 2. **The workspace is caller-pinned** — `static` / task workspace at a
//!    stable address, never moved or reused while a session is live (the
//!    self-referential contract, same as the R3 `UrMultipartDecoder` pools:
//!    the handle borrows its own workspace's slot).
//! 3. **At most one live session per workspace** — a second `open` on a busy
//!    workspace answers `ERR_SLOT_OCCUPIED` (-23) BEFORE touching anything.
//! 4. **`close` is total and idempotent** — a fresh workspace, a workspace
//!    whose `open` failed, and an already-closed workspace all answer `OK`
//!    with a defined no-op; the zeroizing drop runs exactly once per session
//!    (the slot's serial guard backs this up). After `close` the same
//!    workspace may be re-opened with a new scan.
//!
//! # Workspace contract (Z3.3c caller-workspace, R3-style)
//!
//! - The caller hands over `shlosilo_keysource_qr_ws_len()` bytes in a
//!   `static` or task workspace (BSS is zero-filled — REQUIRED initial state:
//!   the `live` marker's zero value means "no session", which is what makes
//!   `close` before the first `open` a defined no-op).
//! - The glue writes that workspace only through these entries. The caller
//!   must not inspect or rewrite it.
//! - The workspace must stay at a stable address from the first `open` until
//!   the matching `close` (the live handle borrows the slot inside it —
//!   self-referential placement, `ptr::write`, never `Box`; Z6 zero-heap).
//!
//! # Two-model boundary (vs. `shlosilo_session_free_ffi`)
//!
//! Two session-lifecycle models exist and must never mix:
//!
//! - **caller-placement model** (`shlosilo_sign_session_ffi` /
//!   `shlosilo_session_free_ffi`): the CALLER constructs and owns the
//!   `KeySession` storage and drops it through `shlosilo_session_free_ffi`.
//! - **QR glue model** (this module): the session is owned by the workspace
//!   slot through the single-owner [`KeySessionHandle`]; it is released ONLY
//!   by `shlosilo_keysource_qr_close_ffi` (or the workspace teardown). A
//!   session obtained from `shlosilo_keysource_qr_open_ffi` MUST NOT be
//!   passed to `shlosilo_session_free_ffi` — that would drop the slot-owned
//!   session behind the live handle's back and turn the next `close` into a
//!   double drop.
//!
//! # SAFETY posture
//!
//! Single-threaded firmware discipline, same as the existing FFI handle docs:
//! one workspace is owned by one execution context — never used concurrently
//! from an interrupt or another thread while a call on it is in flight (the
//! same rule `shlosilo_sign_session_ffi` carries for its handles). All raw
//! dereferences below are bounded by the checked entry contracts documented
//! on each function.

use core::ffi::{c_int, c_uint};
use core::mem::MaybeUninit;

use shlosilo::entropy::seed_qr;
use shlosilo::error::{ShlosiloError, ShlosiloErrorKind};
use shlosilo::ffi::error_code::{
    to_ffi_code, ERR_BUFFER_TOO_SMALL, ERR_NULL_POINTER, ERR_SLOT_OCCUPIED, OK,
};
use shlosilo::types::key_session::KeySession;

use super::{KeySessionHandle, KeySessionSlot};

/// Scan-payload budget for the FFI entries: larger than any QR symbol can
/// deliver (a QR code tops out around 3 KiB) and far above the biggest plate
/// payload (96 digits). Over-budget input is rejected before any slice is
/// formed (P0-03 discipline).
const SCAN_PAYLOAD_MAX_LEN: usize = 4096;

/// The workspace-carried state (exactly one per caller workspace).
///
/// `#[repr(C)]` only so the shape is documented; no field offset is part of
/// any contract — the glue places the WHOLE struct at an aligned address
/// inside the workspace.
#[repr(C)]
struct QrWs {
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

/// Typed workspace base: align the raw `ws` up to `QrWs`.
///
/// # Safety
///
/// `ws` must be the caller workspace from the entry contract: at least
/// [`shlosilo_keysource_qr_ws_len`] valid bytes, exclusive to this glue,
/// pinned at a stable address. The returned pointer is derived from `ws` —
/// same validity.
#[inline(always)]
unsafe fn ws_state(ws: *mut u8) -> *mut QrWs {
    let align = core::mem::align_of::<QrWs>();
    let addr = (ws as usize).wrapping_add(align - 1) & !(align - 1);
    addr as *mut QrWs
}

/// Bounded scan slice: `(data, data_len)` → `&[u8]`, `None` over budget.
///
/// The C contract is that `data` points at `data_len` reachable bytes; the
/// budget keeps a lying `data_len` from demanding an absurd `from_raw_parts`.
fn scan_payload<'a>(data: *const u8, data_len: c_uint) -> Option<&'a [u8]> {
    let len = data_len as usize;
    if len > SCAN_PAYLOAD_MAX_LEN {
        return None;
    }
    if len == 0 {
        return Some(&[]);
    }
    // SAFETY: non-null (entry-checked), `len` non-zero and bounded by the scan
    // budget; pointer validity for `len` bytes is the C side's contract.
    Some(unsafe { core::slice::from_raw_parts(data, len) })
}

/// Workspace capacity for one QR scan-flow session (C-ABI workspace contract
/// v1: runtime query, never frozen into the ABI).
///
/// Pure: no state, no side effects. Covers the [`QrWs`] state (slot + live
/// handle) plus the alignment slop any base address needs — the same
/// `size_of`/`align_of` computation the placement carve uses (contract 3:
/// one layout source of truth).
#[no_mangle]
pub extern "C" fn shlosilo_keysource_qr_ws_len() -> c_uint {
    let align = core::mem::align_of::<QrWs>();
    (core::mem::size_of::<QrWs>() + align - 1) as c_uint
}

/// Task 5a: open a signing session from one scanned seed-QR payload.
///
/// Pipeline (all in RAM, zero persistence): `seed_qr::decode` (full plate
/// validation — recognition order, word-index range, BIP-39 checksum) →
/// `KeySession::from_entropy` → [`KeySessionSlot::open`] in the caller
/// workspace. The staged plaintext dies before the session goes live
/// (`SeedEntropy: ZeroizeOnDrop`).
///
/// - `ws` / `ws_len`: caller workspace — `shlosilo_keysource_qr_ws_len()`
///   bytes, zero-initialized, pinned (see module docs). `ws_len` under
///   capacity answers `ERR_BUFFER_TOO_SMALL` (-20) before anything runs.
/// - `data` / `data_len`: raw scanned bytes (CompactSeedQR 16/32 bytes, or
///   SeedQR standard 48/96 digits). **The only material input** — there is no
///   seed/mnemonic parameter (v2 §4.1).
/// - `out_session`: receives the live [`KeySession`] pointer for
///   `shlosilo_sign_session_ffi` — valid until
///   [`shlosilo_keysource_qr_close_ffi`]; zeroed (`NULL`) on every failure.
///
/// Returns `0` = Ok, negative = error:
/// - `ERR_NULL_POINTER` (-2): `ws` / `data` / `out_session` NULL;
/// - `ERR_BUFFER_TOO_SMALL` (-20): `ws_len` under capacity;
/// - `ERR_SLOT_OCCUPIED` (-23): a session is already live in this workspace
///   (capacity 1 — close it first; the scanned bytes are NOT consumed, so a
///   retry needs no re-scan... they are the caller's buffer anyway);
/// - the `seed_qr::decode` / `from_entropy` codes through the L2b mapping
///   (e.g. `-21` EncodingError for a non-plate payload, `-31` InvalidMnemonic
///   for a checksum failure, `-14` FeatureNotImplemented for `ur:` transport,
///   `-21` when `data_len` exceeds the scan budget).
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: entry null-checks first; all raw derefs below are bounded by that contract
pub extern "C" fn shlosilo_keysource_qr_open_ffi(
    ws: *mut u8,
    ws_len: c_uint,
    data: *const u8,
    data_len: c_uint,
    out_session: *mut *const KeySession,
) -> c_int {
    if ws.is_null() || data.is_null() || out_session.is_null() {
        return ERR_NULL_POINTER;
    }
    // Gate4 #2 discipline: out-param zeroed up front — every failure path
    // below leaves a deterministic NULL behind.
    unsafe {
        *out_session = core::ptr::null();
    }
    // Capacity BEFORE execution (workspace contract): under-capacity is an
    // explicit error, never a truncated carve.
    if (ws_len as usize) < shlosilo_keysource_qr_ws_len() as usize {
        return ERR_BUFFER_TOO_SMALL;
    }
    let payload = match scan_payload(data, data_len) {
        Some(p) => p,
        None => {
            return to_ffi_code(&ShlosiloError::new(
                ShlosiloErrorKind::EncodingInvalidFormat,
            ))
        }
    };
    // SAFETY: `ws` is non-null with `ws_len >= ws_len()` (checked above) — the
    // documented caller-workspace contract; exclusive single-context use.
    let state = unsafe { ws_state(ws) };
    // `live` read: a plain byte, defined by the workspace contract (zero-
    // initialized before first use; written only by this glue).
    if unsafe { (*state).live } != 0 {
        // Invariant 3: at most one live session per workspace. Refused BEFORE
        // any write — the live session (and any borrowed pointer to it) is
        // never disturbed.
        return ERR_SLOT_OCCUPIED;
    }
    // Full validation + derivation — before ANY workspace write, so a failed
    // open leaves the workspace untouched (close on it stays a defined no-op).
    let entropy = match seed_qr::decode(payload) {
        Ok(e) => e,
        Err(e) => return to_ffi_code(&e),
    };
    let session = match KeySession::from_entropy(entropy.expose(), b"") {
        Ok(s) => s,
        Err(e) => return to_ffi_code(&e),
    };
    // Staged plaintext dies before the session goes live (SecretBytes
    // hygiene: only the KeySession's own ZeroizeOnDrop fields persist).
    drop(entropy);
    // SAFETY: `state` is inside the pinned workspace; `live == 0` means no
    // handle and no borrowed session can be outstanding (the only handle
    // source is the `open` below, and its drop is what clears `live`), so
    // re-placing the slot cannot disturb a live value. `ptr::write` over the
    // previous (empty or never-initialized) slot skips its Drop, which is a
    // no-op for an empty slot — nothing is leaked. The `'static` slot
    // reference is fabricated under the caller-pinning contract (the
    // workspace outlives every use; R3 `UrMultipartDecoder` pattern).
    unsafe {
        core::ptr::write(&mut (*state).slot, KeySessionSlot::empty());
        let slot_ref: &KeySessionSlot = &*core::ptr::addr_of!((*state).slot);
        // `open` is the sole handle source; a fresh slot is empty, so this
        // succeeds — mapped defensively to the invariant code if it ever does
        // not.
        let handle = match slot_ref.open(session) {
            Ok(h) => h,
            Err(_) => {
                return to_ffi_code(&ShlosiloError::new(ShlosiloErrorKind::InvariantViolation))
            }
        };
        core::ptr::write(&mut (*state).handle, MaybeUninit::new(handle));
        // `live` set only after the handle is in place: an interrupting close
        // can never observe `live == 1` without a valid handle.
        (*state).live = 1;
        let live_session: *const KeySession = match (&*(*state).handle.as_ptr()).session() {
            Some(s) => s,
            None => {
                (*state).live = 0;
                return to_ffi_code(&ShlosiloError::new(ShlosiloErrorKind::InvariantViolation));
            }
        };
        *out_session = live_session;
    }
    OK
}

/// Task 5a: close the live QR session in this workspace (error-path and
/// end-of-flow teardown).
///
/// Drops the single-owner handle in place: `KeySessionHandle`'s Drop runs the
/// slot's serial-guarded close — `ZeroizeOnDrop` wipes the seed/spend/view
/// key bytes — and the workspace goes back to the reusable state (invariant
/// 4: the same workspace may be re-opened with a new scan afterwards).
///
/// Total and idempotent by construction:
/// - fresh workspace (`live == 0` from BSS): defined no-op, `OK`;
/// - workspace whose `open` failed: defined no-op, `OK`;
/// - second `close` after a successful one: defined no-op, `OK` — the
///   zeroizing drop already ran exactly once.
///
/// - `ws` NULL → `ERR_NULL_POINTER` (-2). There is no `ws_len`: `ws` must be
///   the same workspace buffer `open` was given (caller-pinned).
///
/// **Lifetime rule**: never call this while a `shlosilo_sign_session_ffi`
/// call on the session pointer from `open` is in flight (same rule as
/// `shlosilo_session_free_ffi`) — the in-flight sign would read freed/zeroed
/// key material. Close only after every sign call has returned. And per the
/// two-model boundary: a QR-glue session is closed HERE, never through
/// `shlosilo_session_free_ffi`.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: null-checked first; single-owner workspace (see below)
pub extern "C" fn shlosilo_keysource_qr_close_ffi(ws: *mut u8) -> c_int {
    if ws.is_null() {
        return ERR_NULL_POINTER;
    }
    // SAFETY: `ws` is the caller workspace from the contract (pinned,
    // exclusive); `ws_len` is unnecessary — placement only needs the base.
    let state = unsafe { ws_state(ws) };
    // SAFETY: `live` is a plain byte (zero-initialized workspace contract).
    if unsafe { (*state).live } == 0 {
        return OK; // invariant 4: no live session → defined no-op
    }
    // SAFETY: `live == 1` means the handle slot holds the live handle
    // (invariant 3 + the open commit order). `assume_init_read` MOVES the
    // handle out — its Drop then runs the serial-guarded close exactly once
    // (drop_in_place on the slot session → key bytes wiped). `live` is
    // cleared BEFORE the drop, so a re-entrant close during the drop sees
    // `0` and no-ops: the drop can never run twice.
    unsafe {
        let handle = (*state).handle.assume_init_read();
        (*state).live = 0;
        drop(handle);
    }
    OK
}
