//! #73 / A4-04: the XMR sign workspace is a carrier-owned STATIC region, not heap.
//!
//! The audit's point was that "forms takes a caller slice" does not mean "the device sign path
//! allocates nothing": the console used to build the workspace out of ~20 `Vec`s per sign (128 KiB
//! `tx_bytes` alone, ~169 KiB live measured), i.e. every signature went through the allocator.
//!
//! This module reserves the front of PSRAM as a fixed pool and nothing else ever allocates from it:
//!
//! ```text
//! 0x1100_0000  +-----------------------------+  <- SIGN arena (carved per sign, reused)
//!              | SIGN_ARENA_BYTES (3 MiB)    |
//!              +-----------------------------+  <- pending payload slot
//!              | PENDING_BYTES (61,440)      |
//!              +-----------------------------+  <- __psram pool end; the LLFF heap starts here
//!              | PSRAM heap (rest of 8 MiB)  |
//! ```
//!
//! Sizing is not a guess: `SignWsLayout::compute().total` for this profile is 2,912,751 bytes
//! (`bash scripts/limits_report.sh pico2`), and `check_capacity()` asserts at bring-up that the
//! layout still fits the arena and that the pending slot covers the profile's inbound payload cap
//! (`limits/*.toml` `ur_payload_max`). The capacity is the same one the FFI carve uses, so the
//! console and forgebox cannot drift: one layout, two consumers.
//!
//! Ownership: `take_sign` / `take_pending` hand out `&'static mut` slices over the reserved
//! region under an exclusive flag, and the guard clears the flag on drop. Aliasing is therefore
//! structurally impossible even though the memory is raw — the same discipline as the C-ABI
//! workspace contract (one workspace, one execution context).

use core::sync::atomic::{AtomicBool, Ordering};

/// The carve-based sign workspace arena. 3 MiB covers the measured 2,912,751-byte layout with
/// ~12% slack; `check_capacity` fails loudly if the layout ever outgrows it.
pub const SIGN_ARENA_BYTES: usize = 3 * 1024 * 1024;

/// Inbound UR payload staging (the XMR request is copied here when a multipart/single-frame
/// decode completes, and read back by the sign flow). Sized from the profile's payload cap.
pub const PENDING_BYTES: usize = shlosilo::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN;

/// Total bytes the sign path owns out of PSRAM; the heap starts after this.
pub const POOL_BYTES: usize = SIGN_ARENA_BYTES + PENDING_BYTES;

const _: () = assert!(
    PENDING_BYTES <= SIGN_ARENA_BYTES,
    "the pending slot is a fraction of the sign arena; a bigger one means the profile changed"
);

/// Set once at PSRAM bring-up: the profile's layout and payload cap fit the reserved regions.
/// A build whose profile outgrew the pool refuses the sign path instead of overflowing.
static CAPACITY_OK: AtomicBool = AtomicBool::new(false);

static SIGN_TAKEN: AtomicBool = AtomicBool::new(false);
static PENDING_TAKEN: AtomicBool = AtomicBool::new(false);
/// Length of the staged payload (0 = nothing staged).
static PENDING_LEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Exclusive handle over the sign arena. Dropping it releases the arena for the next sign.
pub struct SignArena {
    buf: &'static mut [u8],
}

impl Drop for SignArena {
    fn drop(&mut self) {
        SIGN_TAKEN.store(false, Ordering::Release);
    }
}

impl SignArena {
    pub fn as_mut(&mut self) -> &mut [u8] {
        self.buf
    }
}

/// Exclusive handle over the staged payload.
pub struct PendingSlot {
    buf: &'static mut [u8],
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        // One-shot semantics, same as the Vec take this replaces: the request is consumed by the
        // attempt, so a failed sign needs a fresh scan. The staged bytes are not secret (a
        // wallet's sign request is public data) but nothing is kept alive past the flow either.
        PENDING_LEN.store(0, Ordering::Release);
        PENDING_TAKEN.store(false, Ordering::Release);
    }
}

impl PendingSlot {
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..PENDING_LEN.load(Ordering::Acquire)]
    }
}

/// The reserved region base, or `None` when PSRAM never came up (SRAM-only boot) or the
/// bring-up capacity check failed.
fn pool_base() -> Option<usize> {
    if !CAPACITY_OK.load(Ordering::Acquire) {
        return None;
    }
    let (base, size) = crate::psram_region()?;
    if size < POOL_BYTES {
        return None;
    }
    Some(base)
}

/// Take the sign arena exclusively. `None` = PSRAM unavailable or the arena is already taken
/// (a second sign while one is running; the console serialises them anyway).
pub fn take_sign() -> Option<SignArena> {
    let base = pool_base()?;
    if SIGN_TAKEN.swap(true, Ordering::AcqRel) {
        return None;
    }
    // SAFETY: `base .. base + SIGN_ARENA_BYTES` is memory-mapped PSRAM that the LLFF heap was
    // never given (the heap starts at `base + POOL_BYTES`), and the flag above makes this the
    // only outstanding `&mut` over it.
    let buf = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, SIGN_ARENA_BYTES) };
    Some(SignArena { buf })
}

/// Copy `payload` into the reserved staging slot. `false` = too big or PSRAM unavailable.
pub fn stage_pending(payload: &[u8]) -> bool {
    if payload.len() > PENDING_BYTES {
        return false;
    }
    let Some(slot) = take_pending() else {
        return false;
    };
    slot.buf[..payload.len()].copy_from_slice(payload);
    PENDING_LEN.store(payload.len(), Ordering::Release);
    true
}

/// Take the staged payload exclusively.
pub fn take_pending() -> Option<PendingSlot> {
    let base = pool_base()?;
    if PENDING_TAKEN.swap(true, Ordering::AcqRel) {
        return None;
    }
    // SAFETY: as in `take_sign`, over the staging sub-region; exclusive via the flag.
    let buf = unsafe {
        core::slice::from_raw_parts_mut((base + SIGN_ARENA_BYTES) as *mut u8, PENDING_BYTES)
    };
    Some(PendingSlot { buf })
}

/// True when something is staged (the console's "a request is waiting for signing" flag).
pub fn has_pending() -> bool {
    PENDING_LEN.load(Ordering::Acquire) != 0
}

/// Bring-up check + latch: the profile's sign layout must fit the reserved arena and the region
/// must be big enough for the whole pool. Called once from `psram_mark_rw_ok`; the latch is what
/// `take_sign` consults, so a profile that outgrew the pool refuses the sign path instead of
/// overflowing it. Returns the check result for the bring-up log line.
pub fn note_capacity() -> bool {
    let layout = shlosilo::business::sign::SignWsLayout::compute().total;
    let ok = layout <= SIGN_ARENA_BYTES
        && crate::psram_region().is_some_and(|(_, size)| size >= POOL_BYTES);
    CAPACITY_OK.store(ok, Ordering::Release);
    ok
}

/// Bytes the sign layout needs on this profile (for the console's `heap`/status line).
pub fn layout_bytes() -> usize {
    shlosilo::business::sign::SignWsLayout::compute().total
}

/// Where this lives: the pool module, NOT the console shell. The sign path must exist in every
/// flavor that carries it - including the heap-free one, which has no console module at all - so
/// its home cannot be the console. The console is one caller.
/// The measured sign stretch: carve the carrier's static arena and run the flow.
///
/// `#[inline(never)]` is deliberate. The allocation gate
/// (`scripts/pico2_sign_noalloc_check.sh`) measures THIS symbol's reachable call set on the
/// production image; with the body inlined into the console task's poll there is no entry point
/// to measure at all, and "no allocation sites found" becomes indistinguishable from "the
/// instrument is looking at nothing" (the A4-15 blindness class).
///
/// Pool failures map to `BufferTooSmall` (the workspace is unavailable), the same code the FFI
/// carve path uses when a caller's buffer is short.
#[inline(never)]
pub(crate) fn sign_stretch(
    input: shlosilo::business::sign::SignInput<'_>,
    payload: &[u8],
    entropy: &[u8],
    out: &mut [u8],
) -> Result<usize, shlosilo::error::ShlosiloError> {
    let err =
        || shlosilo::error::ShlosiloError::new(shlosilo::error::ShlosiloErrorKind::BufferTooSmall);
    // A4-04: ONE caller-owned arena, carved with the same layout the C-ABI face uses
    // (`SignWsLayout`), instead of ~20 heap `Vec`s per sign. The arena is the reserved static
    // pool at the front of PSRAM (sign_pool), sized once at bring-up; a profile whose layout
    // outgrows it is refused at boot rather than overflowing here.
    let Some(mut arena) = take_sign() else {
        return Err(err());
    };
    let Some(mut ws) = shlosilo::business::sign::carve_sign_ws(arena.as_mut()) else {
        return Err(err());
    };
    shlosilo::business::sign::sign_with_entropy_ws(
        input,
        shlosilo::ur::ur_encode::UrTypeTag::XmrTxUnsigned,
        payload,
        &[], // wallet KI records: not yet retained on pico2 (dev console)
        entropy,
        Some(&mut ws),
        out,
    )
}
