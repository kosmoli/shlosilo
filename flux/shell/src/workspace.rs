//! Memory one run needs — lent by the carrier, never allocated here.
//!
//! forms allocates nothing: every buffer a request needs is carved from caller memory
//! (`SignWsLayout` / `review::build` take it as an argument). The previous slice had the
//! *shell* provision those spans, which made this crate allocator-bound — measured at
//! ~3.1 MB per run on the host profile and, worse, structurally unreachable from a
//! bare-metal carrier (design §10 gap 5: "pico2 cannot adopt the shell until it has a
//! workspace seam — a structural block, not a schedule question").
//!
//! This module is that seam's memory half. The sizes stay forms-answered
//! ([`WorkspaceSizes::compute`] reads them from forms' own published layout numbers), the
//! *storage* belongs to whoever runs the shell: a carrier's statics, a board's PSRAM
//! arena, or — on the host — the convenience owner below (feature `std`).
//!
//! Every number below is forms' own number. None of them is a copy of a constant that
//! lives somewhere else: a second home for a size is how a capacity check and a carve
//! drift apart.

use shlosilo::business::sign::SignWsLayout;
use shlosilo::chain::btc::psbt::KvRec;
use shlosilo::limits;
use shlosilo::types::caps;

/// Lengths of the six spans one run borrows.
///
/// A carrier allocates exactly these and hands them to [`Workspaces`]. `review_recs` is a
/// **count** of [`KvRec`] slots, not a byte length, because the record array's stride is
/// its element type's size — publishing bytes would invite a caller to divide by the wrong
/// number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceSizes {
    /// Request payload copy ([`WorkspaceSizes::request`] bytes).
    ///
    /// Sized by forms' inbound UR payload ceiling (`limits::UR_PAYLOAD_MAX`, a profile
    /// number). A request the carrier assembled from UR frames can never exceed it, and a
    /// carrier with another transport still cannot hand forms more than what forms' parse
    /// paths are sized for — so this is the structural bound, not a guess.
    pub request: usize,
    /// PSBT map pool for the review pages.
    pub review_arena: usize,
    /// PSBT key/value index slots for the review pages (a **count**).
    pub review_recs: usize,
    /// EIP-712 pool plus the review page's formatting scratch.
    pub review_typed: usize,
    /// Sign workspace (`carve_sign_ws` expects exactly `SignWsLayout::compute().total`).
    pub sign_ws: usize,
    /// Signed artifact buffer.
    pub out: usize,
}

impl WorkspaceSizes {
    /// Measure the spans from forms' published layout numbers.
    ///
    /// The typed-data tail length is derived from the total forms publishes for "one
    /// review workspace" minus the two spans it names, because the EIP-712 pool's own
    /// region constants are crate-private. Subtracting keeps the tail correct by
    /// construction when a profile changes the pool's capacities; a hardcoded byte count
    /// would silently under-size it.
    pub fn compute() -> Self {
        let recs_bytes = limits::PSBT_RECS_MAX * core::mem::size_of::<KvRec>();
        let review_typed = shlosilo::ffi::c_abi::review_ws_len()
            .saturating_sub(limits::PSBT_ARENA_BYTES)
            .saturating_sub(recs_bytes);

        WorkspaceSizes {
            request: limits::UR_PAYLOAD_MAX,
            review_arena: limits::PSBT_ARENA_BYTES,
            review_recs: limits::PSBT_RECS_MAX,
            review_typed,
            sign_ws: SignWsLayout::compute().total,
            out: caps::SIGN_OUTPUT_BUF_MAX_LEN,
        }
    }

    /// Bytes per `KvRec`, so a carrier can size its record array itself.
    pub fn kv_rec_bytes(&self) -> usize {
        core::mem::size_of::<KvRec>()
    }

    /// Bytes one run holds at peak (what a carrier's memory budget has to cover).
    pub fn total_bytes(&self) -> usize {
        self.request
            + self.review_arena
            + self.review_recs * core::mem::size_of::<KvRec>()
            + self.review_typed
            + self.sign_ws
            + self.out
    }
}

/// The spans one run borrows.
///
/// Nothing here is owned: the carrier (or whatever holds its memory) keeps ownership for
/// the whole run and gets the spans back afterwards. Alignment is the element type's job —
/// `&mut [u8]` is byte-aligned by contract and `&mut [KvRec]` is aligned by `KvRec`, which
/// is exactly what `carve_sign_ws` / `review::build` / `parse_psbt_any` already assume.
pub struct Workspaces<'a> {
    /// Request payload staging (the flow copies the carrier's payload here once, then
    /// works off `&ws.request[..n]`).
    pub request: &'a mut [u8],
    /// PSBT map pool for the review pages.
    pub review_arena: &'a mut [u8],
    /// PSBT key/value index for the review pages.
    pub review_recs: &'a mut [KvRec],
    /// EIP-712 pool plus the review page's formatting scratch.
    pub review_typed: &'a mut [u8],
    /// Sign workspace.
    pub sign_ws: &'a mut [u8],
    /// Signed artifact buffer.
    pub out: &'a mut [u8],
}

impl<'a> Workspaces<'a> {
    /// Wire a caller's six spans into one workspace.
    ///
    /// Field order is the allocation order in [`WorkspaceSizes::compute`]; keeping one
    /// constructor is what stops a carrier from wiring the record pool into the byte pool.
    pub fn new(
        request: &'a mut [u8],
        review_arena: &'a mut [u8],
        review_recs: &'a mut [KvRec],
        review_typed: &'a mut [u8],
        sign_ws: &'a mut [u8],
        out: &'a mut [u8],
    ) -> Self {
        Workspaces {
            request,
            review_arena,
            review_recs,
            review_typed,
            sign_ws,
            out,
        }
    }

    /// Host convenience: an owner that allocates the spans, then lends them.
    ///
    /// `#[cfg(feature = "std")]` on purpose — a device carrier must not have this available,
    /// because reaching for it is the temptation that made this crate allocator-bound in the
    /// first place.
    ///
    /// Two steps by necessity: [`Workspaces`] *borrows* its spans, so a value that both owns
    /// the `Vec`s and hands out the borrows would be self-referential (`borrow()` on the
    /// owner is the second half). Callers write
    /// `let mut owned = Workspaces::owned(); run_once(&mut c, &cfg, &mut owned.borrow())`.
    #[cfg(feature = "std")]
    pub fn owned() -> OwnedWorkspaces {
        OwnedWorkspaces::new()
    }
}

/// Host convenience: a workspace whose spans a `Vec` owns.
///
/// `#[cfg(feature = "std")]` on purpose — a device carrier must not have this type
/// available, because reaching for it is the temptation that made this crate
/// allocator-bound in the first place.
///
/// It cannot be `Workspaces::owned()`: `Workspaces<'a>` borrows its spans, so a value that
/// both owns the `Vec`s and hands out the borrows would be self-referential (and moving it
/// would invalidate the borrows). Two steps instead — own, then [`OwnedWorkspaces::borrow`].
#[cfg(feature = "std")]
pub struct OwnedWorkspaces {
    request: std::vec::Vec<u8>,
    review_arena: std::vec::Vec<u8>,
    review_recs: std::vec::Vec<KvRec>,
    review_typed: std::vec::Vec<u8>,
    sign_ws: std::vec::Vec<u8>,
    out: std::vec::Vec<u8>,
}

#[cfg(feature = "std")]
impl OwnedWorkspaces {
    /// Allocate exactly what [`WorkspaceSizes::compute`] asks for.
    pub fn new() -> Self {
        let s = WorkspaceSizes::compute();
        OwnedWorkspaces {
            request: std::vec![0u8; s.request],
            review_arena: std::vec![0u8; s.review_arena],
            review_recs: std::vec![KvRec::EMPTY; s.review_recs],
            review_typed: std::vec![0u8; s.review_typed],
            sign_ws: std::vec![0u8; s.sign_ws],
            out: std::vec![0u8; s.out],
        }
    }

    /// The lengths this owner was built from.
    pub fn sizes() -> WorkspaceSizes {
        WorkspaceSizes::compute()
    }

    /// Borrow the six spans for one [`crate::run_once`] call.
    pub fn borrow(&mut self) -> Workspaces<'_> {
        Workspaces {
            request: &mut self.request,
            review_arena: &mut self.review_arena,
            review_recs: &mut self.review_recs,
            review_typed: &mut self.review_typed,
            sign_ws: &mut self.sign_ws,
            out: &mut self.out,
        }
    }
}

#[cfg(feature = "std")]
impl Default for OwnedWorkspaces {
    fn default() -> Self {
        Self::new()
    }
}

/// Bytes one run holds at peak, per span.
///
/// Diagnostic, and the number a carrier's memory budget has to cover. It is measured from
/// the spans the flow actually borrows, so a profile change moves it with the allocation
/// instead of leaving a stale figure in a datasheet.
pub fn workspace_bytes() -> WorkspaceSizes {
    WorkspaceSizes::compute()
}
