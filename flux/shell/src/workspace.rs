//! Memory a run needs, provisioned once per run.
//!
//! forms allocates nothing: every buffer a request needs is carved from caller memory
//! (`SignWsLayout` / `review::build` take it as an argument). The design puts the
//! memory strategy on the flux side ("forms allocates nothing (the zero-heap path;
//! flux owns its memory strategy)", `sign_with_entropy_ws` docs), and the carrier seam
//! as frozen in design §4 has no workspace opening yet — so the shell provisions the
//! spans itself, once per run, from the sizes forms publishes.
//!
//! Every number below is forms' own number. None of them is a copy of a constant that
//! lives somewhere else: a second home for a size is how a capacity check and a carve
//! drift apart.

use shlosilo::business::sign::SignWsLayout;
use shlosilo::chain::btc::psbt::KvRec;
use shlosilo::limits;
use shlosilo::types::caps;

/// Byte lengths of the five spans one run holds.
struct Spans {
    review_arena: usize,
    review_recs: usize,
    review_typed_data: usize,
    sign_ws: usize,
    out: usize,
}

impl Spans {
    fn measure() -> Self {
        // The review side is one contiguous region in the C-ABI carve (arena, records,
        // then the EIP-712 tail). Rust needs the sizes, not the contiguity, so each span
        // is its own allocation — which also means no alignment fix-up: `Vec<u8>` is
        // byte-aligned by contract and `Vec<KvRec>` is aligned by its element type.
        //
        // The typed-data tail length is derived from the total forms publishes for "one
        // review workspace" minus the two spans it names, because the EIP-712 pool's own
        // region constants are crate-private. Subtracting keeps the tail correct by
        // construction when a profile changes the pool's capacities; a hardcoded byte
        // count would silently under-size it.
        let recs_bytes = limits::PSBT_RECS_MAX * core::mem::size_of::<KvRec>();
        let typed_data_bytes = shlosilo::ffi::c_abi::review_ws_len()
            .saturating_sub(limits::PSBT_ARENA_BYTES)
            .saturating_sub(recs_bytes);

        Spans {
            review_arena: limits::PSBT_ARENA_BYTES,
            review_recs: limits::PSBT_RECS_MAX,
            review_typed_data: typed_data_bytes,
            sign_ws: SignWsLayout::compute().total,
            out: caps::SIGN_OUTPUT_BUF_MAX_LEN,
        }
    }
}

/// Bytes one run holds at peak.
///
/// Diagnostic, and the number a carrier's memory budget has to cover. It is measured
/// from the spans that are actually allocated, so a profile change moves it with the
/// allocation instead of leaving a stale figure in a datasheet.
pub fn workspace_bytes() -> usize {
    let s = Spans::measure();
    s.review_arena
        + s.review_recs * core::mem::size_of::<KvRec>()
        + s.review_typed_data
        + s.sign_ws
        + s.out
}

/// The spans one run borrows: review pools, the sign workspace, and the output buffer.
pub(crate) struct Workspaces {
    /// PSBT map pool for the review pages.
    pub(crate) review_arena: Vec<u8>,
    /// PSBT key/value index for the review pages.
    pub(crate) review_recs: Vec<KvRec>,
    /// EIP-712 pool plus the review page's formatting scratch.
    pub(crate) review_typed_data: Vec<u8>,
    /// Sign workspace (`carve_sign_ws` expects exactly `SignWsLayout::compute().total`).
    pub(crate) sign_ws: Vec<u8>,
    /// Signed artifact buffer.
    pub(crate) out: Vec<u8>,
}

impl Workspaces {
    pub(crate) fn provision() -> Self {
        let s = Spans::measure();
        Workspaces {
            review_arena: vec![0u8; s.review_arena],
            review_recs: vec![KvRec::EMPTY; s.review_recs],
            review_typed_data: vec![0u8; s.review_typed_data],
            sign_ws: vec![0u8; s.sign_ws],
            out: vec![0u8; s.out],
        }
    }
}
