//! The sizes the shell publishes are the sizes a run actually borrows.
//!
//! This crate cannot allocate, so a carrier has to allocate *exactly* what
//! [`workspace_bytes`] asks for — which makes the published numbers a contract, not a
//! datasheet. The pin is cheap and it catches the two ways that contract rots: a span that
//! drifts from forms' layout (the typed-data tail is derived by subtraction — see
//! `workspace.rs`), and a span that silently becomes zero (a zero-length span compiles,
//! then fails a carve at run time on a device).
//!
//! Host-only (`std`): it uses `Workspaces::owned()`, the convenience owner the desktop
//! carrier uses, so the assertion covers the same wiring a real host run exercises.

use shlosilo::business::sign::SignWsLayout;
use shlosilo::chain::btc::psbt::KvRec;
use shlosilo::types::caps;
use shlosilo_flux_shell::{workspace_bytes, WorkspaceSizes, Workspaces};

#[test]
fn the_published_sizes_are_the_ones_a_run_borrows() {
    let sizes: WorkspaceSizes = workspace_bytes();
    // The breakdown is worth printing: it is the memory budget a carrier has to cover, and
    // the biggest number in it (the sign workspace) is what made the old shell
    // allocator-bound.
    println!(
        "request {} + review_arena {} + review_recs {}x{} + review_typed {} + sign_ws {} + out {} = {} bytes",
        sizes.request,
        sizes.review_arena,
        sizes.review_recs,
        sizes.kv_rec_bytes(),
        sizes.review_typed,
        sizes.sign_ws,
        sizes.out,
        sizes.total_bytes()
    );

    let mut owner = Workspaces::owned();
    let ws = owner.borrow();
    assert_eq!(ws.request.len(), sizes.request, "request span");
    assert_eq!(ws.review_arena.len(), sizes.review_arena, "review arena");
    assert_eq!(ws.review_recs.len(), sizes.review_recs, "review recs");
    assert_eq!(ws.review_typed.len(), sizes.review_typed, "typed-data tail");
    assert_eq!(ws.sign_ws.len(), sizes.sign_ws, "sign workspace");
    assert_eq!(ws.out.len(), sizes.out, "output buffer");

    // Total = the sum the carrier budgets for (records counted at their element stride).
    assert_eq!(
        sizes.total_bytes(),
        sizes.request
            + sizes.review_arena
            + sizes.review_recs * core::mem::size_of::<KvRec>()
            + sizes.review_typed
            + sizes.sign_ws
            + sizes.out,
        "the published total is the sum of the published spans"
    );

    // forms' own numbers, not copies of them: the sign span is exactly the carve's demand,
    // and the output span is exactly forms' output cap.
    assert_eq!(
        sizes.sign_ws,
        SignWsLayout::compute().total,
        "the sign span is carve_sign_ws's number"
    );
    assert_eq!(
        sizes.out,
        caps::SIGN_OUTPUT_BUF_MAX_LEN,
        "the output span is forms' artifact cap"
    );

    // Nothing may be zero: a zero span compiles and then fails a carve on a device.
    assert!(sizes.request > 0, "request span");
    assert!(sizes.review_arena > 0, "review arena");
    assert!(sizes.review_recs > 0, "review recs");
    assert!(sizes.review_typed > 0, "typed-data tail");
    assert!(sizes.sign_ws > 0, "sign workspace");
    assert!(sizes.out > 0, "output buffer");

    // The request staging span has to cover the largest payload a carrier can assemble from
    // UR frames, which is forms' inbound UR ceiling — not a smaller convenience size.
    assert!(
        sizes.request >= shlosilo::limits::UR_PAYLOAD_MAX,
        "the request span must cover forms' inbound payload ceiling"
    );
}
