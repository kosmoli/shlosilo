//! The flow: one request, in order (design 2026-11-26 §6).
//!
//! ```text
//! carrier.next_request()            -> (type name, payload)
//! forms review::build               -> lines + break mask
//! forms review::page_count/span     -> this page's rows
//! carrier.draw(page) / carrier.action()
//!   Confirm -> forms sign_with_entropy_ws -> carrier.emit(out piece)
//!   refusal -> forms failure_text words   -> carrier.draw(fixed page)
//! ```
//!
//! Nothing in this file decides *what* a request is, *what* the operator must be shown,
//! or *when* a page ends. Those are forms' answers (`business::review`,
//! `review::page_count`/`page_span`, `failure_text`, `type_table`). The only thing this
//! layer owns is the order, and the fact that a refusal never reaches the wire.
//!
//! Red line 1 reminder (design §3): this flow *initiates* review; it does not *guarantee*
//! that a review happened, because nothing in a replaceable shell can. See the crate
//! docs and the slice report for where that guarantee actually lives today.

use shlosilo::business::review;
use shlosilo::business::sign::{carve_sign_ws, sign_with_entropy_ws, SignInput};
use shlosilo::error::{ShlosiloError, ShlosiloErrorCode, ShlosiloErrorKind};
use shlosilo::failure_text;
use shlosilo::network::Network;
use shlosilo::ur::type_table;
use shlosilo::ur::ur_encode::UrTypeTag;

use crate::error::ShellError;
use crate::surface::{Action, Carrier, OutPiece, Page};
use crate::workspace::Workspaces;

/// What the flow needs that no carrier seam provides yet.
///
/// Design §4 freezes four carrier calls and defers `persist`/`entropy`/`now_ms`/
/// `settings`; key material, the wallet's network and the screen's row count are in
/// neither list. Until those seams exist, the caller of [`run_once`] lends them here —
/// which is also why this struct, not the carrier, is where a future `KeySource`,
/// `Settings` and `Entropy` seam will be threaded through.
pub struct ShellConfig<'a> {
    /// BIP-39 seed for this run, borrowed. The shell never copies it; forms' sign entry
    /// takes `SignInput::Seed` by reference and derives nothing of its own here.
    pub seed: &'a [u8; 64],
    /// Wallet network, used by the review renderer when the request cannot tell its own
    /// network (forms prefers the request's derivation when present).
    pub network: Network,
    /// Wallet master fingerprint, for change-output marking in the review lines.
    pub master_fingerprint: Option<[u8; 4]>,
    /// How many review rows the carrier's screen holds on one page.
    ///
    /// The layout half of pagination: forms decides where a *semantic* break may fall
    /// (`Line::no_break_before` / `break_mask`), the platform reports how many rows fit.
    /// This is the platform's number, so it enters here; it is not the shell's to guess
    /// and it is not a forms constant (a device screen and a terminal differ).
    pub rows_per_page: usize,
}

/// Run one request through the flow.
///
/// Returns `Ok(())` only when an artifact was signed and handed to
/// [`Carrier::emit`]. Every other ending is a [`ShellError`]; when forms refused, the
/// carrier has already been shown the fixed failure words.
///
/// # Why the request is copied
///
/// [`Carrier::next_request`] returns a value that borrows the carrier, so the carrier
/// stays mutably borrowed while it lives. The flow needs the payload again after the
/// operator confirms (page turns and the sign call happen in between), so it copies the
/// two fields out up front and lets the borrow end. A carrier lending the request for
/// the whole run instead would save one copy per request — that is a seam change, not a
/// local optimisation, and it is recorded in the slice report.
pub fn run_once<C: Carrier>(carrier: &mut C, config: &ShellConfig<'_>) -> Result<(), ShellError> {
    // A page with zero rows would let `Confirm` authorise a request the operator never
    // saw, so this is refused rather than clamped.
    if config.rows_per_page == 0 {
        return Err(ShellError::Misconfigured);
    }

    // ── 1. one request ───────────────────────────────────────────────────────────
    let Some(request) = carrier.next_request() else {
        return Err(ShellError::NoRequest);
    };
    let type_name = request.type_name.to_owned();
    let payload = request.payload.to_vec();
    // `request` is not dropped explicitly: it holds no resources, and NLL ends the
    // carrier borrow at its last use (right here) — see the note on copying above.

    // Workspaces are provisioned only once there is something to work on: the largest of
    // them (the sign workspace) is megabytes, and a run with no request must not pay for
    // it.
    let mut ws = Workspaces::provision();

    // ── 2. what it is, and what the operator must see: forms decides ─────────────
    let tag = UrTypeTag::from_name(&type_name);
    if !type_table::is_sign(&type_name) {
        // Not a sign request. The product flow routes these elsewhere (the XMR pairing
        // legs, a peer's already-signed artifact) and the scan session must survive them;
        // one run of this shell signs one request, so anything else is a refusal carrying
        // forms' own word for "this is not something I sign".
        return Err(refuse(
            carrier,
            ShlosiloError::new(ShlosiloErrorKind::ChainKindUnsupported),
        ));
    }
    // Whether the operator sees a page at all is forms' answer, not this layer's: the
    // type table marks the XMR exchange legs `is_sign` with `review_gated: false` (they
    // keep their shipped, wallet-validated session flow and have no review face), so a
    // type the table does not gate goes straight to signing — the same thing the device
    // that ships today does. Inventing a page here, or inventing a refusal, would both be
    // a policy this layer has no business making.
    if type_table::review_gated(&type_name) {
        let view = match review::build(
            tag,
            &payload,
            config.network,
            config.master_fingerprint.as_ref(),
            &mut ws.review_arena,
            &mut ws.review_recs,
            &mut ws.review_typed_data,
        ) {
            Ok(view) => view,
            Err(e) => return Err(refuse(carrier, e)),
        };

        // ── 3. page through the review (forms owns both halves of the geometry) ──────
        let break_mask = view.break_mask();
        let count = view.lines().len();
        let pages = review::page_count(count, break_mask, config.rows_per_page);
        let mut page = 0usize;
        loop {
            let (start, len) = review::page_span(count, break_mask, config.rows_per_page, page);
            let mut rows: [&str; review::REVIEW_LINES_MAX] = [""; review::REVIEW_LINES_MAX];
            let mut shown = 0usize;
            if let Some(span) = view.lines().get(start..start + len) {
                for (slot, line) in rows.iter_mut().zip(span.iter()) {
                    *slot = line.as_str();
                }
                shown = span.len();
            }
            carrier.draw(&Page {
                lines: &rows[..shown],
                page: page + 1,
                pages,
                status: None,
            });
            match carrier.action() {
                Action::Next => {
                    if page + 1 < pages {
                        page += 1;
                    }
                }
                Action::Prev => {
                    page = page.saturating_sub(1);
                }
                Action::Cancel => return Err(ShellError::Cancelled),
                Action::Confirm => break,
            }
        }
    }

    // ── 4. sign, out of caller memory ────────────────────────────────────────────
    //
    // The workspace covers exactly `SignWsLayout::compute().total`, so a failed carve
    // means the layout and this allocation disagree — report it as the capacity failure
    // forms' word table already has for "request too large" rather than panicking.
    let Some(mut sign_ws) = carve_sign_ws(&mut ws.sign_ws) else {
        return Err(refuse(
            carrier,
            ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall),
        ));
    };
    // Entropy is empty on purpose: the design defers the carrier's entropy seam (§4), and
    // forms requires it only for the XMR leg (BTC/ETH sign deterministically with
    // RFC-6979). An XMR request does not even reach this line today — forms' review has
    // no XMR builder (`type_table` marks XMR `is_sign` but `review_gated: false`), so the
    // flow stops at step 2 with "request type not supported". Both halves (no XMR review
    // face, no entropy seam) are gaps recorded in the slice report, not choices made here.
    let signed = sign_with_entropy_ws(
        SignInput::Seed { seed: config.seed },
        tag,
        &payload,
        &[],
        &[],
        Some(&mut sign_ws),
        None,
        &mut ws.out,
    );
    let signed_len = match signed {
        Ok(n) => n,
        Err(e) => return Err(refuse(carrier, e)),
    };

    // ── 5. hand it over (framing belongs to the carrier) ─────────────────────────
    let reply = type_table::reply_type(&type_name);
    carrier.emit(&OutPiece {
        type_name: reply,
        bytes: &ws.out[..signed_len],
    });
    Ok(())
}

/// Show forms' fixed words for a refusal, then report it.
///
/// This is the whole failure path on purpose: one class phrase from forms' table, never
/// the code, never the request text, never a payload byte (split-code red line, see
/// `shlosilo::failure_text`). Returning [`ShellError::Refused`] afterwards keeps the
/// "nothing was signed" fact explicit without re-introducing a code.
fn refuse<C: Carrier>(carrier: &mut C, error: ShlosiloError) -> ShellError {
    let code = ShlosiloErrorCode::from_shlosilo_error(error);
    let text = failure_text::sign_failure_text(code)
        .to_str()
        // A fixed CStr from forms is always UTF-8; the fallback keeps the fail-closed
        // property if that ever stops being true (never show raw bytes on a screen).
        .unwrap_or("sign failed");
    let mut rows: [&str; 3] = [""; 3];
    let used = text.lines().count().min(rows.len());
    for (slot, line) in rows.iter_mut().zip(text.lines()) {
        *slot = line;
    }
    carrier.draw(&Page {
        lines: &rows[..used],
        page: 1,
        pages: 1,
        status: None,
    });
    ShellError::Refused
}
