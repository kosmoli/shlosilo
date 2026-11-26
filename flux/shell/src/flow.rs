//! The flow: one request, in order (design 2026-11-26 §6).
//!
//! ```text
//! carrier.next_request()            -> (type name, payload)
//!   type name -> heapless::String<64>, payload -> ws.request[..n]   (borrow ends)
//! forms review::build   (ws.review_arena / recs / typed)  -> lines + break mask
//! forms review::page_count/span                           -> this page's rows
//! carrier.draw(page) / carrier.action()
//!   Confirm -> forms sign_with_entropy_ws (ws.sign_ws, ws.out) -> carrier.emit(out piece)
//!   refusal -> forms failure_text words   -> carrier.draw(fixed page)
//! ```
//!
//! Nothing in this file decides *what* a request is, *what* the operator must be shown,
//! or *when* a page ends. Those are forms' answers (`business::review`,
//! `review::page_count`/`page_span`, `failure_text`, `type_table`). The only thing this
//! layer owns is the order, and the fact that a refusal never reaches the wire.
//!
//! Nothing in this file allocates either: the request is staged into the caller's
//! [`Workspaces`], and every buffer forms needs is one of those spans. That is what makes
//! a bare-metal carrier able to run this flow (design §10 gap 5).
//!
//! Red line 1 reminder (design §3): this flow *initiates* review; it does not *guarantee*
//! that a review happened, because nothing in a replaceable shell can. See the crate
//! docs and the slice report for where that guarantee actually lives today.

use shlosilo::business::review;
use shlosilo::business::sign::{carve_sign_ws, sign_with_entropy_ws, SignInput};
use shlosilo::error::{ErrorContext, ShlosiloError, ShlosiloErrorCode, ShlosiloErrorKind};
use shlosilo::failure_text;
use shlosilo::network::Network;
use shlosilo::ur::type_table;
use shlosilo::ur::ur_encode::UrTypeTag;

use crate::error::ShellError;
use crate::surface::{Action, Carrier, OutPiece, Page, Request};
use crate::workspace::Workspaces;

/// Fixed capacity of the staged UR type name.
///
/// forms' own frame parser caps a type name at `heapless::String<32>`
/// (`ur_multipart::UrMultipartDecoder::type_name`), so 64 is headroom for any name a
/// carrier can legitimately hand over — not a protocol number. A longer name is refused
/// with a capacity failure rather than truncated: a truncated type name would be a
/// *different* name, and the type table would answer for the wrong request.
pub const TYPE_NAME_MAX: usize = 64;

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
/// # Why the request is staged
///
/// [`Carrier::next_request`] returns a value that borrows the carrier, so the carrier
/// stays mutably borrowed while it lives. The flow needs the payload again after the
/// operator confirms (page turns and the sign call happen in between), so it copies the
/// two fields into `ws` — the caller's memory, not the heap — and lets the carrier borrow
/// end before the first `draw`. The copy is bounded by [`WorkspaceSizes::request`], and a
/// payload or type name that does not fit is refused with forms' capacity words (the
/// `RequiredLength` context carries the number internally; nothing of it reaches a
/// screen).
pub fn run_once<C: Carrier>(
    carrier: &mut C,
    config: &ShellConfig<'_>,
    ws: &mut Workspaces<'_>,
) -> Result<(), ShellError> {
    // A page with zero rows would let `Confirm` authorise a request the operator never
    // saw, so this is refused rather than clamped.
    if config.rows_per_page == 0 {
        return Err(ShellError::Misconfigured);
    }

    // Field-precise borrows: the payload only needs `ws.request`, so the review pools and
    // the sign workspace stay free for the mutating calls below.
    let Workspaces {
        request,
        review_arena,
        review_recs,
        review_typed,
        sign_ws,
        out,
    } = ws;

    // ── 1. one request, staged into caller memory ────────────────────────────────
    let mut type_name: heapless::String<TYPE_NAME_MAX> = heapless::String::new();
    let mut payload_len = 0usize;
    // The `Some(...)` arm ends the carrier borrow before the next statement: `staged`
    // holds a `Result<(), ShlosiloError>`, no reference into the carrier.
    let staged = match carrier.next_request() {
        None => return Err(ShellError::NoRequest),
        Some(req) => stage_request(req, &mut type_name, request, &mut payload_len),
    };
    if let Err(e) = staged {
        return Err(refuse(carrier, e));
    }
    let payload: &[u8] = &request[..payload_len];

    // ── 2. what it is, and what the operator must see: forms decides ─────────────
    let tag = UrTypeTag::from_name(type_name.as_str());
    if !type_table::is_sign(type_name.as_str()) {
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
    if type_table::review_gated(type_name.as_str()) {
        let view = match review::build(
            tag,
            payload,
            config.network,
            config.master_fingerprint.as_ref(),
            review_arena,
            review_recs,
            review_typed,
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
    // means the layout and the caller's span disagree — report it as the capacity failure
    // forms' word table already has for "request too large" rather than panicking.
    let Some(mut sign_ws) = carve_sign_ws(sign_ws) else {
        return Err(refuse(
            carrier,
            ShlosiloError::with_context(
                ShlosiloErrorKind::BufferTooSmall,
                ErrorContext::RequiredLength(
                    shlosilo::business::sign::SignWsLayout::compute().total,
                ),
            ),
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
        payload,
        &[],
        &[],
        Some(&mut sign_ws),
        None,
        out,
    );
    let signed_len = match signed {
        Ok(n) => n,
        Err(e) => return Err(refuse(carrier, e)),
    };

    // ── 5. hand it over (framing belongs to the carrier) ─────────────────────────
    let reply = type_table::reply_type(type_name.as_str());
    carrier.emit(&OutPiece {
        type_name: reply,
        bytes: &out[..signed_len],
    });
    Ok(())
}

/// Copy the carrier's request into caller memory.
///
/// Both fields are bounded and both failures are capacity failures (forms' `BufferTooSmall`
/// class, with the required length carried in the context): the type name goes into a
/// `heapless::String` and the payload into `dest`. Splitting this out keeps the borrow of
/// the carrier confined to one expression — see [`run_once`].
fn stage_request(
    request: Request<'_>,
    type_name: &mut heapless::String<TYPE_NAME_MAX>,
    dest: &mut [u8],
    payload_len: &mut usize,
) -> Result<(), ShlosiloError> {
    if type_name.push_str(request.type_name).is_err() {
        return Err(capacity_failure(request.type_name.len()));
    }
    let n = request.payload.len();
    if n > dest.len() {
        return Err(capacity_failure(n));
    }
    dest[..n].copy_from_slice(request.payload);
    *payload_len = n;
    Ok(())
}

/// "This does not fit, and here is how much it needed."
///
/// The number stays in the error's context; the operator only ever sees forms' fixed
/// words for the capacity class (split-code red line).
fn capacity_failure(required: usize) -> ShlosiloError {
    ShlosiloError::with_context(
        ShlosiloErrorKind::BufferTooSmall,
        ErrorContext::RequiredLength(required),
    )
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
