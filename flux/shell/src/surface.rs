//! The carrier seam: four calls, no more (design 2026-11-26 §4).
//!
//! The seam is deliberately narrow. Everything a specific board does that the shell
//! cannot know — read a frame, draw a row, decode a keystroke, frame an artifact —
//! arrives through [`Carrier`]; everything the shell knows (what a request means, what
//! must be shown, when a page ends) stays in forms.
//!
//! Seams the design defers ("后面才加：persist / entropy / now_ms / settings") are NOT
//! present here. Their absence is visible in [`crate::ShellConfig`]: values that will
//! one day come from a carrier are still handed in by whoever calls the flow.

/// One decoded request, as the carrier read it off its own transport.
///
/// The shell never learns how the bytes arrived — camera frames, a file, a pipe are
/// the same thing here. Both fields are what forms consumes: the type name is looked up
/// in forms' own table (`UrTypeTag::from_name`, `type_table`), never parsed.
///
/// # Borrow obligation
///
/// `next_request` hands out a reference into the carrier, i.e. it holds the carrier's
/// `&mut` borrow for as long as the value lives. The flow therefore copies the two
/// fields into the workspace the caller lent it ([`crate::Workspaces`]) before it calls
/// [`Carrier::draw`]; a carrier is not expected to keep the referenced bytes alive past
/// the next call. The copy is bounded by `WorkspaceSizes::request` / `flow::TYPE_NAME_MAX`,
/// and it costs no allocation — which is why carriers own the memory instead of the shell.
pub struct Request<'a> {
    /// UR type name exactly as it arrived (`crypto-psbt`, `eth-sign-request`, ...).
    pub type_name: &'a str,
    /// Decoded payload (the UR message with any CBOR byte-string shell stripped).
    pub payload: &'a [u8],
}

/// One screen's worth of review: lines the shell already paginated, plus the optional
/// status slot.
///
/// `lines` is borrowed from forms' review view — the shell does not wrap, truncate or
/// reformat them, and it does not decide where a page ends either: both halves of
/// pagination come from `review::page_count` / `review::page_span`, which honour the
/// view's own `no_break_before` glue (the 2026-11-25 device defect where a page ended
/// on a label and its value opened the next page is exactly what a second paginator
/// re-introduces).
pub struct Page<'a> {
    /// Rendered rows for this page, in display order.
    pub lines: &'a [&'a str],
    /// 1-based index of this page.
    pub page: usize,
    /// How many pages the operator will see in total (never 0).
    pub pages: usize,
    /// Status-slot content the shell owns (failures, progress, default hint).
    ///
    /// This slice draws no status text: failure words travel as [`Page::lines`] so a
    /// carrier that only knows how to draw rows needs no second text path. The slot is
    /// part of the seam because the design's ownership rules (§3) are about *who*
    /// writes it, not about whether a carrier has a second text area.
    pub status: Option<&'a str>,
}

/// A semantic action — what the operator meant, not which button was pressed.
///
/// The carrier owns the `home|wire|camera` key vocabulary; the shell only knows these
/// four meanings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Sign this request (the operator has seen the pages the shell drew).
    Confirm,
    /// Abandon this request without signing.
    Cancel,
    /// Later page of the same review.
    Next,
    /// Earlier page of the same review.
    Prev,
}

/// The signed artifact, on its way out.
///
/// The pair is the mirror image of [`Request`]: a type name (from forms'
/// `type_table::reply_type`, so the reply carries the name the request used) and the
/// bytes. Framing is the carrier's job — UR text, fountain frames, a file, a QR
/// carousel — because only the carrier knows what its transport accepts.
pub struct OutPiece<'a> {
    /// UR type name the artifact must be published under.
    pub type_name: &'a str,
    /// The payload bytes forms produced.
    pub bytes: &'a [u8],
}

/// What a carrier must implement: transport in, screen out, actions in, artifact out.
pub trait Carrier {
    /// Hand the shell one request.
    ///
    /// `None` means the operator cancelled at the scan page (design §4) — the flow stops
    /// without drawing or signing anything.
    fn next_request(&mut self) -> Option<Request<'_>>;

    /// Draw one page. The carrier owns every pixel; the shell owns the rows.
    fn draw(&mut self, page: &Page<'_>);

    /// Read the next semantic action.
    ///
    /// A carrier must make progress: the flow keeps drawing while the answer is
    /// [`Action::Next`] on the last page or [`Action::Prev`] on the first, so an action
    /// source that never reaches `Confirm`/`Cancel` (an exhausted script, a dead input
    /// device) must answer `Cancel` rather than repeat a page action forever.
    fn action(&mut self) -> Action;

    /// Take the artifact. Called at most once per run, after a successful sign.
    fn emit(&mut self, out: &OutPiece<'_>);
}
