//! flux product shell — the sequence-and-presentation half every carrier shares.
//!
//! Design: `shlosilo-设计-flux外壳与载体分层-2026-11-26` (§3 layers, §4 seam, §6 slice,
//! §10 the gap register this crate is closing).
//!
//! Three layers, three owners:
//!
//! - **forms** (the `shlosilo` crate) owns *meaning and decision*: UR codecs, PSBT /
//!   EIP-712 parsing, the signing primitives, the review **policy** (fold gate, line
//!   content, `break_mask`, page count), the failure vocabulary, the type table.
//! - **this crate** owns *order and presentation*: take one request, ask forms for its
//!   review, hand the pages to the carrier, take an action, ask forms to sign, hand the
//!   artifact back.
//! - **a carrier** (`flux/*`) owns *its own I/O only*: frames, pixels, keys, files,
//!   entropy, clocks, updates. It also owns the **memory** one run needs — see below.
//!
//! # What this crate must never do
//!
//! These are the design's red lines (§3, §8), restated where the code can be read:
//!
//! 1. **No protocol knowledge.** Only `(type_name, payload)` goes into forms and
//!    `(out_type, out_bytes)` comes out. No UR text, no PSBT map, no EIP-712 tree is
//!    parsed or encoded here — the type-name mapping is forms' table
//!    (`UrTypeTag::from_name`, `ur::type_table`), which is the one documented exception.
//! 2. **No pagination geometry.** Page breaks come from `review::page_count` /
//!    `review::page_span` and honour the view's own `break_mask`; the shell never
//!    recomputes where a page may end (a second paginator is how the 2026-11-25 device
//!    defect — a page ending on a label, its value opening the next page — came back).
//! 3. **No security rule.** "Not reviewed, not signed" is not enforced here; the shell
//!    only *initiates* review. A rule that lives in a replaceable layer is a rule that
//!    disappears with it.
//! 4. **No C-ABI face.** Rust carriers link forms directly (design §4), so this crate
//!    defines no `extern "C"` entry, no header, no keep-table row.
//!
//! # Memory: lent in, never allocated (design §10 gap 5)
//!
//! The crate is `no_std` and allocation-free unless the `std` feature is on. One run
//! borrows six spans from the caller ([`Workspaces`], sized by [`WorkspaceSizes`] /
//! [`workspace_bytes`]) instead of provisioning them: the request payload staging, the two
//! review pools, the EIP-712 tail, the sign workspace and the output buffer. A carrier
//! decides where those live (statics, a PSRAM arena, `malloc` on the host). This is what
//! makes the shell reachable from a bare-metal carrier; `--no-default-features` on
//! `thumbv7em-none-eabihf` is the evidence (see `flux/shell/Cargo.toml`).
//!
//! # Scope of this slice
//!
//! One request per run, one page set, one artifact. The state machine the design sketches
//! (SCAN → REVIEW → SIGN → RESULT → EXPORT/SETTINGS), status-slot ownership (sticky
//! failures, collection progress, default hint), the export list and the
//! `persist`/`entropy`/`now_ms`/`settings` seams are deliberately absent — the slice
//! report lists them as follow-ups instead of guessing their shape here.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod error;
pub mod flow;
pub mod surface;
pub mod workspace;

pub use error::ShellError;
pub use flow::{run_once, ShellConfig, TYPE_NAME_MAX};
pub use surface::{Action, Carrier, OutPiece, Page, Request};
pub use workspace::{workspace_bytes, WorkspaceSizes, Workspaces};

#[cfg(feature = "std")]
pub use workspace::OwnedWorkspaces;
