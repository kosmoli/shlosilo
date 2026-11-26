//! Why a shell run stopped.
//!
//! The enum is deliberately payload-free. A run either produced an artifact or it did
//! not, and *why* not is already on the operator's screen: forms' fixed word table
//! (`failure_text::sign_failure_text`) is the only failure vocabulary the user-facing
//! path may use. Carrying an error code here would invite a carrier to print it, which
//! is the split-code red line forms' table exists to keep.

/// Outcome of one [`crate::run_once`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellError {
    /// The carrier had no request to hand over (operator cancelled at the scan page).
    NoRequest,
    /// The operator abandoned the request from the review pages. Nothing was signed.
    Cancelled,
    /// forms refused the request (review) or the signature. The carrier has already
    /// been shown the fixed words for that failure class.
    Refused,
    /// The caller's [`crate::ShellConfig`] cannot drive a flow (a page with no rows
    /// would let a confirm authorise a request nobody saw).
    Misconfigured,
}

impl core::fmt::Display for ShellError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            ShellError::NoRequest => "no request",
            ShellError::Cancelled => "cancelled",
            ShellError::Refused => "refused",
            ShellError::Misconfigured => "misconfigured",
        };
        f.write_str(text)
    }
}

impl std::error::Error for ShellError {}
