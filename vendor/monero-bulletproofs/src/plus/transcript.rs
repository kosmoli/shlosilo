use std_shims::sync::Mutex;
#[cfg(feature = "alloc-fallback")]
use std_shims::vec::Vec;

use curve25519_dalek::{EdwardsPoint, Scalar};

use monero_primitives::keccak256;

// Monero starts BP+ transcripts with the following constant.
// Why this uses a hash to point is completely unknown.
// TODO: This can be promoted to a constant, remove `monero-primitives`
// A3: the transcript constant is computed once behind an atomic ready flag
// (no LazyLock — alloc::sync out of the graph).
static TRANSCRIPT_CELL: Mutex<Option<[u8; 32]>> = Mutex::new(None);
static TRANSCRIPT_READY: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub(crate) fn transcript() -> [u8; 32] {
    if let Some(t) = *TRANSCRIPT_CELL.lock() {
        return t;
    }
    let t = {
        monero_ed25519::Point::biased_hash(keccak256(b"bulletproof_plus_transcript"))
            .compress()
            .to_bytes()
    };
    *TRANSCRIPT_CELL.lock() = Some(t);
    TRANSCRIPT_READY.store(true, core::sync::atomic::Ordering::Release);
    t
}

// TODO: An incremental hash would avoid allocating within this function
pub(crate) fn initial_transcript(commitments: core::slice::Iter<'_, EdwardsPoint>) -> Scalar {
    // Z5.3 final sweep: fixed stack staging for the hash input (16 compressed
    // points max — same bytes into the same hash fn).
    let mut cbuf = [0u8; 512];
    let mut clen = 0usize;
    for V in commitments {
        cbuf[clen..clen + 32].copy_from_slice(&V.compress().to_bytes());
        clen += 32;
    }
    let commitments_hash = monero_ed25519::Scalar::hash(&cbuf[..clen]);
    // Z5.3 F-cut: fixed-size stack concat (byte-identical).
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&transcript()[..]);
    buf[32..].copy_from_slice(&<[u8; 32]>::from(commitments_hash));
    monero_ed25519::Scalar::hash(buf).into()
}
