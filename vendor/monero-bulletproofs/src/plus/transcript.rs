use std_shims::{sync::LazyLock, vec::Vec};

use curve25519_dalek::{EdwardsPoint, Scalar};

use monero_primitives::keccak256;

// Monero starts BP+ transcripts with the following constant.
// Why this uses a hash to point is completely unknown.
// TODO: This can be promoted to a constant, remove `monero-primitives`
pub(crate) static TRANSCRIPT: LazyLock<[u8; 32]> = LazyLock::new(|| {
    monero_ed25519::Point::biased_hash(keccak256(b"bulletproof_plus_transcript"))
        .compress()
        .to_bytes()
});

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
    buf[..32].copy_from_slice(&(*TRANSCRIPT)[..]);
    buf[32..].copy_from_slice(&<[u8; 32]>::from(commitments_hash));
    monero_ed25519::Scalar::hash(buf).into()
}
