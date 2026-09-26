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
    let commitments_hash = monero_ed25519::Scalar::hash(
        commitments
            .flat_map(|V| V.compress().to_bytes())
            .collect::<Vec<_>>(),
    );
    // Z5.3 F-cut: fixed-size stack concat (byte-identical).
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&(*TRANSCRIPT)[..]);
    buf[32..].copy_from_slice(&<[u8; 32]>::from(commitments_hash));
    monero_ed25519::Scalar::hash(buf).into()
}
