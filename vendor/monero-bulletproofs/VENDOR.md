# vendored: monero-bulletproofs 0.1.0 (MIT)

- Upstream: https://github.com/monero-oxide/monero-oxide/tree/main/monero-oxide/ringct/bulletproofs
- Vendored: 2026-09-03, from crates.io monero-bulletproofs 0.1.0
- Commit at vendoring time: recorded in .cargo_vcs_info.json

## Patch (build.rs only)

Upstream build.rs emits `vec![decompress(), decompress(), ... x2048]` —
hundreds of KB of EdwardsPoint temporaries on the stack. On ForgeBox this
HardFaults 4-5s into the first prove_plus.

Patch: emit compressed bytes + a decompress **loop**. Frame stays small;
the Vec lands on the heap. Enabled via `compile-time-generators` feature
(wired in root Cargo.toml).

## Why vendor (per Kosmo's criteria, 2026-09-03)

BP+ generators are protocol-frozen consensus data (fixed CSW set for a
given chain). Generators bytes are pinned by official test vectors, so the
patch touches no cryptographic semantics — it only changes how the frozen
data is materialized (loop instead of unrolled). No active-protocol code
was modified.

## Exit condition (remove vendor)

- Upstream monero-oxide merges an equivalent fix upstream, AND
- the crate releases it (monero-bulletproofs > 0.1.0 on crates.io), AND
- CI + device regression pass on the registry version.

Until then: keep the build.rs patch semantics intact (loop, not unrolled
vec![decompress()]) when touching this vendor tree.
