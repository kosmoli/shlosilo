# Test-face principles (test-writing constitution)

Established 2026-10-28 during the X7 un-gating batch, which uncovered two real
bugs that previous tests could not see. Follow these when adding tests.

## 1. Semantic anchors, not round-trips

A field's meaning must be pinned by a **derivation / commitment invariant** or
a **fixed KAT vector** (hardcoded expected bytes from a known-good source) —
never by round-trip symmetry alone. A serialize→deserialize round trip is
green even when both sides misread the same field in the same wrong way
(wire-convention mistakes are invisible to symmetric tests).

Examples in-tree:
- `tests/p63_xmr_keyimage.rs` — derived key images must equal the known
  KI_HEX table (KAT over the real 1023 fixture).
- `tests/p63_xmr_sign.rs` — the fee anchor (87_740_000) is a fixed value from
  the real captured construction.
- `forms/chain/xmr/tx_signer.rs` `verify_claim_identity` — the receiver-side
  algebraic identity (PIN-3).

Counter-example that bit us: `clsag::verify` parsed the ClsagProof RECORD
form (`pseudo_out ‖ s ‖ c1 ‖ D`) from byte 0 — the wrapper roundtrip test was
vacuous (`let _ = verify_result`) and never caught it.

## 2. No vacuous tests

- Never `let _ = result;` a value the test is supposed to judge. Dropping a
  Result is how a whole verification path stayed unexercised for months.
- Never skip-on-failure (`if let Ok(x) = ... else skip`) in a positive test.
  If the setup is expected to succeed, assert it.
- A positive verification test must FAIL when the artifact is wrong — check
  this by mutation (flip one bit, expect Err) as a companion negative pin.

## 3. Verify tests must use the real verify path

Structural-only checks (counts, lengths, "non-empty") are not verification.
Feed the verifier its real inputs: the real message hash (recomputed from the
artifact, e.g. keccak256 of the serialized prefix), the real rings, the real
pseudo-outs — and assert a good artifact passes AND a tampered one fails.

## 4. Fixtures and keys live in-tree (X7 policy)

Test keys/fixtures are embedded in the repo (test-only material). Env-gated
tests (`SHLOSILO_TEST_*`, `#[ignore]`) are a last resort for genuinely lost
external credentials — say so in the test header when unavoidable.

## 5. Single source of truth for signed material

Whatever the signature layer signs over must be exactly what the wire record
carries. Do not precompute "equivalent" values alongside sign returns and
keep both — that is how `build_and_sign_tx` shipped pseudo-outs the CLSAGs
were not computed over (fixed 2026-10-28; caught by the record/pseudo
cross-check inside `clsag::verify`).
