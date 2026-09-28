# Z6 Allocation-Face Measurement

The formal instrument for the zero-heap claim. Two faces, two claims —
never conflate them:

## 1. REACHABLE face (the security claim)

*"No code reachable from the signing probe entry calls the allocator."*

Proven by **disassembly**, not by runtime luck: `measure.py` recovers the
call graph from the linked ELF (`z6_probe_run` as entry) and reports every
allocator call site (`__rust_alloc*`) with its caller function, split by
reachability. A `REACHABLE-CLEAN` verdict is the static proof that the
signing path cannot allocate — stronger than any counter-based test
(which only covers the inputs it ran).

The probe binary itself carries a `ForbiddingAllocator` (panics on
allocation) as a runtime backstop for hosts where the image can execute.

Why the probe "needs" an allocator at all: rustc's `#[global_allocator]`
lang-item check is eager — while the crate graph links `alloc` anywhere
(non-signing convenience surfaces, verify faces, vendor verify paths, the
CryptoNight scratchpad), a bare `staticlib` cannot link without an
allocator DEFINITION. The definition being present is not a hole in the
claim; the disassembly is the claim.

## 2. GRAPH face (the stub-pull condition)

*"The crate graph links `alloc` at all."*

Probed by `scripts/z6_langitem_check.sh`: it builds the same staticlib
with the allocator stub FEATURE-GATED OUT (`--no-default-features`). While
any crate in the graph references `alloc`, rustc reports
`no global memory allocator found but one is required` → `ALLOC-IN-GRAPH`.
A clean build → `GRAPH-CLEAN` — at that point the stub (and its
`lang-stub` feature) can be deleted from `probe.rs` entirely and the
link-without-allocator IS the proof.

Current graph debt is tracked in the campaign ledger
(`shlosilo/todo/shlosilo-forms纯度审计-2026-09-24.md`, §8.4-0):
the CryptoNight scratchpad (2MB, product input-path KDF) is the named
final item; Cow-typed model fields keep `alloc::borrow` in their modules.

## Running

```sh
bash probes/noalloc/build.sh          # build + link + measure (REACHABLE face)
bash scripts/z6_langitem_check.sh     # GRAPH face
```

`build.sh` writes `z6_report.json` (machine-readable: per-site callers,
reachability flags) and exits 10 on reachable debt.

## Discipline

- A counting-allocator test (e.g. `xmr_sign_zero_alloc`,
  `bt_typed_sign_zero_alloc`) is the RUNTIME receipt for the inputs it
  ran. This instrument is the STATIC receipt for all inputs. Both are
  kept; neither substitutes for the other.
- Any claim in reports/ledger must name its face: "reachable-0
  (disassembly)" or "graph-clean (no allocator definition needed)".
