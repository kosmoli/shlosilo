# Phase-6 attribution and the unvalidated ownership fast path (2026-11-22)

Measurement that named the 40 s (pico2, `usigned_txset_2in_dev` fixture, perf-timing build):

```
tx: ... 6=40101 ... 12=115 13=39977 14=14 15=9 16=9 17=14
```

- 6  = the "key images" window
- 12 = its per-source `derive_input_from_source` loop = **115 ms**
- 13 = its per-destination key-image loop = **39,977 ms**
- 14/15/16/17 = the four crypto operations *inside* that loop = **46 ms total**

So the time is not cryptography: it is `wallet_owns_destination()`, which runs a
9-major x 201-minor lookahead (1,809 basepoint scalar multiplications) **per destination**. The
fixture's foreign payment output (`is_subaddress = false`, not our main address) spent all 1,809
derivations to answer "not ours" - 39.98 s of a 71.5 s sign.

`ownership-fastpath-wip.patch` contains:

1. phases 13..17 instrumentation (that is what produced the numbers above), and
2. the candidate fix: skip the lookahead for destinations flagged `!is_subaddress` (their only
   possible match is the main address, already compared), plus a unit pin for that branch.

**Status: NOT validated.** On hardware the build carrying the fast path crashed reproducibly in
the allocator during the sign (`allocation of 589824 bytes failed | live psram=4627888`), and
reverting to HEAD made the sign work again (72,991 ms, sha 55c4507b...) - so the correlation is
clear but the mechanism is not. The host pin `tests/tx_key_images_wallet2_view.rs` still passes
with the patch, so it is not a wire-semantics violation; the next session should instrument the
allocation that fails (it is the same 576 KiB block that shows up in the "second request" OOM,
pool #76) before re-attempting.
