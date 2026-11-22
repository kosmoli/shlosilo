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

**Status: NOT validated, and it broke hardware twice.** First attempt: a reproducible allocator
panic mid-sign (`allocation of 589824 bytes failed | live psram=4627888`). That block turned out to
be pool #76 - the decode session's leaked pools (fixed since; the pico2 sessions now live in the
static arena and two signs per boot work). Second attempt, on top of the #76 fix: the board instead
reboots **with no crash record at all** (the transcript ends in heartbeats plus the boot smoke test,
and `faultclr` shows nothing), so the sign never finishes and never panics.

No-record resets after a heap that was previously found corrupted point at an out-of-bounds write,
and the fast path's only behavioural difference is that the per-destination key-image list drops
from 2 entries to 1 (the foreign payment output is no longer "owned"). Something downstream is
allowed to assume "one entry per destination". Find that assumption before touching this again:
walk the consumers of `key_images_str` (wire assembly, the `PendingTx` read-back, and whatever the
Cake view exposes) and assert the count relationship. The host pin
`tests/tx_key_images_wallet2_view.rs` passes either way, which is exactly why this needs a host test
that pins the *length* relationship, not just the entries.
