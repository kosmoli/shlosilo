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

**Status: VALIDATED and merged** (commit `b6369bc`). The two earlier "hardware crashes" were
harness artifacts, not this code:

- the first one was pool #76 (the decode session's leaked pools) plus a fountain storm after
  acceptance - both fixed in `f4c2af8`;
- the second one was the capture harness: it never set the device entropy, so the fixture failed to
  decrypt (`EncodingInvalidFormat`, which reads exactly like a broken sign), and it counted the 5 s
  heartbeat banner as a reboot while clearing the crash record before reading it.

Hardware result on the same fixture with fixed entropy: the sign goes from 70,563 ms to
**30,127 ms** (28,244-30,084 ms over four runs, two of them on one boot) and the signed 6098 bytes
are unchanged, sha256 `55c4507b...`. Phase 6: 40,101 -> 200 ms; phase 13: 39,977 -> 67 ms.

Lesson worth keeping: a "no crash record" reset is a claim about the harness first and the firmware
second. `bench/p2_crashcap.py` exists for that - it timestamps every byte from boot through the sign
without filtering or clearing anything, and `[rst]` reports POWMAN's chip-reset flags for the case
fault.rs cannot record (it stores panics and hard faults only).
