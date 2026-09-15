# Entropy assurance — RP2350 TRNG source characterisation (SP 800-90B)

Status: **draft v1 — single-board scope** (2026-09-15). This document records
the entropy-source characterisation for the shlosilo pico2 (RP2350) TRNG:
the raw-source assessment, the consumption-point assessment, the acquisition
mechanics verified on hardware, and the operating-envelope coverage with
explicit gaps. It is an **engineering assessment**, not a CAVP-style
validation submission.

## 1. Scope

Established by this assessment:

- raw ROSC source min-entropy per sample, per chain length and sampling
  interval (NIST SP 800-90B non-IID track, official assessment tool);
- the production consumption point (checked-path EHR stream) per-bit
  min-entropy, hence the conditioning accounting for the production entropy
  path;
- acquisition mechanics: BUSY/VALID handshake, per-block fill timing,
  read-triggered re-arm (DWT cycle-stamped traces).

Not established (explicit gaps, §7): multi-board coverage, voltage
variation, sustained-load interaction, cold-temperature coverage, a
restart-test dataset in the exact `ea_restart` shape, and formal validation.

## 2. Method

### 2.1 Source and operating modes

The noise source is the Arm TrustZone TRNG block on RP2350 (ring
oscillator, `rng_clk`), which per the datasheet can produce 192-bit EHR
blocks. Two operating modes are characterised:

- **raw mode** (diagnostic): all three internal health checks
  (autocorrelation, CRNGT, Von Neumann balancer) bypassed, one ROSC sample
  per `rng_clk` cycle (`SAMPLE_CNT1 = 0`) or at a configured interval —
  the bootrom / pico-sdk raw-streaming configuration
  (datasheet 12.12.4.1; `varm_boot_path.c`; `pico_rand.c`).
- **checked path** (production): all health checks and the Von Neumann
  balancer active, chain 4 / sample 200 — exactly what the production
  reader (`trng::read_block`) presents to the entropy consumers.

### 2.2 Firmware support (bench-gated; production images do not compile it)

- `trngraw <n> [chain|rand] [sample]` — raw-mode capture into a PSRAM
  buffer; `trngrawout [start] [pace_ms]` — paced, block-indexed dump.
- `trngcheck <n>` — capture through the production reader into the same
  buffer; dump via `trngrawout`.
- `trngtrace` — DWT cycle-stamped (BUSY, VALID) waveform around raw
  blocks (mechanism forensics).
- `temp` — on-die temperature (RP2350 TS, datasheet 12.4.6).

Commits: `edd3656` (raw capture), `4d278f2` (bootrom-mirroring BUSY
handshake fix), `686b3de` (trace + temp + rand-chain + limits), `2ca8c1c`
(buffered checked-path capture).

### 2.3 Data-pipeline integrity

Datasets are transported with a paced dump (4 blocks per line, 1 ms per
line) carrying a **block index**, so the host can detect dropped lines and
verify completeness: all datasets used below assembled with **zero gaps**
(and per-dataset SHA-256 recorded).

This discipline exists because the per-line log stream cannot carry
dataset-sized captures: measured on hardware, a 2048-block `trng <n>` run
interleaves ~95 % of its lines (USB log-pipe drops) and a 16384-block run
loses most blocks. Raw captures never used that path (buffered dump from
the start); checked-path datasets use `trngcheck` + `trngrawout`, which
reuses the safe path.

### 2.4 Assessment tool and parameters

- NIST `SP800-90B_EntropyAssessment` (official repo), `ea_non_iid`, the
  non-IID track: H = min over all estimators (MCV, collision, Markov,
  compression, t-tuple, LRS, MultiMCW, lag, MultiMMC, LZ78Y), per
  SP 800-90B §6.2 / non-IID bitstring assessment.
- Invocation: `ea_non_iid -i -a <file> 1` (1 bit per symbol, all bits used).
- Each dataset ≥ 1.5 M samples (SP 800-90B validation scale is 1 M).
- Bit-order ambiguity: the EHR bit order is not specified by the
  datasheet; datasets were assessed in both un-packed orders (LSB-first
  and MSB-first within bytes) and the **conservative minimum** is reported.

## 3. Results

### 3.1 Raw source (bypass mode)

All datasets ≥ 1.5 M bits, zero gaps. H in bits per raw sample.

| dataset | chain | sample | H (bits/sample) | note |
|---|---|---|---|---|
| big_c0 | 0 | 0 | 0.1166 | |
| big_c1 | 1 | 0 | 0.0996 | |
| big_c2 | 2 | 0 | 0.0246 | weak chain |
| big_c3 | 3 | 0 | 0.1276 | best fixed chain |
| big_c3b | 3 | 0 | 0.1258 | repeat (1.5 % spread) |
| big_c4 | 4 | 0 | 0.1188 | production chain |
| rand1 | rand 0..3 | 0 | 0.1252 | bootrom-style chain randomisation |
| c4s200 | 4 | 200 | **0.7007** | **production sampling point** |

### 3.2 Production consumption point (checked path; VN + checks active)

Captured via the production reader (`trngcheck`; health checks + VN active,
chain 4 / sample 200). All datasets zero gaps.

| dataset | blocks | bits | H' lsb | H' msb | conservative | temp |
|---|---|---|---|---|---|---|
| postvn2_main | 16384 | 3.15 M | 0.7294 | 0.7394 | **0.7294** | 30.4 °C |
| postvn2_epoch2 | 8192 | 1.57 M | 0.8077 | 0.8192 | 0.8077 | 33.7 °C |
| postvn2_epoch3 | 8192 | 1.57 M | 0.7318 | 0.7424 | 0.7318 | 32.8 °C |

Epoch spread ≈ 10 % (0.729-0.808); the accounting below uses the
**conservative minimum 0.729**. Reader stats: 935-978 µs/block,
health-check retries fire and recover (crngt ≤ 3, autocorr ≤ 1 per run),
zero-blocks and timeouts 0 across all runs.

- Per 192-bit EHR block: **h_block ≈ 140 bits** (at the conservative rate).

A self-heating attempt to produce an elevated-temperature datapoint (6 ×
`perfbench fmul 30000000`, ≈ 4 min sustained load) showed **no measurable
die-temperature change** (33.2 → 33.2-33.7 °C): the temperature axis
requires an external thermal source (see §7).

### 3.3 Acquisition mechanics (verified on hardware)

- BUSY is high while an acquisition run is in flight and falls when the
  EHR block is complete; **reading the EHR restarts sampling** (verified by
  poll-only traces: after a read, BUSY=1/VALID=0 observed with no
  intervening register writes).
- Fill duration = 192 × `SAMPLE_CNT1` cycles + ~104 cycles of state-machine
  overhead (DWT-traced: 296 cycles at sample 0; 36 404-38 127 at sample
  200; busy-wait spin counts scale linearly with `SAMPLE_CNT1`).
- A busy-wait that waits for BUSY *after* the per-block setup can see the
  fill already complete at sample 0 (setup writes overlap the short fill);
  EHR_VALID is set at the read on every block (`ehr_invalid = 0` across
  all datasets).
- Health-check failure statistics on the checked path are visible and
  retried by the reader; no zero-blocks or odd states in any dataset.

## 4. Consumption model and conditioning accounting

Production entropy path for the XMR signing seed
(`fill_entropy_from_trng` → 64 bytes): four `conditioned32` calls, each
SHA-256 over two 192-bit EHR blocks (384 input bits).

- SHA-256 is a **vetted conditioning function** (SP 800-90B §3.1.5.1.1,
  `nw` = 256). With `h_in` = 2 × 140.0 = 280.1 bits,
  `ea_conditioning -v 384 256 256 280.1` → **h_out = 256 bits**
  (ε = 2^-31.6, "close to n_out/nw").
- The 64-byte seed buffer (two invocations) therefore carries **512 bits**
  of assessed min-entropy.

Independent cross-check (raw framing): at the production sampling point the
raw source carries 0.70 bits/sample; the Von Neumann balancer consumes
≥ 384 raw samples per 192-bit block (2 per output bit) → ≥ 269 bits of raw
entropy per block, so the raw path alone already supports the same
conditioner claim.

Note on framing: SP 800-90B vetted-conditioner accounting for the Von
Neumann balancer itself is degenerate (`nw` = 1 → ~1 bit/block), which is
why the assessment above is framed at the block's **digital output
boundary** (the EHR stream), the usage the datasheet's own compliance
statement describes. A formal validation would either adopt this boundary
explicitly or move the extraction to a raw → SHA-256 path (bootrom-style),
where the accounting has no ambiguity (`n_in` = 1024 raw samples gives a
full-entropy 256-bit output with a large margin at the measured rate).

## 5. Operating-envelope coverage

| axis | coverage | detail |
|---|---|---|
| chain 0-4 | ✓ | full fixed set at sample 0 + production chain 4 at sample 200 |
| chain randomisation | ✓ | per-block 0..3 randomisation dataset |
| sampling interval | ✓ (2 points) | sample 0 and sample 200 (production) |
| boot epochs | ✓ | ≥ 4 full reboots (flash cycles) + 4 in-session source-restart epochs |
| source restarts | ✓ (soft) | each capture job starts/stops the source; raw repeat spread 8 % (0.118-0.128), checked-path epoch spread 10 % (0.729-0.808) |
| die temperature | ✗ (gap) | self-heating (≈4 min sustained load) produced no measurable change; needs external thermal source |
| boards | ✗ (gap) | single Pico 2 board |
| voltage | ✗ (gap) | fixed USB supply only |
| load interaction | ✗ (gap) | capture path runs synchronously (executor stalled); interaction with concurrent load not characterised |
| sustained long-run | partial | multi-dataset coverage; no multi-hour soak |

## 6. Usage notes for the production path

- Defaults (chain 4 / sample 200, checked path) are the characterised
  operating point — keep them; moving either changes the measured numbers
  above (chain and interval both materially affect the raw rate).
- The consumed entropy has a comfortable margin: h_out is capped by the
  conditioner width (256 bits per 32-byte output), not by source entropy.
- `trngraw`/`trngcheck`/`trngtrace`/`temp` are bench-gated: the CI flavour
  check (`check_pico2_flavors.sh`) asserts they are absent from production
  images.

## 7. Gaps and follow-ups

1. multi-board repeat (2+ boards) — pending hardware availability;
2. voltage variation — requires an adjustable supply on VSYS;
3. sustained-load capture (async `capture_raw` with executor yields);
4. cold-soak and hot-soak datasets (elevated datapoint in progress);
5. `ea_restart`-shaped dataset (1000 restarts × 1000 samples) — needs a
   restart-loop collector;
6. formal validation trail: CAVP-style conditioning documentation for the
   chosen extraction boundary.

## 8. References

- RP2350 datasheet §12.12 (TRNG), §12.4.6 (temperature sensor);
- Arm TrustZone TRNG TRM (ARM 100976) and characterisation application
  note; RP2350 TRNG characterisation guidance in the datasheet;
- `pico-bootrom-rp2350` `src/main/arm/varm_boot_path.c`;
- pico-sdk `pico_rand/rand.c`;
- NIST SP 800-90B (final, Jan 2018), esp. §3.1.5 (conditioning), §6.2
  (non-IID assessment); FIPS 140-3 IG D.K (full-entropy criterion);
- `usnistgov/SP800-90B_EntropyAssessment` (tool used, `ea_non_iid` /
  `ea_conditioning`).

## Annex A — dataset inventory

All datasets: zero transport gaps (block-index verified). SHA-256 of
the packed capture file. Raw datasets are `raw_<label>.bin`;
checked-path datasets `postvn2_<label>.bin` (session-local;
reproducible via the bench commands in §2.2).

| dataset | mode | blocks | bits | sha256 (packed) |
|---|---|---|---|---|
| big_c0 | raw | 8192 | 1572864 | 539812a36f6dea89f251c7f627199d99… |
| big_c1 | raw | 8192 | 1572864 | ea1f2707f0220c51851cf6fd3b5d8a0b… |
| big_c2 | raw | 8192 | 1572864 | ee78b0bf6b0ddcb595a30157d5a686c0… |
| big_c3 | raw | 16384 | 3145728 | 119f7f5a20ca9d43d13e8ae374758bd0… |
| big_c3b | raw | 8192 | 1572864 | c06a2f851209b13b734a3065148e6091… |
| big_c4 | raw | 8192 | 1572864 | 8149237995ff563a825ad9ded4e3f0fd… |
| c0 | raw | 2048 | 393216 | 840f00538e98e830bcd5578c76905153… |
| c1 | raw | 2048 | 393216 | e2ff750ea7c9629f524ad7a1652d9dd3… |
| c2 | raw | 2048 | 393216 | 633a848cb4f1b375b0276ef82738ca89… |
| c3 | raw | 2048 | 393216 | 5b6209710c8c72bc79dfc9a6f05b8c67… |
| c4 | raw | 2048 | 393216 | bf04753355df29dc62ae245a8f4ef9b3… |
| c4s200 | raw | 8192 | 1572864 | 624e46b6f4ebf52c49ffaa085910b705… |
| dbg | raw | 64 | 12288 | 264ed01be32cfa7a082f144ce788d243… |
| hotc3 | raw | 8192 | 1572864 | d4a1f3623f937166f96bbee510cbb510… |
| rand1 | raw | 8192 | 1572864 | 21b92dd2a2b29c2387b44b4908bf88e3… |
| s0 | raw | 64 | 12288 | 39ac0e9926edf996581b0251b6168489… |
| s2 | raw | 64 | 12288 | a203242e51accd579483463e437c4043… |
| s20 | raw | 64 | 12288 | a402d45bf773c333b3fc33872b08a5a3… |
| s200 | raw | 64 | 12288 | 390723243bc285d49591ea3fa83dcb04… |
| smoke | raw | 64 | 12288 | 04134e57fdf0abe951adc63a932bfcb0… |
| postvn2_epoch2 | checked | 8192 | 1572864 | cfb72130740c0f128946058892626918… |
| postvn2_hot | checked | 8192 | 1572864 | 1daa2b86a3c3508b9c14154d26f30a89… |
| postvn2_main | checked | 16384 | 3145728 | 08311169d0b70fa97431b660260cdc59… |

*postvn_postvn1 (preliminary checked-path dataset, transport-integrity suspect — superseded by postvn2_main).*
