#!/usr/bin/env bash
# shlosilo gate batch — bare exit codes, no trimming by change surface.
# NOTE: the MUST-RED pin suite is GREEN (2026-10-31): the expected-red
# manifest (= the tests/ pin_red_* set) is EMPTY again — the I12 pin landed
# red the same day and the WP2 first-batch fix turned it green, and it is
# renamed to its invariant name (tests/tx_key_images_wallet2_view.rs). Any
# failing test on any face is a real failure.
cd ~/works/shlosilo-poc4 || exit 99
bash scripts/check_fixtures.sh > /tmp/g_fixt.log 2>&1; echo "FIXTURES=$?"
# Dependency versions: every resolvable Cargo.lock must be current (`--locked`); CI
# passes the same flag to its cargo commands and re-checks the locks after the build.
bash scripts/check_locks.sh > /tmp/g_locks.log 2>&1; echo "LOCKS=$?"
# forms/ must answer every input with a Result: panic-class macros are budget 0
# (recoverable failures like an oversized request are BufferTooSmall, never abort).
python3 scripts/check_no_panic.py > /tmp/g_nopanic.log 2>&1; echo "NOPANIC=$?"
# FFI graded audit F-1 (2026-11-19): no FFI entry may build a slice straight from an
# unbounded caller length — a `c_uint` claim exceeds isize::MAX on 32-bit targets.
bash scripts/check_ffi_raw_len.sh > /tmp/g_ffilen.log 2>&1; echo "FFILEN=$?"
# Resource budget report for the host profile: proves the report is producible from the
# production layout functions and fits the declared heap (exit 2 = over budget).
bash scripts/limits_report.sh host > /tmp/g_limitsreport.log 2>&1; echo "LIMITSREPORT=$?"
# Pool #58: fp-chain coverage manifest (fingerprint binding + visible-failure
# word chain pins) must stay intact — a renamed/removed/ignored pin is red.
bash scripts/check_fp_chain.sh > /tmp/g_fpchain.log 2>&1; echo "FPCOV=$?"
# WP1 I1 (C4): dependency direction — the core must never reference the
# profile layer (profile → canonical ← core only).
bash scripts/check_profile_boundary.sh > /tmp/g_profile.log 2>&1; echo "PROFILE=$?"
# WP1 I8 delete drill (C5 double build): the `profile-keystone` dialect
# feature is NON-default — TEST/TESTNOALLOC/KEYSRC are the "dialect OFF"
# variant (Cake only, green = downstream zero-awareness proof) and TESTALL
# (--all-features) is the "dialect ON" variant. Both variants must stay green.
# TEST/TESTALL run through the zero-on-alloc wrapper (jemalloc zero:true) so
# uninitialized reads surface deterministically - same path as CI test steps.
bash scripts/test_zero_on_alloc.sh --offline --all-targets --no-fail-fast > /tmp/g_test.log 2>&1; echo "TEST=$?"
# T-04: mirror CI "Tests (all features)" — the feature-gated contract pins
# (inv2/inv3 fptr round-trips) only compile under their features.
bash scripts/test_zero_on_alloc.sh --offline --all-targets --all-features --no-fail-fast > /tmp/g_testall.log 2>&1; echo "TESTALL=$?"
# Pool §46 (2026-10-21): no-default-features test face (was ~796 compile
# errors before the cfg-widening sweep). Expected-red manifest: EMPTY (the
# three pins on this face were fixed in the same batch).
# Chain axis (batch 1): `default` now carries chain-btc/eth/xmr, so a bare
# --no-default-features build would also drop all three chains and stop testing
# the chain code this face covers today. The three are named explicitly to keep
# the face measuring what it measured before (the chain SUBSETS are the
# CHAINAXES step's job, not this one's).
bash scripts/test_zero_on_alloc.sh --offline --no-default-features --features chain-btc,chain-eth,chain-xmr --all-targets --no-fail-fast > /tmp/g_testnoalloc.log 2>&1; echo "TESTNOALLOC=$?"
# A4 pico2 leak pin (2026-11-21): the generator-table one-shot fallback only exists on the
# alloc-fallback face that the pico2 firmware builds with (`default-features = false`). The
# default-feature batch below cannot see it, so this face gets its own step: three XMR signs
# must not grow the live heap (it used to grow 2 x 163,840 B per sign).
cargo test --offline --release --no-default-features --features alloc-fallback,chain-btc,chain-eth,chain-xmr --test xmr_device_peak_fixture xmr_sign_does_not_leak_generator_tables > /tmp/g_pico2leak.log 2>&1; echo "PICO2LEAK=$?"
# CI "flux keysource" parity: the keysource package has its own test face
# (qr_ffi FFI arity contracts etc.) that the root batch never compiles. Both key-supply
# flavors are covered: the plate-only default (which an ungated `SeKeySource` re-export had
# left uncompilable) and `--features se` (the SE face; its se_ffi tests carry required-features).
( cargo test --offline -p shlosilo-flux-keysource \
  && cargo test --offline -p shlosilo-flux-keysource --features se ) > /tmp/g_keysrc.log 2>&1; echo "KEYSRC=$?"
bash scripts/clippy.sh > /tmp/g_clippy.log 2>&1; echo "CLIPPY=$?"
cargo check --offline --target armv7-unknown-linux-gnueabihf > /tmp/g_arm.log 2>&1; echo "ARM=$?"
# The embedded faces are compile-surface checks, not carrier builds: name the smallest
# real bare-metal profile so build.rs does not have to guess (it refuses to default
# to host for a bare-metal target).
# Chain axis (batch 1): the profiles declare all three chains, and the firmware these
# checks describe carries them, so the chain features are named explicitly here — a
# bare --no-default-features build would now also drop the chain layers and stop being
# the face this step exists to measure.
SHLOSILO_LIMITS=pico2 cargo check --lib --no-default-features --features chain-btc,chain-eth,chain-xmr --target thumbv7em-none-eabihf > /tmp/g_embed1.log 2>&1; echo "EMBED1=$?"
SHLOSILO_LIMITS=pico2 cargo check --lib --no-default-features --features chain-btc,chain-eth,chain-xmr,device-timing,generator-cache-ffi,prove-timing-ffi,cn-timing-ffi,tx-phase-timing-ffi,perf-bench-ffi > /tmp/g_embed2.log 2>&1; echo "EMBED2=$?"
SHLOSILO_LIMITS=pico2 cargo clippy --offline --target thumbv8m.main-none-eabihf --manifest-path flux/pico2/Cargo.toml --all-features -- -D warnings > /tmp/g_pico2.log 2>&1; echo "PICO2=$?"
# pico2 build-flavor face (audit #17 P1-01, extended 2026-11-19 with the A4-01/A4-02 canaries):
# builds production + bench + perf flavors and asserts the bench-only surface is absent from
# production, present in bench, AND that the production no-session refusal really exists.
bash scripts/check_pico2_flavors.sh > /tmp/g_pico2flavors.log 2>&1; echo "PICO2FLAVORS=$?"
# #73 / A4-04 (2026-11-22): the pico2 sign stretch must not go through the allocator. Measured on
# the production image from one non-inlined entry, with the console dispatcher as the sensitivity
# control; allocation in our own code is red, the frozen third-party sites are named in the gate.
bash scripts/pico2_sign_noalloc_check.sh > /tmp/g_pico2signalloc.log 2>&1; echo "PICO2SIGNAlloc=$?"
# #74 / A4-05 (2026-11-22): the allocator is a carrier capability, not a given. Builds the flavor
# without the console shell and asserts the image carries the sign path and ZERO allocator symbols;
# the console flavor is the sensitivity control (and is left on disk for the gates above).
bash scripts/pico2_heapless_check.sh > /tmp/g_pico2heapless.log 2>&1; echo "PICO2HEAPLESS=$?"
bash flux/host-sim/build.sh > /tmp/g_hostsim.log 2>&1; echo "HOSTSIM_BUILD=$?"
# The run assertion (expected device output) lives in scripts/check_hostsim.sh,
# shared with CI — it used to be a `grep -c` here that only printed counts, so a
# changed exit shape passed locally while CI failed on its own copy of the grep.
bash scripts/check_hostsim.sh > /tmp/g_sim.log 2>&1; echo "HOSTSIM_RUN=$?"
bash flux/forgebox/build.sh > /tmp/g_forgebox.log 2>&1; echo "FORGEBOX=$?"
# A4-15 (2026-11-21): the forgebox device image must not be able to reach the allocator from any
# product face, and the instrument must be able to see allocations at all (it re-measures the pico2
# image, which allocates, as a sensitivity control). Runs after FORGEBOX (builds the ELF) and PICO2.
bash scripts/forgebox_noalloc_check.sh > /tmp/g_forgeboxnoalloc.log 2>&1; echo "FORGEBOXNOALLOC=$?"
# 密钥供给 §11 (2026-11-21): the device image must expose only the entropy face of the SE
# keystore. The keystone3-parity full-record read (which returns a seed) is compiled out; this
# measures the ELF instead of trusting the #if.
bash scripts/forgebox_keystore_surface_check.sh > /tmp/g_keystoresurface.log 2>&1; echo "KEYSTORESURFACE=$?"
# 密钥供给 §11, the module boundary half: the SE key-supply module is a replaceable piece, so a
# plate-only carrier must be buildable WITHOUT it. This builds the SHLOSILO_WITH_SE=0 flavor into
# its own dirs and asserts the SE face is absent from that image AND present in the canonical one
# (an instrument that cannot see the symbols would make the absence vacuous). Runs after FORGEBOX
# (needs the canonical ELF) and after KEYSTORESURFACE (needs it intact).
bash scripts/forgebox_se_isolation_check.sh > /tmp/g_forgeboxseiso.log 2>&1; echo "FORGEBOXSEISO=$?"
# The C keystore data plane's own host test (keystone3-format golden vectors, OTP three-factor,
# wear/auth paths, and the narrow-vs-full entropy equality). It builds the parity full-record path
# ON so that code is exercised somewhere.
bash flux/forgebox/tests/host_keystore/run.sh > /tmp/g_keystore.log 2>&1; echo "KEYSTORE=$?"
cargo check --offline --manifest-path fuzz/Cargo.toml > /tmp/g_fuzz.log 2>&1; echo "FUZZ=$?"
bash scripts/check_header.sh > /tmp/g_hdr.log 2>&1; echo "HDRKEEP=$?"
cargo fmt --all -- --check > /tmp/g_fmt.log 2>&1; echo "FMT=$?"
bash scripts/vendor_baseline_check.sh > /dev/null 2>&1; echo "BASELINE=$?"
# B-8 (G17): decode our artifacts with the keystone SDK - the parser real wallets
# use. `npm ci` is offline-friendly (lockfile) but the first run needs the
# registry; the gate itself is what must be green.
( cd tools/sdk-gate && npm ci --silent > /tmp/g_sdkgate_npm.log 2>&1 \
    && cd ../.. && cargo run --offline --quiet --example dump_sdk_artifacts -- /tmp/sdk_artifacts > /tmp/g_sdkgate_dump.log 2>&1 \
    && ( cd tools/sdk-gate && node run.mjs /tmp/sdk_artifacts ) ) > /tmp/g_sdkgate.log 2>&1; echo "SDKGATE=$?"
bash probes/noalloc/build.sh > /tmp/g_probe.log 2>&1; echo "PROBE=$?"
# Vendor reference-oracle tests (2026-10-21, Z5.3 test-infra): the vendored
# bulletproofs' own suite is the non-pow2 proof-correctness oracle (m=1..16
# prove+verify); cryptonight mirrors the CI "Vendor crate tests" step (local
# batch must cover the CI surface). Release mode: the OsRng loops take
# minutes in debug.
( cd vendor/cryptonight && cargo test --offline --features cn-timing --lib ) > /tmp/g_vendor_cn.log 2>&1; echo "VENDOR_CN=$?"
( cd vendor/monero-bulletproofs && cargo test --offline --release ) > /tmp/g_vendor_bp.log 2>&1; echo "VENDOR_BP=$?" 
# CI-parity #1 (2026-11-24): the production carrier target is armv7 (LuckyFox) and
# CI lints it cross-target — c_char is u8 on ARM, so pointer-cast lints surface only
# there. The local batch did not run it, so a change could pass locally and fail CI.
cargo clippy --offline --all-targets --target armv7-unknown-linux-gnueabihf -- -D warnings > /tmp/g_arm7.log 2>&1; echo "ARM7LINT=$?"
# CI-parity #2 (2026-11-24): CI checks every feature-gated FFI/timing surface on its
# own. A cfg typo on one feature shows up nowhere else — the default and all-features
# batches can both stay green.
FEATMATRIX=0
for f in device-timing generator-cache-ffi perf-bench-ffi prove-timing-ffi cn-timing-ffi tx-phase-timing-ffi; do
    cargo check --offline --features "$f" > "/tmp/g_feat_$f.log" 2>&1 || FEATMATRIX=1
done
echo "FEATMATRIX=$FEATMATRIX"
# Chain axis (design note §9.4, batch 1): the 7 combinations (3 single + 3 double +
# 1 all-on) compile on the host face, and the symbol criterion is DOUBLE-EDGED — a
# disabled chain must own zero symbols in the rlib AND an enabled chain's sampled
# symbols must be present in the same rlib (only verifying absence cannot tell
# "compiled out" from "instrument blind"; same lesson as FORGEBOXSEISO). Sizes are
# printed per combination. Each combination is built against a generated
# `limits/chainaxes-<combo>.toml` whose [chains] block matches it, because build.rs
# refuses a profile that contradicts the compiled feature set.
bash scripts/check_chain_axes.sh > /tmp/g_chainaxes.log 2>&1; echo "CHAINAXES=$?"
# The synthetic-request injector and its verifier (tools/ur-inject). The verifier is
# what decides whether a device signature is valid, so a broken tool would hand out
# false assurance — its own self-test signs known payloads and drives the real CLI.
( cd tools/ur-inject && npm ci --silent > /tmp/g_urinject_npm.log 2>&1 \
    && cd ../.. && node tools/ur-inject/selftest.mjs ) > /tmp/g_urinject.log 2>&1; echo "URINJECT=$?"
