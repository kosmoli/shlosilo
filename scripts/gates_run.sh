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
bash scripts/test_zero_on_alloc.sh --offline --no-default-features --all-targets --no-fail-fast > /tmp/g_testnoalloc.log 2>&1; echo "TESTNOALLOC=$?"
# CI "flux keysource" parity: the keysource package has its own test face
# (qr_ffi FFI arity contracts etc.) that the root batch never compiles.
cargo test --offline -p shlosilo-flux-keysource > /tmp/g_keysrc.log 2>&1; echo "KEYSRC=$?"
bash scripts/clippy.sh > /tmp/g_clippy.log 2>&1; echo "CLIPPY=$?"
cargo check --offline --target armv7-unknown-linux-gnueabihf > /tmp/g_arm.log 2>&1; echo "ARM=$?"
# The embedded faces are compile-surface checks, not carrier builds: name the smallest
# real bare-metal profile so build.rs does not have to guess (it refuses to default
# to host for a bare-metal target).
SHLOSILO_LIMITS=pico2 cargo check --lib --no-default-features --target thumbv7em-none-eabihf > /tmp/g_embed1.log 2>&1; echo "EMBED1=$?"
SHLOSILO_LIMITS=pico2 cargo check --lib --no-default-features --target thumbv7em-none-eabihf --features device-timing,generator-cache-ffi,prove-timing-ffi,cn-timing-ffi,tx-phase-timing-ffi,perf-bench-ffi > /tmp/g_embed2.log 2>&1; echo "EMBED2=$?"
SHLOSILO_LIMITS=pico2 cargo clippy --offline --target thumbv8m.main-none-eabihf --manifest-path flux/pico2/Cargo.toml --all-features -- -D warnings > /tmp/g_pico2.log 2>&1; echo "PICO2=$?"
# pico2 build-flavor face (audit #17 P1-01, extended 2026-11-19 with the A4-01/A4-02 canaries):
# builds production + bench + perf flavors and asserts the bench-only surface is absent from
# production, present in bench, AND that the production no-session refusal really exists.
bash scripts/check_pico2_flavors.sh > /tmp/g_pico2flavors.log 2>&1; echo "PICO2FLAVORS=$?"
bash flux/host-sim/build.sh > /tmp/g_hostsim.log 2>&1; echo "HOSTSIM_BUILD=$?"
timeout 60 flux/host-sim/sim_l3 > /tmp/g_sim.log 2>&1; echo "HOSTSIM_RUN=$?"
grep -c "signed tx (111 bytes)" /tmp/g_sim.log; grep -c "all steps completed" /tmp/g_sim.log
bash flux/forgebox/build.sh > /tmp/g_forgebox.log 2>&1; echo "FORGEBOX=$?"
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
