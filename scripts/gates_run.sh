#!/usr/bin/env bash
# shlosilo gate batch — bare exit codes, no trimming by change surface.
# NOTE: the MUST-RED pin suite is GREEN except the expected-red manifest
# (= the tests/ pin_red_* set, grep-derived). Current manifest (1 entry,
# 2026-10-31): pin_red_tx_key_images_wallet2_view_includes_change (I12 —
# tx_key_images wallet2-view contract; the sign leg's inverted filter is the
# known defect, the fix lands in WP2's first batch and the pin is renamed
# together with it). Failures ON the manifest are known-red; any OTHER
# failing test on any face is a real failure.
cd ~/works/shlosilo-poc4 || exit 99
bash scripts/check_fixtures.sh > /tmp/g_fixt.log 2>&1; echo "FIXTURES=$?"
# Pool #58: fp-chain coverage manifest (fingerprint binding + visible-failure
# word chain pins) must stay intact — a renamed/removed/ignored pin is red.
bash scripts/check_fp_chain.sh > /tmp/g_fpchain.log 2>&1; echo "FPCOV=$?"
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
cargo check --lib --no-default-features --target thumbv7em-none-eabihf > /tmp/g_embed1.log 2>&1; echo "EMBED1=$?"
cargo check --lib --no-default-features --target thumbv7em-none-eabihf --features device-timing,generator-cache-ffi,prove-timing-ffi,cn-timing-ffi,tx-phase-timing-ffi,perf-bench-ffi > /tmp/g_embed2.log 2>&1; echo "EMBED2=$?"
cargo clippy --offline --target thumbv8m.main-none-eabihf --manifest-path flux/pico2/Cargo.toml --all-features -- -D warnings > /tmp/g_pico2.log 2>&1; echo "PICO2=$?"
bash flux/host-sim/build.sh > /tmp/g_hostsim.log 2>&1; echo "HOSTSIM_BUILD=$?"
timeout 60 flux/host-sim/sim_l3 > /tmp/g_sim.log 2>&1; echo "HOSTSIM_RUN=$?"
grep -c "signed tx (111 bytes)" /tmp/g_sim.log; grep -c "all steps completed" /tmp/g_sim.log
bash flux/forgebox/build.sh > /tmp/g_forgebox.log 2>&1; echo "FORGEBOX=$?"
cargo check --offline --manifest-path fuzz/Cargo.toml > /tmp/g_fuzz.log 2>&1; echo "FUZZ=$?"
bash scripts/check_header.sh > /tmp/g_hdr.log 2>&1; echo "HDRKEEP=$?"
cargo fmt --all -- --check > /tmp/g_fmt.log 2>&1; echo "FMT=$?"
bash scripts/vendor_baseline_check.sh > /dev/null 2>&1; echo "BASELINE=$?"
bash probes/noalloc/build.sh > /tmp/g_probe.log 2>&1; echo "PROBE=$?"
# Vendor reference-oracle tests (2026-10-21, Z5.3 test-infra): the vendored
# bulletproofs' own suite is the non-pow2 proof-correctness oracle (m=1..16
# prove+verify); cryptonight mirrors the CI "Vendor crate tests" step (local
# batch must cover the CI surface). Release mode: the OsRng loops take
# minutes in debug.
( cd vendor/cryptonight && cargo test --offline --features cn-timing --lib ) > /tmp/g_vendor_cn.log 2>&1; echo "VENDOR_CN=$?"
( cd vendor/monero-bulletproofs && cargo test --offline --release ) > /tmp/g_vendor_bp.log 2>&1; echo "VENDOR_BP=$?" 
