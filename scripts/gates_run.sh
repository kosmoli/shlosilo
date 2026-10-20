#!/usr/bin/env bash
# shlosilo gate batch — bare exit codes, no trimming by change surface.
# NOTE: TEST/TESTALL exit 1 is EXPECTED while MUST-RED pins stay red
# (Kosmo 2026-10-20 decision: red pins keep failing on purpose, no
# should_panic — forgetting unfixed bugs is worse than a red CI).
# Expected-red manifest (everything else failing = real breakage):
#   pin_red_sign_real_cake_unsigned_addkeys_change_input  (tests/tx2_whitebox_tools.rs)
#   pin_red_sign_path_change_to_own_subaddress_uses_main_txkey (tests/xmr_subaddr_sign_roundtrip.rs)
#   pin_red_sign_three_outputs_bp_scratch_index_oob (tests/xmr_subaddr_sign_roundtrip.rs)
#   pin_red_to_seed_returns_all_zero (tests/pin_mnemonic_to_seed.rs)
#   pin_red_import_does_not_pollute_transfers_zero (tests/pin_import_key_images_pollution.rs)
#   pin_red_fallback_fill_no_duplicate_selected (tests/pin_signed_key_images_wallet_indexed.rs)
#   pin_red_single_frame_carries_real_cake_message (tests/pin_ur_single_frame_budget.rs)
#   pin_red_details_pool_handles_nine_outputs (tests/pin_details_pool_over8.rs)
cd ~/works/shlosilo-poc4 || exit 99
bash scripts/check_fixtures.sh > /tmp/g_fixt.log 2>&1; echo "FIXTURES=$?"
# TEST/TESTALL run through the zero-on-alloc wrapper (jemalloc zero:true) so
# uninitialized reads surface deterministically - same path as CI test steps.
bash scripts/test_zero_on_alloc.sh --offline --all-targets --no-fail-fast > /tmp/g_test.log 2>&1; echo "TEST=$?"
# T-04: mirror CI "Tests (all features)" — the feature-gated contract pins
# (inv2/inv3 fptr round-trips) only compile under their features.
bash scripts/test_zero_on_alloc.sh --offline --all-targets --all-features --no-fail-fast > /tmp/g_testall.log 2>&1; echo "TESTALL=$?"
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
