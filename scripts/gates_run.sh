#!/usr/bin/env bash
# shlosilo gate batch — bare exit codes, no trimming by change surface.
cd ~/works/shlosilo-poc4 || exit 99
cargo test --offline --all-targets > /tmp/g_test.log 2>&1; echo "TEST=$?"
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
