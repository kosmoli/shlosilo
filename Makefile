# shlosilo monorepo entry points.
#
#   make forgebox   build the C-host firmware (MH1903, flux/forgebox) and sign it
#   make pico2      build the Rust-native board image (RP2350, flux/pico2)
#   make pico2-uf2  build + pack the board image into a flashable UF2
#   make pico2-bench       build the bench-flavored image (adds the bench-only
#                          console surface; audit #17)
#   make pico2-bench-uf2   build + pack the bench-flavored UF2
#   make pico2-perf-uf2    bench surface + XMR phase-timing probes (perf work)
#   make pico2-check-flavors  assert the bench surface is absent from the
#                          production image and present in the bench image
#   make host-sim   build + link the POSIX simulator (flux/host-sim)
#   make clean-appearances  remove ignored appearance build products
#   make test       test suite, default features
#   make test-all   test suite, --all-features
#   make check      clippy + embedded check gate

.PHONY: forgebox pico2 pico2-uf2 pico2-bench pico2-bench-uf2 pico2-perf-uf2 pico2-check-flavors host-sim clean-appearances test test-all check help

forgebox:
	cd flux/forgebox && bash build.sh

pico2:
	cd flux/pico2 && cargo build --release

pico2-uf2:
	cd flux/pico2 && cargo build --release
	cd flux/pico2 && python3 pack_uf2.py

# Bench build: adds the bench-only console surface (xmrseed / entropy / TRNG
# diagnostics) that production images must not contain (audit #17 P1-01).
pico2-bench:
	cd flux/pico2 && cargo build --release --features bench

pico2-bench-uf2:
	cd flux/pico2 && cargo build --release --features bench
	cd flux/pico2 && python3 pack_uf2.py

# Perf-work build: bench console surface + XMR phase-timing probes +
# device-primitive benchmarks + the out-of-line dalek codegen (diagnostic;
# the firmware for perf runs). codegen-compact measured -192 ms/sign on
# the 2026-09-15 A/B (bp1 -179, bp5 -365; byte-identical output).
pico2-perf-uf2:
	cd flux/pico2 && cargo build --release --features bench,perf-timing,perf-bench,codegen-compact
	cd flux/pico2 && python3 pack_uf2.py

# Same script the CI appearances job runs (see scripts/check_pico2_flavors.sh).
pico2-check-flavors:
	bash scripts/check_pico2_flavors.sh

host-sim:
	bash flux/host-sim/build.sh

# Ignored build products must never be used as evidence of the current tree
# (audit #16 P2-02: a stale libshlosilo.a once masked a broken host-sim
# link). CI rebuilds all of these from a clean checkout; this target is the
# local equivalent.
clean-appearances:
	rm -rf flux/forgebox/build flux/forgebox/shlosilo flux/host-sim/sim_l3
	@echo "removed ignored appearance build products (rebuild: make forgebox | make host-sim)"

test:
	cargo test --offline --all-targets

test-all:
	cargo test --offline --all-targets --all-features

check:
	bash scripts/clippy.sh

help:
	@echo "targets: forgebox | pico2 | pico2-uf2 | host-sim | test | test-all | check"
