# shlosilo monorepo entry points.
#
#   make forgebox   build the C-host firmware (MH1903, flux/forgebox) and sign it
#   make pico2      build the Rust-native board image (RP2350, flux/pico2)
#   make pico2-uf2  build + pack the board image into a flashable UF2
#   make host-sim   build + link the POSIX simulator (flux/host-sim)
#   make test       test suite, default features
#   make test-all   test suite, --all-features
#   make check      clippy + embedded check gate

.PHONY: forgebox pico2 pico2-uf2 host-sim test test-all check help

forgebox:
	cd flux/forgebox && bash build.sh

pico2:
	cd flux/pico2 && cargo build --release

pico2-uf2:
	cd flux/pico2 && cargo build --release
	cd flux/pico2 && python3 pack_uf2.py

host-sim:
	bash flux/host-sim/build.sh

test:
	cargo test --offline --all-targets

test-all:
	cargo test --offline --all-targets --all-features

check:
	bash scripts/clippy.sh

help:
	@echo "targets: forgebox | pico2 | pico2-uf2 | host-sim | test | test-all | check"
