#!/usr/bin/env python3
"""Find which dep's LINK closure pulls alloc. Manifest is rebuilt from scratch."""
import subprocess

MANIFEST = """[package]
name = "z6-probe-min"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
crate-type = ["staticlib"]

[dependencies]
shlosilo = { path = "/home/komo/works/shlosilo-poc4", default-features = false }
zeroize = { version = "1", default-features = false }
rand_core = { version = "0.6", default-features = false }
monero-clsag = { version = "0.1", default-features = false }
monero-bulletproofs = { path = "/home/komo/works/shlosilo-poc4/vendor/monero-bulletproofs", default-features = false, features = ["compile-time-generators"] }
base58-monero = { version = "2", default-features = false }
cuprate-cryptonight = { path = "/home/komo/works/shlosilo-poc4/vendor/cryptonight", default-features = false }
chacha20 = { version = "0.9", default-features = false }
k256 = { version = "0.14", default-features = false, features = ["ecdsa"] }
sha3 = { version = "0.10", default-features = false }
subtle = { version = "2.5", default-features = false }
crypto-bigint = { version = "0.5", default-features = false }
monero-ed25519 = { version = "0.1", default-features = false }
monero-io = { version = "0.1", default-features = false }
heapless = "0.8"

[patch.crates-io]
curve25519-dalek = { path = "/home/komo/works/shlosilo-poc4/vendor/curve25519-dalek" }
monero-clsag = { path = "/home/komo/works/shlosilo-poc4/vendor/monero-clsag" }
monero-ed25519 = { path = "/home/komo/works/shlosilo-poc4/vendor/monero-ed25519" }
monero-io = { path = "/home/komo/works/shlosilo-poc4/vendor/monero-io" }
monero-bulletproofs-generators = { path = "/home/komo/works/shlosilo-poc4/vendor/monero-bulletproofs-generators" }
base58-monero = { path = "/home/komo/works/shlosilo-poc4/vendor/base58-monero" }
std-shims = { path = "/home/komo/works/shlosilo-poc4/vendor/std-shims" }
"""

EXPRS = {
    "control (empty)": "",
    "shlosilo const": "let _ = shlosilo::types::caps::RING_MAX;",
    "monero_clsag": "let _ = monero_clsag::RING_MAX;",
    "monero_bulletproofs": "let _ = monero_bulletproofs::MAX_COMMITMENTS;",
    "base58_monero": "let _ = base58_monero::base58::FULL_BLOCK_SIZE;",
    "chacha20": "let _ = chacha20::KeySize::U32;",
    "k256": "let _ = k256::Scalar::ZERO;",
    "sha3": "let _ = sha3::Keccak256::new();",
    "subtle": "let _ = subtle::Choice::from(0u8);",
    "crypto_bigint": "let _ = crypto_bigint::U256::ZERO;",
    "monero_ed25519": "let _ = monero_ed25519::Scalar::ZERO;",
    "monero_io": "let _ = monero_io::read_u64;",
    "cuprate_cryptonight": "let _ = cuprate_cryptonight::hash_v0_into;",
    "heapless": "let _ = heapless::Vec::<u8, 1>::new();",
}

TMPL = """#![no_std]
#![no_main]
use core::panic::PanicInfo;
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {{ loop {{}} }}

#[no_mangle]
pub extern "C" fn z6_probe_run() {{
    {body}
}}
"""

open("/tmp/probe_min/Cargo.toml", "w").write(MANIFEST)

def build(body):
    open("/tmp/probe_min/src/lib.rs", "w").write(TMPL.format(body=body))
    r = subprocess.run(["cargo", "build", "--release", "--target", "thumbv7em-none-eabihf"],
                       capture_output=True, text=True, cwd="/tmp/probe_min")
    if "Finished" in r.stderr or "Finished" in r.stdout:
        return "PASS"
    if "no global memory allocator" in r.stderr:
        return "ALLOC-REQ"
    return "OTHER"

for name, body in EXPRS.items():
    print(f"{name:22s} {build(body)}")
