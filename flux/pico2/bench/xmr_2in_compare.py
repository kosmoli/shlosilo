#!/usr/bin/env python3
"""Compare the device blob against the host A/B reference (byte-exact).

The reference is a host sign of the same fixture with the same fixed entropy, produced by the
`sign_with_fixed_entropy_for_ab` tool test. It used to live in bare /tmp and vanished when /tmp got
cleaned, which turned this step into "FAIL: blob mismatch" on a perfectly good device run
(2026-11-22). Now:

* the reference lives under `target/p2-ab/` (build output, not a /tmp artifact);
* if it is missing, this script regenerates it before comparing;
* if it cannot be regenerated (the tool test needs the fixture view key), it says so and exits 3 -
  an unavailable reference is not a mismatch.
"""
import hashlib
import os
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[3]
DEV_BLOB = pathlib.Path("/tmp/xmr_2in_device.bin")
REF = REPO / "target" / "p2-ab" / "p64_host_ab.bin"
# The bench wallet's entropy - the same one the carrier is given with `entropy <hex>` before feeding
# the device-key fixture. Not a secret: it is the deterministic test wallet, and the tool test needs
# it to restore the same keys. Overridable for a different fixture.
DEV_ENTROPY = os.environ.get(
    "P64_ENTROPY_HEX",
    "4a9291a702c0ba28aa285882efde4f2c9237556ceb685570d595fd6586074530",
)


def regenerate() -> bool:
    REF.parent.mkdir(parents=True, exist_ok=True)
    print(f"reference missing -> regenerating {REF}")
    proc = subprocess.run(
        [
            "cargo", "test", "--offline", "--release",
            "--test", "p64_xmr_multi_input", "sign_with_fixed_entropy_for_ab",
            "--", "--ignored", "--nocapture",
        ],
        cwd=REPO,
        env={
            **os.environ,
            "P64_AB_OUT": str(REF),
            "P64_ENTROPY_HEX": DEV_ENTROPY,
            # The embedded default fixture is the WATCH-ONLY one, which the device-keys wallet cannot
            # decrypt (host signing then fails with EncodingInvalidFormat, which reads like a code
            # bug). The bench signs the device-keys variant, so the reference must be built from it.
            "P64_FIXTURE_PATH": "tests/fixtures/unsigned_txset_2in_dev.bin",
        },
        capture_output=True,
        text=True,
    )
    for line in (proc.stdout + proc.stderr).strip().splitlines()[-4:]:
        print(f"  {line}")
    return proc.returncode == 0 and REF.exists()


if not DEV_BLOB.exists():
    print(f"FAIL: {DEV_BLOB} missing - run xmr_2in_bringup.py first")
    sys.exit(2)
if not REF.exists() and not regenerate():
    print("SKIP: host A/B reference unavailable (the tool test needs the fixture view key)")
    sys.exit(3)

dev = DEV_BLOB.read_bytes()
ref = REF.read_bytes()
print(f"device: {len(dev)} bytes sha256={hashlib.sha256(dev).hexdigest()}")
print(f"host  : {len(ref)} bytes sha256={hashlib.sha256(ref).hexdigest()}")

if dev == ref:
    print("MATCH: byte-exact A/B ok")
    sys.exit(0)

print("MISMATCH")
for i in range(min(len(dev), len(ref))):
    if dev[i] != ref[i]:
        print(f"first diff at byte {i}: dev={dev[i]:02x} host={ref[i]:02x}")
        break
else:
    print(f"length differs: dev={len(dev)} host={len(ref)}")
sys.exit(1)
