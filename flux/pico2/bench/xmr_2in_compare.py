#!/usr/bin/env python3
"""Compare the device blob against the host A/B reference (byte-exact)."""
import hashlib, sys

dev = open("/tmp/xmr_2in_device.bin", "rb").read()
ref = open("/tmp/p64_host_ab.bin", "rb").read()
print(f"device: {len(dev)} bytes sha256={hashlib.sha256(dev).hexdigest()}")
print(f"host  : {len(ref)} bytes sha256={hashlib.sha256(ref).hexdigest()}")

if dev == ref:
    print("MATCH: byte-exact A/B ✓")
    sys.exit(0)
print("MISMATCH")
# locate the first difference for diagnosis
n = min(len(dev), len(ref))
for i in range(n):
    if dev[i] != ref[i]:
        print(f"first diff at byte {i}: dev={dev[i]:02x} host={ref[i]:02x}")
        break
sys.exit(1)
