#!/usr/bin/env python3
"""Byte-level archaeology: where does 'alloc' sit in shlosilo's rmeta?"""
import glob
import os

paths = glob.glob("/home/komo/works/shlosilo-poc4/probes/noalloc/target/thumbv7em-none-eabihf/release/deps/libshlosilo-*.rmeta")
path = max(paths, key=os.path.getmtime)
data = open(path, "rb").read()
print(f"rmeta: {os.path.basename(path)}  {len(data)} bytes")

needle = b"alloc"
off = 0
shown = 0
while shown < 15:
    i = data.find(needle, off)
    if i < 0:
        break
    lo = max(0, i - 24)
    hi = min(len(data), i + 32)
    ctx = data[lo:hi]
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in ctx)
    print(f"@{i:6d}: {printable}")
    off = i + 1
    shown += 1
print("total:", data.count(needle))
