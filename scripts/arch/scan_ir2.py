#!/usr/bin/env python3
"""Find enclosing function names for __rust_alloc* calls (newest shlosilo .ll)."""
import glob
import re

paths = glob.glob("/home/komo/works/shlosilo-poc4/probes/noalloc/target/thumbv7em-none-eabihf/release/deps/shlosilo-*.ll")
path = max(paths, key=lambda p: __import__("os").path.getmtime(p))
print("IR:", path.split("/")[-1])
cur = None
hits = {}
for line in open(path, errors="replace"):
    if line.startswith("define "):
        m = re.search(r"@([\w.$]+)\(", line)
        cur = m.group(1) if m else line.strip()[:80]
    elif line.startswith("}"):
        cur = None
    elif cur and ("__rust_alloc" in line or "__rust_dealloc" in line or "__rust_realloc" in line or "__rust_alloc_zeroed" in line):
        hits.setdefault(cur, 0)
        hits[cur] += 1

for fn, n in sorted(hits.items(), key=lambda kv: -kv[1]):
    print(f"{n:4d}  {fn[:150]}")
print(f"TOTAL: {len(hits)} functions")
