#!/usr/bin/env python3
"""Scan ALL fresh .ll files in the probe build for allocator references."""
import glob
import os
import re
import time

now = time.time()
lls = [p for p in glob.glob("/home/komo/works/shlosilo-poc4/probes/noalloc/target/thumbv7em-none-eabihf/release/deps/*.ll")
       if now - os.path.getmtime(p) < 3600]
print(f"{len(lls)} fresh .ll files")
for path in sorted(lls):
    cur = None
    hits = {}
    for line in open(path, errors="replace"):
        if line.startswith("define "):
            m = re.search(r"@([\w.$]+)\(", line)
            cur = m.group(1) if m else "?"
        elif line.startswith("}"):
            cur = None
        elif cur and ("__rust_alloc" in line or "__rust_dealloc" in line or "__rust_realloc" in line or "__rust_alloc_zeroed" in line):
            hits.setdefault(cur, 0)
            hits[cur] += 1
    if hits:
        print(f"\n== {path.split('/')[-1]}")
        for fn, n in sorted(hits.items(), key=lambda kv: -kv[1])[:8]:
            print(f"{n:4d}  {fn[:130]}")
