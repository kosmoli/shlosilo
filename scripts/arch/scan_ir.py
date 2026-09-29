#!/usr/bin/env python3
"""Find enclosing function names for __rust_alloc* calls in the shlosilo LLVM IR."""
import re

path = "/home/komo/works/shlosilo-poc4/probes/noalloc/target/thumbv7em-none-eabihf/release/deps/shlosilo-838b429edee402fd.ll"
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
