#!/usr/bin/env python3
# SP 800-90B assessment runner (ea_non_iid over collected datasets).
# (archived 2026-09-15 from the working /tmp scripts; paths inside may need review)
"""Assess all raw + post-VN datasets with the official SP 800-90B tool."""
import glob
import json
import os
import re
import subprocess

TOOL_DIR = "/home/komo/codebases/SP800-90B_EntropyAssessment/cpp"
OUT = "/tmp/full_assessment_results.json"

jobs = []
# raw datasets (bypass): file pattern raw_<label>_1bit.bin
for f in sorted(glob.glob("/tmp/raw_*_1bit.bin")):
    label = os.path.basename(f)[len("raw_"):-len("_1bit.bin")]
    # skip derived msb variant + tiny
    size = os.path.getsize(f)
    if size < 100_000:
        continue
    jobs.append((label, f, "raw"))
# post-VN datasets
for f in sorted(glob.glob("/tmp/postvn_*_1bit.bin")):
    label = "postvn_" + os.path.basename(f)[len("postvn_"):-len("_1bit.bin")]
    size = os.path.getsize(f)
    if size < 100_000:
        continue
    jobs.append((label, f, "postvn"))

results = {}
for label, path, kind in jobs:
    r = subprocess.run(
        [f"{TOOL_DIR}/ea_non_iid", "-i", "-a", "-v", path, "1"],
        capture_output=True, text=True, timeout=3600,
    )
    out = r.stdout
    m = re.search(r"H_original: ([\d.]+)", out)
    h = float(m.group(1)) if m else None
    est = dict(re.findall(r"\t(\S[^\n=]*?) Estimate = ([\d.]+)", out))
    ld = re.search(r"Loaded (\d+) samples", out)
    n = int(ld.group(1)) if ld else 0
    results[label] = {"kind": kind, "n": n, "H": h, "estimators": {k.strip(): float(v) for k, v in est.items()}}
    print(f"{label:16s} {kind:6s} n={n:9d} H={h}", flush=True)

with open(OUT, "w") as f:
    json.dump(results, f, indent=2)
print(f"\nsaved to {OUT}")
