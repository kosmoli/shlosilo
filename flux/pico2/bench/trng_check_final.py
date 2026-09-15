#!/usr/bin/env python3
# Checked-path capture via `trngcheck` + paced dump (production-reader datasets).
# (archived 2026-09-15 from the working /tmp scripts; paths inside may need review)
"""Formal post-VN dataset: `trngcheck` into buffer, dump via `trngrawout`.

Usage: python3 check_final.py <label> <nblocks> [pace_ms]

The dump is paced + block-indexed (same machinery as raw datasets); gaps are
detected and reported. Output: /tmp/postvn2_<label>.bin (+_1bit, .json).
"""
import hashlib
import json
import os
import re
import select
import sys
import termios
import threading
import time
import tty

label = sys.argv[1] if len(sys.argv) > 1 else "main"
nblocks = int(sys.argv[2]) if len(sys.argv) > 2 else 16384
pace = int(sys.argv[3]) if len(sys.argv) > 3 else 1

fd = os.open("/dev/ttyACM0", os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
tty.setraw(fd)
try:
    termios.tcflush(fd, termios.TCIFLUSH)
except termios.error:
    pass
buf = bytearray()
stop = threading.Event()
transcript = open(f"/tmp/check_final_{label}_transcript.txt", "wb")


def reader():
    while not stop.is_set():
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                c = os.read(fd, 8192)
            except OSError:
                break
            if c:
                buf.extend(c)
                transcript.write(c)
                transcript.flush()


th = threading.Thread(target=reader, daemon=True)
th.start()
time.sleep(1.0)
text = lambda: buf.decode(errors="replace")  # noqa: E731

os.write(fd, b"\nfaultclr\n")
time.sleep(0.3)
before = len(buf)
os.write(fd, b"\nversion\n")
time.sleep(0.8)
m = re.search(r"v0\.5\.0-poc4\+([a-z0-9-]+)", text()[before:])
fw = m.group(1) if m else "?"
print(f"firmware: {fw}", flush=True)

# 1) capture via production reader
before = len(buf)
os.write(fd, f"\ntrngcheck {nblocks}\n".encode())
print(f">>> trngcheck {nblocks}", flush=True)
t0 = time.time()
while time.time() - t0 < 1800:
    t = text()[before:]
    if "[tchk] captured" in t or "capture failed" in t:
        break
    time.sleep(0.5)
time.sleep(0.5)
cm = re.search(r"\[tchk\] captured (\d+) checked-path blocks = (\d+) bits in (\d+) ms \(([\d]+) us/block;[^\n]*", text()[before:])
if cm:
    print(f"    {cm.group(0)}", flush=True)
else:
    fm = re.search(r"\[tchk\] capture failed[^\n]*", text()[before:])
    sys.exit(f"FAIL: capture ({(fm.group(0) if fm else 'no line')}" + ")")

# 2) dump
before = len(buf)
os.write(fd, f"\ntrngrawout 0 {pace}\n".encode())
print(f">>> trngrawout 0 {pace}", flush=True)
t0 = time.time()
while time.time() - t0 < 60:
    if "[traw] dump" in text()[before:]:
        break
    time.sleep(0.3)
dm = re.search(r"\[traw\] dump 0\.\.(\d+) \(", text()[before:])
total = int(dm.group(1)) if dm else int(cm.group(1))
print(f"    dumping {total} blocks...", flush=True)

assembled = bytearray(total * 24)
seen = bytearray(total)
LINE_RE = re.compile(r"\[traw\] (\d+) ([0-9a-f]+)")
deadline = time.time() + max(120, total // 4 * pace / 1000 * 8 + 120)
while time.time() < deadline:
    t = text()[before:]
    for mm in LINE_RE.finditer(t):
        idx = int(mm.group(1))
        hexs = mm.group(2)
        nblk = len(hexs) // 48
        for j in range(nblk):
            b = idx + j
            if b < total and not seen[b]:
                seen[b] = 1
                a = b * 24
                assembled[a:a + 24] = bytes.fromhex(hexs[j * 48:(j + 1) * 48])
    if "[traw] done" in t:
        break
    have = sum(seen)
    if have % 4096 < 16:
        print(f"    ... {have}/{total}", flush=True)
    time.sleep(0.4)

have = sum(seen)
gaps = [i for i, v in enumerate(seen) if not v]
print(f"    received {have}/{total}; gaps: {len(gaps)}", flush=True)

stop.set()
th.join(timeout=2)
os.close(fd)
transcript.close()

data = bytes(assembled)
with open(f"/tmp/postvn2_{label}.bin", "wb") as f:
    f.write(data)
onebit = bytearray(len(data) * 8)
for i, byte in enumerate(data):
    for b in range(8):
        onebit[i * 8 + b] = (byte >> b) & 1
with open(f"/tmp/postvn2_{label}_1bit.bin", "wb") as f:
    f.write(onebit)

sha = hashlib.sha256(data).hexdigest()
meta = {
    "label": label,
    "firmware": fw,
    "path": "checked (production reader; VN + health checks; chain 4 / sample 200)",
    "blocks_total": total,
    "blocks_received": have,
    "gaps": len(gaps),
    "gap_first": gaps[:8],
    "sha256": sha,
    "capture_line": cm.group(0),
    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
}
with open(f"/tmp/postvn2_{label}.json", "w") as f:
    json.dump(meta, f, indent=2)
print(f"sha256: {sha[:32]}...")
print(f"-> /tmp/postvn2_{label}.bin")
