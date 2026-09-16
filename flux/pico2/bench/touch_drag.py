#!/usr/bin/env python3
"""Definitive axis-orientation capture for the FT6236 (pico2).

The five-point calibration left a label/order ambiguity: the raw corner
set is the same rectangle under several orientations, and a touch trail
painted with the wrong orientation looks "swapped" to the user. This run
captures two KNOWN screen-space drags (left->right, top->bottom, each
repeated) and reports, per drag segment, which raw axis moved and in
which direction - which pins the orientation exactly.

Usage: touch_drag.py [window_s]   (default 150)
Output: /tmp/touch-drag.log + segment summary on stdout.
"""
import os
import re
import select
import sys
import time
import tty

DEV = "/dev/ttyACM0"
OUT = "/tmp/touch-drag.log"
WINDOW = float(sys.argv[1]) if len(sys.argv) > 1 else 150.0
GAP = 1.0  # seconds of no contact that split drag segments

fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
tty.setraw(fd)
PAT = re.compile(
    r"\[touch\] #\d+ fingers=(\d+) gesture=0x([0-9a-f]{2}) raw=\((\d+), (\d+)\)"
)


def drain():
    out = b""
    while True:
        r, _, _ = select.select([fd], [], [], 0.05)
        if not r:
            break
        d = os.read(fd, 8192)
        if not d:
            break
        out += d
    return out


drain()
os.write(fd, b"\n")
time.sleep(0.25)
drain()

log = open(OUT, "w")
t0 = time.time()
samples = []  # (t, fingers, x, y)
last_progress = 0.0
print("drag capture running - do the drags now", flush=True)

while time.time() - t0 < WINDOW:
    os.write(fd, b"touch 1\n")
    time.sleep(0.07)
    chunk = drain().decode("utf-8", "replace")
    now = time.time() - t0
    for line in chunk.splitlines():
        m = PAT.search(line)
        if not m:
            continue
        f, x, y = int(m.group(1)), int(m.group(3)), int(m.group(4))
        samples.append((now, f, x, y))
        log.write(f"{now:7.3f} f={f} raw=({x},{y})\n")
    log.flush()
    if now - last_progress > 15:
        last_progress = now
        print(f"  .. {now:.0f}s, {len(samples)} samples", flush=True)

log.close()
os.close(fd)

# Segmentation over contact samples only.
contact = [s for s in samples if s[1] > 0]
segs = []
cur = []
for s in contact:
    if cur and s[0] - cur[-1][0] > GAP:
        segs.append(cur)
        cur = []
    cur.append(s)
if cur:
    segs.append(cur)

print("=== segments ===", flush=True)
for i, seg in enumerate(segs):
    a, b = seg[0], seg[-1]
    dx, dy = b[2] - a[2], b[3] - a[3]
    dom = "x" if abs(dx) >= abs(dy) else "y"
    print(
        f"#{i}: n={len(seg)} t={a[0]:.1f}..{b[0]:.1f}s "
        f"start=({a[2]},{a[3]}) end=({b[2]},{b[3]}) "
        f"d=({dx:+d},{dy:+d}) dominant={dom}",
        flush=True,
    )
print(f"total samples={len(samples)} contact={len(contact)} -> {OUT}", flush=True)
