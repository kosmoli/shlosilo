#!/usr/bin/env python3
"""Edge-middle calibration pass for the FT6236: resolves axis signs.

The four corners are symmetric, so they cannot tell whether an axis is
inverted; edge MIDDLES can. The user touches, in order:
  left-middle, right-middle, top-middle, bottom-middle.
Classification is self-checking: x-edge touches sit near y~240
(half of 480) with x far from centre; y-edge touches sit near x~160
(half of 320) with y far from centre.

Output: /tmp/touch-edges.log (timestamped contact samples).
"""
import os
import re
import select
import sys
import time
import tty

DEV = "/dev/ttyACM0"
OUT = "/tmp/touch-edges.log"
WINDOW = float(sys.argv[1]) if len(sys.argv) > 1 else 45.0

fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
tty.setraw(fd)
PAT = re.compile(r"\[touch\] #\d+ fingers=(\d+) gesture=0x([0-9a-f]{2}) raw=\((\d+), (\d+)\)")


def drain():
    out = b""
    while True:
        r, _, _ = select.select([fd], [], [], 0.06)
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
samples = 0
contacts = 0
seen_points = []

print(f"edge window {WINDOW:.0f}s - touch left/right/top/bottom middles now", flush=True)

while time.time() - t0 < WINDOW:
    os.write(fd, b"touch 1\n")
    time.sleep(0.15)
    chunk = drain().decode("utf-8", "replace")
    for line in chunk.splitlines():
        m = PAT.search(line)
        if not m:
            continue
        fingers, gest, x, y = int(m.group(1)), m.group(2), int(m.group(3)), int(m.group(4))
        samples += 1
        if fingers > 0 or x > 0 or y > 0:
            contacts += 1
            ts = time.time() - t0
            log.write(f"t={ts:6.2f} fingers={fingers} ev={gest} raw=({x},{y})\n")
            log.flush()
            if not seen_points or seen_points[-1] != (x, y):
                seen_points.append((x, y))
                print(f"  new point at {ts:5.1f}s: ({x},{y})", flush=True)

log.close()
os.close(fd)
print(f"done: {samples} samples, {contacts} contacts; distinct points:")
for p in seen_points:
    print("   ", p)
print(f"log -> {OUT}")
