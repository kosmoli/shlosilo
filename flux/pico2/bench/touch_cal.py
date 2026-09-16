#!/usr/bin/env python3
"""Touch calibration capture: poll the touch controller and log every
contact sample during a window, so the coordinate mapping (raw FT6236
12-bit domain -> 320x480 screen, axis order and inversion) can be
derived from real finger positions.

The user is asked to touch the four corners and the centre in order.
Output: /tmp/touch-cal.log (raw + interpreted per axis).
"""
import os
import re
import select
import sys
import time
import tty

DEV = "/dev/ttyACM0"
OUT = "/tmp/touch-cal.log"
WINDOW = float(sys.argv[1]) if len(sys.argv) > 1 else 60.0

fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
tty.setraw(fd)


def drain():
    out = b""
    while True:
        r, _, _ = select.select([fd], [], [], 0.08)
        if not r:
            break
        d = os.read(fd, 8192)
        if not d:
            break
        out += d
    return out


drain()
os.write(fd, b"\n")
time.sleep(0.3)
drain()

log = open(OUT, "w")
t0 = time.time()
seen = 0
nz = 0
print(f"capture window {WINDOW:.0f}s - touch the screen now (log: {OUT})", flush=True)

buf = b""
while time.time() - t0 < WINDOW:
    os.write(fd, b"touch 1\n")
    time.sleep(0.25)
    buf += drain()

text = buf.decode("utf-8", "replace")
for line in text.splitlines():
    m = re.search(r"\[touch\] #\d+ fingers=(\d+) gesture=0x([0-9a-f]{2}) raw=\((\d+), (\d+)\)", line)
    if not m:
        continue
    fingers, gest, x, y = int(m.group(1)), m.group(2), int(m.group(3)), int(m.group(4))
    seen += 1
    if fingers > 0 or x > 0 or y > 0:
        nz += 1
        log.write(f"t={time.time()-t0:6.1f} fingers={fingers} ev={gest} raw=({x},{y})\n")
        log.flush()

log.close()
os.close(fd)
print(f"done: {seen} samples, {nz} with contact -> {OUT}")
