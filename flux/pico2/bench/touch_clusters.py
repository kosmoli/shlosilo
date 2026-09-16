#!/usr/bin/env python3
"""Three-target touch probe with real timestamps (FT6236 calibration).

The four-corner sweep left an ambiguity: the raw corner set is the same
rectangle whether the digitizer is axis-aligned (plain 1:1 mapping) or
mounted rotated 90 degrees - only the *order* the corners were touched
distinguishes the two, and that cannot be recovered from the data.

This probe removes the ambiguity by asking for three targets in a fixed
order and classifying each cluster from its raw position:
  1) the black block at the screen's TOP-LEFT  (plain: ~(30,25) | rot90: ~(285,35))
  2) the black block at the screen's BOTTOM-RIGHT (plain: ~(276,446) | rot90: ~(31,443))
  3) the screen centre (both: ~(149,240))
Each target becomes a ground-truth anchor for the affine fit.

Samples are logged with real timestamps; clusters separated by >1.0 s.

Usage: touch_clusters.py [window_s]
Output: /tmp/touch-clusters.log + live cluster summary on stdout.
"""
import os
import re
import select
import sys
import time
import tty

DEV = "/dev/ttyACM0"
OUT = "/tmp/touch-clusters.log"
WINDOW = float(sys.argv[1]) if len(sys.argv) > 1 else 240.0
GAP = 1.0

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

samples = open(OUT, "w")
t0 = time.time()
clusters = []
cur = []
last_ts = None


def close_cluster():
    global cur
    if not cur:
        return
    xs = [c[1] for c in cur]
    ys = [c[2] for c in cur]
    avg = (round(sum(xs) / len(xs)), round(sum(ys) / len(ys)))
    clusters.append((avg, len(cur), cur[0][0], cur[-1][0]))
    print(
        f"CLUSTER avg=({avg[0]},{avg[1]}) n={len(cur)} "
        f"t={cur[0][0]:.1f}..{cur[-1][0]:.1f}s",
        flush=True,
    )
    cur = []


print("probe running: touch TOP-LEFT block, wait, BOTTOM-RIGHT, wait, centre", flush=True)

while time.time() - t0 < WINDOW:
    os.write(fd, b"touch 1\n")
    time.sleep(0.12)
    chunk = drain().decode("utf-8", "replace")
    now = time.time() - t0
    for line in chunk.splitlines():
        m = PAT.search(line)
        if not m:
            continue
        fingers, _gest, x, y = (
            int(m.group(1)),
            m.group(2),
            int(m.group(3)),
            int(m.group(4)),
        )
        if fingers == 0 and x == 0 and y == 0:
            continue
        samples.write(f"{now:8.3f} f={fingers} raw=({x},{y})\n")
        samples.flush()
        if cur and last_ts is not None and now - last_ts > GAP:
            close_cluster()
        cur.append((now, x, y))
        last_ts = now

close_cluster()
samples.close()
os.close(fd)
print("=== clusters ===", flush=True)
for avg, n, a, b in clusters:
    print(f"  avg=({avg[0]},{avg[1]}) n={n} t={a:.1f}..{b:.1f}s", flush=True)
print(f"all samples -> {OUT}", flush=True)
