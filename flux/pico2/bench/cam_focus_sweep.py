#!/usr/bin/env python3
"""Focus sweep: capture frames continuously for N seconds while the operator
slowly moves the board away from a bright, structured target (20 cm -> 2 m).
For each frame, print the Tenengrad focus metric; the peak marks the lens's
focus distance. The best frame is kept for inspection.

Tenengrad = mean of (gx^2 + gy^2) over the frame - the standard sharpness
metric (maximised at best focus for a textured target).
"""
import glob
import os
import select
import subprocess
import sys
import time
import tty

import numpy as np

SECS = int(sys.argv[1]) if len(sys.argv) > 1 else 90
STRIDE = sys.argv[2] if len(sys.argv) > 2 else "4"

DEVS = sorted(glob.glob('/dev/ttyACM*')) or sorted(glob.glob('/dev/ttyUSB*'))
DEV = DEVS[0]
print('console:', DEV)


def read_pgm(path):
    data = open(path, 'rb').read()
    i = data.index(b'255\n') + 4
    hdr = data[:i].split()
    w = int(hdr[1])
    body = np.frombuffer(data[i:], dtype=np.uint8)
    rows = body.size // w
    return body[:rows * w].reshape(rows, w).astype(float)


def tenengrad(img):
    gx = np.diff(img, axis=1)
    gy = np.diff(img, axis=0)
    return float((gx[:-1] ** 2 + gy[:, :img.shape[1] - 1] ** 2).mean())


t0 = time.time()
best = (0.0, None)
n = 0
while time.time() - t0 < SECS:
    n += 1
    out = f'/tmp/fsweep_{n:02d}.pgm'
    r = subprocess.run(
        ['python3', '/home/komo/works/shlosilo-poc4/flux/pico2/bench/cam_dump.py',
         STRIDE, '0', out],
        capture_output=True, text=True, timeout=90)
    if not os.path.exists(out):
        print(f'  frame {n}: dump failed ({r.stderr.strip()[:60]})')
        continue
    img = read_pgm(out)
    t = tenengrad(img)
    el = time.time() - t0
    mark = ''
    if t > best[0]:
        best = (t, out)
        mark = '  <-- best so far'
    print(f'  t={el:5.1f}s frame {n}: Tenengrad {t:8.0f}  mean {img.mean():5.1f} '
          f'std {img.std():5.1f}{mark}')

print(f'\nBEST: {best[1]} at Tenengrad {best[0]:.0f}')
print('(operator: if the sharpest frame was near the end, the focus is farther '
      'than the sweep reached)')
os.system(f'cp {best[1]} /tmp/fsweep_best.pgm' if best[1] else 'true')
