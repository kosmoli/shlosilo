#!/usr/bin/env python3
"""Controlled focus-distance test: capture at fixed distances while the
operator holds the board pointed at a bright high-contrast target (the
monitor with the QR fullscreen).

For each distance: 2 frames at stride 2, Tenengrad sharpness on the central
60% region (where the target should be), plus a saved PGM for inspection.

Usage: cam_focus_dist.py [dist1 dist2 ...]   (cm, default 25 40 60 90 130)
"""
import glob
import os
import subprocess
import sys
import time

import numpy as np

DISTS = [int(x) for x in sys.argv[1:]] or [25, 40, 60, 90, 130]


def read_pgm(path):
    data = open(path, 'rb').read()
    i = data.index(b'255\n') + 4
    hdr = data[:i].split()
    w = int(hdr[1])
    body = np.frombuffer(data[i:], dtype=np.uint8)
    rows = body.size // w
    return body[:rows * w].reshape(rows, w).astype(float)


def tenengrad(img, frac=0.6):
    h, w = img.shape
    y0, y1 = int(h * (1 - frac) / 2), int(h * (1 + frac) / 2)
    x0, x1 = int(w * (1 - frac) / 2), int(w * (1 + frac) / 2)
    c = img[y0:y1, x0:x1]
    gx = np.diff(c, axis=1)
    gy = np.diff(c, axis=0)
    return float((gx[:-1] ** 2 + gy[:, :c.shape[1] - 1] ** 2).mean())


def capture(path):
    r = subprocess.run(
        ['python3', '/home/komo/works/shlosilo-poc4/flux/pico2/bench/cam_dump.py',
         '2', '0', path],
        capture_output=True, text=True, timeout=90)
    return os.path.exists(path)


print('=== focused distance test ===')
print('Target: the monitor showing the QR fullscreen. Hold the board so the')
print('QR is centred, at each distance below. Hold still ~4 s per step.')
print()

results = []
for d in DISTS:
    print(f'--> HOLD AT ~{d} cm  (4 s)', flush=True)
    time.sleep(3.0)
    vals = []
    for k in range(2):
        p = f'/tmp/dist_{d:03d}_{k}.pgm'
        if capture(p):
            img = read_pgm(p)
            t = tenengrad(img)
            vals.append(t)
            print(f'    frame {k}: Tenengrad(center) {t:8.0f}  mean {img.mean():5.1f} '
                  f'std {img.std():5.1f}  -> {p}', flush=True)
        time.sleep(0.5)
    results.append((d, max(vals) if vals else 0.0))

print()
print('=== SUMMARY (distance cm -> best Tenengrad) ===')
for d, t in results:
    bar = '#' * min(60, int(t / 100))
    print(f'  {d:4d} cm: {t:8.0f}  {bar}')
best = max(results, key=lambda x: x[1])
print(f'\nBest distance: {best[0]} cm (Tenengrad {best[1]:.0f})')
