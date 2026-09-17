#!/usr/bin/env python3
"""Scan sweep: capture frames continuously while the operator slowly moves
the board toward/away from the QR, decoding each frame with BOTH decoders
(rqrr on-device style + zxing on the host) and reporting per-frame focus.

This turns the whole distance range into ONE user session: hold the board
pointing at the QR (centred!), start at the far end, and move slowly and
smoothly toward it until the script says stop.

Usage: cam_scan_sweep.py [seconds] [stride]
"""
import glob
import os
import subprocess
import sys
import time

import numpy as np
from PIL import Image

SECS = int(sys.argv[1]) if len(sys.argv) > 1 else 75
STRIDE = sys.argv[2] if len(sys.argv) > 2 else "2"


def read_pgm(path):
    data = open(path, 'rb').read()
    i = data.index(b'255\n') + 4
    hdr = data[:i].split()
    w = int(hdr[1])
    body = np.frombuffer(data[i:], dtype=np.uint8)
    rows = body.size // w
    return body[:rows * w].reshape(rows, w).astype(np.uint8)


def tenengrad(img):
    f = img.astype(float)
    gx = np.diff(f, axis=1)
    gy = np.diff(f, axis=0)
    return float((gx[:-1] ** 2 + gy[:, :-1] ** 2).mean())


def zxing(img):
    """zxing-cpp (host, robust) via the project venv."""
    p = '/tmp/_sweep_zx.png'
    Image.fromarray(img).save(p)
    code = (
        'import sys,zxingcpp;from PIL import Image;'
        'r=zxingcpp.read_barcodes(Image.open(sys.argv[1]),try_rotate=True,try_downscale=True,'
        'try_invert=True);'
        'print(r[0].text if r else "")'
    )
    out = subprocess.run(['/tmp/qrvenv/bin/python', '-c', code, p],
                         capture_output=True, text=True, timeout=60)
    return out.stdout.strip()


def rqrr(path):
    out = subprocess.run(['/tmp/qrcheck/target/release/pgm_decode', path],
                         capture_output=True, text=True, timeout=60)
    for line in out.stdout.splitlines():
        if 'rqrr + ours : OK' in line:
            return line.split('OK', 1)[1].strip()
    return ''


print(f'scan sweep: {SECS}s — hold the QR CENTRED and move SLOWLY and SMOOTHLY')
print('(far end -> near end; the script reports every frame)')
print()

t0 = time.time()
n = 0
hits = []
while time.time() - t0 < SECS:
    n += 1
    path = f'/tmp/sweep_{n:03d}.pgm'
    r = subprocess.run(
        ['python3', '/home/komo/works/shlosilo-poc4/flux/pico2/bench/cam_dump.py',
         STRIDE, '0', path],
        capture_output=True, text=True, timeout=90)
    if not os.path.exists(path):
        print(f'  frame {n}: capture failed')
        continue
    img = read_pgm(path)
    t = tenengrad(img)
    el = time.time() - t0
    z = ''
    rq = ''
    try:
        z = zxing(img)
    except Exception:
        pass
    if not z:
        try:
            rq = rqrr(path)
        except Exception:
            pass
    tag = ''
    if z:
        tag = f'  <<< ZXING DECODE: {z[:60]!r}'
        hits.append((path, 'zxing', z))
    elif rq:
        tag = f'  <<< RQRR DECODE: {rq[:60]!r}'
        hits.append((path, 'rqrr', rq))
    print(f'  t={el:5.1f}s frame {n:02d} {path}: focus {t:7.0f} '
          f'mean {img.mean():5.1f} std {img.std():5.1f}{tag}', flush=True)

print()
if hits:
    print('=== DECODE HITS ===')
    for p, d, t in hits:
        print(f'  {p} [{d}] {t!r}')
else:
    print('=== no decode in this pass ===')
